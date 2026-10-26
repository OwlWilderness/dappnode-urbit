"""Synthetic owner-CA tests; no owner credentials or target state."""
import hashlib
import importlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
import fcntl
import json
import time
import base64

BASE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE / 'src/manager'))
SCRATCH = Path(os.environ.get('IMPORTER_TEST_SCRATCH') or tempfile.gettempdir()).resolve()
NAMES = ('admin.example.test', 'ship.example.test')
OPENSSL = next((p for p in ('/opt/homebrew/opt/openssl@3/bin/openssl', '/usr/local/opt/openssl@3/bin/openssl', shutil.which('openssl')) if p and Path(p).is_file()), None)
ENV = {k: v for k, v in os.environ.items() if not k.startswith(('OPENSSL_', 'SSL_CERT_', 'SSLKEYLOG'))}
ENV.update(OPENSSL_CONF='/dev/null', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')


def openssl(*args):
    assert OPENSSL, 'OpenSSL 3 is required'
    result = subprocess.run([OPENSSL, *map(str, args)], env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if result.returncode:
        raise AssertionError('Synthetic OpenSSL fixture operation failed')
    return result.stdout


class OwnerTLS(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='owner-tls-test-', dir=SCRATCH)
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.control = self.base / 'control'
        self.ca = self.base / 'root.pem'
        self.ca_key = self.base / 'root.key'
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=Synthetic owner CA', '-days', '2', '-keyout', self.ca_key, '-out', self.ca, '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0', '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
        self.pin = hashlib.sha256(openssl('x509', '-in', self.ca, '-outform', 'DER')).hexdigest()

    def ensure(self, names=NAMES, pin=None):
        self.assertTrue((BASE / 'src/manager/owner_tls.py').is_file(), 'Owner TLS implementation missing (scaffold RED)')
        return importlib.import_module('owner_tls').ensure_owner_tls(self.control, names, pin or self.pin)

    def sign(self, request, names=NAMES, days='1', key=None, extra=''):
        ext = self.base / 'leaf.ext'
        ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\nsubjectAltName=' + ','.join('DNS:' + n for n in names) + '\n' + extra)
        exchange = self.control / 'owner-tls-public'
        shutil.copyfile(self.ca, exchange / 'root-ca.pem')
        if days in ('-1', 'future'):
            (self.base / 'index').write_text('')
            (self.base / 'serial').write_text('10\n')
            config = self.base / 'ca.cnf'
            config.write_text('[ca]\ndefault_ca=ca_default\n[ca_default]\ndatabase=' + str(self.base / 'index') + '\nserial=' + str(self.base / 'serial') + '\nnew_certs_dir=' + str(self.base) + '\ndefault_md=sha256\npolicy=policy\n[policy]\ncommonName=supplied\n')
            start, end = ('20000101000000Z', '20000102000000Z') if days == '-1' else ('20990101000000Z', '20990102000000Z')
            openssl('ca', '-batch', '-notext', '-config', config, '-in', request, '-cert', self.ca, '-keyfile', self.ca_key, '-startdate', start, '-enddate', end, '-extfile', ext, '-out', exchange / 'server.pem')
        else:
            openssl('x509', '-req', '-in', request, '-CA', self.ca, '-CAkey', key or self.ca_key, '-set_serial', '17', '-days', days, '-extfile', ext, '-out', exchange / 'server.pem')
        for name in ('root-ca.pem', 'server.pem'):
            (exchange / name).chmod(0o644)

    def test_wrong_pin_refused(self):
        pending = self.ensure(pin='0' * 64)
        self.sign(pending['request'])
        with self.assertRaises(ValueError):
            self.ensure(pin='0' * 64)

    def test_wrong_names_refused(self):
        pending = self.ensure()
        self.sign(pending['request'], names=('wrong.example.test', NAMES[1]))
        with self.assertRaises(ValueError):
            self.ensure()

    def test_wrong_key_refused(self):
        pending = self.ensure()
        other = self.base / 'other.csr'
        openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=Synthetic other', '-keyout', self.base / 'other.key', '-out', other)
        self.sign(other)
        with self.assertRaises(ValueError):
            self.ensure()

    def test_expired_refused(self):
        pending = self.ensure()
        self.sign(pending['request'], days='-1')
        with self.assertRaises(ValueError):
            self.ensure()

    def test_extra_san_refused(self):
        pending = self.ensure()
        self.sign(pending['request'], names=(*NAMES, 'extra.example.test'))
        with self.assertRaises(ValueError):
            self.ensure()

    def test_ca_leaf_refused(self):
        pending = self.ensure()
        self.sign(pending['request'], extra='basicConstraints=critical,CA:TRUE\n')
        with self.assertRaises(ValueError):
            self.ensure()

    def test_client_only_refused(self):
        pending = self.ensure()
        self.sign(pending['request'], extra='extendedKeyUsage=clientAuth\n')
        with self.assertRaises(ValueError):
            self.ensure()

    def test_settings_replay_refused_before_upload(self):
        self.ensure()
        for names, pin in ((NAMES[::-1], self.pin), (NAMES, 'f' * 64)):
            with self.subTest(names=names, pin=pin):
                with self.assertRaises(ValueError):
                    self.ensure(names=names, pin=pin)

    def test_invalid_settings_no_creation(self):
        for names, pin in ((('UPPER.test', NAMES[1]), self.pin), ((NAMES[0], NAMES[0]), self.pin), (('*.test', NAMES[1]), self.pin), (NAMES, self.pin.upper()), (NAMES, 'xyz'), (('127.0.0.1', NAMES[1]), self.pin)):
            with self.subTest(names=names):
                with self.assertRaises(ValueError):
                    self.ensure(names=names, pin=pin)
                self.assertFalse(self.control.exists())

    def test_parent_traversal_path_refused(self):
        original = self.control
        self.control = original / '..' / original.name
        with self.assertRaises(ValueError):
            self.ensure()
        self.assertFalse(original.exists())

    def test_private_permissions_not_repaired(self):
        pending = self.ensure()
        Path(pending['key']).chmod(0o644)
        with self.assertRaises(ValueError):
            self.ensure()
        self.assertEqual(Path(pending['key']).stat().st_mode & 0o777, 0o644)

    def test_upload_symlink_refused(self):
        pending = self.ensure()
        self.sign(pending['request'])
        root = self.control / 'owner-tls-public/root-ca.pem'
        root.unlink()
        root.symlink_to(self.ca)
        with self.assertRaises(ValueError):
            self.ensure()

    def test_upload_writable_refused(self):
        pending = self.ensure()
        self.sign(pending['request'])
        (self.control / 'owner-tls-public/server.pem').chmod(0o666)
        with self.assertRaises(ValueError):
            self.ensure()

    def test_upload_extra_pem_refused(self):
        pending = self.ensure()
        self.sign(pending['request'])
        leaf = self.control / 'owner-tls-public/server.pem'
        leaf.write_bytes(leaf.read_bytes() + self.ca.read_bytes())
        with self.assertRaises(ValueError):
            self.ensure()

    def test_oversize_incomplete_upload_refused(self):
        self.ensure()
        (self.control / 'owner-tls-public/server.pem').write_bytes(b'x' * 65537)
        with self.assertRaises(ValueError):
            self.ensure()

    def test_invalid_incomplete_upload_refused(self):
        self.ensure()
        (self.control / 'owner-tls-public/server.pem').write_text('not a certificate')
        with self.assertRaises(ValueError):
            self.ensure()

    def test_wrong_name_leaf_without_root_refused(self):
        pending = self.ensure()
        self.sign(pending['request'], names=('wrong.example.test', NAMES[1]))
        (self.control / 'owner-tls-public/root-ca.pem').unlink()
        with self.assertRaises(ValueError):
            self.ensure()

    def test_non_ca_root_alone_refused(self):
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=Not a CA', '-days', '2', '-keyout', self.base / 'nonca.key', '-out', self.ca, '-addext', 'basicConstraints=critical,CA:FALSE')
        self.pin = hashlib.sha256(openssl('x509', '-in', self.ca, '-outform', 'DER')).hexdigest()
        self.ensure()
        shutil.copyfile(self.ca, self.control / 'owner-tls-public/root-ca.pem')
        with self.assertRaises(ValueError):
            self.ensure()

    def test_leaf_future_without_root_refused(self):
        pending = self.ensure()
        self.sign(pending['request'], days='future')
        (self.control / 'owner-tls-public/root-ca.pem').unlink()
        with self.assertRaises(ValueError):
            self.ensure()

    def test_missing_valid_pair_awaits(self):
        self.ensure()
        shutil.copyfile(self.ca, self.control / 'owner-tls-public/root-ca.pem')
        self.assertEqual(self.ensure()['state'], 'AWAITING_CERTIFICATE')

    def test_partial_state_never_regenerates(self):
        pending = self.ensure()
        Path(pending['request']).unlink()
        before = Path(pending['key']).stat().st_ino
        with self.assertRaises(ValueError):
            self.ensure()
        self.assertEqual(Path(pending['key']).stat().st_ino, before)

    def test_ready_upload_replacement_refused(self):
        pending = self.ensure()
        self.sign(pending['request'])
        self.ensure()
        self.sign(pending['request'], days='2')
        with self.assertRaises(ValueError):
            self.ensure()

    def test_ready_survives_upload_removal(self):
        pending = self.ensure()
        self.sign(pending['request'])
        ready = self.ensure()
        (self.control / 'owner-tls-public/root-ca.pem').unlink()
        (self.control / 'owner-tls-public/server.pem').unlink()
        self.assertEqual(self.ensure(), ready)

    def test_concurrent_initialization_single_key(self):
        self.control.mkdir(mode=0o700)
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.ensure(), range(4)))
        self.assertTrue(all(result == results[0] for result in results))

    def test_openssl3_required_before_creation(self):
        module = importlib.import_module('owner_tls')
        real = module._openssl
        def old_version(*args, **kwargs):
            return b'OpenSSL 1.1.1t\n' if args == ('version',) else real(*args, **kwargs)
        with patch.object(module, '_openssl', side_effect=old_version):
            with self.assertRaises(ValueError):
                self.ensure()
        self.assertFalse(self.control.exists())

    def test_long_canonical_dns_uses_san_not_cn_limit(self):
        names = ('a' * 63 + '.long.example.test', NAMES[1])
        pending = self.ensure(names=names)
        self.sign(pending['request'], names=names)
        self.assertEqual(self.ensure(names=names)['state'], 'READY')

    def test_snapshot_tamper_refused(self):
        pending = self.ensure()
        self.sign(pending['request'])
        ready = self.ensure()
        leaf = Path(ready['certificate'])
        leaf.chmod(0o600)
        leaf.write_bytes(leaf.read_bytes() + b'\n')
        leaf.chmod(0o444)
        with self.assertRaises(ValueError):
            self.ensure()

    def test_partial_validation_stage_locks(self):
        self.ensure()
        (self.control / 'owner-tls/.validate').mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            self.ensure()

    def test_deleted_snapshot_does_not_reenroll(self):
        pending = self.ensure()
        self.sign(pending['request'])
        ready = self.ensure()
        shutil.rmtree(Path(ready['certificate']).parent)
        with self.assertRaises(ValueError):
            self.ensure()

    def test_lock_symlink_refused(self):
        self.control.mkdir(mode=0o700)
        (self.control / '.owner-tls.lock').symlink_to(self.ca)
        with self.assertRaises(ValueError):
            self.ensure()
        self.assertFalse((self.control / 'owner-tls').exists())

    def test_public_directory_symlink_refused(self):
        self.ensure()
        public = self.control / 'owner-tls-public'
        public.rename(self.base / 'exchange')
        public.symlink_to(self.base / 'exchange')
        with self.assertRaises(ValueError):
            self.ensure()

    def test_wrong_signer_refused(self):
        pending = self.ensure()
        trusted = self.ca.read_bytes()
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=Synthetic owner CA', '-days', '2', '-keyout', self.ca_key, '-out', self.ca, '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0', '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
        self.sign(pending['request'])
        (self.control / 'owner-tls-public/root-ca.pem').write_bytes(trusted)
        with self.assertRaises(ValueError):
            self.ensure()

    def test_pinned_root_invalid_self_signature_refused(self):
        der = bytearray(openssl('x509', '-in', self.ca, '-outform', 'DER'))
        der[-1] ^= 1
        encoded = base64.b64encode(der)
        self.ca.write_bytes(b'-----BEGIN CERTIFICATE-----\n' + b'\n'.join(encoded[i:i+64] for i in range(0, len(encoded), 64)) + b'\n-----END CERTIFICATE-----\n')
        self.pin = hashlib.sha256(der).hexdigest()
        self.ensure()
        shutil.copyfile(self.ca, self.control / 'owner-tls-public/root-ca.pem')
        with self.assertRaises(ValueError):
            self.ensure()

    def test_failed_atomic_commit_retains_uncertain_state(self):
        pending = self.ensure()
        self.sign(pending['request'])
        module = importlib.import_module('owner_tls')
        with patch.object(module, 'rename_without_replace', side_effect=module.StorageError('synthetic refusal')):
            with self.assertRaises(ValueError):
                self.ensure()
        self.assertFalse((self.control / 'owner-tls/validated').exists())
        self.assertTrue((self.control / 'owner-tls/.validate').is_dir())
        with self.assertRaises(ValueError):
            self.ensure()

    def test_inherited_tls_overrides_are_disabled(self):
        with patch.dict(os.environ, {'OPENSSL_CONF': str(self.base / 'nonexistent-config'), 'SSL_CERT_FILE': str(self.base / 'nonexistent-ca'), 'SSL_CERT_DIR': str(self.base / 'nonexistent-dir'), 'SSLKEYLOGFILE': str(self.base / 'keylog')}):
            pending = self.ensure()
            self.sign(pending['request'])
            self.assertEqual(self.ensure()['state'], 'READY')
        self.assertFalse((self.base / 'keylog').exists())

    def test_owner_key_upload_refused_without_read(self):
        self.ensure()
        (self.control / 'owner-tls-public/root.key').write_text('not actually a key')
        with self.assertRaises(ValueError):
            self.ensure()

    def test_invalid_upload_can_be_corrected_before_activation(self):
        pending = self.ensure()
        self.sign(pending['request'], names=('wrong.example.test', NAMES[1]))
        with self.assertRaises(ValueError):
            self.ensure()
        self.sign(pending['request'])
        self.assertEqual(self.ensure()['state'], 'READY')

    def test_fresh_process_waits_for_permanent_lock_then_reuses(self):
        pending = self.ensure()
        self.sign(pending['request'])
        ready = self.ensure()
        lock_path = self.control / '.owner-tls.lock'
        inode = lock_path.stat().st_ino
        with lock_path.open('rb') as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            script = 'import sys,json; sys.path.insert(0,sys.argv[1]); from owner_tls import ensure_owner_tls; print(json.dumps(ensure_owner_tls(sys.argv[2],json.loads(sys.argv[3]),sys.argv[4])))'
            child = subprocess.Popen([sys.executable, '-c', script, str(BASE / 'src/manager'), str(self.control), json.dumps(NAMES), self.pin], env=ENV, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            try:
                time.sleep(0.15)
                self.assertIsNone(child.poll())
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
                output, _ = child.communicate(timeout=15)
                self.assertEqual(child.returncode, 0)
                self.assertEqual(json.loads(output), ready)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate()
        self.assertEqual(lock_path.stat().st_ino, inode)

    def test_csr_owner_signature_ready_restart(self):
        pending = self.ensure()
        self.assertEqual(pending['state'], 'AWAITING_CERTIFICATE')
        self.assertIsNone(pending['certificate'])
        openssl('req', '-in', pending['request'], '-verify', '-noout')
        self.sign(pending['request'])
        ready = self.ensure()
        self.assertEqual(ready['state'], 'READY')
        self.assertEqual(ready, self.ensure())
        self.assertEqual(Path(ready['key']).stat().st_mode & 0o777, 0o600)
        self.assertEqual(Path(ready['certificate']).stat().st_mode & 0o777, 0o444)
        self.assertEqual(Path(ready['ca']).stat().st_mode & 0o777, 0o444)
        self.assertNotEqual(Path(ready['ca']).parent, self.control / 'owner-tls-public')


if __name__ == '__main__':
    unittest.main()
