"""Host-only synthetic Docker-save fixtures; never contact an engine."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'tools/local-candidate/verify_image.py'
DB = b'P:musl\nV:1-r0\nA:x86_64\nL:MIT\no:musl\n\n'
DOC = 'usr/share/doc/uvm/LICENSE.md'
MANIFEST = 'usr/share/doc/uvm/notice-files.json'
ELF = b'\x7fELF\x02\x01' + b'\0' * 12 + b'\x3e\0' + b'\0' * 44


def load():
    if not SCRIPT.is_file():
        raise AssertionError('scaffold RED: candidate verifier missing')
    spec = importlib.util.spec_from_file_location('candidate_verifier', SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(data):
    return hashlib.sha256(data).hexdigest()


def tar(entries):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, data, kind, mode, uid, gid in entries:
            item = tarfile.TarInfo(name)
            item.type, item.mode, item.uid, item.gid = kind, mode, uid, gid
            if kind == tarfile.REGTYPE:
                item.size = len(data)
            elif kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                item.linkname = '/urbit/private'
            archive.addfile(item, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    return out.getvalue()


def fixture(overrides=None, omit=()):
    raw = json.dumps({'schema_version': 1, 'destination': '/usr/share/doc/uvm',
                      'files': {'LICENSE.md': sha(b'public notice')}}).encode()
    data = {DOC: b'public notice', MANIFEST: raw, 'opt/importer/runtime.py': b'public code',
            'bin/urbit': ELF, 'lib/apk/db/installed': DB}
    contract = {'manifest_sha256': sha(raw), 'manifest_bytes': raw,
                'notice_count': 1, 'dockerfile_sha256': sha(b'Dockerfile'),
                'files': {p: {'sha256': sha(value), 'size': len(value),
                              'role': 'notice' if p == DOC else 'manifest' if p == MANIFEST
                              else 'elf' if p == 'bin/urbit' else 'code',
                              'source': 'LICENSE.md' if p == DOC else 'build/notice-files.json'
                              if p == MANIFEST else 'build/vere-release.json' if p == 'bin/urbit'
                              else 'tools/browser-importer/runtime.py'}
                          for p, value in data.items() if p != 'lib/apk/db/installed'}}
    entries = {}
    for path, content in data.items():
        for parent in Path(path).parents:
            if str(parent) != '.':
                entries[str(parent)] = (str(parent), b'', tarfile.DIRTYPE, 0o755, 0, 0)
        mode = 0o444 if path in (DOC, MANIFEST) else 0o555 if path == 'bin/urbit' else 0o644
        entries[path] = (path, content, tarfile.REGTYPE, mode, 0, 0)
    entries['urbit/private-canary'] = ('urbit/private-canary', b'NEVER-RETAIN', tarfile.REGTYPE, 0o600, 10000, 10000)
    for name, entry in (overrides or {}).items():
        entries[name] = entry
    for name in omit:
        entries.pop(name)
    layer = tar(list(entries.values()))
    layer_name = '1' * 64 + '/layer.tar'
    image_id = 'sha256:' + 'a' * 64
    outer_manifest = json.dumps([{'Config': 'a' * 64 + '.json', 'Layers': [layer_name]}]).encode()
    blob = tar([(layer_name, layer, tarfile.REGTYPE, 0o644, 0, 0),
                ('a' * 64 + '.json', b'PRIVATE-CONFIG-CANARY', tarfile.REGTYPE, 0o644, 0, 0),
                ('manifest.json', outer_manifest, tarfile.REGTYPE, 0o644, 0, 0)])
    metadata = {'image_id': image_id, 'architecture': 'amd64', 'layers': ['sha256:' + sha(layer)]}
    return io.BytesIO(blob), metadata, contract


class CandidateVerifier(unittest.TestCase):
    def test_small_real_stream_verifies_exact_files_and_packages(self):
        m = load()
        stream, metadata, contract = fixture()
        result = m.verify_stream(stream, metadata, contract)
        self.assertEqual(result['status'], 'PASS_SELECTED_CANDIDATE_FILES')
        self.assertEqual(result['package_count'], 1)
        self.assertEqual(result['packages'][0]['name'], 'musl')
        self.assertEqual(len(result['selected_files']), 5)
        self.assertFalse(result['config_parsed'])
        self.assertFalse(result['container_executed'])
        self.assertFalse(result['unexpected_image_files_checked'])
        self.assertNotIn('content', repr(result['selected_files']))
        self.assertNotIn('NEVER-RETAIN', repr(result))
        self.assertNotIn('PRIVATE-CONFIG-CANARY', repr(result))
        self.assertEqual(result['_installed_apk_db'], DB)

    def test_shell_entrypoint_requires_service_read_not_execute_permission(self):
        m = load()
        path = 'usr/local/bin/docker-entrypoint.sh'
        content = b'#!/bin/sh\nexec python3 /opt/importer/package_service.py "$@"\n'
        for mode in (0o644, 0o400):
            stream, metadata, contract = fixture({
                'usr/local': ('usr/local', b'', tarfile.DIRTYPE, 0o755, 0, 0),
                'usr/local/bin': ('usr/local/bin', b'', tarfile.DIRTYPE, 0o755, 0, 0),
                path: (path, content, tarfile.REGTYPE, mode, 0, 0)})
            contract['files'][path] = {'sha256': sha(content), 'size': len(content),
                                      'role': 'code', 'source': 'build/docker-entrypoint.sh'}
            with self.subTest(mode=mode):
                if mode == 0o644:
                    self.assertEqual(m.verify_stream(stream, metadata, contract)['status'],
                                     'PASS_SELECTED_CANDIDATE_FILES')
                else:
                    with self.assertRaises(ValueError):
                        m.verify_stream(stream, metadata, contract)


    def test_hash_mode_owner_and_missing_path_drift_refused(self):
        m = load()
        bad_entries = [
            (DOC, b'changed', tarfile.REGTYPE, 0o444, 0, 0),
            (MANIFEST, b'{"files":{"urbit/private":"bad"}}', tarfile.REGTYPE, 0o444, 0, 0),
            (DOC, b'public notice', tarfile.REGTYPE, 0o644, 0, 0),
            (DOC, b'public notice', tarfile.REGTYPE, 0o440, 0, 0),
            (DOC, b'public notice', tarfile.REGTYPE, 0o444, 10000, 0),
            (DOC, b'public notice', tarfile.REGTYPE, 0o444, 0, 10000),
            ('usr/share/doc', b'', tarfile.DIRTYPE, 0o777, 0, 0),
            ('usr/share/doc', b'', tarfile.DIRTYPE, 0o750, 0, 0),
            ('usr/share/doc', b'', tarfile.DIRTYPE, 0o755, 10000, 0),
            (DOC, b'', tarfile.SYMTYPE, 0o444, 0, 0),
            ('usr/share/doc', b'', tarfile.SYMTYPE, 0o755, 0, 0),
            ('bin/urbit', ELF, tarfile.REGTYPE, 0o444, 0, 0),
            ('opt/importer/runtime.py', b'public code', tarfile.REGTYPE, 0o666, 0, 0),
        ]
        for entry in bad_entries:
            stream, metadata, contract = fixture({entry[0]: entry})
            with self.subTest(path=entry[0], mode=entry[3], uid=entry[4]), self.assertRaises(ValueError):
                m.verify_stream(stream, metadata, contract)
        for name in (DOC, MANIFEST, 'usr/share/doc', 'lib/apk/db/installed'):
            stream, metadata, contract = fixture(omit=[name])
            with self.subTest(missing=name), self.assertRaises(ValueError):
                m.verify_stream(stream, metadata, contract)

    def test_private_or_noncanonical_selection_refused_before_read(self):
        m = load()
        class Unreadable:
            def read(self, size):
                raise AssertionError('read before allowlist validation')
        for path in ('urbit/control/auth.json', 'etc/shadow', 'usr/share/doc/uvm/../../private',
                     'opt/importer/not-selected.py', 'usr/share/doc/uvm/unknown.txt',
                     './usr/share/doc/uvm/LICENSE.md'):
            _, metadata, contract = fixture()
            contract['files'][path] = dict(contract['files'][DOC])
            with self.subTest(path=path), self.assertRaises(ValueError):
                m.verify_stream(Unreadable(), metadata, contract)


    def test_contract_uses_actual_dockerfile_and_all_frozen_notice_hashes(self):
        m = load()
        contract = m.build_contract(ROOT)
        self.assertEqual(contract['notice_count'], 395)
        self.assertEqual(contract['files']['opt/importer/runtime.py']['source'], 'tools/browser-importer/runtime.py')
        self.assertEqual(contract['files']['usr/local/bin/docker-entrypoint.sh']['source'], 'build/docker-entrypoint.sh')
        self.assertEqual(contract['files']['bin/urbit']['sha256'],
                         '47ad302e8934271dfc00dcdab1d553c6d6460b105e3099ff47e0e4e4231bb26d')
        self.assertEqual(contract['files']['bin/urbit']['size'], 24044936)
        self.assertEqual(sum(v['role'] == 'code' for v in contract['files'].values()), 16)
        self.assertEqual(len(contract['files']), 413)
        self.assertEqual(contract['dockerfile_sha256'], sha((ROOT / 'build/Dockerfile').read_bytes()))
        self.assertEqual(m.load_parser().MAX_SELECTED, 32 * 1024**2)


    def test_config_and_unselected_payloads_never_extracted(self):
        m = load()
        stream, metadata, contract = fixture()
        acquired = []
        original = tarfile.TarFile.extractfile
        def selected(archive, member):
            acquired.append(member.name)
            if member.name not in {*contract['files'], 'lib/apk/db/installed', 'manifest.json', '1' * 64 + '/layer.tar'}:
                raise AssertionError('unselected payload acquired')
            return original(archive, member)
        with patch.object(tarfile.TarFile, 'extractfile', selected):
            result = m.verify_stream(stream, metadata, contract)
        self.assertNotIn('a' * 64 + '.json', acquired)
        self.assertNotIn('urbit/private-canary', acquired)
        self.assertNotIn('NEVER-RETAIN', repr(result))

    def test_collector_only_inspects_public_leaves_and_streams_with_no_container(self):
        m = load()
        stream, metadata, contract = fixture()
        class Producer:
            stdout = stream
            pid = 99999999
            returncode = None
            def poll(self):
                return self.returncode
            def wait(self, timeout=None):
                self.returncode = 0
                return 0
        import subprocess
        response = subprocess.CompletedProcess([], 0, json.dumps(metadata), '')
        with patch.object(m, 'build_contract', return_value=contract), \
                patch.object(subprocess, 'run', return_value=response) as inspect, \
                patch.object(subprocess, 'Popen', return_value=Producer()) as save:
            result = m.collect(metadata['image_id'], ROOT)
        self.assertEqual(inspect.call_count, 2)
        cmd = inspect.call_args.args[0]
        self.assertEqual(cmd[:4], ['docker', 'image', 'inspect', '--format'])
        self.assertNotIn('Config', cmd[4])
        self.assertEqual(set(json.loads(response.stdout)), {'image_id', 'architecture', 'layers'})
        self.assertEqual(save.call_args.args[0], ['docker', 'image', 'save', metadata['image_id']])
        self.assertIs(save.call_args.kwargs['stderr'], subprocess.DEVNULL)
        self.assertIs(save.call_args.kwargs['stdout'], subprocess.PIPE)
        self.assertTrue(save.call_args.kwargs['start_new_session'])
        self.assertEqual(result['package_count'], 1)

    def test_publish_keeps_only_flat_metadata_and_exact_apk_db(self):
        m = load()
        stream, metadata, contract = fixture()
        result = m.verify_stream(stream, metadata, contract)
        with tempfile.TemporaryDirectory(dir=os.environ.get('IMPORTER_TEST_SCRATCH')) as temp:
            output = Path(temp).resolve() / 'evidence'
            m.publish(result, output)
            self.assertEqual({p.name for p in output.iterdir()}, {'inventory.json', 'installed-apk-db.txt'})
            saved = json.loads((output / 'inventory.json').read_text())
            self.assertEqual(saved['package_count'], 1)
            self.assertNotIn('_installed_apk_db', saved)
            self.assertEqual((output / 'installed-apk-db.txt').read_bytes(), DB)
            self.assertNotIn('public code', (output / 'inventory.json').read_text())
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            self.assertEqual((output / 'inventory.json').stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                m.publish(result, output)
            link = Path(temp).resolve() / 'link'
            link.symlink_to(output, target_is_directory=True)
            with self.assertRaises(OSError):
                m.publish(result, link / 'no-write')
            self.assertFalse((output / 'no-write').exists())


    def test_cli_refusal_is_sanitized_and_precedes_any_docker_call(self):
        m = load()
        import contextlib
        with tempfile.TemporaryDirectory(dir=os.environ.get('IMPORTER_TEST_SCRATCH')) as temp:
            output = Path(temp).resolve() / 'new'
            args = ['--image', 'alpine:latest', '--source-root', str(ROOT), '--output', str(output)]
            stderr, stdout = io.StringIO(), io.StringIO()
            with patch.object(m, 'collect') as collect, contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
                code = m.main(args)
            self.assertEqual(code, 1)
            collect.assert_not_called()
            self.assertFalse(output.exists())
            self.assertEqual(stdout.getvalue(), '')
            self.assertEqual(stderr.getvalue(), 'REFUSED: candidate public-file verification failed\n')
            args[1] = 'sha256:' + 'a' * 64
            with patch.object(m, 'collect', side_effect=ValueError('SECRET-CANARY')), \
                    contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
                self.assertEqual(m.main(args), 1)
            self.assertNotIn('SECRET-CANARY', stderr.getvalue())
            self.assertFalse(output.exists())

    def test_elf_byte_limit_refuses_before_payload_acquisition(self):
        m = load()
        stream, metadata, contract = fixture({'bin/urbit': ('bin/urbit', ELF + b'x' * 100, tarfile.REGTYPE, 0o555, 0, 0)})
        acquired = []
        original = tarfile.TarFile.extractfile
        def record(archive, member):
            acquired.append(member.name)
            return original(archive, member)
        with patch.object(m, 'MAX_ELF', 80), patch.object(tarfile.TarFile, 'extractfile', record):
            with self.assertRaises(ValueError):
                m.verify_stream(stream, metadata, contract)
        self.assertNotIn('bin/urbit', acquired)


    def test_layer_binding_whiteouts_and_parser_defaults_remain_fail_closed(self):
        m = load()
        stream, metadata, contract = fixture()
        metadata['layers'] = ['sha256:' + '0' * 64]
        with self.assertRaisesRegex(ValueError, 'RootFS'):
            m.verify_stream(stream, metadata, contract)
        stream, metadata, contract = fixture()
        blob = stream.getvalue().replace(b'"Config": "' + b'a' * 64, b'"Config": "' + b'b' * 64)
        with self.assertRaisesRegex(ValueError, 'filename'):
            m.verify_stream(io.BytesIO(blob), metadata, contract)
        stream, metadata, contract = fixture({'usr/share/doc/uvm/.wh.LICENSE.md':
            ('usr/share/doc/uvm/.wh.LICENSE.md', b'', tarfile.REGTYPE, 0o000, 0, 0)})
        # Same-layer whiteout does not delete a file created in that layer.
        self.assertEqual(m.verify_stream(stream, metadata, contract)['notice_count'], 1)
        original = importlib.util.spec_from_file_location('unchanged_inventory', ROOT / 'scripts/inventory-public-image.py')
        assert original is not None and original.loader is not None
        parser = importlib.util.module_from_spec(original)
        original.loader.exec_module(parser)
        self.assertEqual(parser.MAX_SELECTED, 8 * 1024**2)
        self.assertEqual(parser.MAX_RETAINED, 16 * 1024**2)
        self.assertFalse(parser.public_notice('opt/importer/runtime.py'))

    def test_existing_output_and_unknown_arguments_refuse_without_payload_echo(self):
        m = load()
        import contextlib
        with tempfile.TemporaryDirectory(dir=os.environ.get('IMPORTER_TEST_SCRATCH')) as temp:
            args = ['--image', 'sha256:' + 'a' * 64, '--source-root', str(ROOT), '--output', temp]
            err = io.StringIO()
            with patch.object(m, 'collect') as collect, contextlib.redirect_stderr(err):
                self.assertEqual(m.main(args), 1)
            collect.assert_not_called()
            with contextlib.redirect_stderr(err):
                self.assertEqual(m.main(args + ['--unknown', 'SECRET-CANARY']), 1)
            self.assertNotIn('SECRET-CANARY', err.getvalue())


    def test_main_success_publishes_only_the_selected_receipt(self):
        m = load()
        import contextlib
        stream, metadata, contract = fixture()
        result = m.verify_stream(stream, metadata, contract)
        with tempfile.TemporaryDirectory(dir=os.environ.get('IMPORTER_TEST_SCRATCH')) as temp:
            output = Path(temp).resolve() / 'new'
            stdout = io.StringIO()
            with patch.object(m, 'collect', return_value=result), contextlib.redirect_stdout(stdout):
                code = m.main(['--image', metadata['image_id'], '--source-root', str(ROOT), '--output', str(output)])
            self.assertEqual(code, 0)
            receipt = json.loads(stdout.getvalue())
            self.assertEqual(receipt['package_count'], 1)
            self.assertEqual(receipt['selected_file_count'], 5)
            self.assertEqual(set(receipt), {'status', 'notice_count', 'selected_file_count', 'package_count',
                                            'layer_count', 'config_parsed', 'container_executed'})
            self.assertEqual(json.loads((output / 'inventory.json').read_text())['status'], receipt['status'])


if __name__ == '__main__':
    unittest.main()
