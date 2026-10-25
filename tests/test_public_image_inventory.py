"""Host-only synthetic tests; no Docker daemon or container execution."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/inventory-public-image.py'


def load():
    if not SCRIPT.is_file():
        raise AssertionError('scaffold RED: inventory script is absent')
    spec = importlib.util.spec_from_file_location('public_image_inventory', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DB = b'P:musl\nV:1.2.5-r0\nA:x86_64\nL:MIT\no:musl\nc:0123456789abcdef0123456789abcdef01234567\nD:so:libc.musl-x86_64.so.1\nF:usr/share/licenses/musl\nR:COPYRIGHT\n\n'


class Packages(unittest.TestCase):
    def test_actual_records_not_declarations(self):
        m = load()
        packages = m.parse_apk(DB)
        self.assertEqual(len(packages), 1)
        self.assertEqual(packages[0]['name'], 'musl')
        self.assertEqual(packages[0]['version'], '1.2.5-r0')
        self.assertEqual(packages[0]['origin'], 'musl')
        self.assertEqual(packages[0]['source_commit'], '0123456789abcdef0123456789abcdef01234567')
        self.assertEqual(packages[0]['notice_paths'], ['usr/share/licenses/musl/COPYRIGHT'])

    def test_malformed_or_duplicate_package_records_refused(self):
        m = load()
        for data in (b'', DB + DB, DB.replace(b'V:1.2.5-r0\n', b''),
                     DB.replace(b'P:musl', b'P:../musl'),
                     DB.replace(b'c:0123456789abcdef0123456789abcdef01234567', b'c:bad'),
                     DB.replace(b'L:MIT', b'L:MIT\nL:GPL-2.0'), b'not-an-apk-record'):
            with self.subTest(data=data), self.assertRaises(m.InventoryError):
                m.parse_apk(data)


def tar(entries):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w', format=tarfile.USTAR_FORMAT) as tf:
        for name, data, kind in entries:
            member = tarfile.TarInfo(name)
            member.type = kind
            if kind == tarfile.REGTYPE:
                member.size = len(data)
            elif kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                member.linkname = data.decode()
            tf.addfile(member, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    return buf.getvalue()


def image(layers, config=b'PRIVATE-CONFIG-CANARY'):
    names = [('%064x/layer.tar' % (i + 1)) for i in range(len(layers))]
    image_id = 'sha256:' + 'a' * 64
    manifest = json.dumps([dict(Config='a' * 64 + '.json', Layers=names)]).encode()
    # Deliberately unordered layers, with manifest last as in actual docker save.
    blob = tar([(n, data, tarfile.REGTYPE) for n, data in reversed(list(zip(names, layers)))] +
               [('a' * 64 + '.json', config, tarfile.REGTYPE),
                ('manifest.json', manifest, tarfile.REGTYPE)])
    metadata = dict(image_id=image_id, architecture='amd64',
                    layers=['sha256:' + hashlib.sha256(x).hexdigest() for x in layers])
    return io.BytesIO(blob), metadata


class Streaming(unittest.TestCase):
    def test_invalid_image_identity_refused_before_stream_read(self):
        m = load()
        class Unreadable:
            def read(self, size):
                raise AssertionError('stream touched before identity validation')
        for meta in (dict(image_id='a' * 64, architecture='amd64', layers=[]),
                     dict(image_id='sha256:' + 'a' * 64, architecture='arm64', layers=[]),
                     dict(image_id='sha256:' + 'a' * 64, architecture='amd64', layers=['bad'])):
            with self.subTest(meta=meta), self.assertRaises(m.InventoryError):
                m.inventory_stream(Unreadable(), meta)

    def test_whiteout_and_opaque_final_view_in_manifest_not_archive_order(self):
        m = load()
        old = tar([('lib/apk/db/installed', DB.replace(b'1.2.5', b'1.1.1'), tarfile.REGTYPE)])
        for marker in ('lib/apk/db/.wh.installed', 'lib/apk/.wh.db', 'lib/apk/db/.wh..wh..opq'):
            deleted = tar([(marker, b'', tarfile.REGTYPE)])
            stream, meta = image([old, deleted])
            with self.subTest(marker=marker), self.assertRaises(m.InventoryError):
                m.inventory_stream(stream, meta)
            # Whiteouts affect lower layers only, regardless of entry ordering.
            replacement = tar([('lib/apk/db/installed', DB, tarfile.REGTYPE),
                               (marker, b'', tarfile.REGTYPE)])
            stream, meta = image([old, replacement])
            self.assertEqual(m.inventory_stream(stream, meta)['packages'][0]['version'], '1.2.5-r0')

    def test_path_link_digest_and_budget_refusals(self):
        m = load()
        for path, payload, kind in (
            ('../escape', b'bad', tarfile.REGTYPE),
            ('lib/apk/db/installed', b'/private', tarfile.SYMTYPE),
            ('lib/apk/db/installed', b'/private', tarfile.LNKTYPE),
            ('lib/apk/db/installed', b'', tarfile.CHRTYPE),
        ):
            stream, meta = image([tar([(path, payload, kind)])])
            with self.subTest(path=path, kind=kind), self.assertRaises(m.InventoryError):
                m.inventory_stream(stream, meta)
        layer = tar([('lib/apk/db/installed', DB, tarfile.REGTYPE)])
        stream, meta = image([layer])
        meta['layers'] = ['sha256:' + '0' * 64]
        with self.assertRaisesRegex(m.InventoryError, 'digest'):
            m.inventory_stream(stream, meta)
        from unittest.mock import patch
        for field, value in (('MAX_STREAM', 1024), ('MAX_LAYER', 1024), ('MAX_SELECTED', 8)):
            stream, meta = image([layer])
            with self.subTest(field=field), patch.object(m, field, value), self.assertRaises(m.InventoryError):
                m.inventory_stream(stream, meta)

    def test_precise_installed_python_notice_not_general_library_reads(self):
        m = load()
        notice = 'usr/lib/python3.14/LICENSE.txt'
        db = DB + b'P:python3\nV:3.14.8-r0\nA:x86_64\nL:PSF-2.0\no:python3\nF:usr/lib/python3.14\nR:LICENSE.txt\n\n'
        stream, meta = image([tar([('lib/apk/db/installed', db, tarfile.REGTYPE),
                                  (notice, b'Exact installed public notice', tarfile.REGTYPE)])])
        result = m.inventory_stream(stream, meta, [notice])
        self.assertEqual(result['selected_files'][notice]['content'], b'Exact installed public notice')
        self.assertEqual(result['packages'][1]['notice_paths'], [notice])
        self.assertFalse(m.public_notice('usr/lib/python3.14/private.py'))

    def test_malformed_whiteout_and_selected_retention_cap_refused(self):
        m = load()
        layer = tar([('lib/apk/db/.wh.installed', b'not-empty', tarfile.REGTYPE),
                     ('lib/apk/db/installed', DB, tarfile.REGTYPE)])
        stream, meta = image([layer])
        with self.assertRaises(m.InventoryError):
            m.inventory_stream(stream, meta)
    def test_selected_retention_cap_refused(self):
        m = load()
        from unittest.mock import patch
        layer = tar([('lib/apk/db/installed', DB, tarfile.REGTYPE)])
        stream, meta = image([layer])
        original = tarfile.TarFile.extractfile
        acquired = []
        def selected(tf, member):
            acquired.append(member.name)
            return original(tf, member)
        with patch.object(m, 'MAX_RETAINED', 1, create=True), patch.object(tarfile.TarFile, 'extractfile', selected):
            with self.assertRaises(m.InventoryError):
                m.inventory_stream(stream, meta)
        self.assertNotIn('lib/apk/db/installed', acquired)

    def test_unsupported_and_ambiguous_archive_refusals(self):
        m = load()
        layer = tar([('lib/apk/db/installed', DB, tarfile.REGTYPE)])
        for entries in (
            [('index.json', b'{}', tarfile.REGTYPE)],
            [('manifest.json', b'[{}]', tarfile.REGTYPE)],
            [('manifest.json', b'[null]', tarfile.REGTYPE)],
            [('manifest.json', b'[]', tarfile.REGTYPE)],
            [('manifest.json', b'{}', tarfile.REGTYPE)],
        ):
            _, meta = image([layer])
            with self.subTest(entries=entries), self.assertRaises(m.InventoryError):
                m.inventory_stream(io.BytesIO(tar(entries)), meta)
        duplicate = tar([('lib/apk/db/installed', DB, tarfile.REGTYPE),
                         ('lib/apk/db/installed', DB, tarfile.REGTYPE)])
        stream, meta = image([duplicate])
        with self.assertRaisesRegex(m.InventoryError, 'duplicate'):
            m.inventory_stream(stream, meta)
        replacement = tar([('lib/apk', b'/private', tarfile.SYMTYPE)])
        stream, meta = image([layer, replacement])
        with self.assertRaises(m.InventoryError):
            m.inventory_stream(stream, meta)

    def test_notice_selection_refuses_general_and_noncanonical_paths(self):
        m = load()
        for path in ('etc/shadow', 'usr/share/doc/x/../LICENSE', './usr/share/doc/x/LICENSE'):
            layer = tar([('lib/apk/db/installed', DB, tarfile.REGTYPE)])
            stream, meta = image([layer])
            with self.subTest(path=path), self.assertRaises(m.InventoryError):
                m.inventory_stream(stream, meta, [path])

    def test_stream_binds_layers_in_manifest_order_without_config_read(self):
        m = load()
        layer = tar([('lib/apk/db/installed', DB, tarfile.REGTYPE),
                     ('urbit/private-canary', b'NEVER-RETAIN', tarfile.REGTYPE)])
        stream, metadata = image([layer])
        original = tarfile.TarFile.extractfile
        acquired = []
        def selected(tf, member):
            name = member.name if isinstance(member, tarfile.TarInfo) else member
            acquired.append(name)
            if name.endswith('.json') and name != 'manifest.json':
                raise AssertionError('config acquired')
            return original(tf, member)
        from unittest.mock import patch
        with patch.object(tarfile.TarFile, 'extractfile', selected):
            result = m.inventory_stream(stream, metadata)
        self.assertEqual(result['package_count'], 1)
        self.assertEqual(result['packages'][0]['name'], 'musl')
        self.assertEqual(result['selected_files']['lib/apk/db/installed']['content'], DB)
        self.assertNotIn('urbit/private-canary', acquired)
        self.assertNotIn('NEVER-RETAIN', repr(result))


class Collector(unittest.TestCase):
    def test_cli_refuses_nonliteral_image_before_output(self):
        import subprocess
        import os
        import tempfile
        with tempfile.TemporaryDirectory(dir=os.environ.get('IMPORTER_TEST_SCRATCH')) as temp:
            target = Path(temp).resolve() / 'refused'
            completed = subprocess.run([__import__('sys').executable, str(SCRIPT), '--image', 'alpine:latest',
                                        '--output', str(target)], capture_output=True, text=True)
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse(target.exists())

    def test_only_selected_inspect_and_stream_save_commands(self):
        m = load()
        from unittest.mock import patch
        import subprocess
        layer = tar([('lib/apk/db/installed', DB, tarfile.REGTYPE)])
        stream, meta = image([layer])
        class Producer:
            stdout = stream
            returncode = None
            pid = 99999999
            def wait(self, timeout=None):
                self.returncode = 0
                return 0
            def poll(self):
                return self.returncode
        response = subprocess.CompletedProcess([], 0, json.dumps(meta), '')
        with patch.object(m.subprocess, 'run', return_value=response) as inspect, \
                patch.object(m.subprocess, 'Popen', return_value=Producer()) as save:
            result = m.collect(meta['image_id'])
        self.assertEqual(result['package_count'], 1)
        self.assertEqual(inspect.call_count, 2)
        cmd = inspect.call_args.args[0]
        self.assertEqual(cmd[:3], ['docker', 'image', 'inspect'])
        self.assertIn('{{json .Id}}', cmd[4])
        self.assertNotIn('Config', ' '.join(cmd))
        self.assertEqual(save.call_args.args[0], ['docker', 'image', 'save', meta['image_id']])

    def test_metadata_refusal_before_producer_start(self):
        m = load()
        from unittest.mock import patch
        import subprocess
        image_id = 'sha256:' + 'a' * 64
        response = subprocess.CompletedProcess([], 0, json.dumps(dict(image_id=image_id, architecture='arm64', layers=[])), '')
        with patch.object(m.subprocess, 'run', return_value=response), patch.object(m.subprocess, 'Popen') as producer:
            with self.assertRaises(m.InventoryError):
                m.collect(image_id)
            producer.assert_not_called()

    def test_publish_is_exclusive_flat_and_secret_free(self):
        m = load()
        import os
        import tempfile
        with tempfile.TemporaryDirectory(dir=os.environ.get('IMPORTER_TEST_SCRATCH')) as temp:
            root = Path(temp).resolve() / 'new'
            stream, meta = image([tar([('lib/apk/db/installed', DB, tarfile.REGTYPE)])])
            result = m.inventory_stream(stream, meta)
            m.publish(result, str(root))
            saved = json.loads((root / 'inventory.json').read_text())
            self.assertEqual(saved['package_count'], 1)
            self.assertEqual((root / 'installed-apk-db.txt').read_bytes(), DB)
            self.assertNotIn('content', saved['selected_files'][m.DB_PATH])
            with self.assertRaises(FileExistsError):
                m.publish(result, str(root))


if __name__ == '__main__':
    unittest.main()
