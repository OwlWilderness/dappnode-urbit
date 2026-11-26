import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
import tempfile
import io
import struct

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / 'tools/issue3_fresh_attempt/owned_report.py'


class OwnedReportTests(unittest.TestCase):
    def module(self):
        self.assertTrue(MODULE.is_file(), 'owned report successor missing (scaffold RED)')
        spec = importlib.util.spec_from_file_location('owned_report', MODULE)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_owned_schema_not_obsolete_default_heap_flags(self):
        m = self.module()
        build = dict(status='COMPILE_PASS', attempt=m.BUILD_ATTEMPT,
                     build_exit_code=0, artifact_complete=True, settled=True,
                     build_launched=True, error=None)
        static = dict(status='PASS', architecture='linux/amd64',
                      executable_sha256=m.SHA, executable_bytes=m.SIZE,
                      owned_callbacks_registered=True, gmp_registration_retained=True,
                      normal_libc_cleanup_retained=True, openssl_cleanup_linked=True,
                      source_receipts_verified=True, frozen_recipe_verified=True,
                      no_uvm_i3_symbols=True, static_no_interp_or_dynamic=True,
                      vere_executed=False)
        self.assertTrue(m.validate_owned_receipts(build, static))
        for key in ('settled', 'artifact_complete'):
            bad = dict(build, **{key: False})
            with self.assertRaises(ValueError):
                m.validate_owned_receipts(bad, static)
        for key in ('owned_callbacks_registered', 'source_receipts_verified'):
            bad = dict(static, **{key: False})
            with self.assertRaises(ValueError):
                m.validate_owned_receipts(build, bad)

    def test_static_callback_addresses_not_disassembler_annotations(self):
        m = self.module()
        symbols = {'u3_openssl_arena_malloc': 0x17018f0,
                   'u3_openssl_arena_realloc': 0x17019d0,
                   'u3_openssl_arena_free': 0x1701e20}
        text = ('movl\t$0x17018f0, %edi\n'
                'movl\t$0x17019d0, %esi\n'
                'movl\t$0x1701e20, %edx\n'
                'callq\t0x1357b70 <CRYPTO_set_mem_functions>')
        self.assertTrue(m.callback_arguments(text, symbols))
        self.assertFalse(m.callback_arguments(text.replace('17018f0', '17018f1'), symbols))
        self.assertFalse(m.callback_arguments(text.replace('%edi', '%esi'), symbols))
        self.assertFalse(m.callback_arguments(text.replace('CRYPTO_set_mem_functions', 'other'), symbols))

    def test_report_versions_exact_and_duplicate_rejected(self):
        m = self.module()
        self.assertTrue(hasattr(m, 'report_versions'), 'parser scaffold RED')
        text = ('urbit 4.6\ngmp: 6.3.0\nsigsegv: 2.14\n'
                'openssl: OpenSSL 3.5.9 29 Sep 2026\n'
                'openssl-headers: OpenSSL 3.5.9 29 Sep 2026\n'
                'curl-linked: 8.23.0\ncurl-headers: 8.23.0\n'
                'libuv: 1.48.0\nlibh2o: 0.16.0\nlmdb: 0.9.31\ncurl: 8.23.0\n')
        self.assertTrue(all(m.report_versions(text, '3.5.9', '8.23.0').values()))
        for bad in (text.replace('3.5.9', '3.5.90'), text + 'curl-linked: 8.23.0\n',
                    text.replace('8.23.0', '8.22.0')):
            self.assertFalse(all(m.report_versions(bad, '3.5.9', '8.23.0').values()))

    def test_cached_base_refuses_implicit_volume_and_wrong_arch(self):
        m = self.module()
        self.assertTrue(hasattr(m, 'validate_base'), 'base gate scaffold RED')
        image = dict(id=m.IMAGE, arch='amd64', os='linux', volumes=None)
        self.assertTrue(m.validate_base(image))
        for key, value in [('volumes', {'/urbit': {}}), ('arch', 'arm64'), ('id', 'other')]:
            with self.assertRaises(ValueError):
                m.validate_base(dict(image, **{key: value}))

    def test_create_command_exact_report_only(self):
        m = self.module()
        self.assertTrue(hasattr(m, 'create_command'), 'command scaffold RED')
        args = m.create_command('issue3-b04-report-test')
        self.assertTrue(hasattr(m, 'GUEST'), 'effective preexec admission scaffold RED')
        self.assertEqual(args[-3:], [m.IMAGE, '-c', m.GUEST])
        for value in ('--pull=never', '--network=none', '--log-driver=none', '--read-only',
                      '--user=10000:10000', '--memory=256m', '--memory-swap=256m',
                      '--cpus=1', '--pids-limit=32', '--entrypoint=/bin/sh'):
            self.assertIn(value, args)
        self.assertEqual(sum(x.startswith('--mount=') for x in args), 1)
        self.assertTrue(next(x for x in args if x.startswith('--mount=')).endswith(',readonly'))
        self.assertNotIn('--rm', args)

    def test_effective_guest_guard_before_exact_exec(self):
        m = self.module()
        self.assertTrue(hasattr(m, 'GUEST'), 'effective guard scaffold RED')
        with tempfile.TemporaryDirectory(dir=m.SCRATCH) as tmp:
            root = Path(tmp)
            files = {'memory.max': '268435456', 'memory.swap.max': '0',
                     'cpu.max': '100000 100000', 'pids.max': '32'}
            for name, text in files.items():
                (root/name).write_text(text+'\n')
            (root/'meminfo').write_text('MemAvailable: 1048576 kB\n')
            script = m.GUEST.replace('/sys/fs/cgroup/', str(root)+'/').replace(
                '/proc/meminfo', str(root/'meminfo')).replace(
                'exec /candidate -R', 'printf "TARGET_ONCE\\n"')
            proc = subprocess.run(['/bin/sh', '-c', script], capture_output=True, text=True, timeout=3)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout.count('TARGET_ONCE'), 1)
            (root/'memory.swap.max').write_text('1\n')
            bad = subprocess.run(['/bin/sh', '-c', script], capture_output=True, text=True, timeout=3)
            self.assertNotEqual(bad.returncode, 0)
            self.assertNotIn('TARGET_ONCE', bad.stdout)

    def test_live_bounded_capture_reaps_timeout_no_retry(self):
        m = self.module()
        self.assertTrue(hasattr(m, 'load'), 'loader scaffold RED')
        supervision = m.load('report_supervision_test', m.HERE/'supervision.py')
        start = __import__('time').monotonic()
        with self.assertRaisesRegex(ValueError, 'deadline'):
            supervision.capture([sys.executable, '-c', 'import time; time.sleep(10)'],
                                io.BytesIO(), lambda: False, lambda: None, timeout=.1)
        self.assertLess(__import__('time').monotonic()-start, 3)

    def test_static_elf_rejects_dynamic_program_headers(self):
        m = self.module()
        self.assertTrue(hasattr(m, 'static_headers'), 'ELF scaffold RED')
        data = bytearray(120)
        data[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<H', data, 18, 62)
        struct.pack_into('<Q', data, 32, 64)
        struct.pack_into('<HH', data, 54, 56, 1)
        struct.pack_into('<I', data, 64, 1)
        self.assertTrue(m.static_headers(data))
        for kind in (2, 3):
            struct.pack_into('<I', data, 64, kind)
            with self.assertRaises(ValueError):
                m.static_headers(data)

    def test_prestart_control_refusal_does_not_start(self):
        m = self.module()
        self.assertTrue(hasattr(m, 'start_once'), 'one-shot scaffold RED')
        with tempfile.TemporaryDirectory(dir=m.SCRATCH) as tmp:
            folder = Path(tmp)
            capture = __import__('unittest.mock', fromlist=['Mock']).Mock()
            query = __import__('unittest.mock', fromlist=['Mock']).Mock(return_value={'memory': 1})
            with self.assertRaises(ValueError):
                m.start_once(folder, 'a'*64, 'issue3-b04-report-test', query, capture)
            capture.assert_not_called()
            self.assertFalse((folder/'started.json').exists())

    def test_settlement_stops_only_owned_and_does_not_retry(self):
        m = self.module()
        self.assertTrue(hasattr(m, 'settle'), 'settlement scaffold RED')
        cid = 'a'*64
        calls = []
        states = iter([dict(id=cid, running=True, pid=9, status='running', oom_killed=False),
                       dict(id=cid, running=False, pid=0, status='exited', oom_killed=False)])
        def query(args, **kwargs):
            calls.append(args)
            return 'stopped'
        final = m.settle(cid, lambda timeout: next(states), query)
        self.assertEqual(final['pid'], 0)
        self.assertEqual(calls, [['stop', '--time=5', cid]])

    def test_prestart_mutations_and_exclusive_single_start(self):
        m = self.module()
        cid, name = 'a'*64, 'issue3-b04-report-test'
        controls = m.expected_controls(cid, name)
        for key, value in [('memory', 1), ('mounts', []), ('ports', 1),
                           ('network', 'default'), ('cmd', ['ship']), ('readonly', False)]:
            with self.subTest(key=key), tempfile.TemporaryDirectory(dir=m.SCRATCH) as tmp:
                called = []
                with self.assertRaises(ValueError):
                    m.start_once(Path(tmp), cid, name, lambda _: dict(controls, **{key: value}),
                                 lambda *args: called.append(args))
                self.assertEqual(called, [])
        with tempfile.TemporaryDirectory(dir=m.SCRATCH) as tmp, patch.object(m, 'identity', return_value=b'exact'):
            folder = Path(tmp)
            calls = []
            def capture(argv, sink):
                calls.append(argv)
                sink.write(b'public fixture only\n')
            m.start_once(folder, cid, name, lambda _: controls, capture)
            with self.assertRaises(FileExistsError):
                m.start_once(folder, cid, name, lambda _: controls, capture)
            self.assertEqual(calls, [m.DOCKER+['start', '--attach', cid]])

    def test_settlement_deadline_refuses_without_stop(self):
        m = self.module()
        calls = []
        with self.assertRaisesRegex(ValueError, 'deadline'):
            m.settle('a'*64, lambda timeout: calls.append('inspect'),
                     lambda *a, **k: calls.append('mutate'), deadline=0)
        self.assertEqual(calls, [])

    def test_optional_docker_tmpfs_uses_map_lookup(self):
        m = self.module()
        self.assertNotIn('json .HostConfig.Tmpfs', m.FORMAT)
        self.assertIn('json (index .HostConfig "Tmpfs")', m.FORMAT)

    def test_recovery_only_unstarted_exact_owned_container(self):
        m = self.module()
        self.assertTrue(hasattr(m, 'validate_recovery'), 'created-only recovery scaffold RED')
        previous = dict(status='FAILED', client_exit_code=None)
        self.assertTrue(m.validate_recovery(previous, m.CREATED_ID, '0001-01-01T00:00:00Z', False))
        for previous_, cid, date, started in [
                (dict(previous, client_exit_code=0), m.CREATED_ID, '0001-01-01T00:00:00Z', False),
                (previous, 'a'*64, '0001-01-01T00:00:00Z', False),
                (previous, m.CREATED_ID, '2026-10-30T21:00:00Z', False),
                (previous, m.CREATED_ID, '0001-01-01T00:00:00Z', True)]:
            with self.assertRaises(ValueError):
                m.validate_recovery(previous_, cid, date, started)

    def test_live_capture_caps_public_output(self):
        m = self.module()
        supervision = m.load('report_supervision_cap_test', m.HERE/'supervision.py')
        with self.assertRaisesRegex(ValueError, 'output cap'):
            supervision.capture([sys.executable, '-c', 'print("x"*70000)'],
                                io.BytesIO(), lambda: False, lambda: None, timeout=3)


if __name__ == '__main__':
    unittest.main()