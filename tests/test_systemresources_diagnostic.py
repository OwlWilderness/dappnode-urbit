"""Host-only diagnostic parser tests: never compiler/engine qualification."""
import importlib.util
from pathlib import Path
import unittest

PATH=Path(__file__).resolve().parents[1]/'tools/issue3_systemresources_diagnostic/guest.py'
class DiagnosticTests(unittest.TestCase):
    def test_first_failed_allocation_not_unrelated_errno(self):
        self.assertTrue(PATH.is_file(), 'diagnostic observer missing (scaffold RED)')
        spec=importlib.util.spec_from_file_location('diagnostic_guest',PATH)
        assert spec and spec.loader
        mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
        obs=mod.TraceFilter(4096)
        for line in [b'7 openat(0,"public",0) = -1 errno=2 (No such file)\n',
                     b'7 mmap(NULL,62918656,3,34,-1,0) = -1 errno=12 (Cannot allocate memory)\n',
                     b'7 clone(0x123,0,0,0,0) = -1 errno=11 (Resource temporarily unavailable)\n']:
            obs.feed(line)
        self.assertEqual(obs.first_failure['syscall'],'mmap')
        self.assertEqual(obs.first_failure['errno'],12)
        self.assertNotIn(b'openat',obs.retained)
        self.assertIn(b'clone',obs.retained)

    def test_command_preserves_sandbox_and_adds_no_trace_privileges(self):
        host=PATH.with_name('host.py')
        self.assertTrue(host.is_file(),'diagnostic host missing (scaffold RED)')
        spec=importlib.util.spec_from_file_location('diagnostic_host',host)
        assert spec and spec.loader
        mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
        p={'name':'issue3-b04-probe-systemresources-d01','python':{'path':'/usr/bin/python3.14'},
           'base':{'image_id':'sha256:'+'a'*64},'mounts':{'inputs':'/inputs-host','controller':'/control-host','toolchain':'/tool-host','request':'/request-host','observer':'/observer-host'}}
        cmd=mod.make_command(p,Path('/diagnostic-host'))
        for token in ('--memory=1073741824','--memory-swap=1073741824','--cpus=1','--pids-limit=64','--read-only','--network=none','--user=10000:10000','--cap-drop=ALL','--pull=never'):
            self.assertIn(token,cmd)
        self.assertFalse(any('cap-add' in x or 'seccomp' in x or 'cpuset' in x for x in cmd))
        self.assertEqual(sum(x.startswith('--mount=') for x in cmd),6)
        self.assertEqual(cmd[-1],'/diagnostic/guest.py')

if __name__=='__main__': unittest.main()
