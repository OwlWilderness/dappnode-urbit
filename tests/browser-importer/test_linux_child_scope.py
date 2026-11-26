"""Real Linux kernel qualification fixtures: skipped, NOT qualified, on Darwin.

Only synthetic storage/processes. The official fixed-binary verification leaf is
replaced; production setup, scope ownership, settlement and manager code are real.
Each case runs in a dedicated process so subreaper/audit state cannot leak.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parents[2] / 'tools/browser-importer'
DRIVER = r'''
import json, os, pathlib, signal, subprocess, sys, threading, time
sys.path.insert(0, sys.argv[1])
import runtime, managed_service
from importer import Importer
root, mode = pathlib.Path(sys.argv[2]), sys.argv[3]
worker = """import os,pathlib,signal,sys,time
root, mode = pathlib.Path(sys.argv[1]), sys.argv[2]
signal.signal(signal.SIGTERM, signal.SIG_IGN)
if mode == 'session': os.setsid()
if mode == 'fds': os.closerange(3, 1024)
(root/'ready').write_text(str(os.getpid()))
while not (root/'finish').exists(): time.sleep(.01)
"""
leader = """import os,pathlib,sys,time
root, mode, worker = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
if mode == 'clean':
    (root/'ready').touch()
    while True: time.sleep(.01)
if os.fork() == 0:
    if mode == 'exec': os.execv(sys.executable, [sys.executable,'-B','-c',worker,str(root),mode])
    exec(worker, {'__name__':'__main__', 'sys':sys})
else:
    while not (root/'ready').exists(): time.sleep(.01)
"""
# Keep the kernel scope and official adapter methods intact; replace only Vere.
def launch(self, ship_fd, lock_fd):
    assert os.fstat(lock_fd).st_ino == os.stat(root/'pier').st_ino
    return subprocess.Popen([sys.executable, '-B', '-c', leader, str(root), mode, worker],
                            pass_fds=(ship_fd, lock_fd))
runtime.OfficialRuntimeAdapter._launch_verified = launch
engine = managed_service.production_engine(*(root/p for p in ('pier','uploads','control')))
assert engine.runtime_adapter.scope.kernel.subreaper()
assert threading.active_count() == 1
(root/'pier/ship/.urb').mkdir(parents=True)
engine.job = {'id':'a'*32, 'state':'READY_LOCKED','offset':1,'total_bytes':1,'expanded_limit':1}
engine._persist()
# Audit prevents unrelated children, rather than allowing waitpid(-1) to steal them.
for spawn in (lambda: subprocess.Popen([sys.executable,'-c','pass']), os.fork):
    try: spawn()
    except RuntimeError: pass
    else: raise AssertionError('unowned spawn admitted')
try: runtime.OwnedChildScope.prepare()
except ValueError: pass
else: raise AssertionError('second coordinator admitted')
try:
    engine.start(confirmed_stopped=True)
    end=time.monotonic()+5
    while not (root/'ready').exists() and time.monotonic()<end: time.sleep(.01)
    assert (root/'ready').exists()
    if mode == 'clean':
        engine.stop()
        assert engine.runtime['state']=='STOPPED'
        (root/'ready').unlink()
        engine.start(confirmed_stopped=True)
        engine.begin_close()
        engine.close()
        assert engine._closed
        assert json.loads((root/'control/runtime.json').read_text())['state']=='STOPPED'
        # A new process/coordinator, not live adoption, is needed for a real reopen.
    else:
        engine.child.wait(timeout=5)
        scope=engine.runtime_adapter.scope
        real_settled=scope.settled
        scope.settled=lambda child: real_settled(child, timeout=.2)
        try: engine.stop()
        except runtime.ImportError: pass
        else: raise AssertionError('living escaped descendant settled')
        assert engine.runtime['state']=='FAULT'
        assert not engine.status()['start_available']
        assert (root/'ready').exists()
        os.kill(int((root/'ready').read_text()), 0)
        # Fixture cleanup only. Once the descendant exits, real ECHILD is positive
        # settlement and a retry must not permanently dead-end the clean lifecycle.
        (root/'finish').touch()
        end=time.monotonic()+5
        while not real_settled(engine.child, timeout=.1) and time.monotonic()<end: pass
        engine.stop()
        engine.close()
finally:
    (root/'finish').touch()
    if engine.child is not None:
        if engine.child.poll() is None: engine.child.kill()
        engine.child.wait(timeout=5)
        engine.runtime_adapter.scope.settled(engine.child)
    Importer.close(engine)
print('synthetic Linux owned scope passed:', mode)
'''


@unittest.skipUnless(sys.platform.startswith('linux'),
                     'Linux subreaper/kernel path UNQUALIFIED on this platform; no Docker/VM execution')
class LinuxChildScopeTests(unittest.TestCase):
    def run_case(self, mode):
        with tempfile.TemporaryDirectory(dir=os.environ['IMPORTER_TEST_SCRATCH']) as directory:
            result = subprocess.run([sys.executable, '-B', '-c', DRIVER, str(TOOLS), directory, mode],
                                    env={'PATH': os.defpath, 'PYTHONDONTWRITEBYTECODE':'1',
                                         'TMPDIR':os.environ['IMPORTER_TEST_SCRATCH']},
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=25)
            self.assertEqual(result.returncode, 0, result.stdout.decode())
            self.assertIn(b'synthetic Linux owned scope passed:', result.stdout)

    def test_real_linux_clean_start_stop_start_shutdown(self): self.run_case('clean')
    def test_real_linux_adopted_fork_refuses_until_exit(self): self.run_case('fork')
    def test_real_linux_adopted_exec_refuses_until_exit(self): self.run_case('exec')
    def test_real_linux_closed_fds_do_not_evade_ancestry(self): self.run_case('fds')
    def test_real_linux_new_session_does_not_evade_ancestry(self): self.run_case('session')


if __name__ == '__main__':
    unittest.main()
