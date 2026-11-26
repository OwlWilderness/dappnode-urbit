"""Real authenticated PrivateServer request threads; synthetic runtime leaf only.

Every case has a fresh process, production_engine/subreaper/audit and real Linux
waitpid(__WALL) ECHILD. READY is deliberately synthetic here; genuine import and
Vere/package qualification lives in tests/issue19-lifecycle, not in these claims.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parents[2] / 'tools/browser-importer'
DRIVER = r'''
import hashlib,http.client,json,os,pathlib,signal,subprocess,sys,threading,time
sys.path.insert(0,sys.argv[1])
import runtime,managed_service,server
from importer import Importer
root,mode=pathlib.Path(sys.argv[2]),sys.argv[3]
def until(predicate,seconds=6):
    end=time.monotonic()+seconds
    while not predicate():
        assert time.monotonic()<end,'fixture deadline'
        time.sleep(.01)
release=threading.Event();entered=threading.Event();launch_release=threading.Event()
launch_tids=[];echild=[]
worker="""import os,pathlib,signal,sys,time
root=pathlib.Path(sys.argv[1]);mode=sys.argv[2]
signal.signal(signal.SIGTERM,signal.SIG_IGN)
if mode=='setsid': os.setsid()
os.closerange(3,4096)
(root/'ready').write_text(str(os.getpid()))
while not (root/'finish').exists(): time.sleep(.01)
"""
leader="""import os,pathlib,sys,time
root=pathlib.Path(sys.argv[1]);mode=sys.argv[2]
if mode in ('live','exited','race'):
    (root/'ready').touch()
    while True: time.sleep(.01)
if os.fork()==0:
    os.execv(sys.executable,[sys.executable,'-B','-c',sys.argv[3],str(root),mode])
while not (root/'ready').exists(): time.sleep(.01)
"""
def launch(self,ship_fd,lock_fd):
    launch_tids.append(threading.get_native_id());entered.set()
    if mode=='race': assert launch_release.wait(6)
    return subprocess.Popen([sys.executable,'-B','-c',leader,str(root),mode,worker],pass_fds=(ship_fd,lock_fd))
runtime.OfficialRuntimeAdapter._launch_verified=launch
engine=managed_service.production_engine(*(root/p for p in ('pier','uploads','control')))
assert threading.active_count()==1
scope=engine.runtime_adapter.scope
real_wait=scope.kernel.wait
def wait():
    try: return real_wait()
    except ChildProcessError:
        echild.append(threading.get_native_id());raise
scope.kernel.wait=wait
real_settled=scope.settled
scope.settled=lambda child:real_settled(child,timeout=.15)
(root/'pier/ship/.urb').mkdir(parents=True)
engine.job={'id':'a'*32,'state':'READY_LOCKED','offset':1,'total_bytes':1,'expanded_limit':1}
engine._persist()
salt=b'1'*16;password='synthetic-http-fixture-not-an-owner-secret'
credential={'salt':salt.hex(),'hash':hashlib.scrypt(password.encode(),salt=salt,n=16384,r=8,p=1).hex()}
http=server.make_server(engine,('127.0.0.1',0),credential)
original_finish=server.Handler.finish
def finish(self):
    if self.path=='/api/start' and mode=='live': assert release.wait(6)
    original_finish(self)
server.Handler.finish=finish
serving=threading.Thread(target=http.serve_forever);serving.start()
cookie=None;csrf=None
def request(path,params,authenticated=True):
    c=http.client.HTTPConnection('127.0.0.1',http.server_port,timeout=8)
    headers={'Origin':http.origin,'Content-Type':'application/json'}
    if authenticated and cookie: headers.update({'Cookie':cookie,'X-CSRF-Token':csrf})
    c.request('POST',path,json.dumps(params),headers)
    response=c.getresponse();status=response.status
    value=json.loads(response.read());set_cookie=response.getheader('Set-Cookie');c.close()
    return status,value,set_cookie
# Name the server separately to avoid shadowing the stdlib HTTP client.
'''
# Keep the dedicated-driver source readable without importing a test-only server.
DRIVER = DRIVER.replace('import hashlib,http.client,', 'import hashlib,http.client as http_client,').replace('http.client.HTTPConnection', 'http_client.HTTPConnection') + r'''
try:
    assert request('/api/start',{'confirmed_stopped':True},False)[0]==401
    status,value,set_cookie=request('/api/login',{'password':password},False)
    assert status==200;cookie=set_cookie.split(';')[0];csrf=value['csrf']
    for spawn in (lambda:subprocess.Popen([sys.executable,'-c','pass']),os.fork):
        try: spawn()
        except RuntimeError: pass
        else: raise AssertionError('unrelated spawn admitted')
    if mode=='race':
        result=[]
        client=threading.Thread(target=lambda:result.append(request('/api/start',{'confirmed_stopped':True})))
        client.start();assert entered.wait(6)
        # The owned request currently holds spawn admission; another Python
        # thread must still be denied, not confused with the authorized TID.
        try: subprocess.Popen([sys.executable,'-c','pass'])
        except RuntimeError: pass
        else: raise AssertionError('unrelated concurrent spawn admitted')
        server.request_shutdown(http)
        assert engine._closing
        launch_release.set();client.join(8);assert not client.is_alive()
        serving.join(8);http.server_close();engine.close()
        assert result[0][0]==200 and engine._closed
        assert json.loads((root/'control/runtime.json').read_text())['state']=='STOPPED'
        try: engine.start(confirmed_stopped=True)
        except runtime.ImportError: pass
        else: raise AssertionError('close admission reopened')
    else:
        assert request('/api/start',{'confirmed_stopped':True})[0]==200
        until(lambda:(root/'ready').exists())
        tid=launch_tids[0]
        assert tid!=os.getpid()
        if mode=='live': assert pathlib.Path('/proc/self/task',str(tid)).exists()
        else: until(lambda:not pathlib.Path('/proc/self/task',str(tid)).exists())
        if mode in ('fds','setsid','exec'):
            engine.child.wait(timeout=6)
            assert request('/api/stop',{})[0]==409
            assert engine.runtime['state']=='FAULT' and not echild
            os.kill(int((root/'ready').read_text()),0)
            (root/'finish').touch()
            until(lambda:real_settled(engine.child,timeout=.1))
        assert request('/api/stop',{})[0]==200
        assert engine.runtime['state']=='STOPPED' and echild
        # No process can remain hidden behind a cached scope result.
        try: os.waitpid(-1,os.WNOHANG|0x40000000)
        except ChildProcessError: pass
        else: raise AssertionError('actual ECHILD absent')
finally:
    release.set();launch_release.set();(root/'finish').touch()
    server.request_shutdown(http);serving.join(8);http.server_close()
    if engine.child is not None:
        if engine.child.poll() is None: engine.child.kill()
        engine.child.wait(timeout=6);real_settled(engine.child,timeout=3)
    if not engine._closed: engine.close()
assert echild and len(launch_tids)==1
print('HTTP_SCOPE_RESULT '+json.dumps({'mode':mode,'launch_count':len(launch_tids),'echild_observed':True,'closed':engine._closed}))
'''


@unittest.skipUnless(sys.platform.startswith('linux'), 'Actual Linux HTTP-thread ownership requires isolated Linux')
class HTTPChildScopeTests(unittest.TestCase):
    def run_case(self, mode):
        with tempfile.TemporaryDirectory(dir=os.environ['IMPORTER_TEST_SCRATCH']) as root:
            p = subprocess.run([sys.executable, '-B', '-c', DRIVER, str(TOOLS), root, mode],
                               env={'PATH':os.defpath, 'TMPDIR':os.environ['IMPORTER_TEST_SCRATCH']},
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=35)
            self.assertEqual(p.returncode, 0, p.stdout.decode())
            self.assertIn(b'"echild_observed": true', p.stdout)

    def test_authenticated_live_spawn_tid_stop_echild(self): self.run_case('live')
    def test_authenticated_exited_spawn_tid_stop_echild(self): self.run_case('exited')
    def test_closed_fds_descendant_refuses_until_exit(self): self.run_case('fds')
    def test_setsid_descendant_refuses_until_exit(self): self.run_case('setsid')
    def test_exec_descendant_refuses_until_exit(self): self.run_case('exec')
    def test_close_during_request_start_drains_without_reopen(self): self.run_case('race')


if __name__ == '__main__': unittest.main()
