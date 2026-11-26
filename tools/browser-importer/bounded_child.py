"""Direct-owned waitpid and finite streaming; no Popen polling/wait/communicate."""
import os,signal,select,subprocess,time
COMPOSE_PATH='/usr/libexec/docker/cli-plugins/docker-compose'
COMPOSE_HOME='/run/issue19-compose-home'
def command_env():
 return {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':COMPOSE_HOME,'DOCKER_CONFIG':COMPOSE_HOME,
         'DOCKER_HOST':'unix:///var/run/docker.sock','PYTHONDONTWRITEBYTECODE':'1'}
def identity(s):
 return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_mode,s.st_uid,s.st_gid,s.st_nlink)
class ComposeArgv(list):
 """Path execution, NOT fd-bound execution.

 Admission authority MUST protect invocation, target bytes, all ancestors and
 empty config against concurrent writers from acquisition THROUGH child exec.
 Metadata checks detect substitutions; they cannot exclude a privileged writer
 racing the last check and exec. No advisory lock or repeated stat proves that
 premise. If continuing protection cannot be established, do not invoke.
 """
 def __init__(self,values,path,target,before,opened):
  super().__init__(values);self.path=path;self.target=target;self.before=before;self.opened=opened
 def verify(self):
  if (identity(self.before)!=identity(self.path.lstat()) or self.target!=self.path.resolve(strict=True)
      or identity(self.opened)!=identity(os.stat(self.target,follow_symlinks=False))):
   raise ValueError('COMPOSE_CHANGED')
def compose_command(desc,args,deadline):
 import hashlib,pathlib,stat
 if not isinstance(desc,dict) or desc.get('path')!=COMPOSE_PATH:raise ValueError('COMPOSE_SELECTION')
 home=pathlib.Path(COMPOSE_HOME);s=home.lstat()
 if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o700 or list(home.iterdir()):raise ValueError('COMPOSE_CONFIG')
 p=pathlib.Path(desc['path']);before=p.lstat();target=p.resolve(strict=True)
 fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  st=os.fstat(fd)
  if not stat.S_ISREG(st.st_mode):raise ValueError('COMPOSE_REGULAR')
  argv=ComposeArgv([desc['path'],*args],p,target,before,st)
  argv.verify() # Bind retained open fd to the currently named target BEFORE hash.
  h=hashlib.sha256()
  while True:
   if time.monotonic()>=deadline:raise ValueError('COMMAND_DEADLINE')
   raw=os.read(fd,1048576)
   if not raw:break
   h.update(raw)
  if identity(st)!=identity(os.fstat(fd)) or h.hexdigest()!=desc['sha256']:raise ValueError('COMPOSE_CHANGED')
  argv.verify() # Named-target identity must still match AFTER hashing.
 finally:os.close(fd)
 return argv
class OwnershipLost(Exception):pass
class Owned:
 def __init__(self,p):self.p=p;self.pid=p.pid;self.status=None;self.lost=False;self.signals=[]
 def reap(self):
  if self.lost:raise OwnershipLost('OWNERSHIP_LOST')
  if self.status is not None:return True
  if self.p.returncode is not None:
   self.lost=True;raise OwnershipLost('OWNERSHIP_LOST')
  try:pid,status=os.waitpid(self.pid,os.WNOHANG)
  except ChildProcessError:
   self.lost=True;raise OwnershipLost('OWNERSHIP_LOST') from None
  if pid==self.pid:
   self.status=status;self.p.returncode=os.waitstatus_to_exitcode(status);return True
  return False
 def empty(self):
  try:os.killpg(self.pid,0)
  except ProcessLookupError:return True
  except PermissionError:return False
  return False
 def send(self,sig):
  # Re-check exact ownership at the signal boundary; no post-reap signalling.
  if not self.reap() and not self.empty():
   os.killpg(self.pid,sig);self.signals.append(sig)
 def settle(self,endpoint,first=signal.SIGTERM):
  if time.monotonic()>=endpoint:return False
  self.send(first)
  escalation=min(endpoint,time.monotonic()+.2)
  while time.monotonic()<endpoint:
   if self.reap():return self.empty() and time.monotonic()<endpoint
   if time.monotonic()>=escalation:
    self.send(signal.SIGKILL);escalation=endpoint
   time.sleep(min(.01,max(0,endpoint-time.monotonic())))
  return False

def collect(argv,endpoint,work_end,limit=65536,env=None):
 if not time.monotonic()<work_end<=endpoint:raise ValueError('COMMAND_DEADLINE')
 if isinstance(argv,ComposeArgv):argv.verify() # Last check; protected/no-writer premise continues through exec.
 p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
   close_fds=True,start_new_session=True,env=env)
 owned=Owned(p);out=bytearray();eof=False;reason=None
 try:
  os.set_blocking(p.stdout.fileno(),False)
  while time.monotonic()<work_end:
   reaped=owned.reap()
   if eof and reaped:break
   ready,_,_=select.select([] if eof else [p.stdout],[],[],min(.02,max(0,work_end-time.monotonic())))
   if ready:
    b=os.read(p.stdout.fileno(),min(8192,limit+1-len(out)))
    if not b:eof=True
    else:
     out.extend(b)
     if len(out)>limit:reason='OUTPUT_LIMIT';break
  if reason is None and not(eof and owned.reap() and time.monotonic()<work_end):reason='COMMAND_DEADLINE'
  if reason is None and not owned.empty():reason='COMMAND_UNSETTLED'
  if reason is None and p.returncode!=0:reason='COMMAND_REFUSED'
  if reason is None and time.monotonic()>=work_end:reason='COMMAND_DEADLINE'
 except OwnershipLost:reason='OWNERSHIP_LOST'
 except BaseException:
  p.stdout.close()
  try:owned.settle(endpoint,signal.SIGKILL)
  except BaseException:pass
  raise
 finally:p.stdout.close()
 if reason is not None:
  settled=False
  try:settled=owned.settle(endpoint,signal.SIGKILL)
  except OwnershipLost:pass
  exc=ValueError(reason)
  exc.settlement={'reaped':owned.status is not None,'ownership_lost':owned.lost,
     'group_empty':owned.empty(),'settled':settled,'acquired_bytes':len(out),'eof':eof,'endpoint':endpoint}
  raise exc
 return {'stdout':bytes(out),'exit':p.returncode,'reaped':True,'group_empty':True,'eof':True,'acquired_bytes':len(out)}
