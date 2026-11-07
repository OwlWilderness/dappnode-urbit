"""Permanent legacy-0.1.5 recovery service.

Trust model: approved admin noninterference, disabled auto-updates and settled
admitted installs; private PID/mount namespaces, no escape or outside writer.
NOT universal host exclusion. Native/controller bridge must positively bind these
prerequisites. Missing bridge is a hard refusal, never an operator stopped flag.
All startup paths are idle. No repair/Start from constructor, status or restart.
"""
import contextlib
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import ssl
import stat
import threading
import urllib.request
from urllib.parse import urlsplit

from importer import ImportError
import legacy015_recovery as journal
from runtime import ManagedImporter
import server as legacy_http

BUILD = 'legacy015-permanent-recovery-1'
PACKAGE = 'uvm.public.dappnode.eth'
VOLUME = 'uvmpublicdappnodeeth_ship_data'

class MissingNativeBridge(ImportError):
    pass

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def _atomic(fd, name, value):
    pending = '.recovery-' + secrets.token_hex(16)
    raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()+b'\n'
    journal._write(fd, pending, raw)
    os.replace(pending, name, src_dir_fd=fd, dst_dir_fd=fd)
    os.fsync(fd)
    if journal._read(fd, name, 65536)[0] != raw:
        raise ImportError('Durable recovery state readback mismatch.')

class NativeRPC:
    """Actual Dappmanager admin POST /rpc. No login, credential lookup or logging.
    Authenticated session is supplied in memory by the authorized controller host.
    HTTPS verification is mandatory; redirects and HTTP downgrade are forbidden.
    """
    def __init__(self, origin, cookie_supplier, tls_context):
        parsed = urlsplit(origin)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.path or
                parsed.query or parsed.fragment or parsed.username or
                tls_context.verify_mode != ssl.CERT_REQUIRED or not tls_context.check_hostname):
            raise ValueError('Exact verified HTTPS native origin required.')
        self.origin, self.cookie, self.tls = origin, cookie_supplier, tls_context
    def call(self, method, params=None):
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                raise OSError('Native redirect refused.')
        request = urllib.request.Request(self.origin+'/rpc',
            data=json.dumps({'method':method,'params':[] if params is None else [params]}).encode(),
            headers={'Content-Type':'application/json','Origin':self.origin,'Cookie':self.cookie()}, method='POST')
        opener = urllib.request.build_opener(NoRedirect,urllib.request.HTTPSHandler(context=self.tls))
        with opener.open(request, timeout=10) as response:
            raw=response.read(1024*1024+1)
            if response.status != 200 or len(raw)>1024*1024: raise OSError('Native RPC unavailable.')
        value=json.loads(raw)
        if type(value) is not dict or value.get('error') or 'result' not in value:
            raise OSError('Native RPC refused; no raw error reflected.')
        return value['result']

class NativeController:
    """Trusted external controller; NEVER runs in the ship container.

    rpc is NativeRPC (or an existing authenticated native call transport).
    bridge is privileged, executable native lifecycle evidence, NOT a dictionary:
      admit(package, old_id, new_id, volume, build, generation, prior_attempt)
      revalidate(tx, generation, bindings)
    Stock v0.2.129 routes do not expose the required install-drain/inspect primitive.
    There is deliberately no fallback implementation or synthetic proof format.
    Controller process must own the install's actual awaited completion before
    registering it. Bridge must settle already admitted updater/manual/rollback jobs.
    """
    def __init__(self, rpc, bridge):
        self.rpc, self.bridge = rpc, bridge
        self.lock = threading.Lock()
        self.completed = None
        self.tx = None
    def require_bridge(self):
        if (self.bridge is None or not callable(getattr(self.bridge,'admit',None)) or
                not callable(getattr(self.bridge,'revalidate',None))):
            raise MissingNativeBridge('Missing native install-drain/inspect lifecycle bridge; stock packageGet does not supply it.')
    def install(self, manifest, compose, image_file_id):
        """Native dev install, separate from worker admit/repair; no repair payload.
        Caller supplies exact reviewed descriptors/imageFileId from existing upload.
        Lost response never marks completion. No rollback/retry is synthesized.
        """
        with self.lock:
            self.require_bridge()
            if self.tx is not None or self.completed is not None: raise ImportError('Controller installation already consumed.')
            old=self.rpc.call('packageGet', {'dnpName':PACKAGE})
            self.rpc.call('autoUpdateSettingsEdit',{'id':PACKAGE,'enabled':False})
            self.rpc.call('autoUpdateSettingsEdit',{'id':'system-packages','enabled':False})
            self._updates()
            # settle() must close prior admitted installs, not sample an empty queue.
            if not callable(getattr(self.bridge,'settle_admitted_installs',None)):
                raise MissingNativeBridge('Missing positive admitted-install/rollback settlement operation.')
            self.bridge.settle_admitted_installs(PACKAGE)
            result=self.rpc.call('packageInstallDev',{'manifest':manifest,'compose':compose,'imageFileId':image_file_id})
            current=self.rpc.call('packageGet',{'dnpName':PACKAGE})
            self.completed=(old,current)
            return result
    def _updates(self):
        data=self.rpc.call('autoUpdateDataGet')
        rows=data['dnpsToShow']
        for ident in (PACKAGE,'system-packages'):
            match=[row for row in rows if row['id']==ident]
            if len(match)!=1 or match[0]['enabled'] is not False:
                raise ImportError('Effective target/system auto-update must remain disabled.')
    def _container(self, pkg):
        containers=pkg['containers']
        if len(containers)!=1 or containers[0]['serviceName']!='ship': raise ImportError('Sole ship service required.')
        c=containers[0]
        mounts=[v for v in c['volumes'] if v.get('name')==VOLUME and v['container']=='/urbit']
        if len(mounts)!=1: raise ImportError('Exact retained native volume mapping required.')
        return c
    def call(self, action, body):
        with self.lock:
            self.require_bridge()
            if self.completed is None: raise ImportError('No acknowledged native install completion in this controller.')
            if action not in ('begin','check','finish'): raise ImportError('Unknown controller operation.')
            self._updates()
            current=self.rpc.call('packageGet',{'dnpName':PACKAGE})
            packages=self.rpc.call('packagesGet')
            current_c=self._container(current)
            old_c=self._container(self.completed[0]); installed_c=self._container(self.completed[1])
            if current_c['containerId']!=installed_c['containerId'] or current_c['containerId']==old_c['containerId']:
                raise ImportError('Maintenance replacement identity changed/not replaced.')
            consumers=[c for pkg in packages for c in pkg['containers']
                       if any(v.get('name')==VOLUME for v in c['volumes'])]
            if len(consumers)!=1 or consumers[0]['containerId']!=current_c['containerId']:
                raise ImportError('Native retained volume is not exclusive to replacement.')
            if any(c['containerId']==old_c['containerId'] for p in packages for c in p['containers']):
                raise ImportError('Prior managed container still present.')
            if not current_c['running']: raise ImportError('Maintenance worker is not running.')
            if action=='begin':
                if self.tx is not None: raise ImportError('Controller admission replay refused.')
                self.tx=self.bridge.admit(PACKAGE, old_c['containerId'],current_c['containerId'],VOLUME,BUILD,body['generation'],body.get('prior'))
                if not isinstance(self.tx,str) or len(self.tx)!=32: raise ImportError('Invalid bridge transaction identity.')
                self.generation=body['generation']
            elif self.tx!=body['tx'] or self.generation!=body['generation']:
                raise ImportError('Stale controller transaction/generation.')
            self.bridge.revalidate(self.tx,body['generation'],body.get('bindings',{}))
            return {'tx':self.tx,'generation':self.generation}

class ControllerChannel:
    """Worker -> scoped external controller over mutual TLS, no user proof input.
    Configuration is fixed private service control data, never request/env fields.
    Controller must verify the client certificate and bind BUILD/generation/paths.
    """
    def __init__(self, control): self.control=Path(control)
    def call(self, action, body):
        fd=journal._directory(self.control)
        try: raw,_=journal._read(fd,'recovery-controller.json',16384)
        except FileNotFoundError:
            raise MissingNativeBridge('Native controller channel not provisioned; recovery remains stopped.') from None
        finally: os.close(fd)
        cfg=journal._object(raw)
        if set(cfg)!={'origin','ca','certificate','key'}: raise ImportError('Invalid scoped controller configuration.')
        origin=cfg['origin']; parsed=urlsplit(origin)
        if parsed.scheme!='https' or not parsed.hostname or parsed.path or parsed.query or parsed.fragment or parsed.username:
            raise ImportError('Verified controller HTTPS origin required.')
        context=ssl.create_default_context(cafile=cfg['ca'])
        context.load_cert_chain(cfg['certificate'],cfg['key'])
        nonce=secrets.token_hex(32)
        request=urllib.request.Request(origin+'/legacy015/'+action,
            data=json.dumps({'nonce':nonce,'build':BUILD,**body}).encode(),
            headers={'Content-Type':'application/json'},method='POST')
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*args,**kw): raise OSError('Controller redirect refused.')
        opener=urllib.request.build_opener(NoRedirect,urllib.request.HTTPSHandler(context=context))
        with opener.open(request, timeout=10) as response:
            raw=response.read(16385)
            if response.status!=200 or len(raw)>16384: raise ImportError('Controller unavailable.')
        result=journal._object(raw)
        if result.pop('nonce',None)!=nonce: raise ImportError('Controller challenge mismatch.')
        return result

class Lease:
    def __init__(self, engine): self.engine=engine
    @contextlib.contextmanager
    def exclude_and_settle(self, target):
        if {k:str(v) for k,v in target.items()}!={k:str(self.engine.paths[k]) for k in ('pier','control','evidence')}:
            raise ImportError('Recovery target substitution refused.')
        yield self
    def revalidate(self, bindings):
        self.engine.check('check',bindings)

class RecoveryEngine:
    """No ManagedImporter exists during structural stopped maintenance.
    Only authenticated Start after durable repair can construct a launcher.
    Any process restart is idle; partial transaction survives as uncertainty.
    """
    def __init__(self,pier,uploads,control,*,evidence=None,controller=None,runtime_adapter=None,**limits):
        self.paths={k:Path(os.path.abspath(v)) for k,v in (('pier',pier),('uploads',uploads),('control',control),
                    ('evidence',evidence or Path(control).parent/'legacy015-evidence'))}
        self.fd=journal._directory(self.paths['control'])
        self.lockfd=None
        try:
            self.lockfd=os.open('legacy-recovery.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=self.fd)
            st=os.fstat(self.lockfd)
            if (not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)&0o077):
                raise ImportError('Unsafe permanent recovery lock.')
            fcntl.flock(self.lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BaseException:
            if self.lockfd is not None: os.close(self.lockfd)
            os.close(self.fd)
            raise
        self.mutex=threading.RLock(); self.generation=secrets.token_hex(32)
        self.controller=controller or ControllerChannel(control)
        self.adapter=runtime_adapter; self.limits=limits
        self.manager=None; self.writer_admitted=False; self.closed=False
        self.admission_attempted=False
        try: self.record=self._load()
        except BaseException:
            os.close(self.lockfd); os.close(self.fd)
            raise
    def _load(self):
        try: raw,_=journal._read(self.fd,'legacy-recovery-state.json',65536)
        except FileNotFoundError: return {'state':'MAINTENANCE'}
        record=journal._object(raw)
        if record.get('build')!=BUILD: raise ImportError('Unknown recovery state build; preserve evidence.')
        if record.get('state')=='REPAIRED':
            try: self._verify_success(record)
            except BaseException: return {**record,'state':'UNCERTAIN'}
        elif record.get('state')!='MAINTENANCE':
            return {**record,'state':'UNCERTAIN'}
        return record
    def save(self, state, **extra):
        record={**self.record,**extra,'state':state,'build':BUILD,'generation':self.generation}
        self.record=record # fail closed in memory even if persistence fails
        _atomic(self.fd,'legacy-recovery-state.json',record)
    def _raw(self,name): return journal._read(self.fd,name,65536)[0]
    def _verify_success(self,record):
        if (journal._object(self._raw('runtime.json'))!={'state':'STOPPED'} or
                digest(self._raw('runtime.json'))!=record['runtime_sha256'] or
                digest(self._raw('job.json'))!=record['job_sha256']):
            raise ImportError('Recovered journal changed.')
        for key, pair in record['roots'].items():
            fd=journal._directory(self.paths[key])
            try: st=os.fstat(fd)
            finally: os.close(fd)
            if [st.st_dev,st.st_ino]!=pair: raise ImportError('Recovered physical roots changed.')
        evidence=self.paths['evidence']/record['evidence']
        fd=journal._directory(evidence)
        try:
            for name,sha in record['evidence_hashes'].items():
                if digest(journal._read(fd,name,65536)[0])!=sha: raise ImportError('Original recovery evidence changed.')
        finally: os.close(fd)
    def check(self,action,bindings=None):
        result=self.controller.call(action,{'generation':self.generation,'tx':self.record.get('tx'),
            'prior':self.record.get('prior'),
            'paths':{k:str(v) for k,v in self.paths.items()},
            'bindings':{k:[str(p),d,i] for k,(p,d,i) in (bindings or {}).items()}})
        if (not isinstance(result,dict) or result.get('generation')!=self.generation or
                not isinstance(result.get('tx'),str) or len(result['tx'])!=32 or
                (action!='begin' and result['tx']!=self.record.get('tx'))):
            raise ImportError('Controller lease mismatch.')
        return result['tx']
    def admit_maintenance(self):
        with self.mutex:
            if (self.closed or self.writer_admitted or self.admission_attempted or
                    self.record['state'] not in ('MAINTENANCE','REPAIRED','UNCERTAIN')):
                raise ImportError('Fresh maintenance-only replacement required; no same-generation writer recovery.')
            # A later explicit admission is possible only through a NEW native
            # replacement. Bridge must reconcile/refuse prior uncertain ownership;
            # merely restarting this process cannot establish that replacement.
            self.admission_attempted=True
            prior={k:self.record[k] for k in ('state','tx','generation','evidence','evidence_hashes','roots','job_sha256','runtime_sha256') if k in self.record}
            self.save('ADMITTING',prior=prior)
            try:
                tx=self.check('begin')
                evidence=self.paths['evidence']
                # Creation is an explicit maintenance action, never startup behavior.
                try: evidence.mkdir(mode=0o700)
                except FileExistsError: pass
                fd=journal._directory(evidence); os.fsync(fd); os.close(fd)
                parent=journal._directory(evidence.parent); os.fsync(parent); os.close(parent)
                self.save('ARMED',tx=tx)
            except BaseException:
                self.save('UNCERTAIN')
                raise ImportError('Maintenance admission uncertain; keep replacement installed.') from None
            return self.status()
    def recover(self):
        with self.mutex:
            if self.closed or self.writer_admitted or self.record['state']!='ARMED':
                raise ImportError('Separate native maintenance admission required; recovery replay refused.')
            self.save('REPAIRING')
            try:
                evidence=journal.recover(self.paths['pier'],self.paths['control'],self.paths['evidence'],authority=Lease(self))
                self.check('finish')
                fd=journal._directory(evidence)
                try: hashes={n:digest(journal._read(fd,n,65536)[0]) for n in ('runtime.before','job.before','bindings.json')}
                finally: os.close(fd)
                roots={}
                for k,p in self.paths.items():
                    fd=journal._directory(p)
                    try: st=os.fstat(fd); roots[k]=[st.st_dev,st.st_ino]
                    finally: os.close(fd)
                self.save('REPAIRED',evidence=evidence.name,evidence_hashes=hashes,roots=roots,
                          runtime_sha256=digest(self._raw('runtime.json')), job_sha256=digest(self._raw('job.json')))
                self._verify_success(self.record)
            except BaseException:
                self.save('UNCERTAIN')
                raise ImportError('Recovery uncertain; retained evidence/fence, no automatic retry or Start.') from None
            return self.status()
    def start(self,*,confirmed_stopped=False):
        with self.mutex:
            if self.closed or confirmed_stopped is not True or self.record['state']!='REPAIRED':
                raise ImportError('Explicit Start requires acknowledged durable repair, never maintenance intent.')
            self._verify_success(self.record)
            if self.manager is not None:
                self.manager.close()
                self.manager=None
            self.save('WRITER_ADMITTED') # crash before/after launch never reauthorizes Start
            self.writer_admitted=True
            try:
                self.manager=ManagedImporter(self.paths['pier'],self.paths['uploads'],self.paths['control'],
                    runtime_adapter=self.adapter,**self.limits)
                self.manager.start(confirmed_stopped=True)
            except BaseException:
                self.save('UNCERTAIN')
                raise ImportError('Explicit Start uncertain; native replacement required before recovery.') from None
            return self.status()
    def stop(self):
        with self.mutex:
            if self.manager is None: raise ImportError('No runtime owned by this process.')
            self.manager.stop()
            self.save('REPAIRED',runtime_sha256=digest(self._raw('runtime.json')))
            return self.status()
    def status(self):
        with self.mutex:
            if self.manager:
                result=self.manager.status()
            else:
                try:
                    job=journal._object(self._raw('job.json')); runtime=journal._object(self._raw('runtime.json'))
                    if runtime!={'state':'STOPPED'}:
                        runtime={'state':'RECOVERY_REQUIRED'} # persisted intent is not an owned running process
                    result={'state':job.get('state'),'runtime':runtime}
                except (OSError,journal.RecoveryRefused):
                    result={'state':'RECOVERY_REQUIRED','runtime':{'state':'RECOVERY_REQUIRED'}}
            result['maintenance']={'state':self.record['state'],'feature_retained':True,'build':BUILD,
                'admission_available':not self.writer_admitted and not self.admission_attempted and not self.closed and self.record['state'] in ('MAINTENANCE','REPAIRED','UNCERTAIN'),
                'generation':self.generation,'trust_model':'APPROVED_ADMIN_NONINTERFERENCE'}
            result['start_available']=not self.closed and self.record['state']=='REPAIRED'
            return result
    def capacity(self): return {'maintenance_only':self.manager is None}
    def close(self):
        with self.mutex:
            if self.closed:return
            if self.manager is not None: self.manager.close()
            os.close(self.lockfd); os.close(self.fd); self.closed=True
    def __enter__(self): return self
    def __exit__(self,*args): self.close()

class RecoveryHandler(legacy_http.Handler):
    def do_POST(self):
        if not self.path.startswith('/api/maintenance/'):
            # Inception/upload/delete endpoints are deliberately unavailable in this legacy worker.
            if self.path not in ('/api/login','/api/logout','/api/start','/api/stop'):
                return self.reply(404,{'error':'Legacy maintenance endpoint not found.'})
            return super().do_POST()
        if not self.host_allowed() or self.headers.get_all('Origin',[])!=[self.server.origin]:
            return self.reply(403,{'error':'Origin or Host rejected.'})
        session=self.session()
        if not session: return self.reply(401,{'error':'Authentication required.'})
        if self.headers.get_all('X-CSRF-Token',[])!=[session['csrf']]:
            return self.reply(403,{'error':'CSRF token rejected.'})
        try:
            if self.headers.get_all('Content-Type',[])!=['application/json'] or self.body()!=b'{}':
                raise ValueError()
            if self.path=='/api/maintenance/admit': value=self.server.engine.admit_maintenance()
            elif self.path=='/api/maintenance/recover': value=self.server.engine.recover()
            else: return self.reply(404,{'error':'Unknown maintenance operation.'})
            return self.reply(200,value)
        except ValueError: return self.reply(400,{'error':'Exact empty JSON object required; no stopped assertions or paths accepted.'})
        except (ImportError,OSError,journal.RecoveryRefused,journal.RecoveryUncertain):
            return self.reply(409,{'error':'Maintenance refused or uncertain; retain replacement, inspect durable status/evidence.'})
    def do_PUT(self): self.reply(405,{'error':'Method rejected.'})
    do_DELETE=do_PUT

def make_server(engine,bind,credential,**options):
    httpd=legacy_http.make_server(engine,bind,credential,**options)
    httpd.RequestHandlerClass=RecoveryHandler
    return httpd

def main():
    # Reuse exact existing argument, credential, TLS and enrollment plumbing.
    legacy_http.make_server=make_server_for_main
    return legacy_http.main(engine_class=RecoveryEngine)

_original_make_server=legacy_http.make_server
def make_server_for_main(engine,bind,credential,**options):
    httpd=_original_make_server(engine,bind,credential,**options)
    httpd.RequestHandlerClass=RecoveryHandler
    return httpd

if __name__=='__main__': raise SystemExit(main())
