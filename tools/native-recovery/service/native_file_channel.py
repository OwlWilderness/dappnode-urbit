"""Root File Manager delegation, not a host-cessation proof or a NativeAuthority.

The trusted external administrator performs real stop/install/readback BEFORE
issuing repair. This worker cannot verify those native actions independently.
This narrowly scoped policy relies on the declared maintenance/noninterference
and ordinary-container-confinement assumptions; hostile root/escaped writers are
outside it. No mTLS, private Admin fetch, terminal, socket or Docker in worker.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
import time

import permanent_recovery as base
import trusted_admin_journal as journal

POLICY='TRUSTED_NATIVE_ADMIN_MAINTENANCE_V1'
COMMAND=Path('/opt/importer/native-command.json')
STATUS='native-file-status.json'
SOURCES=('native_file_channel.py','trusted_admin_journal.py','permanent_recovery.py',
         'legacy015_recovery.py','managed_service.py','runtime.py')
START_CONFIRMATION='Start the retained pier after native legacy015 repair'

class Refused(Exception): pass

def read_command(path=COMMAND):
    """All-root nofollow ancestry + regular nonwritable root leaf; no UID override."""
    path=Path(path)
    if not path.is_absolute(): raise Refused('Absolute protected path required.')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for component in path.parts[1:-1]:
            st=os.fstat(fd)
            if st.st_uid!=0 or stat.S_IMODE(st.st_mode)&0o022:
                raise Refused('Root-owned nonwritable command ancestry required.')
            child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd); fd=child
        st=os.fstat(fd)
        if st.st_uid!=0 or stat.S_IMODE(st.st_mode)&0o022:
            raise Refused('Root-owned nonwritable command parent required.')
        leaf=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
        with os.fdopen(leaf,'rb') as source:
            st=os.fstat(source.fileno())
            if (not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or
                    stat.S_IMODE(st.st_mode)&0o022 or not 0<st.st_size<=65536):
                raise Refused('Strict root-owned regular command required.')
            raw=source.read(65537)
            after=os.fstat(source.fileno())
            stable=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
            if stable(after)!=stable(st) or len(raw)!=st.st_size: raise Refused('Command changed during read.')
            return raw,(st.st_dev,st.st_ino,st.st_mtime_ns,st.st_size,base.digest(raw))
    finally: os.close(fd)

def source_hashes():
    root=Path(__file__).parent
    return {name:base.digest((root/name).read_bytes()) for name in SOURCES}

class Delegation:
    def __init__(self,engine,raw,token):
        self.engine,self.raw,self.token=engine,raw,token
        self.command=journal._object(raw)
        c=self.command
        expected={'policy','generation','sequence','transaction','operation','expires',
                  'old_container_id','container_id','sources','native_receipt_sha256',
                  'runtime_sha256','job_sha256','confirmation','prior_state_sha256'}
        if set(c)!=expected or c['policy']!=POLICY: raise Refused('Unknown command schema/policy.')
        if c['generation']!=engine.generation: raise Refused('Stale worker generation.')
        if (type(c['sequence']) is not int or c['sequence']!=engine.record.get('native_sequence',0)+1 or
                type(c['expires']) is not int or not 0<c['expires']-time.time()<=900):
            raise Refused('Command sequence/expiry refused.')
        for field,width in [('transaction',32),('old_container_id',64),('container_id',64),
                            ('native_receipt_sha256',64),('runtime_sha256',64),('job_sha256',64)]:
            if type(c[field]) is not str or not re.fullmatch('[0-9a-f]{%d}'%width,c[field]):
                raise Refused('Command identity refused.')
        if c['old_container_id']==c['container_id'] or c['sources']!=source_hashes():
            raise Refused('Replacement/source binding refused.')
        if c['operation'] not in ('repair','start','stop','reconcile'): raise Refused('Unknown bounded operation.')
        if c['operation']=='reconcile':
            if type(c['prior_state_sha256']) is not str or not re.fullmatch('[a-f0-9]{64}',c['prior_state_sha256']):
                raise Refused('Exact prior durable state hash required.')
        elif c['prior_state_sha256'] is not None: raise Refused('Unexpected prior-state binding.')
        if c['confirmation']!=(START_CONFIRMATION if c['operation']=='start' else None):
            raise Refused('Separate exact Start confirmation required.')
        self.receipt_path=COMMAND.parent/('native-receipt-'+c['transaction']+'.json')
        self.receipt_raw,self.receipt_token=read_command(self.receipt_path)
        if base.digest(self.receipt_raw)!=c['native_receipt_sha256']:
            raise Refused('Retained native receipt hash mismatch.')
        if c['operation']=='reconcile':
            retained=journal._object(self.receipt_raw)
            resume=retained.get('resume',{})
            prior=journal._object(engine.record.get('native_command_raw','{}'))
            if (resume.get('stopped_container_id')!=c['container_id'] or
                    resume.get('boot_generation')!=engine.generation or
                    resume.get('before_stop_generation')==engine.generation or
                    not re.fullmatch('[a-f0-9]{64}',str(resume.get('before_stop_generation',''))) or
                    resume.get('prior_state_sha256')!=c['prior_state_sha256'] or
                    resume.get('prior_command_sha256')!=engine.record.get('native_command_sha256')):
                raise Refused('Fresh stopped/booted generation and prior outcome receipt required.')
            events=retained.get('events',[])
            stops=[i for i,e in enumerate(events) if e.get('method')=='dappnode_stop_package' and
                   e.get('result')=={'dnpName':'uvm.public.dappnode.eth','results':[
                       {'container':'DAppNodePackage-ship.uvm.public.dappnode.eth','ok':True}]}]
            exited=[i for i,e in enumerate(events) if e.get('method')=='packageGet/packagesGet' and
                    e.get('result',{}).get('containerId')==c['container_id'] and e['result'].get('state')=='exited']
            if not any(a<b for a in stops for b in exited):
                raise Refused('Actual retained native Stop completion and exited observation required.')
            if (prior!=engine.record.get('native_pending') or
                    prior.get('policy')!=POLICY or prior.get('sources')!=c['sources'] or
                    prior.get('generation')!=engine.record.get('generation') or
                    prior.get('old_container_id')!=c['old_container_id'] or prior.get('container_id')!=c['container_id'] or
                    base.digest(engine.record['native_command_raw'].encode())!=engine.record.get('native_command_sha256') or
                    prior.get('sequence')!=engine.record.get('native_sequence')):
                raise Refused('Unaccounted prior command outcome.')
            tx=prior.get('transaction','')
            if not re.fullmatch('[a-f0-9]{32}',str(tx)): raise Refused('Prior transaction malformed.')
            prior_receipt,_=read_command(COMMAND.parent/('native-receipt-'+tx+'.json'))
            if base.digest(prior_receipt)!=prior.get('native_receipt_sha256'):
                raise Refused('Prior real native receipt missing/changed.')
        self.deadline=time.monotonic()+min(900,c['expires']-time.time())
        self.verify_delegation({k:engine.paths[k] for k in ('pier','control','evidence')})
    def verify_delegation(self,target,bindings=None):
        expected={k:self.engine.paths[k] for k in ('pier','control','evidence')}
        if target!=expected: raise Refused('Fixed retained paths required.')
        raw,token=read_command()
        if raw!=self.raw or token!=self.token: raise Refused('Native delegation changed.')
        raw,token=read_command(self.receipt_path)
        if raw!=self.receipt_raw or token!=self.receipt_token: raise Refused('Native receipt retention changed.')
        if time.time()>=self.command['expires'] or time.monotonic()>=self.deadline:
            raise Refused('Native delegation expired; no renewal.')
        # Inode/byte checks below are physical local checks, NOT native revalidation.
        for path,dev,ino in (bindings or {}).values():
            st=os.stat(path,follow_symlinks=False)
            if (st.st_dev,st.st_ino)!=(dev,ino): raise Refused('Bound local inode changed.')

class FileEngine(base.RecoveryEngine):
    record: dict
    def __init__(self,*args,**kwargs):
        # Existing generic/controller APIs remain present but unused and fail closed.
        super().__init__(*args,**kwargs)
        self.native_error=None; self.active=None; self.last_raw=None
        self.halt=threading.Event()
        if os.geteuid()!=10000:
            self.close(); raise Refused('Packaged service UID10000 required.')
        # Startup is read-only and idle. Prior durable outcome stays byte-exact;
        # its old generation cannot authorize Start. Only explicit reconcile can.
        self.thread=threading.Thread(target=self._poll,daemon=True)
        self.thread.start()
    def check(self,*args,**kwargs):
        raise Refused('Generic controller contract unavailable under this separate policy.')
    def admit_maintenance(self): raise Refused('Use authenticated native File Manager command.')
    def recover(self): raise Refused('Use authenticated native File Manager command.')
    def start(self,**kwargs): raise Refused('Use a separate exact native Start command.')
    def stop(self): raise Refused('Use a separate native Stop command.')
    def _load(self):
        # Unlike the generic engine, retain known states/outcomes for reconciliation.
        # Unknown/malformed records are never rewritten or made Start-eligible.
        try: raw,_=journal._read(self.fd,'legacy-recovery-state.json',65536)
        except FileNotFoundError: return {'state':'MAINTENANCE'}
        record=journal._object(raw)
        if record.get('build')!=base.BUILD: raise Refused('Unknown recovery state build.')
        return record
    def status(self):
        result=super().status()
        result['start_available']=(result['start_available'] and self.record.get('generation')==self.generation)
        return result
    def _reconcile_check(self,c):
        r=self.record
        if self.manager is not None or self.writer_admitted:
            raise Refused('Reconciliation requires freshly booted idle worker after native full Stop.')
        if base.digest(self._raw('legacy-recovery-state.json'))!=c['prior_state_sha256']:
            raise Refused('Prior durable outcome changed.')
        pending=r.get('native_pending',{})
        if (r.get('native_outcome') not in ('COMPLETE','PENDING','INTERRUPTED') or
                pending.get('operation') not in ('repair','start','stop','reconcile') or
                pending.get('sequence')!=r.get('native_sequence') or
                r['state'] not in ('REPAIRED','WRITER_ADMITTED','UNCERTAIN') or
                (pending.get('operation')=='repair' and r['state']!='REPAIRED')):
            raise Refused('Incomplete repair/unaccounted outcome remains fenced.')
        # Validate original roots/job/evidence independently of mutable runtime intent.
        runtime=journal._object(self._raw('runtime.json'))
        if set(runtime)!={'state'} or runtime['state'] not in ('STOPPED','STARTING','RUNNING','FAULT','RECOVERY_REQUIRED'):
            raise Refused('Unknown runtime journal remains fenced.')
        complete=r.get('native_completed',{})
        if r['native_outcome']=='COMPLETE' and (complete.get('sequence')!=r['native_sequence'] or
                complete.get('operation')!=pending['operation'] or
                complete.get('command_sha256')!=r.get('native_command_sha256')):
            raise Refused('Completed acknowledgement does not bind the last command.')
        known_writer=(pending['operation']=='start' or (pending['operation']=='stop' and
                      complete.get('operation')=='start' and complete.get('sequence')==r['native_sequence']-1))
        if not known_writer and (runtime!={'state':'STOPPED'} or
                base.digest(self._raw('runtime.json'))!=r.get('runtime_sha256')):
            raise Refused('Runtime mutation without accounted writer ownership remains fenced.')
        if base.digest(self._raw('job.json'))!=r.get('job_sha256'):
            raise Refused('Original committed job changed.')
        for key,pair in r['roots'].items():
            fd=journal._directory(self.paths[key])
            try: st=os.fstat(fd)
            finally: os.close(fd)
            if [st.st_dev,st.st_ino]!=pair: raise Refused('Original physical root changed.')
        saved=self.paths['evidence']/r['evidence']
        if saved.parent!=self.paths['evidence']: raise Refused('Evidence path escaped.')
        fd=journal._directory(saved)
        try:
            if set(r['evidence_hashes'])!={'runtime.before','job.before','bindings.json','native-command.json','native-receipt.json'}:
                raise Refused('Complete original repair evidence required.')
            for name,sha in r['evidence_hashes'].items():
                if base.digest(journal._read(fd,name,65536)[0])!=sha: raise Refused('Original evidence changed.')
            if journal._read(fd,'job.before',65536)[0]!=self._raw('job.json'):
                raise Refused('Original job/evidence mismatch.')
        finally: os.close(fd)
        for entry in r.get('native_reconciliations',[]):
            p=self.paths['evidence']/entry['directory']
            if p.parent!=self.paths['evidence']: raise Refused('Reconcile evidence path escaped.')
            fd=journal._directory(p)
            try:
                for name,sha in entry['hashes'].items():
                    if base.digest(journal._read(fd,name,65536)[0])!=sha: raise Refused('Reconcile evidence changed.')
            finally: os.close(fd)
        return runtime
    def _execute(self,raw,token):
        with self.mutex:
            return self._apply(Delegation(self,raw,token))
    def _apply(self,permit):
        """Transition layer; production reaches this only via strict Delegation."""
        with self.mutex:
            raw=permit.raw; c=permit.command; op=c['operation']; runtime=None
            if op=='repair':
                if self.record['state']!='MAINTENANCE' or self.record.get('native_sequence',0)!=0:
                    raise Refused('Prior mutation/repair/reopen cannot be reconciled automatically.')
            elif op=='start':
                if self.record['state']!='REPAIRED' or self.record.get('generation')!=self.generation:
                    raise Refused('Only this generation repaired once may explicitly Start.')
                self._verify_success(self.record)
            elif op=='reconcile':
                runtime=self._reconcile_check(c)
            elif self.manager is None: raise Refused('No child owned by this generation.')
            for name in ('runtime.json','job.json'):
                if base.digest(self._raw(name))!=c[name.split('.')[0]+'_sha256']:
                    raise Refused('Exact retained journal binding changed.')
            if op!='repair' and (c['container_id']!=self.record['native_container_id'] or
                    c['old_container_id']!=self.record['native_old_container_id']):
                raise Refused('Command changed native transaction binding.')
            self.active=permit
            # Durable spend precedes ANY journal mutation or runtime launch.
            prior_raw=self._raw('legacy-recovery-state.json') if op=='reconcile' else None
            self.save(self.record['state'],native_sequence=c['sequence'],native_command_sha256=base.digest(raw),
                      native_command_raw=raw.decode(),native_pending=c,native_outcome='PENDING',
                      native_container_id=c['container_id'],native_old_container_id=c['old_container_id'])
            try:
                if op=='repair':
                    self.save('REPAIRING')
                    evidence=self.paths['evidence']
                    try: evidence.mkdir(mode=0o700)
                    except FileExistsError: pass
                    fd=journal._directory(evidence); os.fsync(fd); os.close(fd)
                    parent=journal._directory(evidence.parent); os.fsync(parent); os.close(parent)
                    saved=journal.recover(self.paths['pier'],self.paths['control'],evidence,permit=permit)
                    fd=journal._directory(saved)
                    try:
                        journal._write(fd,'native-command.json',raw)
                        journal._write(fd,'native-receipt.json',permit.receipt_raw); os.fsync(fd)
                        hashes={n:base.digest(journal._read(fd,n,65536)[0]) for n in
                                ('runtime.before','job.before','bindings.json','native-command.json','native-receipt.json')}
                    finally: os.close(fd)
                    roots={}
                    for k,p in self.paths.items():
                        fd=journal._directory(p)
                        try: st=os.fstat(fd); roots[k]=[st.st_dev,st.st_ino]
                        finally: os.close(fd)
                    permit.verify_delegation({k:self.paths[k] for k in ('pier','control','evidence')})
                    self.save('REPAIRED',evidence=saved.name,evidence_hashes=hashes,roots=roots,
                              runtime_sha256=base.digest(self._raw('runtime.json')),
                              job_sha256=base.digest(self._raw('job.json')))
                    self._verify_success(self.record)
                elif op=='reconcile':
                    # Retain the exact prior outcome, not just a replacement label.
                    saved=self.paths['evidence']/('native-resume-'+c['transaction'])
                    saved.mkdir(mode=0o700)
                    fd=journal._directory(saved)
                    try:
                        for name,data in [('state.before',prior_raw),('native-command.json',raw),('native-receipt.json',permit.receipt_raw)]:
                            journal._write(fd,name,data)
                        os.fsync(fd)
                        hashes={name:base.digest(journal._read(fd,name,65536)[0]) for name in
                                ('state.before','native-command.json','native-receipt.json')}
                    finally: os.close(fd)
                    fd=journal._directory(self.paths['evidence']);os.fsync(fd);os.close(fd)
                    history=self.record.get('native_reconciliations',[])+[{'directory':saved.name,'hashes':hashes}]
                    self.save('UNCERTAIN',native_reconciliations=history)
                    if runtime!={'state':'STOPPED'}:
                        # Genuine fresh native full Stop was delegated; preserve the
                        # known writer journal through the unchanged atomic helper.
                        cessation=journal.recover(self.paths['pier'],self.paths['control'],self.paths['evidence'],permit=permit)
                        fd=journal._directory(cessation)
                        try: h={name:base.digest(journal._read(fd,name,65536)[0]) for name in ('runtime.before','job.before','bindings.json')}
                        finally: os.close(fd)
                        history=history+[{'directory':cessation.name,'hashes':h}]
                    permit.verify_delegation({k:self.paths[k] for k in ('pier','control','evidence')})
                    self.save('REPAIRED',native_reconciliations=history,
                              runtime_sha256=base.digest(self._raw('runtime.json')))
                    self._verify_success(self.record)
                elif op=='start':
                    permit.verify_delegation({k:self.paths[k] for k in ('pier','control','evidence')})
                    base.RecoveryEngine.start(self,confirmed_stopped=True)
                else: base.RecoveryEngine.stop(self)
                self.save(self.record['state'],native_outcome='COMPLETE',native_completed={
                    'sequence':c['sequence'],'operation':op,'command_sha256':base.digest(raw),
                    'runtime_sha256':base.digest(self._raw('runtime.json')),
                    'job_sha256':base.digest(self._raw('job.json'))})
            except BaseException:
                self.save('UNCERTAIN',native_outcome='INTERRUPTED'); raise
            finally: self.active=None
    def _publish(self):
        with self.mutex:
            status={'policy':POLICY,'generation':self.generation,'state':self.record['state'],
                    'sequence':self.record.get('native_sequence',0),'sources':source_hashes(),
                    'feature_retained':True,'error':self.native_error,
                    'runtime_sha256':base.digest(self._raw('runtime.json')),
                    'job_sha256':base.digest(self._raw('job.json')),
                    'durable_generation':self.record.get('generation'),
                    'command_sha256':self.record.get('native_command_sha256'),
                    'outcome':self.record.get('native_outcome'),
                    'state_sha256':base.digest(self._raw('legacy-recovery-state.json')) if self.record.get('build') else None}
            base._atomic(self.fd,STATUS,status)
    def _poll(self):
        while not self.halt.is_set():
            try:
                try: raw,token=read_command()
                except FileNotFoundError: raw=None; token=None
                if raw is not None and token is not None and raw!=self.last_raw:
                    self.last_raw=raw
                    known_prior=(base.digest(raw)==self.record.get('native_command_sha256') and
                                 self.record.get('native_pending',{}).get('generation')!=self.generation)
                    if not known_prior:
                        try: self._execute(raw,token); self.native_error=None
                        except BaseException: self.native_error='REFUSED_OR_UNCERTAIN'
                self._publish()
            except BaseException:
                self.native_error='CHANNEL_UNAVAILABLE'
            self.halt.wait(0.5)
    def close(self):
        if hasattr(self,'halt'):
            self.halt.set()
            if hasattr(self,'thread') and threading.current_thread()!=self.thread: self.thread.join(timeout=3)
        super().close()

class NativeOnlyHandler(base.RecoveryHandler):
    def do_POST(self):
        if self.path not in ('/api/login','/api/logout'):
            return self.reply(403,{'error':'Native File Manager is the only lifecycle control channel.'})
        return super().do_POST()

def main():
    # Keep established TLS/login/status plumbing, not an alternative writer API.
    def make_server(engine,bind,credential,**options):
        httpd=base._original_make_server(engine,bind,credential,**options)
        httpd.RequestHandlerClass=NativeOnlyHandler
        return httpd
    base.legacy_http.make_server=make_server
    return base.legacy_http.main(engine_class=FileEngine)

if __name__=='__main__': raise SystemExit(main())
