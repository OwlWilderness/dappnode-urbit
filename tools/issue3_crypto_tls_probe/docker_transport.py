"""Bounded CLI transport; explicit host/engine identities, no ambient context.

No import-time Docker. Queries retain only positively selected public fields.
The binary artifact stream is distinct from bounded target diagnostic capture.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tarfile
import time

from . import execution, outer, output_contract, prepare, supervisor, wire, settlement
from .stage import open_regular, save_new

CLIENT='/Applications/Docker.app/Contents/Resources/bin/docker'
CLIENT_SHA='b12e1e7a3cd2cebd2d3b03bbb58368e7c2439a3c09003e175029815b6ccc0e24'
CONTROLLERS={'execution.py','supervisor.py','stage.py','prepare.py','bind_b04.py','probe.c',
             'wire.py','phase_worker.py','output_contract.py'}
FIELDS={
 'id':'.Id','name':'.Name','label':'(index .Config.Labels "org.uvm.issue3")',
 'image':'.Image','user':'.Config.User','entrypoint':'.Config.Entrypoint','cmd':'.Config.Cmd',
 'readonly':'.HostConfig.ReadonlyRootfs','network':'.HostConfig.NetworkMode',
 'logging':'.HostConfig.LogConfig.Type','privileged':'.HostConfig.Privileged',
 'ports':'(len .HostConfig.PortBindings)','memory':'.HostConfig.Memory','swap':'.HostConfig.MemorySwap',
 'cpus':'.HostConfig.NanoCpus','pids':'.HostConfig.PidsLimit','cap_drop':'.HostConfig.CapDrop',
 'cap_add':'.HostConfig.CapAdd','security':'.HostConfig.SecurityOpt','restart':'.HostConfig.RestartPolicy.Name',
 'cgroupns':'.HostConfig.CgroupnsMode','ipc':'.HostConfig.IpcMode','pid_mode':'.HostConfig.PidMode',
 'devices':'.HostConfig.Devices','device_requests':'.HostConfig.DeviceRequests',
 'binds':'.HostConfig.Binds','volumes_from':'.HostConfig.VolumesFrom','auto_remove':'.HostConfig.AutoRemove','core':'.HostConfig.Ulimits',
 'tmpfs':'(index .HostConfig "Tmpfs")','status':'.State.Status','running':'.State.Running',
 'pid':'.State.Pid','exit_code':'.State.ExitCode','oom_killed':'.State.OOMKilled','started_at':'.State.StartedAt'}
FORMAT='{'+','.join('"'+k+'":{{json '+v+'}}' for k,v in FIELDS.items())
FORMAT+=',"mount_options":[{{range $i,$m := .HostConfig.Mounts}}{{if $i}},{{end}}{"source":{{json $m.Source}},"target":{{json $m.Target}},"readonly":{{json $m.ReadOnly}},"nonrecursive":{{json $m.BindOptions.NonRecursive}}}{{end}}]'
FORMAT+=',"mounts":[{{range $i,$m := .Mounts}}{{if $i}},{{end}}{"type":{{json $m.Type}},"source":{{json $m.Source}},"destination":{{json $m.Destination}},"rw":{{json $m.RW}}}{{end}}]}'


def export_public(stream,destination,phase):
    """Validate every literal member before writing; no general extraction."""
    allowed=output_contract.allowed(phase)
    destination=Path(destination); destination.mkdir(mode=0o700)
    seen=set(); total=0
    with open_regular(Path(stream)) as source:
        for _ in range(1000):
            line=source.readline(4097)
            prepare.require(len(line)<=4096 and line.endswith(b'\n'),'bounded export preamble')
            if line==b'ISSUE3_EXPORT\n': break
            if line.startswith(b'ISSUE3_EVIDENCE '):
                frame=json.loads(line[len(b'ISSUE3_EVIDENCE '):])
                prepare.require(set(frame)=={'name','data'} and output_contract.early_record(frame['name'],frame['data'])==frame['data'], 'early frame schema')
            else:
                prepare.require(line.startswith(b'ISSUE3_GUEST '),'export preamble grammar')
        else: raise ValueError('export marker missing')
        with tarfile.open(fileobj=source,mode='r|') as archive:
            for row in archive:
                prepare.require(row.name in allowed and row.name not in seen and row.isfile() and
                    row.linkname=='' and not row.pax_headers and 0<=row.size<=67108864,'public export member refused')
                seen.add(row.name); total+=row.size
                prepare.require(len(seen)<=128 and total<=94*1024**2,'public export aggregate cap')
                path=destination/row.name; path.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
                reader=archive.extractfile(row)
                prepare.require(reader is not None,'export member unavailable')
                with reader, path.open('xb') as sink:
                    remaining=row.size
                    while remaining:
                        data=reader.read(min(1048576,remaining))
                        prepare.require(data,'short artifact export')
                        sink.write(data); remaining-=len(data)
                    sink.flush(); os.fsync(sink.fileno())
                path.chmod(0o444)
    worker=json.loads((destination/'worker.json').read_text()) if 'worker.json' in seen else None
    guest_supervisor=json.loads((destination/'supervisor.json').read_text()) if 'supervisor.json' in seen else None
    if worker is None or worker.get('success') is not True or worker.get('heartbeat_errors')!=[]:
        result_path=destination/(phase+'-result.json')
        failed=json.loads(result_path.read_text()) if result_path.is_file() else {}
        return dict(files=len(seen),bytes=total,phase=phase,artifact_validated=False,
            worker_success=False,compiler=failed.get('process') if phase=='compile' else None,
            guest_supervisor=guest_supervisor,error='WORKER_FAILED_OR_INCOMPLETE',target_crypto_qualified=False,final_elf_acceptance=False)
    prepare.require(phase+'-result.json' in seen,'complete worker export required')
    result=json.loads((destination/(phase+'-result.json')).read_text())
    if phase=='compile':
        binary=execution.static_elf(destination/'probe')
        prepare.require(binary==result['binary'] and supervisor.digest(destination/'probe.map',16777216)==result['map'],
                        'exported ELF/map identity mismatch')
        (destination/'probe').chmod(0o555)
    else:
        prepare.require(len(result.get('cases',[]))==15,'complete sequential case export required')
        for i,(mode,fault) in enumerate(supervisor.CASES):
            row=result['cases'][i]
            prepare.require((row['mode'],row['fault'])==(mode,fault),'case ordering')
            prefix=destination/f'runtime/{i:02d}-{mode}-{fault}'
            with open_regular(prefix/'stdout') as f: stdout=f.read(16385)
            prepare.require(len(stdout)<=16384,'exported case stdout bound')
            prepare.validate_result(stdout.decode(),row['process']['returncode'],mode,fault)
    return dict(files=len(seen),bytes=total,phase=phase,artifact_validated=True,
                guest_supervisor=guest_supervisor,
                binary=result['binary'] if phase=='compile' else None,
                target_crypto_qualified=False,final_elf_acceptance=False)


class DockerCLI:
    def __init__(self,profile,evidence):
        t=profile['transport']
        prepare.require(t.get('path')==CLIENT and t.get('sha256')==CLIENT_SHA and
            re.fullmatch(r'unix:///[A-Za-z0-9_./+-]+',t.get('endpoint','')) and
            type(t.get('engine_id')) is str and t['engine_id'],'exact client/endpoint required')
        self.profile=profile; self.root=Path(evidence)
        self.argv=(CLIENT,'--host='+t['endpoint']); self.counter=0

    def bind_settlement(self,folder,deadline):
        prepare.require(settlement.read(self.profile,folder)['deadline_monotonic']==deadline and
            getattr(self,'settlement_end',deadline)==deadline,'immutable query settlement endpoint mismatch')
        self.settlement_end=deadline

    def query(self,args,timeout=5,absent=False):
        end=getattr(self,'settlement_end',None)
        if end is not None: timeout=min(timeout,settlement.remaining(end))
        self.root.mkdir(mode=0o700,exist_ok=True)
        self.counter+=1
        prepare.require(self.counter<=1000,'bounded daemon query count')
        budget=dict(supervisor.BUDGETS['compile'],seconds=min(timeout,10),stdout=16384,stderr=2048,
                    combined_capture=18432,file_bytes=32768)
        folder=self.root/f'query-{self.counter:04d}'
        row=supervisor.capture(self.argv+tuple(args),folder,budget,**({'deadline':end} if end is not None else {}))
        if end is not None: settlement.remaining(end)
        if absent and row['reason']=='EXIT' and row['returncode']==1:
            # Docker's exact missing-object diagnostic only; transport failure is
            # not absence. This output is from the explicitly selected object.
            text=(folder/'stderr').read_text()
            prepare.require('No such' in text and ('object' in text or 'container' in text),'inspect transport failure')
            return None
        prepare.require(row['reason']=='EXIT' and row['returncode']==0 and row['reaped'], 'bounded Docker request failed')
        return (folder/'stdout').read_text().strip()

    def identity(self,profile,deadline=None):
        def budget(): return 5 if deadline is None else settlement.remaining(deadline,5)
        budget()
        prepare.require(supervisor.digest(Path(CLIENT),128*1024**2)['sha256']==CLIENT_SHA,'client bytes drift')
        row=json.loads(self.query(['info','--format',
            '{"id":{{json .ID}},"arch":{{json .Architecture}},"os":{{json .OSType}},"cgroup":{{json .CgroupVersion}}}'],timeout=budget()))
        prepare.require(row['id']==profile['transport']['engine_id'] and row['os']=='linux' and row['cgroup']=='2',
                        'selected Linux cgroup-v2 daemon identity')
        binding=profile['amd64_execution_binding']
        managed = binding == dict(kind='engine-managed-platform',engine_id=row['id'],
            endpoint=profile['transport']['endpoint'],platform='linux/amd64',
            emulator_identity_verified=False,provenance_limitation_accepted=True)
        prepare.require((row['arch'] in ('x86_64','amd64') and binding['kind']=='native') or
            (row['arch'] in ('aarch64','arm64') and (managed or (binding['kind']=='exact-emulator' and
             binding.get('engine_id')==row['id'] and binding.get('verified') is True))), 'verified AMD64 execution binding required')
        image=json.loads(self.query(['image','inspect','--format',
            '{"image_id":{{json .Id}},"architecture":{{json .Architecture}},"os":{{json .Os}},"volumes":{{json .Config.Volumes}},"onbuild":{{json .Config.OnBuild}}}',profile['base']['image_id']],timeout=budget()))
        image['volumes']=len(image['volumes'] or {}); image['onbuild']=len(image['onbuild'] or [])
        prepare.require(image==profile['base'],'cached image identity/configuration drift')
        budget()

    def verify_inputs(self,profile):
        deadline=time.monotonic()+90
        import sys
        host=profile['host_controllers']
        prepare.require(set(host)=={'outer.py','docker_transport.py','watchdog.py'},'complete host controller binding')
        extra=profile.get('host_settlement_controllers',{})
        prepare.require(set(extra)=={'settlement.py','settlement_verifier.py'},'complete settlement controller binding')
        execution.verify_public_file(Path(sys.executable).resolve(),profile['host_python'],deadline)
        for name,pin in {**host,**extra,**profile['controllers']}.items():
            execution.verify_public_file(prepare.HERE/name,pin,deadline)
        for key in ('request','observer'):
            path=Path(profile['mounts'][key])
            prepare.require(path.is_dir() and not any(path.iterdir()),'fresh empty '+key+' tree required')
        prepare.require(hashlib.sha256(wire.encoded(profile['manifest'])).hexdigest()==
            'd709310c00aa8fbb6b182560bb89df4124622505cc380ab5e37be8f65bb61404','exact original b04 manifest')
        for key,source in profile['mounts'].items():
            path=Path(source)
            prepare.require(path==path.resolve() and path.is_dir(),'present canonical readonly '+key+' tree required')
        prepare.prepare(Path(profile['mounts']['inputs']),profile['manifest'])
        pins=profile['controllers']; prepare.require(set(pins)==CONTROLLERS,'complete isolated controller namespace')
        root=Path(profile['mounts']['controller'])
        expected={str(Path('tools/issue3_crypto_tls_probe')/name) for name in pins}
        actual=set()
        for p in root.rglob('*'):
            prepare.require(not p.is_symlink(),'controller symlink')
            if p.is_file(): actual.add(p.relative_to(root).as_posix())
        prepare.require(actual==expected,'controller import closure namespace')
        for name,pin in pins.items(): execution.verify_public_file(root/'tools/issue3_crypto_tls_probe'/name,pin,deadline)
        # Full pinned compiler/sysroot inventory, no substitute cache or SDK.
        tool=profile['toolchain']; prefix='zig-x86_64-linux-0.15.2/'
        prepare.require(hashlib.sha256(wire.encoded(tool['files'])).hexdigest()==tool['inventory_sha256']==
            'ce70d945c37fd7a3601f4d0d0d68628be4a5811027054e497929fb1ea94b0276','exact toolchain inventory')
        root=Path(profile['mounts']['toolchain']); expected=set()
        for name,pin in tool['files'].items():
            prepare.require(name.startswith(prefix) and (name==prefix+'zig' or name.startswith(prefix+'lib/')),'toolchain path')
            relative=name[len(prefix):]; expected.add(relative)
            execution.verify_public_file(root/relative,{k:pin[k] for k in ('bytes','sha256')},deadline)
        actual=set()
        for p in root.rglob('*'):
            prepare.require(not p.is_symlink() and time.monotonic()<deadline,'toolchain tree bound')
            if p.is_file(): actual.add(p.relative_to(root).as_posix())
        prepare.require(actual==expected,'exact extracted toolchain tree')
        if profile['phase']=='run':
            execution.verify_public_file(Path(profile['mounts']['program'])/'probe',profile['probe'],deadline)

    def arm_guard(self,profile,folder,deadline=None):
        import subprocess,sys
        folder=Path(folder)
        code='import sys; sys.path.insert(0,'+repr(str(Path(__file__).resolve().parents[2]))+'); from tools.issue3_crypto_tls_probe.watchdog import main; raise SystemExit(main())'
        self.guard=subprocess.Popen([sys.executable,'-I','-S','-c',code,'--folder',str(folder),
            '--parent',str(os.getpid()),'--deadline',str(deadline if deadline is not None else time.monotonic()+outer.phase_seconds(profile))],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
            start_new_session=True,close_fds=True,env={'PATH':'/usr/bin:/bin','TMPDIR':os.environ.get('TMPDIR','/work')})
        save_new(folder/'watchdog-pid.json',wire.encoded(dict(pid=self.guard.pid)))
        end=min(time.monotonic()+10,deadline if deadline is not None else profile['experiment']['deadline_monotonic'])
        while not (folder/'watchdog-ready.json').is_file():
            prepare.require(self.guard.poll() is None and time.monotonic()<end,'independent watchdog failed to arm')
            time.sleep(.05)

    def finish_guard(self,folder,deadline):
        prepare.require(settlement.read(self.profile,folder)['deadline_monotonic']==deadline,
                        'shared watchdog endpoint mismatch')
        process=getattr(self,'guard',None)
        if process is None:
            return dict(settled=not (Path(folder)/'create-spent.json').exists(),armed=False)
        try: process.wait(timeout=settlement.remaining(deadline))
        except __import__('subprocess').TimeoutExpired:
            return dict(settled=False,error='watchdog still active; exact-owned manual recovery required')
        path=Path(folder)/'watchdog-result.json'
        if not path.is_file(): return dict(settled=False,error='watchdog result unavailable')
        with open_regular(path) as f: data=f.read(16385)
        prepare.require(len(data)<=16384,'watchdog result cap')
        settlement.remaining(deadline)
        return json.loads(data)

    def verify_settlement(self,folder,deadline):
        """One separate read-only verifier, launched and joined before return."""
        import subprocess,sys
        folder=Path(folder)
        endpoint=settlement.read(self.profile,folder)
        prepare.require(endpoint['deadline_monotonic']==deadline,'shared verifier endpoint mismatch')
        settlement.remaining(deadline)
        save_new(folder/'independent-verifier-spent.json',wire.encoded(dict(automatic_retry=False)))
        code='import sys; sys.path.insert(0,'+repr(str(Path(__file__).resolve().parents[2]))+'); from tools.issue3_crypto_tls_probe.settlement_verifier import main; raise SystemExit(main())'
        child=None
        try:
            settlement.remaining(deadline)
            child=subprocess.Popen([sys.executable,'-I','-S','-c',code,'--folder',str(folder)],
                stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                start_new_session=True,close_fds=True,
                env={'PATH':'/usr/bin:/bin','TMPDIR':os.environ.get('TMPDIR','/work'),
                     'PYTHONDONTWRITEBYTECODE':'1'})
            save_new(folder/'independent-verifier-pid.json',wire.encoded(dict(pid=child.pid,pgid=child.pid)))
            child.wait(timeout=settlement.remaining(deadline))
            with open_regular(folder/'independent-verification.json') as stream: data=stream.read(16385)
            prepare.require(len(data)<=16384,'independent verification receipt cap')
            result=json.loads(data)
            from .watchdog import read_json
            cid=read_json(folder/'owned.json')['container_id']
            prepare.require(result.get('verifier_pid')==child.pid and result.get('container_id')==cid and
                result.get('profile_sha256')==endpoint['profile_sha256'] and
                result.get('deadline_monotonic')==deadline,'independent verification identity/endpoint drift')
            result['verifier_process']=dict(pid=child.pid,returncode=child.returncode,reaped=True)
            result['release_allowed']=(child.returncode==0 and result.get('safety_verified') is True and
                result.get('checked_within_shared_deadline') is True and result.get('release_allowed') is True and
                time.monotonic()<deadline)
            return result
        except Exception as exc:
            # Never reset the endpoint to wait for a late verifier. An unreaped
            # observer retains the slot; no target action or automatic retry.
            reaped=False
            if child is not None:
                if child.poll() is None: child.kill()
                reaped=child.poll() is not None
            return dict(safety_verified=False,checked_within_shared_deadline=False,release_allowed=False,
                error=type(exc).__name__+': '+str(exc)[:1000],
                verifier_process=dict(pid=child.pid if child else None,reaped=reaped))

    def collision(self,name):
        return bool(self.query(['ps','-aq','--no-trunc','--filter','name=^/'+name+'$']))

    def create(self,argv): return self.query(argv)

    def inspect(self,target,timeout=5):
        text=self.query(['inspect','--format',FORMAT,target],timeout=timeout,absent=True)
        if text is None: return None
        row=json.loads(text); row['mounts'].sort(key=lambda m:m['destination'])
        row['mount_options'].sort(key=lambda m:m['target'])
        # Null devices is Docker's empty slice, not an absent field.
        if row['devices'] is None: row['devices']=[]
        return row

    def stop(self,cid,timeout): return self.query(['stop','--time=5',cid],timeout=timeout)
    def kill(self,cid,timeout): return self.query(['kill',cid],timeout=timeout)

    def attach(self,cid,folder,seconds,monitor):
        folder=Path(folder); capture=folder/'attach'
        position=0; exported=False; guest=None; last=0; seen=set()
        early=folder/'early'; early.mkdir(mode=0o700)
        def tick():
            nonlocal position,exported,guest,last
            path=capture/'stdout'
            if not path.exists(): return
            with path.open('rb') as f:
                f.seek(position)
                while not exported:
                    line=f.readline(4097)
                    prepare.require(len(line)<=4096,'bounded worker frame')
                    if not line.endswith(b'\n'): break
                    position=f.tell()
                    if line==b'ISSUE3_EXPORT\n': exported=True; break
                    if line.startswith(b'ISSUE3_EVIDENCE '):
                        frame=json.loads(line[len(b'ISSUE3_EVIDENCE '):])
                        prepare.require(set(frame)=={'name','data'},'early frame fields')
                        name=frame['name']; data=output_contract.early_record(name,frame['data'])
                        prepare.require(data==frame['data'] and name not in seen and len(seen)<len(output_contract.EARLY),'unique bounded early frame')
                        target=early/name; target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                        save_new(target,wire.encoded(data)); seen.add(name)
                        for directory in (early,folder):
                            fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                            try: os.fsync(fd)
                            finally: os.close(fd)
                        if name=='compile/child-controls.json':
                            ack=Path(self.profile['mounts']['observer'])/'compile-controls-ack.json'
                            outer.atomic_json(ack,dict(sha256=hashlib.sha256(wire.encoded(data)).hexdigest()))
                        continue
                    prepare.require(line.startswith(b'ISSUE3_GUEST '),'worker frame grammar')
                    guest=json.loads(line[len(b'ISSUE3_GUEST '):])
            now=time.monotonic()
            if guest is not None and not exported and now-last>=.5:
                monitor(guest); last=time.monotonic()
        budget=dict(supervisor.BUDGETS['compile'],seconds=seconds,stdout=96*1024**2,
                    stderr=1048576,combined_capture=97*1024**2,file_bytes=96*1024**2)
        row=supervisor.capture(self.argv+('start','--attach',cid),capture,budget,monitor=tick)
        # Preserve attach outcome before parsing any terminal export. Drain frames
        # written immediately before EOF/kill, even when monitor failed earlier.
        save_new(folder/'attach-result.json',wire.encoded(row))
        try: tick()
        except Exception as exc: row['early_error']=type(exc).__name__
        # Exported files are retained even when validation subsequently refuses.
        try:
            row['export']=export_public(capture/'stdout',folder/'public',self.profile['phase'])
        except Exception as exc:
            row['export']=dict(phase=self.profile['phase'],artifact_validated=False,error=type(exc).__name__)
        process=early/'compile/process.json'
        public=folder/'public'
        if not process.is_file(): process=public/'compile/process.json'
        row['compiler']=row['export'].get('compiler')
        if process.is_file():
            try:
                with open_regular(process) as source: data=source.read(16385)
                prepare.require(len(data)<=16384,'compiler process receipt cap')
                row['compiler']=output_contract.early_record('compile/process.json',json.loads(data))
            except Exception as exc: row['compiler_receipt_error']=type(exc).__name__
        def observed(name): return (early/name).is_file() or (public/name).is_file()
        row['compiler_launch']=dict(intent=observed('stage-launch-intent.json'),
            inherited_controls=observed('compile/inherited-controls.json'),
            preexec_controls=observed('compile/child-controls.json'),
            popen_returned=observed('compile/pid.json'),post_exec_controls_observed=False)
        save_new(folder/'attach-report.json',wire.encoded(row))
        return row
