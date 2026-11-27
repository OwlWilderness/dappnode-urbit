"""Read-only post-run closeout; never creates/starts/execs a container."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import time

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO))
from tools.issue3_systemresources_diagnostic.host import ROOT, PRIOR, pin, put
from tools.issue3_crypto_tls_probe.docker_transport import DockerCLI

def main():
    result=json.loads((ROOT/'result.json').read_text())
    intent=json.loads((ROOT/'intent.json').read_text())
    d=DockerCLI(intent['profile_input_only'],ROOT/'closeout-transport')
    final=d.inspect(result['cid'])
    b02old=json.loads((PRIOR/'independent-b02-preserved.json').read_text())
    b02=json.loads(d.query(['inspect','--format','{"id":{{json .Id}},"running":{{json .State.Running}},"pid":{{json .State.Pid}},"oom":{{json .State.OOMKilled}},"mounts":{{json .Mounts}}}',b02old['id']]))
    assert b02==b02old,'retained b02 changed'
    running=d.query(['ps','-q','--no-trunc']).splitlines()
    pidfiles=list(ROOT.rglob('pid.json'))+[ROOT/'watchdog-pid.json']
    pids={json.loads(p.read_text())['pid'] for p in pidfiles}
    pids.add(json.loads((ROOT/'watchdog-ready.json').read_text())['parent'])
    processes=[]
    for pid in sorted(pids):
        try: os.kill(pid,0); absent=False
        except ProcessLookupError: absent=True
        processes.append({'pid':pid,'absent':absent})
    assert all(p['absent'] for p in processes),'owned host process remains'
    assert final['pid']==0 and final['running'] is False and final['oom_killed'] is False and not running
    frames=[json.loads(x) for x in (ROOT/'attach/stdout').read_text().splitlines()]
    cr=next(x['data'] for x in frames if x['kind']=='compiler_result')
    samples=[x['data'] for x in frames if x['kind']=='sample']
    zig=[x for x in samples if x['status'].get('Name')=='zig']
    child=next(x['data'] for x in frames if x['kind']=='effective_child')
    trace=next(x['data'] for x in frames if x['kind']=='selected_trace')
    summary={'sample_count':len(samples),'zig_sample_count':len(zig),
        'sample_start':samples[0]['at_monotonic'],'sample_end':samples[-1]['at_monotonic'],
        'sample_max_gap_seconds':max(b['at_monotonic']-a['at_monotonic'] for a,b in zip(samples,samples[1:])),
        'compiler_status_values':{k:sorted({x['status'][k] for x in zig if k in x['status']}) for k in ('Threads','Cpus_allowed_list','Seccomp','NoNewPrivs')},
        'zig_vm_peak_bytes':max(int(x['status']['VmPeak'].split()[0])*1024 for x in zig),
        'zig_rss_sample_max_bytes':max(int(x['status']['VmRSS'].split()[0])*1024 for x in zig),
        'cgroup_memory_peak_bytes':int(cr['after']['cgroup']['memory.peak']),
        'pids_peak':int(cr['after']['cgroup']['pids.peak']),
        'pids_events':cr['after']['cgroup']['pids.events'],'memory_events':cr['after']['cgroup']['memory.events'],
        'engine_free_sample_min_bytes':min(x['engine_free_bytes'] for x in samples),
        'stdout_bytes':cr['stdout_bytes'],'compiler_stderr_exact':trace,'compiler_stderr_pin':{'bytes':len(trace.encode()),'sha256':hashlib.sha256(trace.encode()).hexdigest()},
        'wrapper_plus_compile_elapsed_seconds':cr['elapsed_seconds'],
        'address_space_headroom_at_vm_peak_bytes':1073741824-max(int(x['status']['VmPeak'].split()[0])*1024 for x in zig),
        'per_worker_stack_source_bytes':60*1024**2,'first_failed_syscall_errno':None,
        'root_cause':'UNPROVEN; VA/thread-stack pressure strongly supported by affinity10, pids.peak11 and VmPeak near1GiB; syscall tracing unobservable',
        'telemetry_is_sampled':True,'sampled_threads_not_peak':True}
    tests=subprocess.run([sys.executable,'-m','unittest','discover','-s','tests','-p','test_systemresources_diagnostic.py','-v'],cwd=REPO,capture_output=True,text=True,timeout=30)
    (ROOT/'host-tests.log').write_text(tests.stdout+tests.stderr)
    assert tests.returncode==0
    host_tests={'returncode':tests.returncode,'log':pin(ROOT/'host-tests.log'),'scope':'2 host parser/control-construction tests; no target qualification'}
    protected=json.loads((ROOT/'protected-before.json').read_text())
    assert protected=={k:pin(k) for k in protected}
    receipt={'schema':'issue3-systemresources-d01-closeout-v1','attempt':result['attempt'],
        'executed_compiler_invocations':1,'runtime_cases':0,'automatic_retry':False,
        'compiler_result':cr,'summary':summary,'effective_child':child,
        'host_tests':host_tests,'independent_final':final,'independent_b02':b02,'owned_host_processes':processes,
        'watchdog_pid':json.loads((ROOT/'watchdog-pid.json').read_text())['pid'],
        'watchdog_result':result['watchdog_result'],'watchdog_reaped':result['watchdog_reaped'],
        'running_container_ids':running,'engine_slot_released':True,'A_pass':False,'crypto_tls_qualified':False,
        'B_can_proceed_under_independent_owner_grant':True,'cleanup_performed':False,'history_unchanged':True,
        'source_pins':{str(p.relative_to(REPO)):pin(p) for p in [REPO/'tools/issue3_systemresources_diagnostic/guest.py',REPO/'tools/issue3_systemresources_diagnostic/host.py',Path(__file__),REPO/'tests/test_systemresources_diagnostic.py']},
        'intent_pin':pin(ROOT/'intent.json'),'host_result_pin':pin(ROOT/'result.json'),'guest_capture_pin':pin(ROOT/'attach/stdout'),
        'deadline_satisfied':result['completed_monotonic']<intent['settlement_deadline_monotonic'],
        'active_and_settlement_elapsed_seconds':result['completed_monotonic']-(intent['active_deadline_monotonic']-60)}
    put(ROOT,'closeout.json',receipt)
    # Durable complete public diagnostic evidence; exact names/hashes manifest.
    files=sorted(p for p in ROOT.rglob('*') if p.is_file())
    assert sum(p.stat().st_size for p in files)<32*1024**2
    manifest={str(p.relative_to(ROOT)):pin(p) for p in files}
    put(ROOT,'evidence-manifest.json',manifest)
    archive=REPO/'docs/openssl-candidate-evidence/b04-systemresources-d01-20261031-evidence.tar.gz'
    with tarfile.open(archive,'x:gz') as tar:
        for p in files+[ROOT/'evidence-manifest.json']: tar.add(p,arcname=str(p.relative_to(ROOT)),recursive=False)
    # Independent readback verifies every payload against the manifest.
    with tarfile.open(archive,'r:gz') as tar:
        seen=set()
        for member in tar:
            if member.name=='evidence-manifest.json': continue
            assert member.name not in seen; seen.add(member.name)
            data=tar.extractfile(member).read()
            assert {'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}==manifest[member.name]
        assert seen==set(manifest)
    receipt['archive']={'path':str(archive.relative_to(REPO)),**pin(archive),'payload_members':len(manifest),'members':len(manifest)+1,'all_payloads_verified':True}
    target=REPO/'docs/openssl-candidate-evidence/b04-systemresources-d01-20261031.json'
    put(target.parent,target.name,receipt)
    print(json.dumps({'summary':summary,'receipt':str(target),'receipt_pin':pin(target),'archive':receipt['archive'],'owned_processes':len(processes),'host_tests':host_tests,'engine_slot_released':True,'deadline_elapsed':receipt['active_and_settlement_elapsed_seconds']},indent=2))

if __name__=='__main__':main()
