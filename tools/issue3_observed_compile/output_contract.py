"""Positive public-output namespace, shared by exporter and host receiver."""
from . import supervisor
from .prepare import require
import math
import time
from typing import Any

FINALIZATION_SECONDS = 15
EXPORT_SECONDS = 10


def observation_name(index):
    require(type(index) is int and 0<=index<16,'finite observation index')
    return f'compile/observer-v1-{index:02d}.json'


OBSERVATIONS = {observation_name(i) for i in range(16)}


def observation_record(data):
    from . import timeout_observer as o
    require(type(data) is dict and set(data)=={'schema','binding','summary'} and
            data['schema']=='issue3-compile-observation-v1','observation envelope')
    s=data['summary']; b=data['binding']
    template=o.Collector(lambda gate:None,lambda:0.,1.)
    require(type(s) is dict and set(s)==set(template.summary()),'fixed observation summary')
    require(s['schema']=='issue3-timeout-observer-v1' and s['status'] in
            ('unobserved','observed','degraded','deadline','sample-cap'),'observation schema/status')
    require(type(s['attempts']) is int and type(s['samples']) is int and
            0<=s['samples']<=s['attempts']<=16,'observation count')
    if b is not None:
        require(type(b) is dict and set(b)=={'pid','start_ticks','executable','cgroup','tmpfs'},'binding namespace')
        o.integer(b['pid']);o.integer(b['start_ticks'])
        require(0<b['pid']<2**31,'binding pid')
        for key in ('executable','cgroup','tmpfs'):
            require(type(b[key]) is list and len(b[key])==2,'binding pair')
            for v in b[key]:o.integer(v)
    if s['samples']:
        require(b is not None,'samples require actual binding')
        first=o.public_row(s['first']);last=o.public_row(s['last'])
        require(all(first[k]==last[k] for k in ('pid','start_ticks','ticks_per_second')) and
                first['pid']==b['pid'] and first['start_ticks']==b['start_ticks'],'binding sample generation')
        require(s['samples']!=1 or first==last,'one sample identity')
        template.first=first;template.last=last
    else:
        require(s['first'] is None and s['last'] is None,'absent observation rows')
    require(b is not None or s['samples']==s['attempts']==0 and s['status']=='degraded','unbound evidence only')
    require(s['status']!='observed' or s['samples']>0 and s['attempts']==s['samples'],'observed samples required')
    require(s['status']!='unobserved' or s['attempts']==s['samples']==0,'unobserved counts')
    require(s['status']!='sample-cap' or s['attempts']==16,'sample cap counts')
    require(s['attempts']-s['samples']<=1,'terminal observation loss count')
    template.attempts=s['attempts'];template.samples=s['samples'];template.status=s['status']
    require(s['evidence_only'] is True,'evidence-only literal')
    for field in ('own_cpu_ticks_delta',):
        if s[field] is not None:o.integer(s[field])
    for field,keys in (('io_bytes_delta',('read_bytes','write_bytes')),('cap_event_deltas',o.CAP_KEYS)):
        if s[field] is not None:
            require(type(s[field]) is dict and set(s[field])==set(keys),'delta namespace')
            for v in s[field].values():
                if v is not None:o.integer(v)
    require(template.summary()==s,'derived observation semantics')
    # Canonical detached projection rejects NaN, unknown/private fields and booleans.
    import json
    return json.loads(json.dumps(data,allow_nan=False))


def frame(name,data):
    import json
    require(name in EARLY,'positive frame name')
    data=early_record(name,data)
    result=b'ISSUE3_EVIDENCE '+json.dumps(dict(name=name,data=data),sort_keys=True,separators=(',',':'),allow_nan=False).encode()+b'\n'
    require(len(result)<=4096,'early frame byte bound')
    return result


def work_deadline(phase, profile):
    maximum={'compile':120,'run':330}[phase]
    until=profile.get('phase_deadline_unix')
    require(type(until) in (int,float) and math.isfinite(until), 'absolute phase deadline required')
    remaining=min(maximum,until-time.time())
    require(remaining>FINALIZATION_SECONDS,'insufficient finalization headroom')
    return time.monotonic()+remaining-FINALIZATION_SECONDS

STAGES = ('admitted','controllers-verified','inputs-verified','toolchain-verified','launch-intent')
EARLY = {'stage-'+s+'.json' for s in STAGES} | {'compile/inherited-controls.json','compile/child-controls.json','compile/pid.json','compile/process.json'}
EARLY |= {'compile/timing-'+event+'.json' for event in supervisor.TIMING_EVENTS}
AUTH_STAGES = ('admission','controllers','inputs','toolchain','launch-validation')
AUTH_FILES = tuple('auth-'+stage+'-'+suffix+'.json' for stage in AUTH_STAGES for suffix in ('entry','end'))
EARLY |= set(AUTH_FILES) | OBSERVATIONS


def bounded_seconds(value, maximum):
    return type(value) in (int,float) and 0<=value<=maximum and math.isfinite(value)


def authentication_record(data: dict[str, Any], stage, suffix):
    require(type(data) is dict and set(data)=={'stage','boundary','monotonic_seconds','remaining_work_seconds'} and
            stage in AUTH_STAGES and data['stage']==stage and
            (suffix=='entry' and data['boundary']=='entry' or
             suffix=='end' and data['boundary'] in ('return','failure')), 'fixed authentication timing')
    require(bounded_seconds(data['monotonic_seconds'],2**53) and
            bounded_seconds(data['remaining_work_seconds'],330), 'bounded authentication timing')
    return dict(data)


def timing_record(data: dict[str, Any], event):
    require(type(data) is dict and set(data)=={'event','monotonic_seconds','remaining_work_seconds',
        'failure_site','timeout_site'} and data['event']==event and event in supervisor.TIMING_EVENTS,
        'fixed timing record')
    require(bounded_seconds(data['monotonic_seconds'],2**53) and
            bounded_seconds(data['remaining_work_seconds'],330), 'bounded timing seconds')
    for key in ('failure_site','timeout_site'):
        require(data[key] is None or data[key] in supervisor.TIMING_SITES, 'fixed timing site')
    require(event=='preexec-failure' or data['failure_site'] is data['timeout_site'] is None,
            'failure sites only on failure receipt')
    return dict(data)


def capture_timing(data: dict[str, Any]):
    keys={'schema','clock','capture_entry_monotonic','work_deadline_monotonic','effective_entry_seconds',
        'popen_return_monotonic','preexec_entry_monotonic','remaining_at_popen_return_seconds',
        'failure_site','timeout_site','postexec_progress','postexec_cpu_seconds','postexec_state',
        'cache_observation','receipt_error','events'}
    require(type(data) is dict and set(data)==keys and data['schema']=='issue3-b04-capture-timing-v1' and
            data['clock']=='process-namespace-monotonic', 'capture timing schema')
    for key in ('capture_entry_monotonic','work_deadline_monotonic'):
        require(bounded_seconds(data[key],2**53), 'capture timing clock')
    require(bounded_seconds(data['effective_entry_seconds'],330), 'capture effective budget')
    for key in ('popen_return_monotonic','preexec_entry_monotonic'):
        require(data[key] is None or bounded_seconds(data[key],2**53), 'optional timing clock')
    require(data['remaining_at_popen_return_seconds'] is None or
            bounded_seconds(data['remaining_at_popen_return_seconds'],330), 'optional effective budget')
    for key in ('failure_site','timeout_site'):
        require(data[key] is None or data[key] in supervisor.TIMING_SITES, 'capture timing site')
    require(all(data[key] is None for key in ('postexec_progress','postexec_cpu_seconds','postexec_state',
            'cache_observation')) and type(data['receipt_error']) is bool, 'unobserved postexec semantics')
    events: dict[str, Any] = data['events']
    require(type(events) is dict and set(events)<=set(supervisor.TIMING_EVENTS),
            'finite timing events')
    return dict(data,events={event:timing_record(row,event) for event,row in events.items()})


def early_record(name, data: dict[str, Any]):
    """Positive, bounded public projection; never argv/profile/raw diagnostics."""
    require(name in EARLY and type(data) is dict, 'early evidence allowlist')
    if name in OBSERVATIONS:
        return observation_record(data)
    if name in AUTH_FILES:
        stage,suffix=name[len('auth-'):-5].rsplit('-',1)
        return authentication_record(data,stage,suffix)
    if name.startswith('compile/timing-'):
        return timing_record(data,name[len('compile/timing-'):-5])
    if name.startswith('stage-'):
        require(data == {'stage':name[6:-5]}, 'fixed stage record')
        return data
    if name.endswith('/inherited-controls.json'):
        require(set(data)=={'rlimit_nofile','observation'} and data['observation']=='child-before-controls' and
            type(data['rlimit_nofile']) in (list,tuple) and len(data['rlimit_nofile'])==2 and
            all(type(v) is int and -1<=v<2**63 for v in data['rlimit_nofile']), 'inherited descriptor controls')
        return data
    if name.endswith('/pid.json'):
        require(set(data)=={'pid','pgid'} and all(type(v) is int and 0<v<2**31 for v in data.values()), 'process identity record')
        return data
    if name.endswith('/child-controls.json'):
        keys={'cpu_affinity','inherited_cpu_affinity','rlimit_as','rlimit_nproc','rlimit_cpu','rlimit_nofile','rlimit_fsize','rlimit_core','observation','post_exec_observation','memory_accounting'}
        require(set(data)==keys and data['observation']=='child-preexec' and data['post_exec_observation'] is False, 'preexec control record')
        for key in keys-{'observation','post_exec_observation','memory_accounting'}:
            values=data[key]
            require(type(values) in (list,tuple) and 0<len(values)<=256 and all(type(v) is int and -1<=v<2**63 for v in values), 'bounded numeric controls')
        require(data['memory_accounting']=='RLIMIT_AS is virtual; independently verified cgroup memory.max is physical charge', 'fixed accounting note')
        return data
    keys={'reason','returncode','reaped','elapsed_seconds','error'}
    require(keys<=set(data), 'process result fields')
    row={k:data[k] for k in keys}
    require(row['reason'] in ('EXIT','TIMEOUT','OUTPUT_LIMIT','INTERRUPTED','LAUNCH_OR_CAPTURE_FAILURE') and
            (row['returncode'] is None or type(row['returncode']) is int and -255<=row['returncode']<=255) and
            type(row['reaped']) is bool and type(row['elapsed_seconds']) in (int,float) and
            0<=row['elapsed_seconds']<=510 and
            (row['error'] is None or row['error'] in ('TimeoutError','ValueError','OSError','FileNotFoundError','PermissionError','SubprocessError','KeyboardInterrupt','SystemExit')), 'bounded process result')
    if 'timing' in data:
        row['timing']=capture_timing(data['timing'])
    return row


def allowed(phase):
    require(phase=='compile','compile-only export')
    captures={'intent.json','pid.json','stdout','stderr','process.json','child-controls.json','inherited-controls.json'}
    files={phase+'-spent.json',phase+'-result.json','worker.json','supervisor.json'} | {'stage-'+s+'.json' for s in STAGES} | set(AUTH_FILES)
    if phase=='compile':
        files|={'probe','probe.map'}|{'compile/'+n for n in captures}|OBSERVATIONS
        files|={'compile/timing-'+event+'.json' for event in supervisor.TIMING_EVENTS}
    elif phase=='run':
        files|={'runtime/intent.json','runtime/matrix.json','runtime/matrix-failed.json'}
        files|={f'runtime/{i:02d}-{mode}-{fault}/'+n for i,(mode,fault) in enumerate(supervisor.CASES) for n in captures}
    else:
        raise ValueError('explicit export phase')
    return files
