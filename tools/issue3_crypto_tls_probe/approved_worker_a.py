"""Explicit October31 worker-A approved staging and one experiment driver.
No implicit retry; requires separate stage or execute selection. Evidence retained.
"""
import json,os,shutil,sys,time
from pathlib import Path
from . import bind_b04,cached_inputs,outer,stage,toolchain_stage,wire
from .docker_transport import DockerCLI,CONTROLLERS
ROOT=Path('/tmp/issue3-b04-probe-approved-20261031-a01')
def put(name,value):
    stage.save_new(ROOT/name,wire.encoded(value))
def stage_once():
    ROOT.mkdir(mode=0o700)
    controllers=sum((Path(__file__).parent/n).stat().st_size for n in CONTROLLERS)
    # Exact known input/toolchain payload plus bounded work/output and capture.
    growth=48583770+343263960+controllers+2*268435456+2*97*1024**2
    free=shutil.disk_usage(ROOT).free
    put('capacity-before-staging.json',dict(host_free_bytes=free,payload_input_bytes=48583770,
        toolchain_bytes=343263960,controller_bytes=controllers,bounded_growth_bytes=growth,
        retained_reserve_bytes=10*1024**3,derived_required_bytes=10*1024**3+growth,
        effective_stronger_host_floor=16*1024**3,engine_admission='fresh guest before every target'))
    if free<max(16*1024**3,10*1024**3+growth): raise ValueError('host staging capacity refusal')
    result=stage.stage_public(ROOT/'public-stage'); put('public-stage-receipt.json',result)
    result=toolchain_stage.stage_public(ROOT/'compiler-stage'); put('compiler-stage-receipt.json',result)
    put('controller-stage-receipt.json',toolchain_stage.stage_controller(ROOT/'controller'))
    for name in ('compile-request','compile-observer','run-request','run-observer'):
        (ROOT/name).mkdir(mode=0o755)
    print('STAGED',ROOT,flush=True)
def execute_once():
    snapshot=json.loads((Path(__file__).parent/'cached-runtime-descriptor.json').read_text())
    compiler=json.loads((Path(__file__).parent/'cached-inputs.json').read_text())['compiler']
    manifest=json.loads((ROOT/'public-stage/binding.json').read_text())['manifest']
    t=snapshot['transport']
    binding=dict(kind='engine-managed-platform',engine_id=t['engine_id'],endpoint=t['endpoint'],
        platform='linux/amd64',emulator_identity_verified=False,provenance_limitation_accepted=True)
    mounts=dict(inputs=str(ROOT/'public-stage/inputs'),toolchain=str(ROOT/'compiler-stage/toolchain'),
        controller=str(ROOT/'controller'),request=str(ROOT/'compile-request'),observer=str(ROOT/'compile-observer'))
    p=outer.compile_profile(snapshot,compiler,manifest,mounts,'issue3-b04-probe-approved-a01-compile',binding)
    put('compile-profile.json',p); g=outer.grant_for(p,time.time()+290); put('compile-grant.json',g)
    # Owner explicitly approved this single experiment and managed-platform policy.
    os.system("printf '\\a'")
    result=outer.run(p,g,ROOT/'compile-execution',DockerCLI(p,ROOT/'compile-transport'))
    print('COMPILE',json.dumps(result),flush=True)
    if result['status']!='TRANSPORT_SETTLED': return 1
    p=outer.run_profile(ROOT/'compile-execution/final-result.json',str(ROOT/'compile-execution/public'),
        str(ROOT/'run-request'),str(ROOT/'run-observer'),'issue3-b04-probe-approved-a01-run')
    put('run-profile.json',p); g=outer.grant_for(p,time.time()+290); put('run-grant.json',g)
    result=outer.run(p,g,ROOT/'run-execution',DockerCLI(p,ROOT/'run-transport'))
    print('RUN',json.dumps(result),flush=True)
    return 0 if result['status']=='TRANSPORT_SETTLED' else 1
if __name__=='__main__':
    if sys.argv[1:] == ['stage']: stage_once()
    elif sys.argv[1:] == ['execute']: raise SystemExit(execute_once())
    else: raise SystemExit('explicit stage or execute required')
