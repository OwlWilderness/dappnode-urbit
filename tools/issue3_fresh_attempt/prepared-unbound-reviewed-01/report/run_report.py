from gate import preflight
CONFIG = preflight(__file__, 'report')
from supervision import output as bounded_output
# Prepared successor; historical controller is immutable.
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parent
BINARY = Path(CONFIG['inputs']['binary']['path'])
EXPECTED = CONFIG['artifacts']['executable_sha256']
IMAGE = CONFIG['artifacts']['image']
DOCKER = ['docker', '--context', CONFIG['docker_context']]
def query(args):
    return bounded_output(DOCKER + args, timeout=30, stderr=subprocess.DEVNULL).decode().strip()
def save(name, value):
    with (ROOT / name).open('x') as f:
        json.dump(value, f, indent=2)
    (ROOT / name).chmod(0o600)
def inventory():
    return {k: sorted(set(query(v).splitlines())) for k, v in {
        'containers': ['ps', '-aq', '--no-trunc'],
        'volumes': ['volume', 'ls', '-q'],
        'images': ['image', 'ls', '-aq', '--no-trunc'],
        'networks': ['network', 'ls', '--no-trunc', '--format={{.ID}}'],
        'tags': ['image', 'ls', '-a', '--no-trunc', '--format={{.Repository}}:{{.Tag}} {{.ID}}']}.items()}
authority = CONFIG['_authorization']
assert authority['controller_sha256'] == hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
assert authority['authorized'] is True
assert not (ROOT / 'spent.json').exists()
assert hashlib.sha256(BINARY.read_bytes()).hexdigest() == EXPECTED
assert not query(['ps', '-q'])
assert query(['image', 'inspect', '--format', '{{.Id}} {{.Architecture}}', IMAGE]) == IMAGE + ' amd64'
import shutil
assert shutil.disk_usage(ROOT).free >= 16 * 1024**3 + 128 * 1024**2
save('before.json', inventory())
name = CONFIG['attempt_id']
assert not query(['ps', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.ID}}'])
argv = ['create', '--name', name, '--label', 'org.uvm.issue3=' + CONFIG['attempt_id'],
        '--platform=linux/amd64', '--pull=never', '--network=none', '--log-driver=none',
        '--read-only', '--user=10000:10000', '--cap-drop=ALL',
        '--security-opt=no-new-privileges:true', '--restart=no', '--ulimit=core=0',
        '--memory=256m', '--memory-swap=256m', '--cpus=1', '--pids-limit=32',
        '--workdir=/', '--entrypoint=/candidate',
        '--mount=type=bind,source=' + str(BINARY) + ',target=/candidate,readonly', IMAGE, '-R']
CONFIG = preflight(__file__, 'report')
save('spent.json', {'owner_grant': authority['owner_grant'], 'scope': 'production build qualification: single no-ship dependency report', 'argv': argv, 'retry_authorized': False})
CONTAINER = query(argv)
assert re.fullmatch('[0-9a-f]{64}', CONTAINER)
save('owned.json', {'container_id': CONTAINER})
fmt = '{"id":{{json .Id}},"name":{{json .Name}},"label":{{json (index .Config.Labels "org.uvm.issue3")}},"image":{{json .Image}},"user":{{json .Config.User}},"entrypoint":{{json .Config.Entrypoint}},"cmd":{{json .Config.Cmd}},"readonly":{{json .HostConfig.ReadonlyRootfs}},"network":{{json .HostConfig.NetworkMode}},"logging":{{json .HostConfig.LogConfig.Type}},"privileged":{{json .HostConfig.Privileged}},"ports":{{len .HostConfig.PortBindings}},"mounts":[{{range $i,$m := .Mounts}}{{if $i}},{{end}}{"type":{{json $m.Type}},"source":{{json $m.Source}},"destination":{{json $m.Destination}},"rw":{{json $m.RW}}}{{end}}],"memory":{{json .HostConfig.Memory}},"swap":{{json .HostConfig.MemorySwap}},"cpus":{{json .HostConfig.NanoCpus}},"pids":{{json .HostConfig.PidsLimit}},"cap_drop":{{json .HostConfig.CapDrop}},"security":{{json .HostConfig.SecurityOpt}},"restart":{{json .HostConfig.RestartPolicy.Name}},"status":{{json .State.Status}},"pid":{{json .State.Pid}}}'
observed = json.loads(query(['inspect', '--format', fmt, CONTAINER]))
expected = {'id':CONTAINER,'name':'/' + CONFIG['attempt_id'],'label':CONFIG['attempt_id'],'image':IMAGE,'user':'10000:10000','entrypoint':['/candidate'],'cmd':['-R'],'readonly':True,'network':'none','logging':'none','privileged':False,'ports':0,'mounts':[{'type':'bind','source':str(BINARY),'destination':'/candidate','rw':False}],'memory':268435456,'swap':268435456,'cpus':1000000000,'pids':32,'cap_drop':['ALL'],'security':['no-new-privileges:true'],'restart':'no','status':'created','pid':0}
assert observed == expected, 'Exact selected metadata refused before start'
save('prestart.json', observed)

FORMAT = '{"id":{{json .Id}},"image":{{json .Image}},"name":{{json .Name}},"label":{{json (index .Config.Labels "org.uvm.issue3")}},"pid":{{json .State.Pid}},"status":{{json .State.Status}},"running":{{json .State.Running}},"exit_code":{{json .State.ExitCode}},"oom_killed":{{json .State.OOMKilled}}}'

def state():
    observed = json.loads(bounded_output(DOCKER + ['inspect', '--format', FORMAT, CONTAINER], text=True, timeout=10))
    if (observed.get('id') != CONTAINER or observed.get('image') != IMAGE or
            observed.get('name') != '/' + CONFIG['attempt_id'] or observed.get('label') != CONFIG['attempt_id'] or
            type(observed.get('pid')) is not int):
        raise ValueError('owned report identity mismatch; manual recovery required')
    return observed

assert hashlib.sha256(BINARY.read_bytes()).hexdigest() == EXPECTED
assert state()['status'] == 'created', 'Never restart a consumed report container'
with (ROOT / 'started.json').open('x') as file:
    json.dump({'container_id': CONTAINER, 'sha256_before': EXPECTED, 'argv': ['-R'],
               'timeout_seconds': 30, 'retry_authorized': False}, file, indent=2)
stop_requested = False

def request_stop(signum, frame):
    global stop_requested
    stop_requested = True

signal.signal(signal.SIGTERM, request_stop)
signal.signal(signal.SIGINT, request_stop)
process = None
error = None
started = time.monotonic()
try:
    from supervision import capture
    from gate import capacity as check_capacity
    initial_free = check_capacity(CONFIG)
    with (ROOT / 'public-report.log').open('xb') as log:
        process = capture(DOCKER + ['start', '--attach', CONTAINER], log,
                          lambda: stop_requested, lambda: check_capacity(CONFIG, initial_free))
except BaseException as exc:
    error = type(exc).__name__ + ': ' + str(exc)
finally:
    if process is not None and process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
    observed = state()
    if observed['running']:
        subprocess.run(DOCKER + ['stop', '--time', '5', CONTAINER], check=True, timeout=10,
                       stdout=subprocess.DEVNULL)
        observed = state()
        if observed['running']:
            subprocess.run(DOCKER + ['kill', CONTAINER], check=True, timeout=10,
                           stdout=subprocess.DEVNULL)
            observed = state()
    after = hashlib.sha256(BINARY.read_bytes()).hexdigest()
    output_path = ROOT / 'public-report.log'
    with output_path.open('rb') as file:
        output = file.read(65537)
    text = output.decode(errors='replace')
    linked = bool(re.search(r'^openssl: OpenSSL 3\.5\.9(?:\s|$)', text, re.M))
    headers = bool(re.search(r'^openssl-headers: OpenSSL 3\.5\.9(?:\s|$)', text, re.M))
    curl_linked = re.findall(r'^curl-linked: ([^\r\n]+)\r?$', text, re.M) == ['8.23.0']
    curl_headers = re.findall(r'^curl-headers: ([^\r\n]+)\r?$', text, re.M) == ['8.23.0']
    passed = (not error and process is not None and process.returncode == 0 and
              observed['status'] == 'exited' and observed['pid'] == 0 and not observed['running'] and
              observed['exit_code'] == 0 and not observed['oom_killed'] and
              after == EXPECTED and len(output) <= 65536 and linked and headers and curl_linked and curl_headers)
    result = dict(status='PASS' if passed else 'FAILED', error=error, container_id=CONTAINER,
                  elapsed_seconds=round(time.monotonic()-started, 3), state=observed,
                  executable_sha256_before=EXPECTED, executable_sha256_after=after,
                  linked_openssl_3_5_9=linked, compiled_headers_3_5_9=headers,
                  linked_curl_8_23_0=curl_linked, compiled_curl_headers_8_23_0=curl_headers,
                  ship_booted=False, cleanup_performed=False, retry_authorized=False)
    after_inventory = inventory()
    save('after.json', after_inventory)
    before_inventory = json.loads((ROOT / 'before.json').read_text())
    from gate import settled_inventory
    settled_inventory(before_inventory, after_inventory, {'containers': [CONTAINER]})
    assert not query(['ps', '-q'])
    result.update(attempt_id=CONFIG['attempt_id'], stage='report', preserved=True, active_after=[])
    (ROOT / 'result.json').write_text(json.dumps(result, indent=2)+'\n')
    print(text)
    print(json.dumps(result, indent=2))
raise SystemExit(0 if passed else 1)
