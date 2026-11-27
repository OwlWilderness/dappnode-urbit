"""b04-only no-state report successor; historical gates/receipts stay immutable.

No import-time engine operations. This is not ship, TLS or package acceptance.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import struct
import subprocess
import tarfile
import time

HERE = Path(__file__).resolve().parent
SCRATCH = Path('/tmp')
BUILD_ATTEMPT = 'issue3-owned-20261030-b04'
BUILD = SCRATCH / 'issue3-owned-trial-20261030-b04-observed'
BINARY = BUILD / 'artifact/urbit'
SHA = 'f2eba68682650ab6d9712017781612f4dbc3c01411c1ba5c7c4ecbb0f186b6b5'
SIZE = 42467624
IMAGE = 'sha256:320994c3b997e2ec6433f717f153e108023c5bec8fefa8d76b83451d16d05ea8'
DOCKER = ['docker', '--context', 'desktop-linux']
EXECUTION_SECONDS = 60
SETTLEMENT_SECONDS = 60
CREATED_ID = '59c19230a6bcaf03004af9c1b7f80805b94d365435bf451718f697a44245a5ff'
GUEST = r'''set -eu
memory=$(cat /sys/fs/cgroup/memory.max)
swap=$(cat /sys/fs/cgroup/memory.swap.max)
cpu=$(cat /sys/fs/cgroup/cpu.max)
pids=$(cat /sys/fs/cgroup/pids.max)
test "$memory" = 268435456
test "$swap" = 0
test "$cpu" = '100000 100000'
test "$pids" = 32
mem=0
while read -r key value unit; do
  case "$key" in MemAvailable:) mem=$value;; esac
done < /proc/meminfo
test "$mem" -ge 262144
free=$(df -Pk / | { read -r header; read -r fs blocks used available rest; printf '%s' "$available"; })
test "$free" -ge 131072
printf 'ISSUE3_RESOURCE {"memory_max":%s,"swap_max":%s,"cpu_max":"%s","pids_max":%s,"engine_free_kib":%s,"mem_available_kib":%s}\n' "$memory" "$swap" "$cpu" "$pids" "$free" "$mem"
exec /candidate -R
'''


def require(ok, message):
    if not ok:
        raise ValueError(message)


def callback_arguments(text, symbols):
    # LLVM objdump does not annotate immediate function-pointer loads. Resolve
    # exact nm addresses in AMD64 ABI argument registers, immediately before call.
    pattern = (r'movl\s+\$0x([0-9a-f]+), %edi[^\n]*\n'
               r'[^\n]*movl\s+\$0x([0-9a-f]+), %esi[^\n]*\n'
               r'[^\n]*movl\s+\$0x([0-9a-f]+), %edx[^\n]*\n'
               r'[^\n]*callq\s+0x[0-9a-f]+ <CRYPTO_set_mem_functions>')
    matches = re.findall(pattern, text)
    expected = tuple(symbols[n] for n in ('u3_openssl_arena_malloc',
                                         'u3_openssl_arena_realloc', 'u3_openssl_arena_free'))
    return len(matches) == 1 and tuple(int(n, 16) for n in matches[0]) == expected


def validate_owned_receipts(build, static):
    require(build.get('status') == 'COMPILE_PASS' and build.get('attempt') == BUILD_ATTEMPT
            and type(build.get('build_exit_code')) is int and build['build_exit_code'] == 0
            and all(build.get(k) is True for k in ('artifact_complete', 'settled', 'build_launched'))
            and build.get('error') is None, 'successful settled owned build required')
    require(static.get('status') == 'PASS' and static.get('architecture') == 'linux/amd64'
            and static.get('executable_sha256') == SHA and static.get('executable_bytes') == SIZE
            and static.get('vere_executed') is False
            and all(static.get(k) is True for k in ('owned_callbacks_registered',
                'gmp_registration_retained', 'normal_libc_cleanup_retained', 'openssl_cleanup_linked',
                'source_receipts_verified', 'frozen_recipe_verified', 'no_uvm_i3_symbols',
                'static_no_interp_or_dynamic')), 'owned static receipt required')
    return True


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError('module specification')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def report_versions(text, openssl, curl):
    def values(key):
        return re.findall(r'^' + re.escape(key) + r': ([^\r\n]+)\r?$', text, re.M)
    def ssl(key):
        found = values(key)
        return len(found) == 1 and bool(re.fullmatch(
            r'OpenSSL ' + re.escape(openssl) + r'(?: [^\r\n]+)?', found[0]))
    return dict(linked_openssl=ssl('openssl'), headers_openssl=ssl('openssl-headers'),
                linked_curl=values('curl-linked') == [curl], headers_curl=values('curl-headers') == [curl])


def validate_base(image):
    require(image == dict(id=IMAGE, arch='amd64', os='linux', volumes=None),
            'cached AMD64 Linux base without implicit VOLUME required')
    return True


def create_command(name):
    require(re.fullmatch('issue3-b04-report-[a-z0-9-]{4,60}', name), 'report-only name')
    return ['create', '--name', name, '--label=org.uvm.issue3=' + name,
            '--platform=linux/amd64', '--pull=never', '--network=none', '--log-driver=none',
            '--read-only', '--user=10000:10000', '--cap-drop=ALL',
            '--security-opt=no-new-privileges:true', '--restart=no', '--ulimit=core=0',
            '--memory=256m', '--memory-swap=256m', '--cpus=1', '--pids-limit=32',
            '--workdir=/', '--entrypoint=/bin/sh',
            '--mount=type=bind,source=' + str(BINARY) + ',target=/candidate,readonly', IMAGE, '-c', GUEST]


def static_headers(data):
    require(len(data) >= 64 and data[:6] == b'\x7fELF\x02\x01' and
            struct.unpack_from('<H', data, 18)[0] == 62, 'AMD64 ELF64 required')
    offset = struct.unpack_from('<Q', data, 32)[0]
    stride, count = struct.unpack_from('<HH', data, 54)
    require(stride == 56 and count > 0 and offset+stride*count <= len(data), 'ELF program table')
    require(all(struct.unpack_from('<I', data, offset+i*stride)[0] not in (2, 3)
                for i in range(count)), 'PT_INTERP/PT_DYNAMIC refused')
    return True


def identity():
    gate = load('owned_public_gate', HERE/'gate.py')
    raw = gate.read_pin(dict(path=str(BINARY), size=SIZE, sha256=SHA))
    require(BINARY.stat().st_mode & 0o777 == 0o555, 'binary mode')
    return raw


def static_qualification(folder):
    raw = identity()
    static_headers(raw)
    verifier = load('owned_source_verifier', BUILD/'artifact/verify_binary.py')
    symbols_text = subprocess.check_output(['nm', str(BINARY)], text=True, timeout=60)
    require('uvm_i3_' not in symbols_text, 'diagnostic symbols refused')
    symbols = {}
    for line in symbols_text.splitlines():
        fields = line.split()
        if len(fields) == 3 and re.fullmatch('[0-9a-fA-F]+', fields[0]):
            symbols[fields[2]] = int(fields[0], 16)
    required = ('u3_openssl_owned_start', 'u3_openssl_owned_seal', 'u3_openssl_arena_init',
        'u3_openssl_arena_malloc', 'u3_openssl_arena_realloc', 'u3_openssl_arena_free',
        'u3_openssl_arena_live_blocks', 'u3_openssl_arena_destroy', 'u3_ssl_shutdown_run',
        'u3_h2o_openssl_shutdown', 'OPENSSL_cleanup', '__gmp_set_memory_functions',
        'u3_openssl_arena_snapshot', 'u3_arena_measure_startup', 'u3_arena_measure_phase',
        'u3_arena_measure_destroyed')
    require(set(required) <= set(symbols), 'required owned symbols')
    def disassemble(name):
        text = subprocess.check_output(['objdump', '--disassemble-symbols='+name, str(BINARY)],
                                       text=True, timeout=60)
        require('<'+name+'>:' in text, 'missing disassembly '+name)
        (folder/(name+'.disassembly.txt')).write_text(text)
        return text
    start = disassemble('u3_openssl_owned_start')
    require(callback_arguments(start, symbols), 'owned callback address/register binding')
    require(all(n in start for n in ('u3_openssl_arena_init', 'u3_arena_measure_startup')),
            'owned startup calls')
    init = disassemble('u3m_init')
    require('__gmp_set_memory_functions' in init, 'GMP registration')
    require('u3_openssl_owned_start' in init or
            'u3_openssl_owned_start' in disassemble('_cm_crypto'), 'crypto startup reachability')
    exit_code = disassemble('exit')
    require(all(n in exit_code for n in ('__funcs_on_exit', 'libc_exit_fini', '__stdio_exit_needed')),
            'normal libc cleanup')
    source = verifier.verify_sources(BUILD/'artifact', BUILD/'frozen-recipe')
    require(b'OpenSSL 3.5.9' in raw and b'OpenSSL 1.1.1w' not in raw, 'version markers')
    static = dict(source, executable_sha256=SHA, executable_bytes=SIZE, architecture='linux/amd64',
                  owned_callbacks_registered=True, gmp_registration_retained=True,
                  normal_libc_cleanup_retained=True, openssl_cleanup_linked=True,
                  no_uvm_i3_symbols=True, static_no_interp_or_dynamic=True,
                  callback_binding='nm-addresses-to-edi-esi-edx-before-CRYPTO_set_mem_functions',
                  required_symbols=list(required), vere_executed=False)
    build = json.loads((BUILD/'result.json').read_text())
    validate_owned_receipts(build, static)
    candidate = json.loads((BUILD/'artifact/candidate.json').read_text())
    require(all(candidate[k] == static[k] for k in ('executable_sha256', 'executable_bytes', 'architecture')),
            'exported candidate identity')
    lock = json.loads((BUILD/'artifact/inputs.json').read_text())
    require(lock['openssl_version'] == '3.5.9' and lock['curl_version'] == '8.23.0', 'version lock')
    # Source verifier above authenticates these patched archive members against
    # final source receipts. Inspect report control flow/manifest pins, not logs.
    with tarfile.open(BUILD/'artifact/source-materials.tar.gz') as archive:
        prefix = lock['inputs']['vere']['root']+'/'
        def source_text(name):
            stream = archive.extractfile(prefix+name)
            if stream is None:
                raise ValueError('missing source member')
            return stream.read().decode()
        main = source_text('pkg/vere/main.c')
        require(re.search(r'if \( c3y == u3_Host.ops_u.rep \)\s*{\s*report\(\);\s*return 0;', main),
                'no-state report return path')
        require('curl-8.23.0.tar.gz' in source_text('ext/curl/build.zig.zon') and
                '.version = "3.5.9"' in source_text('ext/openssl/build.zig.zon'), 'archived version pins')
        (folder/'report-source.c.txt').write_text(main[main.index('static void\nreport(void)'):main.index('/* _stop_exit()')])
    identity()
    return static


FIELDS = {
    'id': '.Id', 'name': '.Name', 'label': '(index .Config.Labels "org.uvm.issue3")',
    'image': '.Image', 'user': '.Config.User', 'entrypoint': '.Config.Entrypoint',
    'cmd': '.Config.Cmd', 'readonly': '.HostConfig.ReadonlyRootfs',
    'network': '.HostConfig.NetworkMode', 'logging': '.HostConfig.LogConfig.Type',
    'privileged': '.HostConfig.Privileged', 'ports': '(len .HostConfig.PortBindings)',
    'memory': '.HostConfig.Memory', 'swap': '.HostConfig.MemorySwap',
    'cpus': '.HostConfig.NanoCpus', 'pids': '.HostConfig.PidsLimit',
    'cap_drop': '.HostConfig.CapDrop', 'security': '.HostConfig.SecurityOpt',
    'restart': '.HostConfig.RestartPolicy.Name', 'status': '.State.Status',
    'pid': '.State.Pid', 'running': '.State.Running', 'exit_code': '.State.ExitCode',
    'oom_killed': '.State.OOMKilled', 'tmpfs': '(index .HostConfig "Tmpfs")',
}
FORMAT = '{'+','.join('"'+k+'":{{json '+v+'}}' for k, v in FIELDS.items())
FORMAT += ',"mounts":[{{range $i,$m := .Mounts}}{{if $i}},{{end}}{"type":{{json $m.Type}},"source":{{json $m.Source}},"destination":{{json $m.Destination}},"rw":{{json $m.RW}}}{{end}}]}'


def expected_controls(cid, name):
    return dict(id=cid, name='/'+name, label=name, image=IMAGE, user='10000:10000',
                entrypoint=['/bin/sh'], cmd=['-c', GUEST], readonly=True, network='none', logging='none',
                privileged=False, ports=0, memory=268435456, swap=268435456,
                cpus=1000000000, pids=32, cap_drop=['ALL'], security=['no-new-privileges:true'],
                restart='no', status='created', pid=0, running=False, exit_code=0, oom_killed=False,
                tmpfs=None, mounts=[dict(type='bind', source=str(BINARY), destination='/candidate', rw=False)])


def save(folder, name, data):
    with (folder/name).open('x') as stream:
        json.dump(data, stream, indent=2)
        stream.write('\n')


def start_once(folder, cid, name, inspect, capture):
    controls = inspect(cid)
    require(controls == expected_controls(cid, name), 'exact report controls refused before start')
    save(folder, 'prestart.json', controls)
    identity()
    # Exclusive marker precedes the single target start. Never rerun this folder.
    save(folder, 'started.json', dict(container_id=cid, executable_sha256=SHA, argv=['-R'],
         execution_seconds=EXECUTION_SECONDS, settlement_seconds=SETTLEMENT_SECONDS,
         retry_authorized=False, started_unix=time.time()))
    with (folder/'public-report.log').open('xb') as sink:
        return capture(DOCKER+['start', '--attach', cid], sink)


def settle(cid, state, query, deadline=None):
    deadline = time.monotonic()+SETTLEMENT_SECONDS if deadline is None else deadline
    def remaining():
        value = deadline-time.monotonic()
        require(value > 0, 'settlement deadline; manual exact-owned recovery required')
        return min(10, value)
    observed = state(timeout=remaining())
    require(observed['id'] == cid, 'settlement identity')
    if observed['running']:
        query(['stop', '--time=5', cid], timeout=remaining())
        observed = state(timeout=remaining())
        if observed['running']:
            query(['kill', cid], timeout=remaining())
            observed = state(timeout=remaining())
    require(time.monotonic() < deadline and observed['id'] == cid and
            observed['running'] is False and observed['pid'] == 0 and observed['status'] == 'exited',
            'owned report did not settle; manual recovery required')
    return observed


def validate_recovery(previous, cid, started_at, started_marker):
    require(previous.get('status') == 'FAILED' and previous.get('client_exit_code') is None
            and cid == CREATED_ID and started_at == '0001-01-01T00:00:00Z'
            and started_marker is False, 'only exact never-started preparation may continue')
    return True


def run(folder, recover_created=False):
    folder = Path(folder).absolute()
    suffix = 'continuation' if recover_created else 'qualification'
    require(folder.parent == SCRATCH and folder.name == 'issue3-b04-report-20261030-'+suffix,
            'exact qualification directory required')
    require(not any((folder/x).exists() for x in ('spent.json', 'started.json', 'result.json')),
            'spent/uncertain report; no retry')
    supervision = load('owned_report_supervision', HERE/'supervision.py')
    def query(args, timeout=10):
        return supervision.output(DOCKER+args, timeout=timeout, text=True).strip()
    def inspect(cid, timeout=10):
        return json.loads(query(['inspect', '--format', FORMAT, cid], timeout=timeout))
    def inventory():
        return {k: sorted(set(query(args).splitlines())) for k, args in {
            'containers': ['ps', '-aq', '--no-trunc'], 'volumes': ['volume', 'ls', '-q'],
            'images': ['image', 'ls', '-aq', '--no-trunc'],
            'networks': ['network', 'ls', '--no-trunc', '--format={{.ID}}']}.items()}
    require(query(['context', 'show']) == 'desktop-linux', 'context selection')
    require(query(['context', 'inspect', 'desktop-linux', '--format', '{{.Endpoints.docker.Host}}']) ==
            'unix:///var/run/docker.sock', 'endpoint')
    require(not query(['ps', '-q']), 'running container admission')
    image = json.loads(query(['image', 'inspect', '--format',
        '{"id":{{json .Id}},"arch":{{json .Architecture}},"os":{{json .Os}},"volumes":{{json .Config.Volumes}}}', IMAGE]))
    validate_base(image)
    name = 'issue3-b04-report-20261030-qualification'
    cid = None
    if recover_created:
        prior = SCRATCH/'issue3-b04-report-20261030-qualification'
        previous = json.loads((prior/'result.json').read_text())
        cid = json.loads((prior/'owned.json').read_text())['container_id']
        validate_recovery(previous, cid,
            query(['inspect', '--format={{.State.StartedAt}}', cid]), (prior/'started.json').exists())
        require(inspect(cid) == expected_controls(cid, name), 'created recovery controls')
        save(folder, 'created-recovery.json', dict(container_id=cid, target_invocations_before=0,
            previous_result_sha256=hashlib.sha256((prior/'result.json').read_bytes()).hexdigest(),
            previous_preserved=True, reason='optional Tmpfs map key formatter failed before start'))
    else:
        require(not query(['ps', '-a', '--filter', 'name=^/'+name+'$', '--format={{.ID}}']), 'name collision')
    static = static_qualification(folder/'fresh-static') if (folder/'fresh-static').is_dir() else None
    require(static is not None, 'fresh-static directory required')
    save(folder, 'fresh-static.json', static)
    gate = load('owned_report_gate', HERE/'gate.py')
    # Cross-bind original results and hashes without altering their schemas.
    public = json.loads((HERE.parents[1]/'docs/openssl-candidate-evidence/instrumented-b04-20261030.json').read_text())
    for name_, desc in public['artifact_hashes'].items():
        gate.read_pin(dict(path=str(BUILD/'artifact'/name_), size=desc['bytes'], sha256=desc['sha256']))
    libraries = json.loads((BUILD/'artifact/public-libraries.json').read_text())
    for name_, desc in libraries['files'].items():
        require(name_.startswith('public-libraries/') and '..' not in Path(name_).parts, 'public library path')
        gate.read_pin(dict(path=str(BUILD/'artifact'/name_), size=desc['bytes'], sha256=desc['sha256']))
    before = inventory()
    save(folder, 'before.json', before)
    admission = dict(host_free=shutil.disk_usage(SCRATCH).free, measured_unix=time.time(),
                     host_admission=16*1024**3+128*1024**2, engine_admission=128*1024**2,
                     engine_capacity_and_effective_cgroups='required in same-container shell before exact exec',
                     execution_seconds=EXECUTION_SECONDS, settlement_seconds=SETTLEMENT_SECONDS,
                     library_files=len(libraries['files']), image=image,
                     controller_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                     supervision_sha256=hashlib.sha256((HERE/'supervision.py').read_bytes()).hexdigest())
    require(int(admission['host_free']) >= int(admission['host_admission']), 'fresh report capacity admission')
    save(folder, 'admission.json', admission)
    cmd = create_command(name)
    save(folder, 'spent.json', dict(scope='owner-authorized one exact b04 no-state -R',
         argv=['start', '--attach', cid] if recover_created else cmd,
         container_created_here=not recover_created,
         controller_sha256=admission['controller_sha256'], retry_authorized=False, created_unix=time.time()))
    if cid is None:
        cid = query(cmd)
    require(re.fullmatch('[0-9a-f]{64}', cid), 'created ID uncertain; stop/manual recovery')
    save(folder, 'owned.json', dict(container_id=cid))
    stop = [False]
    def interrupted(signum, frame):
        stop[0] = True
    old = {s: signal.signal(s, interrupted) for s in (signal.SIGINT, signal.SIGTERM)}
    initial = admission['host_free']
    def capacity():
        free = shutil.disk_usage(SCRATCH).free
        require(free >= 16*1024**3 and initial-free <= 128*1024**2, 'host report floor/growth')
    def capture(argv, sink):
        capacity()
        return supervision.capture(argv, sink, lambda: stop[0], capacity, timeout=EXECUTION_SECONDS)
    process = None
    error = None
    settled = None
    started = time.monotonic()
    try:
        process = start_once(folder, cid, name, inspect, capture)
    except BaseException as exc:
        error = type(exc).__name__+': '+str(exc)
    finally:
        try:
            settled = settle(cid, lambda timeout: inspect(cid, timeout), query,
                             deadline=started+EXECUTION_SECONDS+SETTLEMENT_SECONDS)
        except BaseException as exc:
            error = (error+'; ' if error else '')+'settlement '+type(exc).__name__+': '+str(exc)
        for s, handler in old.items():
            signal.signal(s, handler)
    after_sha = hashlib.sha256(identity()).hexdigest()
    log = folder/'public-report.log'
    raw = log.read_bytes() if log.exists() else b''
    versions = report_versions(raw.decode(errors='replace'), '3.5.9', '8.23.0')
    resources = re.findall(rb'^ISSUE3_RESOURCE (.+)$', raw, re.M)
    effective = json.loads(resources[0]) if len(resources) == 1 else None
    after = inventory()
    save(folder, 'after.json', after)
    preserved = all(set(after[k]) == set(v) | ({cid} if k == 'containers' else set()) for k, v in before.items())
    passed = (error is None and process is not None and process.returncode == 0 and
              settled is not None and settled['exit_code'] == 0 and settled['oom_killed'] is False and
              after_sha == SHA and len(raw) <= 65536 and all(versions.values()) and preserved and
              effective is not None and effective['memory_max'] == 268435456 and effective['swap_max'] == 0 and
              effective['cpu_max'] == '100000 100000' and effective['pids_max'] == 32 and
              effective['engine_free_kib'] >= 131072 and effective['mem_available_kib'] >= 262144)
    result = dict(schema='issue3-owned-report-v1', status='PASS' if passed else 'FAILED',
        attempt_id=name, stage='report', container_id=cid, image=IMAGE, error=error, state=settled,
        client_exit_code=process.returncode if process else None, versions=versions, effective_resources=effective,
        executable_sha256_before=SHA, executable_sha256_after=after_sha,
        public_report_sha256=hashlib.sha256(raw).hexdigest(), public_report_bytes=len(raw),
        elapsed_seconds=time.monotonic()-started, preserved=preserved,
        ship_booted=False, crypto_tls_qualified=False, package_qualified=False,
        retry_authorized=False, cleanup_performed=False, ended_unix=time.time())
    save(folder, 'result.json', result)
    print(raw.decode(errors='replace'))
    print(json.dumps(result, indent=2))
    return passed


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-one-no-state-report', type=Path, required=True)
    parser.add_argument('--continue-exact-created', action='store_true')
    args = parser.parse_args()
    raise SystemExit(0 if run(args.execute_one_no_state_report, args.continue_exact_created) else 1)