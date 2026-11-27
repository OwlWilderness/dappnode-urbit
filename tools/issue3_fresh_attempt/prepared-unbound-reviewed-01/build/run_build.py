from gate import preflight
CONFIG = preflight(__file__, 'build')
# Prepared successor; historical controller is immutable.
import sys
sys.dont_write_bytecode = True
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time
from typing import Any

ATTEMPT = Path(__file__).resolve().parent
ROOT = Path(CONFIG['recipe_dir'])
SCRATCH = Path('/tmp')
BUDGET = 8 * 1024**3
RESERVE = 10 * 1024**3
approval = json.loads((ATTEMPT / 'authorization.json').read_text())
if approval.get('authorized') is not True or approval.get('scope') != CONFIG['attempt_id']:
    raise SystemExit('NO-GO: build authorization missing')
if approval.get('controller_sha256') != hashlib.sha256(Path(__file__).read_bytes()).hexdigest():
    raise SystemExit('NO-GO: frozen controller changed')
actual = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in ROOT.iterdir() if p.is_file()}
if actual != approval['recipe_sha256'] or set(p.name for p in ROOT.iterdir()) != set(actual):
    raise SystemExit('NO-GO: frozen recipe changed')
DOCKER = ['docker', '--context', CONFIG['docker_context']]
if subprocess.check_output(DOCKER + ['ps', '-q'], timeout=30).strip():
    raise SystemExit('NO-GO: active containers')
if subprocess.check_output(DOCKER + ['version', '--format', '{{.Server.Arch}}'], timeout=30).strip() != b'arm64':
    raise SystemExit('NO-GO: local engine differs from recorded ARM64 backend')
def inventory():
    result = {}
    for key, args in {
        'containers': ['ps', '-aq', '--no-trunc'],
        'volumes': ['volume', 'ls', '--format', '{{.Name}}'],
        'images': ['image', 'ls', '-a', '--no-trunc', '--format', '{{.ID}} {{.Repository}}:{{.Tag}}'],
        'networks': ['network', 'ls', '--no-trunc', '--format', '{{.ID}}']
    }.items():
        result[key] = sorted(set(subprocess.check_output(DOCKER + args, timeout=30).decode().splitlines()))
    return result
before_inventory = inventory()
with (ATTEMPT / 'resources-before.json').open('x') as out:
    json.dump(before_inventory, out, indent=2)
sys.path.insert(0, str(ROOT))  # Resolve only this frozen recipe's diagnostic helper.
spec = importlib.util.spec_from_file_location('pinned_recipe', ROOT / 'candidate.py')
if spec is None or spec.loader is None:
    raise SystemExit('NO-GO: frozen recipe loader unavailable')
recipe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recipe)
argv = recipe.image_build_command(ROOT, ATTEMPT / 'artifact', CONFIG['attempt_id'])
argv = DOCKER + argv[1:3] + ['--builder', 'desktop-linux'] + argv[3:]
if '--platform=linux/amd64' not in argv:
    raise SystemExit('NO-GO: wrong build platform')
scratch_kib = int(subprocess.check_output(['du', '-sk', str(SCRATCH)], timeout=20).split()[0])
if scratch_kib > 10 * 1024**2:
    raise SystemExit('NO-GO: whole scratch ceiling')
free = shutil.disk_usage(ATTEMPT).free
if free < BUDGET + RESERVE:
    raise SystemExit('NO-GO: insufficient host headroom; build not launched')
with (ATTEMPT / 'spent.json').open('x') as receipt:
    json.dump(dict(argv=argv, source_hashes={p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in ROOT.iterdir() if p.is_file()}, host_free_before=free,
                   incremental_budget_bytes=BUDGET, reserve_bytes=RESERVE,
                   timeout_seconds=2400, scope='one build-only attempt; no Vere execution'), receipt, indent=2)
started = time.monotonic()
status = 'unknown'
stop_requested = False

def request_stop(signum, frame):
    global stop_requested
    stop_requested = True

signal.signal(signal.SIGTERM, request_stop)
signal.signal(signal.SIGINT, request_stop)

def cancel(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)

preview_offset = 0

def preview_build():
    # Public build output only. Full stream remains in build.log; console is bounded.
    global preview_offset
    path = ATTEMPT / 'build.log'
    size = path.stat().st_size
    if size <= preview_offset:
        return
    with path.open('rb') as reader:
        reader.seek(max(preview_offset, size - 65536))
        text = reader.read(65536).decode(errors='replace')
    preview_offset = size
    events = []
    latest_compiler = None
    for line in text.splitlines():
        begin = line.find('{')
        if begin < 0:
            continue
        try:
            event = json.loads(line[begin:])
        except ValueError:
            continue
        if event.get('status') == 'compiler-output':
            latest_compiler = event.get('text', '')[-800:]
        elif event.get('status') in {'activity', 'entered', 'returned', 'stopped', 'failed', 'passed', 'verified', 'compiler-stream-capped'}:
            events.append(event)
    for event in events[-6:]:
        print(json.dumps({'build_event': event}), flush=True)
    if latest_compiler:
        print(json.dumps({'public_compiler_preview': latest_compiler}), flush=True)

with (ATTEMPT / 'build.log').open('xb') as log:
    process = subprocess.Popen(argv, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                               start_new_session=True)
    print('Build submitted; attempt is spent. Public build log: ' + str(ATTEMPT / 'build.log'), flush=True)
    try:
        while process.poll() is None:
            current = shutil.disk_usage(ATTEMPT).free
            scratch_kib = int(subprocess.check_output(['du', '-sk', str(SCRATCH)], timeout=20).split()[0])
            elapsed = time.monotonic() - started
            preview_build()
            if stop_requested or current < RESERVE or free-current > BUDGET or scratch_kib > 10*1024**2 or elapsed > 2400:
                status = 'STOP_REQUESTED_ENGINE_STATE_REQUIRES_READBACK'
                cancel(process)
                break
            print(json.dumps(dict(elapsed_seconds=round(elapsed), host_free_bytes=current,
                                  scratch_kib=scratch_kib)), flush=True)
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                pass
        else:
            status = 'PASS' if process.returncode == 0 else 'FAILED'
    except BaseException:
        status = 'SUPERVISION_FAILED_ENGINE_STATE_REQUIRES_READBACK'
        cancel(process)
        raise
    finally:
        preview_build()
        result: dict[str, Any] = dict(status=status, exit_code=process.poll(), elapsed_seconds=round(time.monotonic()-started),
                      vere_executed=False, lifecycle_attempted=False, runtime_image_built=False,
                      retry_authorized=False, cleanup_performed=False)
        try:
            after_inventory = inventory()
            (ATTEMPT / 'resources-after.json').write_text(json.dumps(after_inventory, indent=2) + '\n')
            result['missing_retained_resources'] = {k: sorted(set(v) - set(after_inventory[k])) for k, v in before_inventory.items()}
            result['active_after'] = subprocess.check_output(DOCKER + ['ps', '-q'], timeout=30).decode().splitlines()
            result['preserved'] = not any(result['missing_retained_resources'].values())
            result['host_free_bytes_final'] = shutil.disk_usage(ATTEMPT).free
            if not result['preserved'] or result['active_after']:
                status = result['status'] = 'PRESERVATION_REVIEW_REQUIRED'
        except BaseException:
            status = result['status'] = 'CLOSEOUT_REQUIRES_READBACK'
        result.update(attempt_id=CONFIG['attempt_id'], stage='build')
        (ATTEMPT / 'result.json').write_text(json.dumps(result, indent=2)+'\n')
        print(json.dumps(result), flush=True)
with (ATTEMPT / 'build.log').open('rb') as log:
    log.seek(max(0, log.seek(0, 2)-16000))
    print(log.read().decode(errors='replace'))
raise SystemExit(0 if status == 'PASS' else 1)
