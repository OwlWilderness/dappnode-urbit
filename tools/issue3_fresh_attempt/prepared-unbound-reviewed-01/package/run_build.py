from gate import preflight
CONFIG = preflight(__file__, 'package')
# Prepared successor; historical controller is immutable.
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time
import sys

# Background launchers may not inherit the foreground shell exports.
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
from typing import Any

ATTEMPT = Path(__file__).resolve().parent
ROOT = ATTEMPT.parent
FROZEN = Path(CONFIG['package_dir'])
CONTEXT = FROZEN / 'context'
SUPPORT = FROZEN / 'support'
SCRATCH = Path('/tmp')
AUTHORIZATION = json.loads((ATTEMPT / 'authorization.json').read_text())
BINDING = AUTHORIZATION['binding_sha256']
TAG = 'uvm-issue3-openssl3:' + CONFIG['attempt_id']
BUDGET, RESERVE, TIMEOUT = 2 * 1024**3, 16 * 1024**3, 1200
DOCKER = ['docker', '--context', CONFIG['docker_context']]
STOP = False


def build_command():
    return DOCKER + ['buildx', 'build', '--builder', 'desktop-linux',
                     '--platform=linux/amd64', '--pull=false', '--network=default',
                     '--progress=plain', '--load', '--tag', TAG,
                     '--iidfile', str(ATTEMPT / 'image.id'),
                     '--file', str(CONTEXT / 'build/Dockerfile'), str(CONTEXT)]


def within_limits(free, initial, scratch_kib, elapsed):
    return free >= RESERVE and initial - free <= BUDGET and scratch_kib <= 10 * 1024**2 and elapsed <= TIMEOUT


def save(name, value):
    with (ATTEMPT / name).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')
    (ATTEMPT / name).chmod(0o600)


def query(args):
    response = subprocess.run(DOCKER + args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              text=True, timeout=30, check=True)
    if len(response.stdout) > 1024**2:
        raise ValueError('selected metadata bound')
    return response.stdout.strip()


def resources():
    return {'containers': sorted(set(query(['ps', '-aq', '--no-trunc']).splitlines())),
            'images': sorted(set(query(['image', 'ls', '-aq', '--no-trunc']).splitlines())),
            'volumes': sorted(set(query(['volume', 'ls', '-q']).splitlines())),
            'active': sorted(set(query(['ps', '-q', '--no-trunc']).splitlines())),
            'networks': sorted(set(query(['network', 'ls', '--no-trunc', '--format={{.ID}}']).splitlines())),
            'tags': sorted(set(query(['image', 'ls', '-a', '--no-trunc', '--format',
                                     '{{.Repository}}:{{.Tag}} {{.ID}}']).splitlines()))}


def capacity():
    return {'host_free_bytes': shutil.disk_usage(ATTEMPT).free,
            'scratch_kib': int(subprocess.check_output(['du', '-sk', str(SCRATCH)], timeout=20).split()[0])}


def load_package():
    raw = (FROZEN / 'binding.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != BINDING:
        raise ValueError('frozen binding changed')
    manifest = json.loads(raw)
    for name, expected in manifest['support'].items():
        if hashlib.sha256((SUPPORT / name).read_bytes()).hexdigest() != expected['sha256']:
            raise ValueError('frozen support changed')
    spec = importlib.util.spec_from_file_location('frozen_package', SUPPORT / 'build/vere-openssl3/package_image.py')
    assert spec is not None and spec.loader is not None
    package: Any = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(package)
    package.verify(FROZEN, BINDING)
    return package


def image_configuration(image_id):
    projection = '{"id":{{json .Id}},"os":{{json .Os}},"architecture":{{json .Architecture}},"user":{{json .Config.User}},"entrypoint":{{json .Config.Entrypoint}},"cmd":{{json .Config.Cmd}},"workdir":{{json .Config.WorkingDir}},"ports":{{json .Config.ExposedPorts}},"volumes":{{json .Config.Volumes}}}'
    selected = json.loads(query(['image', 'inspect', '--format', projection, image_id]))
    expected = {'id': image_id, 'os': 'linux', 'architecture': 'amd64', 'user': '10000:10000',
                'entrypoint': ['sh', '/usr/local/bin/docker-entrypoint.sh'],
                'cmd': ['--pier-root', '/urbit/pier', '--uploads-root', '/urbit/uploads',
                        '--control-root', '/urbit/control', '--password-hash-file', '/urbit/control/auth.json'],
                'workdir': '/opt/importer', 'ports': {'8443/tcp': {}, '34343/udp': {}},
                'volumes': {'/urbit': {}}}
    if selected != expected:
        raise ValueError('selected image configuration mismatch')
    return selected


def verify_image(package, image_id):
    # Exact public snapshot checked before contract construction; no path-derived
    # or image-supplied filenames become host input selections.
    manifest = package.verify(FROZEN, BINDING)
    snapshot = {}
    for name, expected in manifest['context'].items():
        data = package.read_public(CONTEXT / name)
        if hashlib.sha256(data).hexdigest() != expected['sha256']:
            raise ValueError('context changed before image verification')
        snapshot[name] = data
    verifier = package.image_verifier(SUPPORT)
    contract = verifier.build_contract(CONTEXT, read_regular=lambda _, name: snapshot[name])
    parser = verifier.load_parser()
    parser.inventory_stream = lambda stream, metadata, notice_paths=(): verifier.verify_stream(stream, metadata, contract)
    result = parser.collect(image_id)  # selected inspect + 120s bounded save PIPE
    package.verify(FROZEN, BINDING)
    verifier.publish(result, ATTEMPT / 'image-verification')
    return {'selected_files': len(result['selected_files']), 'notice_count': result['notice_count'],
            'package_count': result['package_count'], 'stream_bytes': result['stream_bytes'],
            'executable_sha256': result['selected_files']['bin/urbit']['sha256'],
            'adapter_sha256': result['selected_files']['opt/importer/runtime.py']['sha256']}


def cancel(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def main():
    global STOP
    # The Docker-save helper uses the same explicitly selected local context.
    os.environ['DOCKER_CONTEXT'] = 'desktop-linux'
    os.environ['TMPDIR'] = str(SCRATCH)
    if (ATTEMPT / 'spent.json').exists() or (ATTEMPT / 'result.json').exists():
        raise SystemExit('REFUSED: retained attempt cannot be replayed')
    started = time.monotonic()
    def request_stop(signum, frame):
        global STOP
        STOP = True
    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    if AUTHORIZATION['controller_sha256'] != hashlib.sha256(Path(__file__).read_bytes()).hexdigest():
        raise SystemExit('REFUSED: controller authorization mismatch')
    package = load_package()
    before = resources()
    admitted = capacity()
    if before['active'] or any(row.split()[0] == TAG for row in before['tags']):
        raise SystemExit('NO-GO: active containers or existing candidate tag')
    if admitted['host_free_bytes'] < BUDGET + RESERVE or not within_limits(
            admitted['host_free_bytes'], admitted['host_free_bytes'], admitted['scratch_kib'], 0):
        raise SystemExit('NO-GO: capacity admission failed; no build submitted')
    save('resources-before.json', before)
    save('admission.json', admitted)
    # Exclusive authority consumption immediately before the single build call.
    save('spent.json', {'approved_by': AUTHORIZATION['owner_grant'],
                       'recorded_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                       'scope': 'one package-image build plus static verification; no Vere or ship execution',
                       'binding_sha256': BINDING, 'argv': build_command(),
                       'controller_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                       'authorization_sha256': hashlib.sha256((ATTEMPT / 'authorization.json').read_bytes()).hexdigest(),
                       'timeout_seconds': TIMEOUT, 'incremental_budget_bytes': BUDGET,
                       'host_free_reserve_bytes': RESERVE, 'scratch_ceiling_bytes': 10 * 1024**3,
                       'retry_authorized': False})
    result = {'status': 'BUILD_PENDING', 'image_id': None, 'build_exit_code': None,
              'static_verification': 'NOT_RUN', 'vere_executed': False, 'ship_executed': False,
              'cleanup_performed': False, 'retry_authorized': False}
    process, offset, preview_budget = None, 0, 32768
    try:
        with (ATTEMPT / 'build.log').open('xb') as log:
            process = subprocess.Popen(build_command(), cwd=CONTEXT, stdout=log, stderr=subprocess.STDOUT,
                                       start_new_session=True)
            print('Package build submitted; attempt spent. No Vere execution.', flush=True)
            while process.poll() is None:
                current = capacity()
                elapsed = time.monotonic() - started
                print(json.dumps({'stage': 'building', 'elapsed_seconds': round(elapsed), **current}), flush=True)
                if STOP or elapsed > TIMEOUT - 150 or not within_limits(
                        current['host_free_bytes'], admitted['host_free_bytes'], current['scratch_kib'], elapsed):
                    result['status'] = 'STOP_REQUESTED_ENGINE_STATE_REQUIRES_READBACK'
                    cancel(process)
                    break
                size = (ATTEMPT / 'build.log').stat().st_size
                if size > 16 * 1024**2:
                    raise ValueError('public build log bound')
                if preview_budget and size > offset:
                    with (ATTEMPT / 'build.log').open('rb') as reader:
                        reader.seek(offset)
                        chunk = reader.read(min(4096, preview_budget))
                    print(chunk.decode(errors='replace'), flush=True)
                    offset += len(chunk)
                    preview_budget -= len(chunk)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            result['build_exit_code'] = process.wait(timeout=5)
        if result['status'].startswith('STOP_'):
            raise ValueError('build stopped; no retry')
        if result['build_exit_code'] != 0:
            result['status'] = 'BUILD_FAILED'
            raise ValueError('build returned failure')
        image_id = (ATTEMPT / 'image.id').read_text().strip()
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id):
            raise ValueError('invalid image output identity')
        result['image_id'] = image_id
        if query(['image', 'inspect', '--format', '{{.Id}}', TAG]) != image_id:
            raise ValueError('fresh tag does not match built image')
        save('image-configuration.json', image_configuration(image_id))
        print('Image built. Starting static selected-file verification; no container start.', flush=True)
        result['verification_summary'] = verify_image(package, image_id)
        result['static_verification'] = 'PASS'
        result['status'] = 'PASS'
    except BaseException as error:
        if process is not None:
            cancel(process)
            result['build_exit_code'] = process.poll()
        if result['status'] in ('BUILD_PENDING', 'PASS'):
            result['status'] = 'FAILED_REQUIRES_READBACK'
        result['error_class'] = type(error).__name__
    finally:
        try:
            after = resources()
            save('resources-after.json', after)
            result['missing_resources'] = {k: sorted(set(before[k]) - set(after[k]))
                                           for k in ('containers', 'images', 'volumes')}
            result['missing_retained_tags'] = sorted(row for row in set(before['tags']) - set(after['tags'])
                                                    if not row.startswith('<none>:'))
            result['added_resources'] = {k: sorted(set(after[k]) - set(before[k]))
                                         for k in ('containers', 'images', 'volumes')}
            result['active_after'] = after['active']
            result['capacity_after'] = capacity()
            result['elapsed_seconds'] = round(time.monotonic() - started, 3)
            package.verify(FROZEN, BINDING)
            if (before['networks'] != after['networks'] or result['added_resources']['containers'] or
                    result['added_resources']['volumes'] or any(result['missing_resources'].values()) or
                    result['missing_retained_tags'] or after['active'] or
                    not within_limits(result['capacity_after']['host_free_bytes'], admitted['host_free_bytes'],
                                      result['capacity_after']['scratch_kib'], result['elapsed_seconds'])):
                result['status'] = 'CLOSEOUT_REFUSED'
        except BaseException as error:
            result['status'] = 'CLOSEOUT_UNCERTAIN'
            result['closeout_error_class'] = type(error).__name__
        result.update(attempt_id=CONFIG['attempt_id'], stage='package')
        save('result.json', result)
        print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
