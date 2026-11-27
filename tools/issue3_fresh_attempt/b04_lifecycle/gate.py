"""Fresh-attempt gate. Public file checks only; no subprocess at import/admission."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

GIB = 1024**3
FROZEN_FILES = ('base.py', 'gate.py', 'lifecycle_guest.py', 'run_lifecycle.py',
                'settlement.py', 'settlement_verifier.py', 'lifecycle_watchdog.py', 'config.json')
STAGES = ('build', 'report', 'package', 'lifecycle')
BOUNDS = {'build': (10*GIB, 8*GIB, 2400), 'report': (16*GIB, 128*1024**2, 30),
          'package': (16*GIB, 2*GIB, 1200), 'lifecycle': (16*GIB, 7*GIB, 1600)}


class Refusal(Exception):
    pass


def require(ok, message):
    if not ok:
        raise Refusal(message)


def strict(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False, 'nonfinite JSON'))


def digest(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def fresh_id(value):
    return isinstance(value, str) and re.fullmatch('issue3-fresh-[a-z0-9-]{6,80}', value) is not None


def safe(path, directory=False):
    # Same ownership/no-follow policy as retained lifecycle base.safe/pinned.
    require(isinstance(path, str), 'input path type')
    p = Path(path)
    require(p.is_absolute() and str(p) == path and '..' not in p.parts and
            not any(c in path for c in ',\n\r\x00'), 'input path')
    for ancestor in [*reversed(p.parents), p]:
        s = ancestor.lstat()
        require(not stat.S_ISLNK(s.st_mode) and s.st_uid in (0, os.getuid()) and
                not s.st_mode & 0o022, 'input unsafe ancestor')
    s = p.lstat()
    require(s.st_uid == os.getuid(), 'input owner')
    require(stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode) and s.st_nlink == 1,
            'input regular file/directory required')
    return s


def read_public(path, limit=1024**2):
    before = safe(path)
    require(before.st_size <= limit, 'input byte limit')
    identity = lambda s: tuple(getattr(s, k) for k in ('st_dev', 'st_ino', 'st_size', 'st_mode', 'st_uid', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns'))
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        require(identity(os.fstat(stream.fileno())) == identity(before), 'input changed')
        raw = stream.read(limit + 1)
        require(len(raw) <= limit and identity(os.fstat(stream.fileno())) == identity(before), 'input changed')
    require(identity(safe(path)) == identity(before), 'input changed')
    return raw


def read_pin(pin, limit=256*1024**2):
    require(isinstance(pin, dict) and set(pin) == {'path', 'size', 'sha256'}, 'input descriptor')
    require(type(pin['size']) is int and 0 < pin['size'] <= limit and digest(pin['sha256']), 'input identity')
    raw = read_public(pin['path'], limit)
    require(len(raw) == pin['size'] and hashlib.sha256(raw).hexdigest() == pin['sha256'], 'input hash/size mismatch')
    return raw


def receipt(pin):
    result = strict(read_pin(pin, 1024**2))
    require(isinstance(result, dict), 'receipt object')
    return result


B04_SHA = 'f2eba68682650ab6d9712017781612f4dbc3c01411c1ba5c7c4ecbb0f186b6b5'
ADAPTER_SHA = 'fced18b0aae3d540b7cfebc72eb2b2f8a924e6e3ea674f6f8e7b5ff122862db9'
PILL_SHA = 'f8b08c53dd6d0aa9c4f7654f0a7bcd11e94089222888a3c99c0a10eedcbb377b'
BUDGET = dict(floor_bytes=10*GIB, growth_bytes=7*GIB, admission_bytes=17*GIB,
              task_bytes=128*1024**2, timeout_seconds=1600, settlement_seconds=210)


def validate_inventory(r, config):
    # This is verify_image.py's REAL inventory.json, not historical qualification.json.
    a = config['artifacts']
    require(isinstance(r, dict) and type(r.get('schema_version')) is int and r['schema_version'] == 1,
            'image inventory schema')
    require(r.get('status') == 'PASS_SELECTED_CANDIDATE_FILES' and
            r.get('package_selector') == 'owned-b04' and r.get('notice_count') == 409,
            'actual b04 selected-file verification required')
    require(r.get('image', {}).get('image_id') == a['image'] and
            r['image'].get('architecture') == 'amd64', 'image substitution')
    require(r.get('owned_lock_sha256') == config['inputs']['binding']['sha256'] and
            r.get('dockerfile_sha256') == config['inputs']['dockerfile']['sha256'] and
            r.get('manifest_sha256') == config['inputs']['notice_manifest']['sha256'] and
            r.get('owned_report_receipt_sha256') ==
            '6c8650dec16390f800ace04414c750e213055fd81950addb2465ee07e8a94d4d',
            'actual source/receipt binding')
    require(r.get('owned_report_schema') == 'issue3-owned-report-v1' and
            r.get('unexpected_image_files_checked') is False and
            r.get('config_parsed') is False and r.get('container_executed') is False and
            r.get('distribution_clearance') is False, 'inventory claim boundary')
    selected = r.get('selected_files')
    require(isinstance(selected, dict) and len(selected) == 430, '429 selected plus APK database')
    for name, size, sha, source, mode in (
        ('bin/urbit', 42467624, B04_SHA, 'build/vere-owned-b04.json', 0o555),
        ('opt/importer/runtime.py', 17624, ADAPTER_SHA, 'build/runtime-b04.py', 0o644)):
        item = selected.get(name, {})
        require(item.get('kind') == 'regular' and type(item.get('mode')) is int and item.get('mode') == mode and
                item.get('uid') == 0 and item.get('gid') == 0 and
                type(item.get('size')) is int and item['size'] == size and
                item.get('sha256') == sha and item.get('source') == source and
                item.get('source_size') == size and item.get('source_sha256') == sha,
                'selected artifact substitution')
    require(isinstance(r.get('packages'), list) and type(r.get('package_count')) is int and
            r['package_count'] == len(r['packages']) and r['package_count'] > 0,
            'APK inventory required')
    return r


INDEPENDENT_OWNER_GRANT = ('New independent owner approval: ONE exact-b04 disposable fake-zod bootstrap, '
    'HTTP200 twice and clean stop, then different-container noncreating reopen of the same fresh '
    'synthetic volume, HTTP200 twice and clean stop. Genuine B PASS and exclusive safe engine required; '
    'A is not a prerequisite and crypto_qualified remains false. No retry, deletion, personal state, '
    'default-entrypoint/manager acceptance, native qualification or deployment.')
B_SUCCESSOR_SHA = '5c113321f8d89eec669c82736112f53086eb2cf1bbb9386d1f485cbf2d4fcf17'
B_IMAGE = 'sha256:27eb11cd36707f662b59688b827717e41668f3bf40d7ca4b496fbb33b5c168fc'


def validate_independent_policy(policy, image, inventory_sha256):
    require(isinstance(policy, dict) and set(policy) == {'schema','grant_id','owner_grant',
            'crypto_qualified','b_result','inventory_sha256','image'}, 'independent D policy required; no A PASS fields')
    require(policy['schema'] == 'issue3-b04-independent-lifecycle-policy-v1' and
            fresh_id(policy['grant_id']) and policy['owner_grant'] == INDEPENDENT_OWNER_GRANT and
            policy['crypto_qualified'] is False, 'new independent D owner grant required')
    require(policy['image'] == image == B_IMAGE and
            policy['inventory_sha256'] == inventory_sha256, 'independent D artifact binding')
    require(policy['b_result'].get('sha256') == B_SUCCESSOR_SHA, 'genuine B successor receipt required')
    b = receipt(policy['b_result'])
    r = b.get('result', {})
    require(b.get('status') == 'PASS_IMAGE_BUILD_AND_STATIC_APK_READBACK' and
            b.get('crypto_qualified') is False and b.get('image_build_invocations') == 1 and
            r.get('status') == 'PASS' and r.get('image_id') == image and
            r.get('build_exit_code') == 0 and r.get('static_verification') == 'PASS' and
            r.get('active_after') == [] and r.get('missing_retained_tags') == [] and
            r.get('missing_resources') == dict(containers=[],images=[],volumes=[]) and
            b['payloads']['attempt/image-verification/inventory.json']['sha256'] == inventory_sha256,
            'genuine successful safely settled B required')
    return policy


def validate_bindings(config, stage='lifecycle'):
    require(config.get('state') == 'BOUND', 'UNBOUND: B package PASS inventory required')
    require(config.get('schema') == 'issue3-b04-lifecycle-config-v1' and stage == 'lifecycle' and
            config.get('stage') == stage, 'configuration schema')
    require(config.get('budget') == BUDGET and all(type(x) is int for x in config['budget'].values()), 'bounds')
    require(config.get('scratch') == '/tmp' and
            config.get('docker_host') == 'unix:///var/run/docker.sock' and
            config.get('bind_prefix') == '/host_mnt' and config.get('docker_context') == 'desktop-linux',
            'backend binding')
    a = config['artifacts']
    require(isinstance(a['image'], str) and re.fullmatch('sha256:[0-9a-f]{64}', a['image']) and
            a['executable_sha256'] == B04_SHA and type(a['executable_size']) is int and
            a['executable_size'] == 42467624 and a['adapter_sha256'] == ADAPTER_SHA and
            type(a['adapter_size']) is int and a['adapter_size'] == 17624, 'exact artifact binding')
    require(set(config['inputs']) == {'binary', 'adapter', 'binding', 'receipt', 'pill', 'dockerfile', 'notice_manifest'},
            'input allowlist')
    values = {k: read_pin(v) for k, v in config['inputs'].items()}
    for key, size, sha in (('binary', 42467624, B04_SHA), ('adapter', 17624, ADAPTER_SHA),
                          ('pill', 217421172, PILL_SHA)):
        require(config['inputs'][key]['size'] == size and config['inputs'][key]['sha256'] == sha,
                'actual bytes required')
    lock = strict(values['binding'])
    require(lock.get('executable_sha256') == B04_SHA and lock.get('executable_bytes') == 42467624,
            'b04 lock required')
    validate_inventory(strict(values['receipt']), config)
    require('owner_policy' in config, 'independent D policy required')
    validate_independent_policy(receipt(config['owner_policy']), a['image'], config['inputs']['receipt']['sha256'])
    return config


def preflight(script, stage):
    import sys
    require(sys.flags.optimize == 0, 'optimized Python refused')
    folder = Path(script).absolute().parent
    config = strict(read_public(str(folder / 'config.json')))
    if config.get('state') == 'UNBOUND':
        return config  # source-only import; every effectful API calls require_bound first
    require(safe(str(folder), True).st_mode & 0o777 == 0o700, 'private fresh task required')
    require(folder.parent == Path(config['scratch']) and folder.name.startswith('issue3-b04-life-'),
            'operation-owned fresh scratch root required')
    bundle = strict(read_public(str(folder / 'bundle.json')))
    names = set(FROZEN_FILES)
    require(bundle.get('schema') == 1 and bundle.get('task') == str(folder) and
            set(bundle.get('files', {})) == names, 'bundle schema')
    for name, sha in bundle['files'].items():
        require(digest(sha) and hashlib.sha256(read_public(str(folder / name))).hexdigest() == sha,
                'frozen source substitution')
    validate_bindings(config, stage)
    return config
