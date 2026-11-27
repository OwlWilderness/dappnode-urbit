"""Fresh-attempt gate. Public file checks only; no subprocess at import/admission."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

GIB = 1024**3
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


def validate_receipts(config):
    stage, artifacts = config['stage'], config['artifacts']
    prior = config['predecessors']
    require(isinstance(prior, list) and [r.get('stage') for r in prior] == list(STAGES[:STAGES.index(stage)]), 'stage sequence')
    ids = [r.get('attempt_id') for r in prior] + [config['attempt_id']]
    require(all(fresh_id(i) for i in ids) and len(ids) == len(set(ids)), 'receipt identity')
    for record in prior:
        r = receipt(record['result'])
        require(r.get('attempt_id') == record['attempt_id'] and r.get('stage') == record['stage'] and
                r.get('status') == 'PASS', 'receipt identity/status')
        if record['stage'] == 'build':
            require(type(r.get('exit_code')) is int and r['exit_code'] == 0 and
                    r.get('preserved') is True and r.get('active_after') == [], 'build receipt settlement')
            v = receipt(record['verification'])
            require(v.get('attempt_id') == record['attempt_id'] and v.get('stage') == 'build' and
                    v.get('build_result_sha256') == record['result']['sha256'],
                    'binary receipt provenance')
            require(v.get('status') == 'PASS' and v.get('architecture') == 'linux/amd64' and
                    v.get('executable_sha256') == artifacts['executable_sha256'] and
                    type(v.get('executable_bytes')) is int and v['executable_bytes'] == artifacts['executable_size'], 'binary receipt identity')
            require(all(v.get(k) is True for k in ('no_uvm_i3_symbols', 'openssl_loom_hook_absent_from_u3m_init',
                        'gmp_registration_retained', 'normal_libc_cleanup_retained', 'openssl_cleanup_linked',
                        'source_receipts_verified', 'frozen_recipe_verified')), 'binary receipt verification')
        elif record['stage'] == 'report':
            require(r.get('error') is None and r.get('executable_sha256_before') == artifacts['executable_sha256'] and
                    r.get('executable_sha256_after') == artifacts['executable_sha256'] and
                    all(r.get(k) is True for k in ('linked_openssl_3_5_9', 'compiled_headers_3_5_9',
                                                'linked_curl_8_23_0', 'compiled_curl_headers_8_23_0')), 'report receipt artifact')
            s = r.get('state', {})
            require(isinstance(s, dict) and s.get('status') == 'exited' and s.get('running') is False and
                    type(s.get('exit_code')) is int and s['exit_code'] == 0 and s.get('oom_killed') is False and
                    type(s.get('pid')) is int and s['pid'] == 0 and digest(r.get('container_id')) and
                    s.get('id') == r['container_id'] and
                    isinstance(record.get('image'), str) and re.fullmatch('sha256:[0-9a-f]{64}', record['image']) and
                    s.get('image') == record['image'] and s.get('name') == '/' + record['attempt_id'] and
                    s.get('label') == record['attempt_id'] and r.get('preserved') is True and
                    r.get('active_after') == [], 'report receipt settlement')
        elif record['stage'] == 'package':
            require(type(r.get('schema_version')) is int and r['schema_version'] == 1 and
                    all(r.get(k) == 'PASS' for k in ('static_verification', 'independent_readback')) and
                    type(r.get('build_exit_code')) is int and r['build_exit_code'] == 0 and
                    r.get('image_id') == artifacts['image'] and
                    r.get('binding_sha256') == config['inputs']['binding']['sha256'], 'package receipt identity')
            v = r.get('verification_summary', {})
            require(v.get('executable_sha256') == artifacts['executable_sha256'] and
                    v.get('adapter_sha256') == artifacts['adapter_sha256'], 'package receipt artifact')
            require(record['result'] == config['inputs']['receipt'], 'package receipt selection')


def validate_bindings(config, stage):
    require(isinstance(config, dict) and config.get('state') == 'BOUND', 'UNBOUND: fresh configuration required')
    require(type(config.get('schema')) is int and config['schema'] == 1 and config.get('stage') == stage and stage in STAGES,
            'configuration schema/stage')
    require(fresh_id(config.get('attempt_id')), 'fresh identity required')
    require(config.get('failure_model') == 'attended-best-effort-stop-retain', 'failure model UNBOUND')
    require(config.get('scratch') == '/tmp' and
            config.get('docker_context') == 'desktop-linux' and
            config.get('docker_host') == 'unix:///var/run/docker.sock' and
            config.get('bind_prefix') == '/host_mnt', 'execution backend binding')
    b = config['budget']
    floor, growth, seconds = BOUNDS[stage]
    expected = dict(floor_bytes=floor, growth_bytes=growth, admission_bytes=floor+growth,
                    scratch_bytes=10*GIB, timeout_seconds=seconds)
    require(b == expected and all(type(x) is int for x in b.values()), 'budget arithmetic/approved envelope')
    a = config['artifacts']
    if stage != 'build':
        require(isinstance(a.get('image'), str) and re.fullmatch('sha256:[0-9a-f]{64}', a['image']) is not None,
                'image identity')
        require(digest(a.get('executable_sha256')) and type(a.get('executable_size')) is int and a['executable_size'] > 0,
                'executable identity')
    if stage == 'lifecycle':
        require(digest(a.get('adapter_sha256')) and type(a.get('adapter_size')) is int and a['adapter_size'] > 0,
                'adapter identity')
    required = {'build': set(), 'report': {'binary'}, 'package': {'binary', 'binding'},
                'lifecycle': {'binary', 'binding', 'receipt', 'pill'}}[stage]
    require(set(config['inputs']) == required, 'input allowlist')
    for pin in config['inputs'].values():
        read_pin(pin)
    if 'binary' in required:
        pin = config['inputs']['binary']
        require(pin['sha256'] == a['executable_sha256'] and pin['size'] == a['executable_size'], 'input binary binding')
    if 'binding' in required:
        binding = receipt(config['inputs']['binding'])
        require(binding.get('candidate_sha256') == a['executable_sha256'] and
                type(binding.get('candidate_bytes')) is int and
                binding['candidate_bytes'] == a['executable_size'], 'source binding executable')
        selected = [('candidate/urbit', 'executable')]
        if stage == 'lifecycle':
            selected.append(('tools/browser-importer/runtime.py', 'adapter'))
        context = binding.get('context')
        require(isinstance(context, dict), 'source descriptor context')
        for name, artifact in selected:
            descriptor = context.get(name)
            require(isinstance(descriptor, dict) and
                    descriptor.get('sha256') == a[artifact + '_sha256'] and
                    type(descriptor.get('bytes')) is int and descriptor['bytes'] == a[artifact + '_size'],
                    'source descriptor artifact')
    validate_receipts(config)
    return config


def validate_approval(config, stage, approval, bundle_sha256, now, action='execute'):
    if (not isinstance(approval, dict) or approval.get('authorized') is not True or
            approval.get('bundle_sha256') != bundle_sha256 or not digest(bundle_sha256) or
            approval.get('stage') != stage or approval.get('attempt_id') != config['attempt_id'] or
            approval.get('action') != action or type(approval.get('expires_unix')) is not int or
            not now < approval['expires_unix'] <= now + 3600 or
            approval.get('failure_model') != config['failure_model'] or
            not isinstance(approval.get('owner_grant'), str) or not approval['owner_grant'].strip()):
        raise Refusal('fresh approval missing, expired or mismatched')


def validate(config, stage, approval, bundle_sha256, now, action='execute'):
    try:
        validate_bindings(config, stage)
        validate_approval(config, stage, approval, bundle_sha256, now, action)
        return config
    except (KeyError, TypeError, ValueError, OSError) as exc:
        raise Refusal('invalid configuration/input/receipt: ' + type(exc).__name__) from None


def settled_inventory(before, after, owned):
    require(set(before) == set(after) and set(owned) <= set(before), 'inventory keys')
    for key, previous in before.items():
        added = set(owned.get(key, []))
        require(not set(previous) & added and set(after[key]) == set(previous) | added, 'inventory preservation/exact ownership')
    return True


def read_authorization(folder, action):
    path = str(folder / ('inspection-approval.json' if action == 'inspect' else 'execution-approval.json'))
    try:
        require(safe(path).st_mode & 0o777 == 0o600, 'approval mode must be 0600')
        return strict(read_public(path, 16384))
    except OSError:
        raise Refusal('fresh approval missing') from None


def now():
    import time
    return time.time()


def capacity(config, initial=None):
    import shutil
    free = shutil.disk_usage(config['scratch']).free
    b = config['budget']
    require(free >= (b['admission_bytes'] if initial is None else b['floor_bytes']), 'capacity admission/floor')
    require(initial is None or initial-free <= b['growth_bytes'], 'capacity growth')
    # Allocated bytes, no payload reads. This is observation, NOT a disk quota.
    total = 0
    deadline = now() + 15
    for root, dirs, files in os.walk(config['scratch'], followlinks=False,
                                     onerror=lambda _: require(False, 'capacity inventory error')):
        require(now() < deadline, 'capacity inventory deadline')
        for name in dirs + files:
            total += os.lstat(os.path.join(root, name)).st_blocks * 512
            require(total <= b['scratch_bytes'], 'capacity whole-scratch ceiling')
    return free


def preflight(script, stage):
    import sys
    require(sys.flags.optimize == 0, 'optimized Python disables inherited assertions; refused')
    folder = Path(script).absolute().parent
    try:
        require(safe(str(folder), True).st_mode & 0o777 == 0o700, 'attempt directory must be private 0700')
        config = strict(read_public(str(folder / 'config.json')))
        require(config.get('state') == 'BOUND', 'UNBOUND: fresh artifact configuration required')
        require(not any(os.path.lexists(folder / name) for name in
                        ('spent.json', 'result.json', 'volume-create-intent.json', 'owned.json')), 'spent/uncertain attempt; no replay')
        raw = read_public(str(folder / 'bundle.json'))
        bundle = strict(raw)
        names = {'gate.py', 'config.json', Path(script).name}
        if stage == 'report':
            names.add('supervision.py')
        if stage == 'lifecycle':
            names |= {'base.py', 'lifecycle_guest.py'}
        require(bundle.get('schema') == 1 and bundle.get('task') == str(folder) and
                bundle.get('stage') == stage and set(bundle.get('files', {})) == names, 'bundle identity')
        for name, expected in bundle['files'].items():
            require(digest(expected) and hashlib.sha256(read_public(str(folder / name))).hexdigest() == expected,
                    'bundle input drift')
        action = 'inspect' if stage == 'lifecycle' and sys.argv[1:] == ['prepare'] else 'execute'
        approval = read_authorization(folder, action)
        validate(config, stage, approval, hashlib.sha256(raw).hexdigest(), now(), action)
        if stage in ('build', 'package'):
            raise Refusal('BLOCKED: engine build closeout, memory/CPU caps and storage quota unsupported; code change and review required')
        capacity(config)
        # Inventory/admission may take seconds: read the grant and clock last.
        approval = read_authorization(folder, action)
        validate_approval(config, stage, approval, hashlib.sha256(raw).hexdigest(), now(), action)
        os.environ['TMPDIR'] = config['scratch']
        os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
        sys.dont_write_bytecode = True
        # Compatibility view of the SAME checked grant, not an authorization writer.
        config['_authorization'] = dict(approval, controller_sha256=bundle['files'][Path(script).name])
        return config
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise Refusal('preflight input/receipt invalid: ' + type(exc).__name__) from None
