"""Bridge current b04 file stages to the retained package build controller.

Import and host admission never invoke Docker. This is not a new controller,
not permission to launch, and does not rewrite the stage or historical evidence.
"""
import json
from . import b04_package_stage as stage

BUILDER = 'issue3-owned-20261029-b02'
TAG = 'uvm-issue3-openssl3:owned-b04-package-20261031-01'
# Same existing retained BuildKit cgroup; do not update/bootstrap it in host prep.
BOUNDS = dict(memory_bytes=6 * 1024**3, swap_total_bytes=6 * 1024**3,
              cpu_quota=200000, cpu_period=100000, cpuset='0-1',
              total_seconds=1200, build_stop_seconds=800, readback_stream_seconds=120,
              readback_wall_allowance_seconds=210, metadata_seconds=5,
              settlement_seconds=60, closeout_seconds=90,
              max_growth_bytes=2 * 1024**3, reserve_bytes=10 * 1024**3,
              stop_headroom_bytes=1024**3, scratch_ceiling_bytes=10 * 1024**3,
              build_log_bytes=16 * 1024**2, image_stream_bytes=1024**3,
              retained_selected_bytes=128 * 1024**2)


def build_command(frozen, attempt):
    context, attempt = stage.absolute(frozen) / 'context', stage.absolute(attempt)
    return ['docker', '--context', 'desktop-linux', 'buildx', 'build', '--builder', BUILDER,
            '--platform=linux/amd64', '--pull=false', '--network=default',
            '--progress=plain', '--provenance=false', '--load', '--tag', TAG,
            '--iidfile', str(attempt / 'image.id'), '--file', str(context / stage.DOCKERFILE),
            str(context)]


class PackageStage:
    def __init__(self, plan, frozen, binding_sha256):
        self.plan_path = stage.absolute(plan)
        self.frozen = stage.absolute(frozen)
        raw = stage.read(self.plan_path.parent, self.plan_path.name)
        if stage.sha(raw) != binding_sha256:
            raise ValueError('current stage plan pin mismatch')
        self.value = json.loads(raw)
        if raw != stage.canonical(self.value):
            raise ValueError('canonical current stage plan required')
        self.binding_sha256 = binding_sha256
        self.verify(self.frozen, binding_sha256)

    def verify(self, frozen, binding_sha256):
        if (stage.absolute(frozen) != self.frozen or
                binding_sha256 != self.binding_sha256 or
                stage.read(self.plan_path.parent, self.plan_path.name) != stage.canonical(self.value)):
            raise ValueError('stage path or external binding drift')
        stage.verify(self.value, self.frozen)
        # Compatibility view only. Never create a historical binding.json.
        return {area: {name.split('/', 1)[1]: {key: item[key] for key in ('bytes', 'mode', 'sha256')}
                       for name, item in self.value['entries'].items() if name.startswith(area + '/')}
                for area in ('context', 'support')}

    def read_public(self, path):
        path = stage.absolute(path)
        try:
            name = path.relative_to(self.frozen).as_posix()
        except ValueError:
            raise ValueError('read outside bound stage') from None
        if name not in self.value['entries']:
            raise ValueError('read outside selected public entries')
        item = self.value['entries'][name]
        data = stage.read(self.frozen, name)
        if len(data) != item['bytes'] or stage.sha(data) != item['sha256']:
            raise ValueError('selected public file drift')
        return data

    def image_verifier(self, support):
        if stage.absolute(support) != self.frozen / 'support':
            raise ValueError('wrong support root')
        self.verify(self.frozen, self.binding_sha256)
        verifier = stage._verifier(support)
        original = verifier.build_contract
        def routed(root, *, read_regular=None):
            if stage.absolute(root) != self.frozen / 'context':
                raise ValueError('wrong context root')
            def reader(_root, name):
                # Genuine report never belongs in the image's context snapshot.
                if name == stage.REPORT:
                    return self.read_public(self.frozen / 'support' / name)
                return (read_regular(_root, name) if read_regular is not None else
                        self.read_public(self.frozen / 'context' / name))
            return original(root, read_regular=reader)
        verifier.build_contract = routed
        return verifier


POLICY_SCHEMA = 'issue3-b04-independent-owner-policy-v1'
RELEASE_SCHEMA = 'issue3-b04-independent-engine-release-v1'
SETTLEMENT_SCHEMA = 'issue3-diagnostic-safety-settlement-v1'


def pinned_record(reference):
    """Read an exact public safety record, never infer qualification from its name."""
    import re
    if (not isinstance(reference, dict) or set(reference) != {'path', 'sha256'} or
            not isinstance(reference['path'], str) or
            not reference['path'].startswith('/') or
            not re.fullmatch('[0-9a-f]{64}', reference['sha256'])):
        raise ValueError('invalid safety record reference')
    path = stage.absolute(reference['path'])
    raw = stage.read(path.parent, path.name)
    if stage.sha(raw) != reference['sha256']:
        raise ValueError('safety record pin drift')
    return json.loads(raw)


def owner_policy(attempt, package):
    auth = json.loads(stage.read(attempt, 'authorization.json'))
    policy = pinned_record(auth['owner_policy'])
    expected = dict(schema=POLICY_SCHEMA, explicit_owner_approval=True,
                    independent_of_phaseA=True, crypto_qualified=False,
                    phaseA_upgrade_authorized=False, runtime_authorized=False,
                    max_image_builds=1, no_retry=True,
                    plan_sha256=package.binding_sha256,
                    elf_sha256=stage.B04_SHA256, genuine_report_sha256=stage.REPORT_SHA256,
                    operation_bounds=BOUNDS)
    if (policy != expected or auth.get('binding_sha256') != package.binding_sha256 or
            auth.get('operation_bounds') != BOUNDS or auth.get('no_retry') is not True or
            auth.get('controller_sha256') != stage.sha(stage.read(attempt, 'controller.py'))):
        raise ValueError('explicit independent owner policy/source bindings required')
    return auth


def phase_b_preflight(attempt, package, query):
    """Safety-only release; no A PASS field is accepted or manufactured."""
    import time
    release_raw = stage.read(attempt, 'engine-release.json')
    release = json.loads(release_raw)
    auth = owner_policy(attempt, package)
    keys = {'schema', 'phase', 'engine_exclusive', 'max_image_builds', 'plan_sha256',
            'owner_policy_sha256', 'authorization_sha256', 'diagnostic_settlement',
            'crypto_qualified', 'expires_unix'}
    now = time.time()
    if (set(release) != keys or release['schema'] != RELEASE_SCHEMA or
            release['crypto_qualified'] is not False or release['engine_exclusive'] is not True or
            release['phase'] != 'B' or type(release['max_image_builds']) is not int or
            release['max_image_builds'] != 1 or release['plan_sha256'] != package.binding_sha256 or
            release['owner_policy_sha256'] != auth['owner_policy']['sha256'] or
            release['authorization_sha256'] != stage.sha(stage.read(attempt, 'authorization.json')) or
            type(release['expires_unix']) is not int or not now < release['expires_unix'] <= now + 3600):
        raise ValueError('independent phase B safety release invalid; no A qualification accepted')
    settled = pinned_record(release['diagnostic_settlement'])
    if (set(settled) != {'schema', 'diagnostic_result', 'diagnostic_complete',
                         'client_reaped', 'engine_active_ids', 'stopped_container_ids',
                         'crypto_qualified'} or settled['schema'] != SETTLEMENT_SCHEMA or
            settled['diagnostic_complete'] is not True or settled['client_reaped'] is not True or
            settled['crypto_qualified'] is not False or settled['engine_active_ids'] != [] or
            not isinstance(settled['stopped_container_ids'], list) or
            not settled['stopped_container_ids']):
        raise ValueError('actual diagnostic settlement/safety required')
    # Preserve the actual result (including failed diagnostics); no PASS translation.
    pinned_record(settled['diagnostic_result'])
    package.verify(package.frozen, package.binding_sha256)
    import re
    for identity in settled['stopped_container_ids']:
        if not isinstance(identity, str) or not re.fullmatch('[0-9a-f]{64}', identity):
            raise ValueError('exact diagnostic container identity required')
        state = json.loads(query(['container', 'inspect', '--format',
                                  '{"id":{{json .Id}},"running":{{.State.Running}},"pid":{{.State.Pid}}}', identity]))
        if state != dict(id=identity, running=False, pid=0):
            raise ValueError('diagnostic engine settlement unsafe')
    if query(['ps', '-q', '--no-trunc']).strip():
        raise ValueError('concurrent engine activity refused')
    builder_state(query, require_stopped=True)
    if (stage.read(attempt, 'engine-release.json') != release_raw or
            owner_policy(attempt, package) != auth):
        raise ValueError('phase release/owner policy changed during admission')


BUILDER_FORMAT = ('{"id":{{json .Id}},"image":{{json .Image}},"memory":{{.HostConfig.Memory}},'
                  '"swap":{{.HostConfig.MemorySwap}},"quota":{{.HostConfig.CpuQuota}},'
                  '"period":{{.HostConfig.CpuPeriod}},"cpuset":{{json .HostConfig.CpusetCpus}},'
                  '"running":{{.State.Running}},"pid":{{.State.Pid}}}')
BUILDER_ID = '8c1e55a9cdd2c77c443a75c82c5939e8cc0c1e237bf6208f71108e00d53bf519'


def builder_state(query, require_stopped=False):
    value = json.loads(query(['container', 'inspect', '--format', BUILDER_FORMAT, BUILDER_ID]))
    expected = dict(id=BUILDER_ID,
                    image='sha256:f27f9c00a3aca2c219642d1500610eade3ddcb6b873ea8847852ab156663d32f',
                    memory=BOUNDS['memory_bytes'], swap=BOUNDS['swap_total_bytes'],
                    quota=BOUNDS['cpu_quota'], period=BOUNDS['cpu_period'], cpuset=BOUNDS['cpuset'])
    if (any(value.get(k) != v for k, v in expected.items()) or
            (require_stopped and (value.get('running') is not False or value.get('pid') != 0))):
        raise ValueError('retained bounded builder identity/control/state mismatch')
    return value


def settle_builder(query):
    if builder_state(query)['running']:
        query(['container', 'stop', '--time', '20', BUILDER_ID])
    builder_state(query, require_stopped=True)


def validate_apks(packages):
    found = {p['name']: p['version'] for p in packages}
    required = dict(python3='3.14.8-r0', zlib='1.3.2-r1', openssl='3.5.9-r0', nginx='1.30.6-r0')
    if any(found.get(name) != version for name, version in required.items()):
        raise ValueError('installed runtime APK pin mismatch')


def render_controller(plan, frozen, binding_sha256):
    """Adapt only the reviewed historical controller's selector/loader seams."""
    import ast
    PackageStage(plan, frozen, binding_sha256)
    root = stage.ROOT
    name = 'tools/issue3_fresh_attempt/historical/package.py.txt'
    raw = stage.read(root, name)
    if stage.sha(raw) != 'fac8eabf2d8c17a723763cf4ed03801d766420e4a1e8f350723dde0da82aba83':
        raise ValueError('historical package controller source drift')
    text = raw.decode()
    def replace(old, new):
        nonlocal text
        if text.count(old) != 1:
            raise ValueError('historical adapter seam drift')
        text = text.replace(old, new)
    def function(name, body):
        node = next(n for n in ast.parse(text).body if isinstance(n, ast.FunctionDef) and n.name == name)
        replace('\n'.join(text.splitlines()[node.lineno - 1:node.end_lineno]), body.rstrip())
    replace("FROZEN = ROOT / 'build_issue3_amd64_curl_package_02'", 'FROZEN = Path(' + repr(str(stage.absolute(frozen))) + ')')
    replace("TAG = 'uvm-issue3-openssl3:amd64-curl-package-01'", 'TAG = execution.TAG')
    replace("BINDING = AUTHORIZATION['binding_sha256']", 'BINDING = ' + repr(binding_sha256))
    replace('BUDGET, RESERVE, TIMEOUT = 2 * 1024**3, 16 * 1024**3, 1200',
            'BUDGET, RESERVE, TIMEOUT = 2 * 1024**3, 11 * 1024**3, 1200')
    function('build_command', 'def build_command():\n    return execution.build_command(FROZEN, ATTEMPT)\n')
    function('load_package', 'def load_package():\n    return execution.PackageStage(Path(' + repr(str(stage.absolute(plan))) + '), FROZEN, BINDING)\n')
    replace('    package = load_package()\n    before = resources()',
            '    package = load_package()\n    execution.phase_b_preflight(ATTEMPT, package, query)\n    before = resources()')
    replace('STOP = False', 'STOP = False\nDEADLINE = float("inf")')
    replace('    global STOP\n    # The Docker-save', '    global STOP, DEADLINE\n    # The Docker-save')
    replace('    started = time.monotonic()', '    started = time.monotonic()\n    DEADLINE = started + TIMEOUT')
    function('query', '''def query(args):
    remaining = DEADLINE - time.monotonic()
    if remaining <= 0:
        raise ValueError('package outer deadline exhausted')
    ceiling = 25 if args[:2] == ['container', 'stop'] else execution.BOUNDS['metadata_seconds']
    response = subprocess.run(DOCKER + args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              text=True, timeout=min(ceiling, remaining), check=True)
    if len(response.stdout) > 1024**2:
        raise ValueError('selected metadata bound')
    return response.stdout.strip()
''')
    replace("    parser = verifier.load_parser()\n    parser.inventory_stream", "    if time.monotonic() + 210 > DEADLINE - 150:\n        raise ValueError('insufficient shared deadline for readback and settlement')\n    parser = verifier.load_parser()\n    parser.inventory_stream")
    replace('elapsed > TIMEOUT - 150', 'elapsed > execution.BOUNDS["build_stop_seconds"]')
    replace('            after = resources()', '            execution.settle_builder(query)\n            after = resources()')
    replace("    verifier.publish(result, ATTEMPT / 'image-verification')",
            "    execution.validate_apks(result['packages'])\n    verifier.publish(result, ATTEMPT / 'image-verification')")
    replace("'approved_by': 'owner combined AMD64 local package authorization; renewed continue'",
            "'approved_by': AUTHORIZATION['owner_grant']")
    replace("    save('spent.json',", "    execution.phase_b_preflight(ATTEMPT, package, query)\n    save('spent.json',")
    replace("    result = {'status': 'BUILD_PENDING',", "    result = {'crypto_qualified': False, 'phaseA_upgrade_authorized': False, 'status': 'BUILD_PENDING',")
    replace("                       'retry_authorized': False})",
            "                       'crypto_qualified': False, 'owner_policy': AUTHORIZATION['owner_policy'],\n                       'engine_release_sha256': hashlib.sha256((ATTEMPT / 'engine-release.json').read_bytes()).hexdigest(),\n                       'retry_authorized': False})")
    # Authenticate both bridge and stager before importing either. Root isn't a context.
    pins = {str(root / n): stage.sha(stage.read(root, n)) for n in
            ('tools/issue3_fresh_attempt/b04_package_execution.py', 'tools/issue3_fresh_attempt/b04_package_stage.py')}
    prefix = ('import hashlib, pathlib, sys\n'
              'sys.dont_write_bytecode = True\n'
              'for name, pin in ' + repr(pins) + '.items():\n'
              '    if hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest() != pin:\n'
              '        raise SystemExit("REFUSED: pinned execution adapter drift")\n'
              'sys.path.insert(0, ' + repr(str(root)) + ')\n'
              'from tools.issue3_fresh_attempt import b04_package_execution as execution\n')
    return prefix + text
