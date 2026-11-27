#!/usr/bin/env python3
"""Materialize NEW successors; never import or execute historical controllers."""
import argparse
import ast
import hashlib
import json
from pathlib import Path

SOURCES = {
    'build': ('build_issue3_amd64_curl_build_02/run_build.py', 'b7e622a9855a8049f1e6cd00b1d6ab2815fcc3f4e55ab6ce9878b969722753dc'),
    'report': ('build_issue3_amd64_curl_report_01/run_report.py', '3fc80797a9aca93f6a6a3601e7e62fcff8ab70dcf003cef08126f55a61aeb4fc'),
    'package': ('build_issue3_amd64_curl_package_build_01/run_build.py', 'fac8eabf2d8c17a723763cf4ed03801d766420e4a1e8f350723dde0da82aba83'),
    'lifecycle': ('build_issue3_amd64_curl_lifecycle_01/run_lifecycle.py', '6cd5c32d16bbdd3b5077285464bc72aa6bed8f29c32dc793883625648a142123'),
    'base': ('build_issue3_amd64_curl_lifecycle_01/base.py', 'd4f0e123d3e87eb39ba0fdda3ed558d6ef6a3921cf10f47c6ddd56d8c6bcc3a6'),
    'guest': ('build_issue3_amd64_curl_lifecycle_01/lifecycle_guest.py', 'd101815557f322796592b680609fda088ef45f3caa48c6e810bb99ae4115b81a'),
}
STAGES = ('build', 'report', 'package', 'lifecycle')


def template(stage):
    gib = 1024**3
    floor, growth, timeout = {
        'build': (10*gib, 8*gib, 2400),
        'report': (16*gib, 128*1024**2, 30),
        'package': (16*gib, 2*gib, 1200),
        'lifecycle': (16*gib, 7*gib, 1600),
    }[stage]
    return dict(schema=1, state='UNBOUND', stage=stage, attempt_id=None,
                artifacts=dict(image=None, executable_sha256=None, executable_size=None,
                               adapter_sha256=None, adapter_size=None),
                inputs={}, predecessors=[], recipe_dir=None, package_dir=None,
                docker_context='desktop-linux', docker_host='unix:///var/run/docker.sock',
                bind_prefix='/host_mnt', scratch='/tmp',
                budget=dict(floor_bytes=floor, growth_bytes=growth, admission_bytes=floor+growth,
                            scratch_bytes=10*gib, timeout_seconds=timeout),
                failure_model='UNBOUND')


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('template anchor drift: ' + old[:80])
    return text.replace(old, new)


def assignments(text, changes):
    tree = ast.parse(text)
    lines = text.splitlines(keepends=True)
    edits = []
    found = set()
    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            edits.append((node.lineno-1, node.end_lineno, '# Prepared successor; historical controller is immutable.\n'))
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            key = node.targets[0].id
            if key in changes:
                found.add(key)
                edits.append((node.lineno-1, node.end_lineno, key + ' = ' + changes[key] + '\n'))
    if found != set(changes):
        raise ValueError('assignment anchors drift: ' + str(set(changes)-found))
    for start, end, value in sorted(edits, reverse=True):
        lines[start:end] = [value]
    return ''.join(lines)


def render(stage, text, config):
    a = "CONFIG['artifacts']"
    inputs = "CONFIG['inputs']"
    changes = {}
    if stage in STAGES:
        changes['DOCKER' if stage != 'lifecycle' else 'SCRATCH'] = (
            "['docker', '--context', CONFIG['docker_context']]" if stage != 'lifecycle' else "Path(CONFIG['scratch'])")
    if stage == 'build':
        changes.update(ATTEMPT='Path(__file__).resolve().parent', ROOT="Path(CONFIG['recipe_dir'])")
        text = replace_once(text, "approval.get('scope') != 'one AMD64 allocator-corrected OpenSSL 3.5.9 curl 8.23.0 candidate build only'", "approval.get('scope') != CONFIG['attempt_id']")
        text = replace_once(text, "recipe.image_build_command(ROOT, ATTEMPT / 'artifact', ATTEMPT.name)", "recipe.image_build_command(ROOT, ATTEMPT / 'artifact', CONFIG['attempt_id'])")
        text = replace_once(text, "        (ATTEMPT / 'result.json').write_text", "        result.update(attempt_id=CONFIG['attempt_id'], stage='build')\n        (ATTEMPT / 'result.json').write_text")
    elif stage == 'report':
        changes.update(BINARY=f"Path({inputs}['binary']['path'])", EXPECTED=f"{a}['executable_sha256']", IMAGE=f"{a}['image']", name="CONFIG['attempt_id']", authority="CONFIG['_authorization']")
        text = replace_once(text, "assert authority['owner_grant'] == 'fresh combined AMD64 build and exact-binary report authorized by owner'", "assert authority['authorized'] is True")
        text = replace_once(text, "save('spent.json',", "CONFIG = preflight(__file__, 'report')\nsave('spent.json',")
        text = replace_once(text, "'org.uvm.issue3=amd64-curl-report-01'", "'org.uvm.issue3=' + CONFIG['attempt_id']")
        text = text.replace("'amd64-curl-report-01'", "CONFIG['attempt_id']")
        text = text.replace("'/issue3-amd64-curl-report-01'", "'/' + CONFIG['attempt_id']")
        changes['FORMAT'] = repr('{"id":{{json .Id}},"image":{{json .Image}},"name":{{json .Name}},"label":{{json (index .Config.Labels "org.uvm.issue3")}},"pid":{{json .State.Pid}},"status":{{json .State.Status}},"running":{{json .State.Running}},"exit_code":{{json .State.ExitCode}},"oom_killed":{{json .State.OOMKilled}}}')
        text = replace_once(text,
            "    return json.loads(subprocess.check_output(DOCKER + ['inspect', '--format', FORMAT, CONTAINER],\n                                             text=True, timeout=10))",
            "    observed = json.loads(subprocess.check_output(DOCKER + ['inspect', '--format', FORMAT, CONTAINER], text=True, timeout=10))\n"
            "    if (observed.get('id') != CONTAINER or observed.get('image') != IMAGE or\n"
            "            observed.get('name') != '/' + CONFIG['attempt_id'] or observed.get('label') != CONFIG['attempt_id'] or\n"
            "            type(observed.get('pid')) is not int):\n"
            "        raise ValueError('owned report identity mismatch; manual recovery required')\n"
            "    return observed")
        text = replace_once(text, "observed['status'] == 'exited' and not observed['running'] and", "observed['status'] == 'exited' and observed['pid'] == 0 and not observed['running'] and")
        tree = ast.parse(text)
        block = next(n for n in tree.body if isinstance(n, ast.Try))
        lines = text.splitlines(keepends=True)
        start, end = block.body[0].lineno - 1, block.body[-1].end_lineno
        lines[start:end] = [
            "    from supervision import capture\n"
            "    from gate import capacity as check_capacity\n"
            "    initial_free = check_capacity(CONFIG)\n"
            "    with (ROOT / 'public-report.log').open('xb') as log:\n"
            "        process = capture(DOCKER + ['start', '--attach', CONTAINER], log,\n"
            "                          lambda: stop_requested, lambda: check_capacity(CONFIG, initial_free))\n"]
        text = ''.join(lines)
        text = replace_once(text, "'images': ['image', 'ls', '-aq', '--no-trunc']", "'images': ['image', 'ls', '-aq', '--no-trunc'],\n        'networks': ['network', 'ls', '--no-trunc', '--format={{.ID}}'],\n        'tags': ['image', 'ls', '-a', '--no-trunc', '--format={{.Repository}}:{{.Tag}} {{.ID}}']")
        text = replace_once(text, "assert all(set(v) <= set(after_inventory[k]) for k, v in before_inventory.items())", "from gate import settled_inventory\n    settled_inventory(before_inventory, after_inventory, {'containers': [CONTAINER]})")
        text = replace_once(text, "    (ROOT / 'result.json').write_text", "    result.update(attempt_id=CONFIG['attempt_id'], stage='report', preserved=True, active_after=[])\n    (ROOT / 'result.json').write_text")
        text = 'from supervision import output as bounded_output\n' + text.replace('subprocess.check_output(', 'bounded_output(')
    elif stage == 'package':
        changes.update(FROZEN="Path(CONFIG['package_dir'])", TAG="'uvm-issue3-openssl3:' + CONFIG['attempt_id']")
        text = replace_once(text, "'owner combined AMD64 local package authorization; renewed continue'", "AUTHORIZATION['owner_grant']")
        text = replace_once(text, "        save('result.json', result)", "        result.update(attempt_id=CONFIG['attempt_id'], stage='package')\n        save('result.json', result)")
    elif stage == 'lifecycle':
        changes.update(BINDING_STATE="CONFIG['state']", IMAGE=f"{a}['image']",
                       PILL=f"Path({inputs}['pill']['path'])", BINDING=f"{inputs}['binding']['sha256']",
                       BINDING_PATH=f"Path({inputs}['binding']['path'])", RECEIPT_PATH=f"Path({inputs}['receipt']['path'])",
                       RECEIPT_SHA=f"{inputs}['receipt']['sha256']", EXECUTABLE_SHA=f"{a}['executable_sha256']",
                       EXECUTABLE_SIZE=f"{a}['executable_size']", ADAPTER_SHA=f"{a}['adapter_sha256']", ADAPTER_SIZE=f"{a}['adapter_size']")
        text = replace_once(text, "    base.durable(str(TASK / 'spent.json'),", "    preflight(__file__, 'lifecycle')\n    base.durable(str(TASK / 'spent.json'),")
        text = replace_once(text, "(21 if initial is None else 16) * GIB", "(CONFIG['budget']['admission_bytes'] if initial is None else CONFIG['budget']['floor_bytes'])")
        text = replace_once(text, "initial - free <= 7 * GIB", "initial - free <= CONFIG['budget']['growth_bytes']")
        text = replace_once(text, "('base.py', 'lifecycle_guest.py', 'run_lifecycle.py', 'test_lifecycle.py')", "('base.py', 'lifecycle_guest.py', 'run_lifecycle.py', 'gate.py', 'config.json')")
        text = replace_once(text, "bind_prefix='/host_mnt', docker_host='unix:///var/run/docker.sock'", "bind_prefix=CONFIG['bind_prefix'], docker_host=CONFIG['docker_host']")
    elif stage == 'guest':
        changes.update(BINDING_STATE=repr(config['state']), EXECUTABLE_SIZE=repr(config['artifacts']['executable_size']),
                       EXECUTABLE_SHA=repr(config['artifacts']['executable_sha256']), ADAPTER_SIZE=repr(config['artifacts']['adapter_size']),
                       ADAPTER_SHA=repr(config['artifacts']['adapter_sha256']))
        pill = config['inputs'].get('pill', {})
        text = replace_once(text, "217421172, 'f8b08c53dd6d0aa9c4f7654f0a7bcd11e94089222888a3c99c0a10eedcbb377b'", repr(pill.get('size')) + ', ' + repr(pill.get('sha256')))
    elif stage == 'base':
        pill = config['inputs'].get('pill', {})
        changes.update(PILL_SIZE=repr(pill.get('size')), PILL_SHA=repr(pill.get('sha256')))
        text = replace_once(text, 'require(free >= 16 * GIB)  # floor8 + growth4 + reserve1 + VM external allowance3',
                            'require(free >= ((16 + 7) if initial is None else 16) * GIB)  # admission = floor + growth')
    text = assignments(text, changes)
    if stage in STAGES:
        text = 'from gate import preflight\nCONFIG = preflight(__file__, ' + repr(stage) + ')\n' + text
    compile(text, '<fresh-' + stage + '>', 'exec')
    return text


def prepare(repo, destination, configurations=None):
    import importlib.util
    spec = importlib.util.spec_from_file_location('fresh_preparation_gate', Path(__file__).with_name('gate.py'))
    assert spec and spec.loader
    validator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validator)
    sources = {}
    for key, (name, digest) in SOURCES.items():
        # A hash mismatch after an unchecked read cannot protect private targets.
        # Portable, byte-identical public fixtures, not ignored historical roots.
        raw = validator.read_public(str(Path(repo) / 'tools/issue3_fresh_attempt/historical' / (key + '.py.txt')))
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('historical public source drift: ' + key)
        sources[key] = raw.decode()
    configurations = configurations or {s: template(s) for s in STAGES}
    if set(configurations) != set(STAGES):
        raise ValueError('exactly four stage configurations required')
    for stage, config in configurations.items():
        if config.get('state') == 'BOUND':
            validator.validate_bindings(config, stage)
        elif config != template(stage):
            raise ValueError('UNBOUND configuration must be the unchanged template')
    destination = Path(destination)
    if not destination.is_absolute() or '..' in destination.parts:
        raise ValueError('absolute fresh destination required')
    validator.safe(str(destination.parent), True)
    rendered = {s: render(s, sources[s], configurations[s]) for s in STAGES}
    destination.mkdir(mode=0o700)
    gate = Path(__file__).with_name('gate.py').read_text()
    for stage in STAGES:
        folder = destination / stage
        folder.mkdir(mode=0o700)
        script = Path(SOURCES[stage][0]).name
        config = configurations[stage] if configurations else template(stage)
        (folder / 'gate.py').write_text(gate)
        (folder / 'config.json').write_text(json.dumps(config, indent=2) + '\n')
        (folder / script).write_text(rendered[stage])
        if stage == 'report':
            (folder / 'supervision.py').write_text(Path(__file__).with_name('supervision.py').read_text())
        if stage == 'lifecycle':
            for key, filename in [('base', 'base.py'), ('guest', 'lifecycle_guest.py')]:
                (folder / filename).write_text(render(key, sources[key], config))
        manifest = dict(schema=1, task=str(folder.absolute()), stage=stage,
                        files={p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in folder.iterdir() if p.is_file()})
        (folder / 'bundle.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
    return destination


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--configurations', type=Path,
                        help='reviewed four-stage JSON; never an authorization file')
    args = parser.parse_args()
    configurations = None
    if args.configurations:
        # The validated configurations select public artifacts only.
        from gate import read_public, strict
        configurations = strict(read_public(str(args.configurations.absolute())))
    print(prepare(args.repo, args.destination, configurations))
