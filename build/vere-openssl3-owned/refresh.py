"""Deterministically refresh this NEW recipe; never edits its baseline.

Run from any cwd:
 python3 build/vere-openssl3-owned/refresh.py --repo /absolute/repository
Copied peer helpers retain tools/<sibling>/ layout. Re-run after the parent
changes integration, shutdown or arena C/pins. This does not build anything.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

BASELINE = ('candidate.py', 'inputs.json', 'Dockerfile', '.dockerignore',
    'builder-apks.json', 'curl-build.zig', 'curl-build.zig.zon', 'sha-stack.c',
    'h2o-socket.c', 'h2o-socket-publication-staged.c', 'verify_binary.py',
    'retain_link_inputs.py', 'source_companion.py', 'package_image.py')
PEERS = ('issue3_openssl_integration', 'issue3_openssl_shutdown', 'issue3_openssl_owned_arena',
         'issue3_arena_measurement')


def replace(text, old, new):
    if text.count(old) != 1:
        raise ValueError('baseline derivation context mismatch: ' + old[:100])
    return text.replace(old, new, 1)


def candidate(text):
    text = replace(text, 'HERE = Path(__file__).resolve().parent', '''HERE = Path(__file__).resolve().parent
import importlib.util as _owned_import
_owned_spec = _owned_import.spec_from_file_location('owned_build_support', HERE / 'owned_support.py')
assert _owned_spec is not None and _owned_spec.loader is not None
owned = _owned_import.module_from_spec(_owned_spec)
_owned_spec.loader.exec_module(owned)''')
    text = replace(text, 'def prepare(attempt, lock, input_dir):\n    trees = {}',
        '''def prepare(attempt, lock, input_dir, *, arena_bytes):
    owned.capacity(arena_bytes)
    owned.validate_recipe(HERE)
    trees = {}''')
    text = replace(text, "    attempt.current = 'source-preparation'\n    attempt.event('passed', compiled=False, vere_executed=False)",
        "    owned.complete_preparation(HERE, source, attempt.output, arena_bytes=arena_bytes)\n"
        "    attempt.current = 'source-preparation'\n    attempt.event('passed', compiled=False, vere_executed=False)")
    text = replace(text, '    cache_digest = None\n',
        '    cache_binding.update(owned.build_bindings(attempt.output))\n    cache_digest = None\n')
    text = replace(text, "    receipt = dict(candidate=lock['candidate'], executable_sha256=sha(data),",
        "    owned_overlay = json.loads((attempt.output / 'owned-overlay.json').read_text())\n"
        "    final_changes = owned.final_source_changes(source, changed, owned_overlay)\n"
        "    receipt = dict(candidate=lock['candidate'] + '-owned-palloc', executable_sha256=sha(data),")
    text = replace(text, 'source_changes={name: sha((source / name).read_bytes()) for name in changed},',
        'source_changes=final_changes, **owned.build_bindings(attempt.output),')
    text = replace(text, '    # Preserve exact archives, patched source, generated headers/configuration,',
        '    owned.copy_delivery(attempt.output, delivery, guard)\n\n'
        '    owned.retain_public_libraries(source, openssl, attempt.output, delivery, guard)\n\n'
        '    # Preserve exact archives, patched source, generated headers/configuration,')
    text = replace(text, "    parser.add_argument('--output', type=Path, required=True)",
        "    parser.add_argument('--arena-bytes', type=int, required=True,\n"
        "                        help='explicit page-aligned reservation; no production default')\n"
        "    parser.add_argument('--output', type=Path, required=True)")
    text = replace(text, "    lock = json.loads((HERE / 'inputs.json').read_text())\n    attempt = Attempt(args.output.resolve())",
        "    owned.capacity(args.arena_bytes)\n    owned.validate_recipe(HERE)\n"
        "    lock = json.loads((HERE / 'inputs.json').read_text())\n    attempt = Attempt(args.output.resolve())")
    text = replace(text, 'trees = prepare(attempt, lock, args.input_dir)',
                   'trees = prepare(attempt, lock, args.input_dir, arena_bytes=args.arena_bytes)')
    text = replace(text, 'def image_build_command(context, export, attempt_id):',
                   'def image_build_command(context, export, attempt_id, *, arena_bytes=None):')
    text = replace(text, "    return ['docker', 'buildx', 'build', '--platform=linux/amd64', '--progress=plain',",
                   "    owned.capacity(arena_bytes)\n"
                   "    return ['docker', 'buildx', 'build', '--platform=linux/amd64', '--progress=plain',")
    text = replace(text, "            '--target=evidence', '--build-arg', 'UVM_BUILD_ATTEMPT_ID=' + attempt_id,",
                   "            '--target=evidence', '--build-arg', 'UVM_OPENSSL_ARENA_BYTES=' + str(arena_bytes),\n"
                   "            '--build-arg', 'UVM_BUILD_ATTEMPT_ID=' + attempt_id,")
    return text


def dockerfile(text):
    text = replace(text, 'WORKDIR /recipe', 'ARG UVM_OPENSSL_ARENA_BYTES\nWORKDIR /recipe')
    text = replace(text, 'COPY inputs.json candidate.py builder-apks.json Dockerfile ./',
        'COPY inputs.json candidate.py builder-apks.json Dockerfile ./\n'
        'COPY owned_support.py owned-recipe.json refresh.py verify_binary.py ./\n'
        'COPY .dockerignore source_companion.py retain_link_inputs.py package_image.py ./\n'
        'COPY h2o-socket-publication-staged.c ./\n'
        'COPY baseline/ ./baseline/\nCOPY tools/ ./tools/')
    text = replace(text, 'RUN python3 candidate.py --openssl-only --output /work/openssl-cache',
        'RUN test -n "$UVM_OPENSSL_ARENA_BYTES" && \\\n'
        '    python3 candidate.py --openssl-only --arena-bytes "$UVM_OPENSSL_ARENA_BYTES" --output /work/openssl-cache')
    text = replace(text, 'FROM openssl AS builder', 'FROM openssl AS builder\nARG UVM_OPENSSL_ARENA_BYTES')
    text = replace(text, '    python3 candidate.py --build --output /work/attempt \\',
        '    python3 candidate.py --build --arena-bytes "$UVM_OPENSSL_ARENA_BYTES" --output /work/attempt \\')
    return text


def refresh(repo):
    repo = Path(repo).resolve()
    baseline, target = repo / 'build/vere-openssl3', Path(__file__).resolve().parent
    if target == baseline.resolve():
        raise ValueError('refuse baseline overwrite')
    baseline_files, helper_files = [], []
    for name in BASELINE:
        path = baseline / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('baseline input absent/nonregular: ' + name)
        destination = target / 'baseline' / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
        baseline_files.append('baseline/' + name)
        if name not in ('candidate.py', 'Dockerfile', '.dockerignore', 'verify_binary.py'):
            shutil.copyfile(path, target / name)
    for peer in PEERS:
        original = repo / 'tools' / peer
        paths = sorted(p for p in original.rglob('*') if p.is_file() and '__pycache__' not in p.parts)
        if not paths:
            raise ValueError('missing helper: ' + peer)
        for path in paths:
            if path.is_symlink() or path.suffix not in ('.py', '.c', '.h', '.inc', '.json', '.pinned', '.patch'):
                raise ValueError('unapproved helper input: ' + str(path))
            relative = 'tools/' + peer + '/' + str(path.relative_to(original))
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)
            helper_files.append(relative)
    # Remove only obsolete copied helper files, never user/source baseline work.
    for peer in PEERS:
        for path in sorted((target / 'tools' / peer).rglob('*')):
            if path.is_file() and '__pycache__' not in path.parts and str(path.relative_to(target)) not in helper_files:
                path.unlink()
    (target / 'candidate.py').write_text(candidate((baseline / 'candidate.py').read_text()))
    (target / 'Dockerfile').write_text(dockerfile((baseline / 'Dockerfile').read_text()))
    names = sorted(set(BASELINE) | {'owned_support.py', 'owned-recipe.json', 'refresh.py'})
    context_files = sorted(set(names + baseline_files + helper_files))
    context_dirs = sorted({str(parent) for name in context_files
                           for parent in Path(name).parents if str(parent) != '.'},
                          key=lambda name: (len(Path(name).parts), name))
    (target / '.dockerignore').write_text('**\n' +
        ''.join('!' + name + '/\n' for name in context_dirs) +
        ''.join('!' + name + '\n' for name in context_files))
    files = baseline_files + helper_files + names
    files.remove('owned-recipe.json')
    hashes = {name: hashlib.sha256((target / name).read_bytes()).hexdigest() for name in sorted(set(files))}
    result = dict(schema_version=1, files=hashes,
                  baseline_files=sorted(baseline_files), helper_files=sorted(helper_files),
                  derivation='exact baseline snapshots + refresh.py deterministic transformations',
                  arena_capacity='explicit build argument; no production default')
    (target / 'owned-recipe.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    args = parser.parse_args()
    manifest = refresh(args.repo)
    print(json.dumps(dict(files=len(manifest['files']), helper_files=len(manifest['helper_files']),
                         baseline_files=len(manifest['baseline_files']), build_executed=False), sort_keys=True))
