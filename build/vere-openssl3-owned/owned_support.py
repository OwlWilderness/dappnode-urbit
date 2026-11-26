"""Build-only owned recipe bindings; no library build or target execution.

Baseline receipts describe hardened intermediate bytes. owned-overlay.json is
always the FINAL map, independently reproducible from pinned public preimages.
"""
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import shutil
import tempfile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def regular(root, name):
    relative = PurePosixPath(name)
    path = Path(root) / name
    if (relative.is_absolute() or '..' in relative.parts or not relative.parts or
            path.resolve() != path.absolute() or not path.is_file()):
        raise ValueError('missing/nonregular recipe input: ' + name)
    return path


def validate_recipe(root):
    root = Path(root).absolute()
    manifest = json.loads(regular(root, 'owned-recipe.json').read_text())
    if manifest.get('schema_version') != 1 or not manifest.get('files'):
        raise ValueError('owned recipe manifest missing files/schema')
    for name, digest in manifest['files'].items():
        if sha(regular(root, name).read_bytes()) != digest:
            raise ValueError('owned recipe input hash mismatch: ' + name)
    for group in ('baseline_files', 'helper_files'):
        if not manifest.get(group) or not set(manifest[group]) <= set(manifest['files']):
            raise ValueError('owned recipe manifest missing ' + group)
    return manifest


def integration(root):
    validate_recipe(root)  # before importing any copied helper
    path = Path(root) / 'tools/issue3_openssl_integration/overlay.py'
    spec = importlib.util.spec_from_file_location('frozen_owned_integration', path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def capacity(value):
    if type(value) is not int or not 131072 <= value <= 4294950912 or value % 16384:
        raise ValueError('explicit arena capacity must be 16384-page aligned in [131072,4294950912]')
    return value


def input_names(module):
    return sorted(set(module.load_shutdown().PINS['hardened_preimages']) |
                  {'pkg/noun/manage.c', 'ext/h2o/socket.c', *module.GRAPH_PINS})


def replay_expected(root, preimages_file, arena_bytes):
    module = integration(root)
    capacity(arena_bytes)
    sources = json.loads(Path(preimages_file).read_text())
    if set(sources) != set(input_names(module)):
        raise ValueError('owned preimage inventory mismatch')
    # The helper binds hardened preimages, H2O and graph before applying. Only
    # selected public files are staged, never source archives or dependencies.
    with tempfile.TemporaryDirectory(prefix='owned-static-replay-') as temporary:
        tree = Path(temporary).resolve()
        for name, text in sources.items():
            path = tree / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        return module.apply(tree, arena_bytes=arena_bytes)


def freeze(root, output):
    root, output = Path(root), Path(output)
    manifest = validate_recipe(root)
    for name in [*manifest['files'], 'owned-recipe.json']:
        destination = output / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / name, destination)
    return manifest


def complete_preparation(root, source, output, *, arena_bytes):
    """Tail of baseline prepare: hardening first, owned composition second."""
    capacity(arena_bytes)
    root, source, output = Path(root), Path(source), Path(output)
    module = integration(root)
    preimages = {name: regular(source, name).read_text() for name in input_names(module)}
    changes = module.apply(source, arena_bytes=arena_bytes)
    baseline = {}
    for name in ('h2o', 'sha', 'allocation', 'curl', 'ca'):
        path = output / (name + '-overlay.json')
        if path.exists():
            final = output / ('baseline-' + path.name)
            path.rename(final)
            baseline[final.name] = sha(final.read_bytes())
    freeze(root, output)
    # freeze copies the baseline H2O payload. Delivery must contain FINAL bytes.
    (output / 'h2o-socket.c').write_bytes((source / 'ext/h2o/socket.c').read_bytes())
    (output / 'owned-preimages.json').write_bytes(json_bytes(preimages))
    receipt = dict(schema_version=1, strategy='process-owned-palloc-adaptation',
        arena_bytes=arena_bytes, source_changes=changes,
        preimages_sha256=sha((output / 'owned-preimages.json').read_bytes()),
        recipe_manifest_sha256=sha((root / 'owned-recipe.json').read_bytes()),
        baseline_intermediate_receipts=baseline,
        baseline_receipts_scope='intermediate-hardening-only-not-final-source',
        vere_executed=False)
    (output / 'owned-overlay.json').write_bytes(json_bytes(receipt))
    (output / 'h2o-overlay.json').write_bytes(json_bytes(dict(
        scope='final-owned', source_changes={n: sha(regular(source, n).read_bytes()) for n in
            ('ext/h2o/build.zig', 'ext/h2o/build.zig.zon', 'ext/h2o/socket.c')},
        socket_sha256=changes['ext/h2o/socket.c'])))
    return receipt


def build_bindings(output):
    output = Path(output)
    overlay = json.loads((output / 'owned-overlay.json').read_text())
    return dict(owned_recipe_manifest_sha256=sha((output / 'owned-recipe.json').read_bytes()),
                owned_arena_bytes=capacity(overlay['arena_bytes']),
                owned_overlay_sha256=sha((output / 'owned-overlay.json').read_bytes()),
                owned_preimages_sha256=sha((output / 'owned-preimages.json').read_bytes()))


def final_source_changes(source, baseline_names, overlay):
    names = sorted(set(baseline_names) | set(overlay['source_changes']))
    changes = {name: sha(regular(source, name).read_bytes()) for name in names}
    if any(changes.get(n) != h for n, h in overlay['source_changes'].items()):
        raise ValueError('owned source receipt mismatch before compilation delivery')
    return changes


def copy_delivery(output, delivery, guard):
    output, delivery = Path(output), Path(delivery)
    manifest = json.loads((output / 'owned-recipe.json').read_text())
    for name in manifest['files']:
        if '/' in name:
            destination = delivery / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            guard.copy_file(output / name, destination)


def retain_public_libraries(source, openssl, output, delivery, guard):
    """Positive public archive/config retention, NOT authenticated link capture.

    Headers/adapters/source remain in source-materials.tar.gz. Retain original
    OpenSSL archives/config plus compiler-emitted static archives; bounded to
    512 MiB total and 256 files. No objects, arbitrary logs or whole cache copy.
    """
    source, openssl, output, delivery = map(Path, (source, openssl, output, delivery))
    selected = []
    for name in ('libcrypto.a', 'libssl.a', 'configdata.pm'):
        path = regular(openssl, name)
        selected.append((path, 'public-libraries/openssl/' + name))
    for cache in (output / 'zig-local-cache', output / 'zig-cache'):
        if cache.is_dir():
            for path in sorted(cache.rglob('*.a')):
                relative = str(path.relative_to(cache))
                regular(cache, relative)
                selected.append((path, 'public-libraries/' + cache.name + '/' + relative))
    if len(selected) > 256 or sum(p.stat().st_size for p, _ in selected) > 512*1024**2:
        raise ValueError('public library retention bound exceeded')
    files = {}
    for path, name in selected:
        destination = delivery / name
        if destination.exists():
            raise ValueError('public library retention collision')
        destination.parent.mkdir(parents=True, exist_ok=True)
        expected = sha(path.read_bytes())
        guard.copy_file(path, destination)
        if sha(destination.read_bytes()) != expected:
            raise ValueError('retained public library hash mismatch')
        files[name] = dict(sha256=expected, bytes=destination.stat().st_size)
    with (delivery / 'public-libraries.json').open('xb') as stream:
        stream.write(json_bytes(dict(schema=1, files=files,
            authenticated_final_link_inputs=False,
            scope='original OpenSSL/config + emitted static archives, not exact final-link provenance',
            headers_and_adapters='source-materials.tar.gz')))
