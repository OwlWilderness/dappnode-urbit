"""Export the public root-host companion; engine-free, never an installer.

Use a quiescent source checkout. An image/package acceptance receipt must bind
this manifest and its own image/descriptor hashes; this is not that receipt.
"""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    'tools/browser-importer/maintenance_provider.py',
    'tools/browser-importer/bounded_child.py',
    'docs/dappmanager-integration.md',
    'tools/browser-importer/maintenance.py',
    'tools/browser-importer/runtime.py',
    'tools/browser-importer/importer.py',
    'tools/browser-importer/archive.py',
    'tools/browser-importer/managed_service.py',
    'tools/browser-importer/package_service.py',
    'tools/browser-importer/server.py',
    'tools/browser-importer/enrollment.py',
    'tools/browser-importer/owner_tls.py',
    'tools/browser-importer/backend_tls.py',
    'tools/browser-importer/public_ingress.py',
    'tools/browser-importer/web/index.html',
    'tools/browser-importer/web/style.css',
    'tools/browser-importer/web/app.mjs',
    'tools/browser-importer/web/enroll.html',
    'tools/browser-importer/web/enroll.mjs',
    'tools/host-integration/dappmanager_lifecycle.py',
    'tools/host-integration/dappmanager_broker.py',
    'tools/host-integration/upstream-dappmanager.patch',
    'tools/prepare-maintenance-host.py',
    'build/docker-entrypoint.sh',
    'docker-compose.yml', 'host-maintenance.compose.yml',
    'build/Dockerfile', 'build/vere-release.json',
    'build/volume_guard.py', '.dockerignore',
    'docs/host-maintenance.md', 'docs/operator-guide.md',
    'LICENSE.md', 'LICENSES/GPL-3.0-only.txt',
)


def export(output):
    if not output.is_absolute():
        raise ValueError('output must be absolute')
    output = output.resolve()
    if output == ROOT or ROOT in output.parents:
        raise ValueError('output must be outside the checkout')
    # Only explicitly public source paths. Never walk private state or scratch.
    contents = {name: (ROOT / name).read_bytes() for name in FILES}
    manifest = {'version': 1, 'deployment_qualified': False,
                'authority': '/var/lib/uvm-maintenance',
                'required_integration': 'trusted create-before-start host orchestration since virgin inception',
                'files': {name: hashlib.sha256(raw).hexdigest() for name, raw in contents.items()}}
    output.mkdir(mode=0o700)  # exclusive: no overwrite/reuse/cleanup
    for name, raw in contents.items():
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with target.open('xb') as stream:
            stream.write(raw)
        if target.read_bytes() != raw:
            raise OSError('companion readback failed')
    # Reject source changes during export; leave partial evidence, never clean it.
    if any((ROOT / name).read_bytes() != raw for name, raw in contents.items()):
        raise OSError('source changed; partial output retained')
    with (output / 'manifest.json').open('x') as stream:
        json.dump(manifest, stream, sort_keys=True, indent=2)
        stream.write('\n')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    export(args.output)
    print('HOST_COMPANION_SOURCE_ONLY_UNQUALIFIED')


if __name__ == '__main__':
    main()
