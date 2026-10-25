"""Exercise the actual Docker ignore matcher with synthetic files only.

No real source tree is sent. Context and probe image are retained; no cleanup.
"""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scratch-root', required=True)
    parser.add_argument('--builder', required=True)
    args = parser.parse_args()
    ignore = (ROOT / '.dockerignore').read_text()
    allowed = [line[1:] for line in ignore.splitlines()
               if line.startswith('!') and not line.endswith('/')]
    forbidden = ['build/unlisted.txt', 'build/nested/unlisted.txt',
                 'tools/unlisted/nested.txt', 'tools/browser-importer/private.key',
                 'tools/browser-importer/bootstrap-authority.html',
                 'tools/browser-importer/web/unlisted.txt', '.env', 'unlisted.txt',
                 'THIRD_PARTY/private.key', 'THIRD_PARTY/vere/notices/unlisted.txt',
                 'THIRD_PARTY/platform/image-baseline/unlisted.txt',
                 'LICENSES/unlisted.txt', 'docs/private.md']
    context = Path(tempfile.mkdtemp(prefix='docker-context-check-', dir=args.scratch_root))
    for name in allowed + forbidden:
        path = context / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('synthetic public marker\n')
    (context / '.dockerignore').write_text(ignore)
    base = (ROOT / 'build/Dockerfile').read_text().splitlines()[0].split()[1]
    assert base.startswith('alpine@sha256:')
    checks = [f'test -f /context/{name}' for name in allowed]
    checks += [f'test ! -e /context/{name}' for name in forbidden]
    dockerfile = context / 'ContextCheck.Dockerfile'
    dockerfile.write_text(f'FROM {base}\nCOPY . /context/\nRUN ' + ' && '.join(checks) + '\n')
    tag = 'dappnode-urbit-context-check:' + uuid.uuid4().hex
    result = subprocess.run(['docker', 'buildx', 'build', '--builder', args.builder,
                             '--platform=linux/amd64', '--network=none', '--load',
                             '--progress=plain', '--tag', tag, '--file', str(dockerfile), str(context)],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=120)
    print(json.dumps({'result': 'PASS' if result.returncode == 0 else 'FAIL',
                      'allowed_paths': len(allowed), 'forbidden_paths': len(forbidden),
                      'context': str(context), 'tag': tag, 'exit_code': result.returncode}))
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
