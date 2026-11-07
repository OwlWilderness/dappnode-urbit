#!/usr/bin/env python3
"""Offline source-only checks; no package build, browser, engine or live workload."""
import ast
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
SERVICE = HERE / 'service'
TESTS = ROOT / 'tests/native-recovery'


def main():
    if sys.version_info < (3, 10):
        raise SystemExit('Python 3.10+ required')
    node = shutil.which('node')
    if not node:
        raise SystemExit('Node.js 18+ required; no package installation performed')
    env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONPATH': str(SERVICE),
           'TMPDIR': str(Path(tempfile.gettempdir()).resolve())}
    index = json.loads((HERE / 'source-parity.json').read_text())
    for entry in index['files']:
        actual = hashlib.sha256((ROOT / entry['path']).read_bytes()).hexdigest()
        if actual != entry['public_sha256']:
            raise SystemExit('Source parity mismatch: ' + entry['path'])
    print('PASS public source parity hashes', flush=True)
    modules = {p.stem for p in SERVICE.glob('*.py')}
    for source in sorted(SERVICE.glob('*.py')):
        text = source.read_text()
        tree = ast.parse(text, filename=str(source))
        compile(tree, str(source), 'exec')
        for item in ast.walk(tree):
            names = ([alias.name.split('.')[0] for alias in item.names] if isinstance(item, ast.Import)
                     else [item.module.split('.')[0]] if isinstance(item, ast.ImportFrom) and item.module else [])
            for name in names:
                if name not in modules and name not in sys.stdlib_module_names:
                    raise SystemExit(f'Unresolved external Python dependency: {source.name}: {name}')
    # Import every supplied module, including delayed package/TLS imports, from this
    # source closure only. None of their guarded main entrypoints are invoked.
    code = 'import importlib; ' + '; '.join(f'importlib.import_module({m!r})' for m in sorted(modules))
    commands = [[sys.executable, '-I', '-B', '-c', f'import sys;sys.path.insert(0,{str(SERVICE)!r});{code}'],
                [sys.executable, '-B', '-m', 'unittest', 'discover', '-s', str(TESTS), '-p', 'test_*.py', '-v']]
    for source in sorted(HERE.glob('*.js')):
        commands.append([node, '--check', str(source)])
    for test in sorted(TESTS.glob('test_*.cjs')):
        commands.append([node, str(test)])
    for command in commands:
        print('RUN ' + ' '.join(command), flush=True)
        subprocess.run(command, cwd=ROOT, env=env, check=True, timeout=60)
    print('PASS focused offline source checks; native/root delivery and appliance lifecycle not requalified', flush=True)


if __name__ == '__main__':
    main()
