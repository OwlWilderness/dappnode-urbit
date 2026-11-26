"""Focused production companion closure; no engine or ship required."""
import ast
import fnmatch
import os
from pathlib import Path
import shlex
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


def packaged_modules():
    result = {}
    for line in (ROOT / 'build/Dockerfile').read_text().splitlines():
        if not line.startswith('COPY --chown=0:0 '):
            continue
        tokens = shlex.split(line)[2:]
        if tokens[-1] == '/opt/importer/':
            result.update({Path(p).stem: ROOT / p for p in tokens[:-1] if p.endswith('.py')})
    return result


class ProductionCompanionClosure(unittest.TestCase):
    def test_provider_lazy_local_dependencies_are_packaged(self):
        modules = packaged_modules()
        local = ROOT / 'tools/browser-importer'
        pending = ['maintenance_provider']
        seen = set()
        while pending:
            name = pending.pop()
            if name in seen:
                continue
            seen.add(name)
            self.assertIn(name, modules, f'production COPY missing local dependency {name}')
            for node in ast.walk(ast.parse(modules[name].read_bytes())):
                names = ([node.module.split('.')[0]] if isinstance(node, ast.ImportFrom) and node.module
                         else [x.name.split('.')[0] for x in node.names] if isinstance(node, ast.Import) else [])
                pending.extend(n for n in names if (local / (n + '.py')).is_file())

    def test_bounded_child_is_admitted_to_build_context(self):
        path = 'tools/browser-importer/bounded_child.py'
        admitted = True
        for line in (ROOT / '.dockerignore').read_text().splitlines():
            rule = line.strip()
            if not rule or rule.startswith('#'):
                continue
            negated = rule.startswith('!')
            pattern = rule[1:] if negated else rule
            if fnmatch.fnmatchcase(path, pattern):
                admitted = negated
        self.assertTrue(admitted, 'production context excludes bounded_child.py')


if __name__ == '__main__':
    unittest.main(verbosity=2)
