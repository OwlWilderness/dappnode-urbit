"""Subprocess-only Linux/root + Docker MODEL seam; no engine qualification.

Copied as sitecustomize into a private test directory. A profile hook changes
only the CLI's external host/Docker boundary, including when Python executes
its source as __main__. Provider, StorageAdmission and maintenance code remain
real and their module/class identity is not changed. Host guard proxies are
restored before the real Provider constructor touches storage.
"""
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

TOOLS = Path(os.environ['PROVIDER_CLI_TOOLS'])
sys.path.insert(0, str(TOOLS))


class ModelDocker:
    def __init__(self):
        self.info = json.loads(Path(os.environ['PROVIDER_CLI_INFO']).read_text())

    def event(self, name, cid):
        with open(os.environ['PROVIDER_CLI_EVENTS'], 'a') as target:
            target.write(json.dumps([name, cid]) + '\n')

    def inspect(self, cid):
        return self.info if self.info is not None and self.info['id'] == cid else None

    def consumers(self, storage):
        return [] if self.info is None else [self.info['id']]

    def stop(self, cid):
        self.event('stop', cid)
        assert self.info is not None
        self.info.update(status='exited', running=False)

    def remove(self, cid):
        self.event('remove', cid)
        self.info = None

    def start(self, cid):
        raise AssertionError('recovery must not start a successor')


def new_provider(provider_class, *args, **kwargs):
    instance = provider_class(*args, **dict(kwargs, owner_uid=os.geteuid()))
    instance._require_host = lambda: None  # explicit unprivileged/Darwin seam
    return instance


def observe_recovery(frame, event, arg):
    if (event == 'call' and frame.f_code.co_name == 'recover_stopped' and
            Path(frame.f_code.co_filename).resolve() == TOOLS / 'maintenance.py'):
        import maintenance_provider
        actual = type(frame.f_locals['admission'])
        with open(os.environ['PROVIDER_CLI_EVENTS'], 'a') as target:
            target.write(json.dumps(['capability', actual is maintenance_provider.StorageAdmission]) + '\n')


def enter_cli(frame, event, arg):
    if (event != 'call' or frame.f_code.co_name != 'main' or
            Path(frame.f_code.co_filename).resolve() != TOOLS / 'maintenance_provider.py'):
        return
    sys.setprofile(observe_recovery)
    namespace = frame.f_globals
    provider_class = namespace['Provider']

    def provider(*args, **kwargs):
        namespace['os'], namespace['sys'] = os, sys
        return new_provider(provider_class, *args, **kwargs)

    # Only main's initial host guard sees these proxies. All storage operations
    # use the real OS, UID, flock/fsync/rename, import preflight and live lease.
    namespace['os'] = SimpleNamespace(geteuid=lambda: 0)
    namespace['sys'] = SimpleNamespace(platform='linux', stderr=sys.stderr)
    namespace['Provider'], namespace['Docker'] = provider, ModelDocker


sys.setprofile(enter_cli)
