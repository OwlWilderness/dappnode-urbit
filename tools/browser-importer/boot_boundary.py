"""Private PID1 startup capability, not a native engine Stop receipt.

The package supervisor admits exactly one management backend in an initially
empty Linux PID namespace. It never respawns that backend. A socketpair (not a
persistent flag, PID guess or HTTP input) binds the backend to that supervisor.
Only the pinned package frontend tree is exempted from the no-writer inventory.
Administrator noninterference and exclusive volume ownership remain required.
"""
import json
import os
from pathlib import Path
import re
import select
import socket
import struct
import sys
import uuid

from local_child import _children

ENV = 'UVM_MANAGEMENT_BOOT_FD'


def process_ids():
    return {int(p.name) for p in Path('/proc').iterdir() if p.name.isdecimal()}


def start_ticks(pid):
    # comm can contain spaces and parentheses.
    return int(Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()[19])


class BootSupervisor:
    @classmethod
    def admit(cls):
        if not sys.platform.startswith('linux') or os.getpid() != 1:
            return None
        if process_ids() != {1} or _children(1):
            raise ValueError('Management boot requires a fresh exclusive PID namespace')
        return cls()

    def __init__(self):
        self.server, self.client = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.server.setblocking(False)
        self.boot_id = uuid.uuid4().hex
        self.namespace = os.stat('/proc/self/ns/pid').st_ino
        self.ticks = start_ticks(1)

    def poll(self, backend, frontends):
        if not select.select([self.server], [], [], 0)[0]:
            return
        try:
            request = self.server.recv(256)
            if not request:
                return
            allowed = {1, backend.pid}
            # Frontends are package-owned non-writers. Track their actual tree,
            # not argv/name allowlists or arbitrary children adopted by PID1.
            todo = [p.pid for p in frontends]
            while todo:
                pid = todo.pop()
                if pid in allowed:
                    raise ValueError('Ambiguous service hierarchy')
                allowed.add(pid)
                todo.extend(_children(pid))
            valid = (request == b'CHECK' and backend.poll() is None and
                     all(p.poll() is None for p in frontends) and
                     os.getpid() == 1 and start_ticks(1) == self.ticks and
                     os.stat('/proc/self/ns/pid').st_ino == self.namespace and
                     not _children(backend.pid) and process_ids() == allowed and
                     _children(1) == {backend.pid, *(p.pid for p in frontends)})
            response = {'boundary': 'LINUX_PID1_MANAGEMENT_BOOT', 'boot_id': self.boot_id,
                        'namespace': self.namespace, 'supervisor_start': self.ticks,
                        'backend_pid': backend.pid, 'remaining_children': 0,
                        'exit_code': None, 'signal': 'NONE'} if valid else None
            self.server.send(json.dumps(response).encode())
        except (OSError, ValueError):
            # Missing/changed process metadata never becomes positive authority.
            try:
                self.server.send(b'null')
            except OSError:
                pass

    def close(self):
        self.server.close()
        self.client.close()


class ManagementBootBoundary:
    @classmethod
    def receive(cls):
        raw = os.environ.pop(ENV, None)
        if raw is None:
            return None
        if not re.fullmatch('[0-9]{1,8}', raw) or not sys.platform.startswith('linux'):
            raise ValueError('Invalid startup capability')
        channel = socket.socket(fileno=int(raw))
        try:
            channel.set_inheritable(False)
            peer, uid, _ = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if (peer != 1 or uid != os.geteuid() or os.getppid() != 1 or
                    channel.type != socket.SOCK_SEQPACKET):
                raise ValueError('Startup capability is not from PID1')
            return cls(channel)
        except BaseException:
            channel.close()
            raise

    def __init__(self, channel):
        self.channel = channel
        self.owner = os.getpid()
        self.namespace = os.stat('/proc/self/ns/pid').st_ino
        self.ticks = start_ticks(1)
        self.used = False

    def settle(self):
        if (self.used or os.getpid() != self.owner or os.getppid() != 1 or
                start_ticks(1) != self.ticks or
                os.stat('/proc/self/ns/pid').st_ino != self.namespace or _children(self.owner)):
            raise ValueError('Startup authority no longer applies')
        self.channel.settimeout(3)
        self.channel.send(b'CHECK')
        evidence = json.loads(self.channel.recv(2048))
        if (not isinstance(evidence, dict) or evidence.get('boundary') != 'LINUX_PID1_MANAGEMENT_BOOT' or
                evidence.get('backend_pid') != self.owner or evidence.get('namespace') != self.namespace or
                evidence.get('supervisor_start') != self.ticks or
                not re.fullmatch('[a-f0-9]{32}', evidence.get('boot_id', ''))):
            self.close()  # A lost/ambiguous response cannot be replayed as proof.
            raise ValueError('PID1 could not establish management-only cessation')
        return evidence

    def close(self):
        self.used = True
        self.channel.close()
