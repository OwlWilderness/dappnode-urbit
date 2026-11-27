"""Explicit isolated-Linux phase entry. No Docker, installer, retry or host fallback.

Runs only within an externally created, owner-approved, positively bound container.
That outer transport must supply fresh identity/control readback as profile data;
this worker verifies effective Linux cgroups again before EVERY target process.
A profile/grant JSON is a trust-boundary input, not a self-authenticating owner grant.
No profile generator or execution authority is supplied here.
"""
import hashlib
import os
from pathlib import Path
import re
import struct
import sys
import time
from contextlib import contextmanager
from typing import Any

from . import wire as binder
from . import prepare, output_contract
from . import supervisor
from .stage import checked_read, open_regular, save_new


def effective_controls(phase, root=Path('/sys/fs/cgroup')):
    """Require cgroup-v2 finite memory, zero swap, CPU, PIDs before child creation."""
    budget = supervisor.BUDGETS[phase]
    expected = {'memory.max':str(budget['memory']), 'memory.swap.max':'0',
                'pids.max':str(budget['pids']), 'cpu.max':'100000 100000'}
    actual = {name:(root/name).read_text().strip() for name in expected}
    prepare.require(actual == expected, 'effective cgroup controls mismatch')
    return actual


def admission(readback):
    prepare.require(type(readback.get('host_free_bytes')) is int and
                    type(readback.get('engine_free_bytes')) is int and
                    readback['host_free_bytes'] >= 16*1024**3 and
                    readback['engine_free_bytes'] >= 16*1024**3 and
                    type(readback.get('observed_unix')) in (int,float) and
                    0 <= time.time()-readback['observed_unix'] < 2,
                    'fresh independent host and engine 16GiB admission required')
    return {k:v for k,v in readback.items() if k not in
            ('host_free_bytes','engine_free_bytes','observed_unix')}


def check_grant(profile, grant, phase):
    if 'descriptor_policy' in profile:
        supervisor.descriptor_budget(profile, phase)
    prepare.require(type(grant) is dict and grant.get('approved') is True and
                    grant.get('phase') == phase and
                    grant.get('binding_sha256') == hashlib.sha256(binder.encoded(profile)).hexdigest() and
                    type(grant.get('expires_unix')) in (int,float) and
                    time.time() < grant['expires_unix'] <= time.time()+300 and
                    grant.get('owner_scope') == 'one-original-retained-library-experiment',
                    'fresh exact phase owner approval required')


def verify_public_file(path, pin, deadline):
    with open_regular(path) as f:
        checked_read(f,pin,deadline)


def static_elf(path):
    """Bounded program-header check, NOT an algorithm or final-b04 attestation."""
    with open_regular(path) as f:
        head = f.read(64)
        prepare.require(len(head) == 64 and head[:7] == b'\x7fELF\x02\x01\x01' and
                        struct.unpack_from('<H',head,16)[0] == 2 and
                        struct.unpack_from('<H',head,18)[0] == 62, 'AMD64 ELF64 required')
        offset = struct.unpack_from('<Q',head,32)[0]
        size,count = struct.unpack_from('<HH',head,54)
        prepare.require(size == 56 and 0 < count <= 128 and offset+size*count <= os.fstat(f.fileno()).st_size,
                        'bounded ELF program headers')
        f.seek(offset)
        for _ in range(count):
            prepare.require(struct.unpack_from('<I',f.read(size))[0] not in (2,3),
                            'static ELF only, no DYNAMIC/INTERP')
    return supervisor.digest(path)


def compile_result(output,row):
    """Keep the compiler outcome even if validation/export subsequently fails."""
    if not (row['reason']=='EXIT' and row['returncode']==0 and row['reaped']):
        save_new(output/'compile-result.json',binder.encoded(dict(status='COMPILE_FAILED_NO_RETRY',
            process=row,final_elf_acceptance=False)))
        raise ValueError('compile failure, stopped without fallback')
    binary=static_elf(output/'probe')
    map_pin=supervisor.retain_link_map(output,row)
    (output/'probe').chmod(0o555)
    return dict(status='RETAINED_PROBE_COMPILED',binary=binary,map=map_pin,process=row)


@contextmanager
def authentication_stage(output, name, deadline):
    """Immutable bounded entry/end records; no profile, path, argv or exception text."""
    prepare.require(name in output_contract.AUTH_STAGES, 'authentication timing stage')
    def record(suffix, boundary):
        now = time.monotonic()
        data = dict(stage=name,boundary=boundary,monotonic_seconds=now,
                    remaining_work_seconds=max(0,deadline-now))
        output_contract.authentication_record(data,name,suffix)
        save_new(output/('auth-'+name+'-'+suffix+'.json'),binder.encoded(data))
    record('entry','entry')
    try:
        yield
    except BaseException:
        record('end','failure')
        raise
    else:
        record('end','return')


def execute(profile: dict[str, Any], grant, phase, transport=None):
    """Execute exactly one phase in the bound Linux worker, never static preparation.

    transport is an optional readback callback for the outer controller; it must
    return exactly the profile's immutable containment projection. There is no
    default daemon access and no arbitrary command or target-program option.
    """
    prepare.require(type(profile) is dict and type(profile.get('base')) is dict,
                    'missing cached execution base binding')
    prepare.require(phase in ('compile','run'), 'explicit compile or run phase')
    phase_deadline = None
    base = profile['base']
    prepare.require(re.fullmatch('sha256:[0-9a-f]{64}',base.get('image_id','')) is not None and
                    base.get('os') == 'linux' and base.get('architecture') == 'amd64' and
                    base.get('volumes') == 0 and base.get('onbuild') == 0,
                    'exact cached non-volume Linux AMD64 base required')
    client = profile.get('transport',{})
    prepare.require(client.get('path') == '/Applications/Docker.app/Contents/Resources/bin/docker' and
                    client.get('sha256') ==
                    'b12e1e7a3cd2cebd2d3b03bbb58368e7c2439a3c09003e175029815b6ccc0e24' and
                    type(client.get('endpoint')) is str and client['endpoint'].startswith('unix:///') and
                    type(client.get('engine_id')) is str and 0 < len(client['engine_id']) <= 256 and
                    type(profile.get('amd64_execution_binding')) is dict,
                    'exact cached client, selected daemon and AMD64 execution binding required')
    check_grant(profile,grant,phase)
    prepare.require(sys.platform == 'linux' and os.getuid() == 10000 and os.getgid() == 10000,
                    'isolated Linux UID/GID10000 required; no host fallback')
    phase_deadline = output_contract.work_deadline(phase,profile)
    output = Path('/output')
    with authentication_stage(output,'admission',phase_deadline):
        if not callable(transport):
            raise ValueError('fresh independently verified outer transport readback required')
        readback = admission(transport())
        expected = dict(image_id=base['image_id'], network='none', readonly=True, swap=0,
            transport_path=client['path'],transport_sha256=client['sha256'],
            engine_endpoint=client['endpoint'],engine_id=client['engine_id'],
            amd64_execution_binding=profile['amd64_execution_binding'],
            memory=supervisor.BUDGETS[phase]['memory'],cpu=1,pids=supervisor.BUDGETS[phase]['pids'],
            user='10000:10000',caps=[],restart='no',ports=[],volumes=[],core=0,
            inputs_readonly=True,toolchain_readonly=True,controller_readonly=True,
            probe_readonly=phase == 'run',
            bounded_work_bytes=268435456,bounded_output_bytes=268435456,
            owned_container_id=profile.get('container_id'))
        prepare.require(binder.encoded(readback) == binder.encoded(expected) and
                        re.fullmatch('[0-9a-f]{64}',profile.get('container_id','')),
                        'exact-owned container containment readback required')
        controls = effective_controls(phase)
    def stage_event(name):
        save_new(output/('stage-'+name+'.json'),binder.encoded(dict(stage=name)))
    stage_event('admitted')
    deadline = min(phase_deadline,time.monotonic()+90)
    with authentication_stage(output,'controllers',phase_deadline):
        verify_public_file(Path(sys.executable),{k:profile['python'][k] for k in ('bytes','sha256')},deadline)
        # The signed/approved profile must bind every public controller byte too.
        for name,pin in profile['controllers'].items():
            prepare.require(name in ('execution.py','supervisor.py','stage.py','prepare.py','bind_b04.py','probe.c',
                                   'wire.py','phase_worker.py','output_contract.py'),
                            'controller allowlist')
            verify_public_file(prepare.HERE/name,pin,deadline)
        prepare.require(set(profile['controllers']) ==
            {'execution.py','supervisor.py','stage.py','prepare.py','bind_b04.py','probe.c',
                                   'wire.py','phase_worker.py','output_contract.py'},'complete controller binding')
    stage_event('controllers-verified')
    with authentication_stage(output,'inputs',phase_deadline):
        stage = Path('/inputs')
        manifest = profile['manifest']
        prepare.require(len(manifest['files']) == 352 and profile['pair'] == 'original',
                        'exact original 352-file selection required')
        prepare.require(hashlib.sha256(binder.encoded(manifest)).hexdigest() ==
            'd709310c00aa8fbb6b182560bb89df4124622505cc380ab5e37be8f65bb61404',
            'authenticated original b04 manifest identity')
        prepare.prepare(stage,manifest)
    stage_event('inputs-verified')
    with authentication_stage(output,'toolchain',phase_deadline):
        # Do not infer compiler/sysroot hashes from --version or use a host SDK.
        toolchain = profile['toolchain']
        prepare.require(toolchain['archive_sha256'] ==
            '02aa270f183da276e5b5920b1dac44a63f1a49e55050ebde3aecc9eb82f93239','pinned Zig archive')
        prepare.require(toolchain['compiler_sha256'] ==
            '2858dc89dbbfdd08cceda1b841e7fd0a793a1a67b49f150bc3d0d1de44ed7f51','pinned Zig executable')
        inventory = toolchain['files']
        prepare.require(hashlib.sha256(binder.encoded(inventory)).hexdigest() ==
            toolchain['inventory_sha256'] ==
            'ce70d945c37fd7a3601f4d0d0d68628be4a5811027054e497929fb1ea94b0276',
            'sysroot inventory binding')
        # Include all bundled Zig lib/compiler-runtime/libc files, not just libc.h.
        root = 'zig-x86_64-linux-0.15.2/'
        for name,pin in inventory.items():
            prepare.require(name.startswith(root+'lib/') or name == root+'zig','toolchain member')
            path = Path('/toolchain')/name[len(root):]
            verify_public_file(path,{k:pin[k] for k in ('bytes','sha256')},deadline)
        actual = set()
        allowed = {name[len(root):] for name in inventory}
        allowed_dirs = {p.as_posix() for name in allowed for p in Path(name).parents if p != Path('.')}
        for count,path in enumerate(Path('/toolchain').rglob('*'),1):
            prepare.require(count <= 40000 and time.monotonic() < deadline,'toolchain tree bound')
            prepare.require(not path.is_symlink(),'toolchain symlink')
            relative = path.relative_to('/toolchain').as_posix()
            if path.is_file():
                actual.add(relative)
            else:
                prepare.require(path.is_dir() and relative in allowed_dirs,'undeclared toolchain directory')
        prepare.require(actual == allowed,'undeclared toolchain files')
        prepare.require(root+'zig' in inventory and inventory[root+'zig']['sha256'] ==
                        toolchain['compiler_sha256'],'compiler inventory entry')
        prepare.require(output.is_dir() and output == output.resolve(), 'owned canonical output mount')
    stage_event('toolchain-verified')
    with authentication_stage(output,'launch-validation',phase_deadline):
        marker = output/('compile-spent.json' if phase == 'compile' else 'run-spent.json')
        prepare.require(binder.encoded(admission(transport())) == binder.encoded(expected),
                        'late outer transport drift')
        effective_controls(phase)
        check_grant(profile,grant,phase)  # Slow observation cannot consume an expired grant.
        prepare.require(time.monotonic() < phase_deadline,'phase deadline before launch')
        save_new(marker,binder.encoded(dict(phase=phase,profile=profile,controls=controls)))
    stage_event('launch-intent')
    if phase == 'compile':
        row = supervisor.capture(supervisor.compile_argv(), output/'compile',
            supervisor.descriptor_budget(profile, phase) if 'descriptor_policy' in profile else
            supervisor.BUDGETS['compile'],deadline=phase_deadline,target_evidence=True,scratch='/work',
            control_ack='/observer/compile-controls-ack.json',timing_evidence=True)
        result = compile_result(output,row)
    else:
        program = Path('/program/probe')
        verify_public_file(program,profile['probe'],deadline)
        static_elf(program)
        def invoke(argv, directory, budget, whole_deadline):
            prepare.require(binder.encoded(admission(transport())) == binder.encoded(expected),
                            'outer transport drift before target run')
            effective_controls('run')
            verify_public_file(program,profile['probe'],time.monotonic()+2)
            row = supervisor.capture(argv,directory,budget,deadline=whole_deadline,
                                     target_evidence=True,scratch='/work')
            row.update(settled=row['reaped'], controls_verified=True)
            return row
        result = supervisor.execute_matrix(str(program),output/'runtime',invoke,deadline=phase_deadline)
    result.update(final_elf_acceptance=False,evidence_scope='retained-library-only',
                  outer_transport_independently_authenticated=False)
    save_new(output/(phase+'-result.json'),binder.encoded(result))
    return result


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase',choices=('plan','compile','run'),default='plan')
    parser.add_argument('--profile',type=Path)
    parser.add_argument('--grant',type=Path)
    parser.add_argument('--readback',type=Path,
        help='fresh public receipt maintained by the independently approved outer observer')
    args = parser.parse_args()
    if args.phase == 'plan':
        from .cached_inputs import inspect_cached
        print(binder.encoded(inspect_cached()).decode(),end='')
        return
    def public_json(path,limit):
        if path is None:
            return None
        with open_regular(path) as stream:
            data = stream.read(limit+1)
        return prepare.parse_json(data.decode(),limit)
    profile = public_json(args.profile,8*1024**2)
    grant = public_json(args.grant,1048576)
    def readback():
        prepare.require(args.readback is not None,'fresh outer readback receipt required')
        with open_regular(args.readback) as stream:
            data = stream.read(16385)
        receipt = prepare.parse_json(data.decode(),16384)
        prepare.require(type(receipt.get('observed_unix')) in (int,float) and
                        0 <= time.time()-receipt['observed_unix'] < 2,
                        'fresh outer readback receipt required')
        return receipt['projection']
    execute(profile,grant,args.phase,readback)


if __name__ == '__main__':
    main()
