"""Selective toolchain/controller physical preparation; never launches a process.

The public entry rechecks the cached pinned inventory. Mechanism fixtures are
explicitly unauthenticated. A fresh directory is exclusive and failures retained.
"""
import hashlib
import json
import os
from pathlib import Path
import tarfile
import time

from . import cached_inputs, prepare, wire
from .stage import archive_name, checked_read, open_regular, relative, save_new


def stage_inventory(attempt,archive,pin,root,files):
    attempt=Path(attempt)
    prepare.require(attempt.is_absolute() and attempt.parent==attempt.parent.resolve(),'canonical stage parent')
    prepare.require(0<len(files)<=20000 and sum(row['bytes'] for row in files.values())<=384*1024**2,
                    'complete toolchain byte/count cap')
    for name in files:
        relative(name)
        prepare.require(name==root+'/zig' or name.startswith(root+'/lib/'),'selected compiler/lib namespace')
    attempt.mkdir(mode=0o700); out=attempt/'toolchain'; out.mkdir(mode=0o700)
    save_new(attempt/'toolchain-intent.json',wire.encoded(dict(files=files,archive=dict(path=str(archive),**pin),compiler_executed=False)))
    deadline=time.monotonic()+90; written=set()
    try:
        with open_regular(Path(archive)) as raw:
            checked_read(raw,pin,deadline); raw.seek(0)
            seen=set(); total=0
            with tarfile.open(fileobj=raw,mode='r|xz') as tar:
                for count,row in enumerate(tar,1):
                    name=archive_name(row); total+=row.size
                    prepare.require(count<=100000 and time.monotonic()<deadline and 0<=row.size and total<=2*1024**3,
                                    'toolchain archive bounds')
                    prepare.require(name.casefold() not in seen,'duplicate toolchain archive member')
                    seen.add(name.casefold())
                    if name not in files: continue
                    expect=files[name]
                    prepare.require(row.isfile() and row.size==expect['bytes'],'toolchain selected type/size')
                    dest=out/name[len(root)+1:]; dest.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                    stream=tar.extractfile(row)
                    prepare.require(stream is not None,'missing compiler member')
                    with stream, dest.open('xb') as sink:
                        checked_read(stream,{k:expect[k] for k in ('bytes','sha256')},deadline,sink)
                        sink.flush(); os.fsync(sink.fileno())
                    dest.chmod(0o555 if name==root+'/zig' else 0o444); written.add(name)
            raw.seek(0); checked_read(raw,pin,deadline)
        prepare.require(written==set(files),'missing selected toolchain member')
        for directory in sorted((p for p in out.rglob('*') if p.is_dir()),key=lambda p:len(p.parts),reverse=True):
            directory.chmod(0o555)
        out.chmod(0o555)
        result=dict(status='STAGED_UNAUTHENTICATED_NOT_EXECUTED',files=len(written),
                    bytes=sum(files[n]['bytes'] for n in written),compiler_executed=False)
        save_new(attempt/'toolchain-stage.json',wire.encoded(result))
        return result
    except BaseException as exc:
        save_new(attempt/'toolchain-failed.json',wire.encoded(dict(error=type(exc).__name__,detail=str(exc)[:1000])))
        raise


def stage_public(attempt):
    inventory=cached_inputs.compiler_inventory(cached_inputs.ARCHIVE,cached_inputs.PIN)
    prepare.require(inventory['sysroot_inventory_sha256']=='ce70d945c37fd7a3601f4d0d0d68628be4a5811027054e497929fb1ea94b0276',
                    'pinned compiler inventory')
    result=stage_inventory(attempt,cached_inputs.ARCHIVE,cached_inputs.PIN,cached_inputs.ROOT,inventory['files'])
    result.update(status='PINNED_TOOLCHAIN_STAGED_NOT_EXECUTED',inventory_sha256=inventory['sysroot_inventory_sha256'])
    save_new(Path(attempt)/'authenticated-toolchain.json',wire.encoded(result))
    return result


def stage_controller(attempt):
    """Future gated staging helper; ships the FULL host/guest import closure."""
    from . import release
    root=Path(attempt);source=Path(__file__).resolve().parents[2]
    prepare.require(root.is_absolute() and root.parent==root.parent.resolve(),'canonical controller stage parent')
    pins=release.inventory(source)
    root.mkdir(mode=0o700)
    for name,pin in pins.items():
        with open_regular(source/name) as stream:data=stream.read(1048577)
        prepare.require(len(data)==pin['bytes'] and hashlib.sha256(data).hexdigest()==pin['sha256'],'closure copy identity')
        dest=root/name;dest.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
        save_new(dest,data);dest.chmod(0o444)
    release.verify(pins,root)
    for directory in sorted((p for p in root.rglob('*') if p.is_dir()),key=lambda p:len(p.parts),reverse=True):
        directory.chmod(0o555)
    root.chmod(0o555)
    return pins


def main():
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--stage-pinned-toolchain',type=Path)
    group.add_argument('--stage-controller',type=Path)
    args=parser.parse_args()
    result=stage_public(args.stage_pinned_toolchain) if args.stage_pinned_toolchain else stage_controller(args.stage_controller)
    print(wire.encoded(result).decode(),end='')


if __name__=='__main__': main()
