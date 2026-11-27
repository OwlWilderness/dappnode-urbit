"""Complete recursive repository Python import closure, including lazy host imports.

The profile binds this positive inventory. Mount the exact inventory at /controller,
not merely the guest entry's eager imports. Standard-library/interpreter closure
is separately bound by the existing pinned Python/loader/toolchain/base contract.
No imports of discovered modules, authority creation or runtime observation here.
"""
import ast
import hashlib
from pathlib import Path
from .prepare import require

PACKAGE='tools.issue3_observed_compile'
ENTRIES=('outer','docker_transport','watchdog','settlement_verifier','phase_worker','execution','toolchain_stage','cached_base','cached_inputs')


def paths(root):
    root=Path(root); todo=[PACKAGE+'.'+name for name in ENTRIES]; seen=set()
    while todo:
        module=todo.pop()
        if module in seen:continue
        require(len(seen)<128,'source import count cap')
        name=module.replace('.','/')+'.py';p=root/name
        require(p.is_file() and not p.is_symlink() and p.resolve()==p,'missing canonical import '+name)
        seen.add(module)
        raw=p.read_bytes();require(len(raw)<=1048576,'source module byte cap')
        tree=ast.parse(raw,filename=name);package=module.split('.')[:-1]
        for n in ast.walk(tree):
            candidates=[]
            if isinstance(n,ast.Import):candidates=[a.name for a in n.names]
            elif isinstance(n,ast.ImportFrom):
                prefix='.'.join(package[:len(package)-n.level+1]) if n.level else ''
                base='.'.join(v for v in (prefix,n.module or '') if v)
                candidates=[base]+[base+'.'+a.name for a in n.names]
            for target in candidates:
                if not target.startswith('tools.'):continue
                f=root/(target.replace('.','/')+'.py')
                if f.is_file():todo.append(target)
                else:
                    # A from-import symbol is not another module. Require the
                    # base module or namespace directory rather than inventing it.
                    require((root/target.replace('.','/')).is_dir() or
                            (root/(target.rsplit('.',1)[0].replace('.','/')+'.py')).is_file(),
                            'unresolved repository import '+target)
    return {m.replace('.','/')+'.py' for m in seen}|{'tools/issue3_observed_compile/probe.c'}


def inventory(root):
    root=Path(root)
    return {n:dict(bytes=len((root/n).read_bytes()),sha256=hashlib.sha256((root/n).read_bytes()).hexdigest())
            for n in sorted(paths(root))}


def verify(pins,root,deadline=None,clock=None):
    root=Path(root)
    require(type(pins) is dict and set(pins)==paths(root),'complete recursive source closure')
    for name,pin in pins.items():
        if deadline is not None:require(clock()<deadline,'source closure deadline')
        require(type(pin) is dict and set(pin)=={'bytes','sha256'},'source descriptor fields')
        raw=(root/name).read_bytes()
        require(type(pin['bytes']) is int and len(raw)==pin['bytes'] and
                hashlib.sha256(raw).hexdigest()==pin['sha256'],'source closure drift '+name)
    if deadline is not None:require(clock()<deadline,'source closure deadline')
    return pins
