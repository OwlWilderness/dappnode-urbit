"""Read-only bounded selected-runtime hashing from one public cached image stream.

Never extracts a member, persists image bytes, creates a container or executes
Python/loader from the image. Image ID/config and ordered layer diffIDs are checked.
"""
import hashlib
import io
import json
from pathlib import PurePosixPath
import re
import struct
import subprocess
import tarfile
import threading
import time

from . import prepare
from .docker_transport import CLIENT

IMAGE='sha256:77ac250acc299f653bf3f1971aaa0bc0882e8bb9e553bf16bf9b07239bc06bb3'
ENDPOINT='unix:///var/run/docker.sock'


class HashReader:
    def __init__(self,source,cap=96*1024**2):
        self.source=source; self.hash=hashlib.sha256(); self.size=0; self.cap=cap
    def read(self,size=-1):
        prepare.require(size>=0,'bounded reads only')
        data=self.source.read(size); self.size+=len(data)
        prepare.require(self.size<=self.cap,'cached image stream cap')
        self.hash.update(data); return data


def selected(name):
    return bool(re.fullmatch(r'(?:usr/(?:local/)?bin/python3(?:\.[0-9]{1,2})?|(?:usr/)?lib/(?:libpython3\.[0-9]{1,2}\.so(?:\.1\.0)?|ld-musl-x86_64\.so\.1)|lib64/ld-linux-x86-64\.so\.2)',name))


def layer_inventory(source):
    raw=HashReader(source); files={}; deleted=[]; opaque=[]; seen=set(); total=0
    with tarfile.open(fileobj=raw,mode='r|') as archive:
        for count,row in enumerate(archive,1):
            name=row.name.rstrip('/') if row.isdir() else row.name
            prepare.require(count<=100000 and not name.startswith('/') and
                all(p not in ('','.','..') for p in name.split('/')) and name not in seen,'canonical layer namespace')
            seen.add(name); total+=row.size
            prepare.require(0<=row.size and total<=96*1024**2,'cached layer expanded cap')
            path=PurePosixPath(name)
            if path.name=='.wh..wh..opq': opaque.append(str(path.parent)); continue
            if path.name.startswith('.wh.'):
                deleted.append(str(path.parent/path.name[4:])); continue
            if not selected(name): continue
            if row.issym():
                files[name]=dict(kind='symlink',target=row.linkname)
            else:
                prepare.require(row.isfile() and row.size<=32*1024**2,'selected public runtime type/bound')
                f=archive.extractfile(row); digest=hashlib.sha256(); size=0; prefix=b''
                with f:
                    while True:
                        chunk=f.read(1048576)
                        if not chunk: break
                        if len(prefix)<65536: prefix=(prefix+chunk)[:65536]
                        size+=len(chunk); digest.update(chunk)
                prepare.require(size==row.size,'short runtime file')
                pin=dict(kind='file',bytes=size,sha256=digest.hexdigest(),mode=row.mode)
                if len(prefix)>=64 and prefix[:6]==b'\x7fELF\x02\x01':
                    pin['elf_machine']=struct.unpack_from('<H',prefix,18)[0]
                    offset=struct.unpack_from('<Q',prefix,32)[0]
                    stride,count=struct.unpack_from('<HH',prefix,54)
                    prepare.require(stride==56 and count<=128 and offset+stride*count<=len(prefix),'bounded runtime ELF metadata')
                    for i in range(count):
                        position=offset+i*stride
                        if struct.unpack_from('<I',prefix,position)[0]==3:
                            start=struct.unpack_from('<Q',prefix,position+8)[0]
                            length=struct.unpack_from('<Q',prefix,position+32)[0]
                            prepare.require(1<length<=512 and start+length<=len(prefix),'runtime loader metadata')
                            pin['pt_interp']=prefix[start:start+length].rstrip(b'\0').decode('ascii')
                files[name]=pin
    while raw.read(1048576): pass
    return dict(sha256=raw.hash.hexdigest(),bytes=raw.size,files=files,deleted=deleted,opaque=opaque)


def inspect_public():
    argv=[CLIENT,'--host='+ENDPOINT]
    fmt='{"image_id":{{json .Id}},"architecture":{{json .Architecture}},"os":{{json .Os}},"volumes":{{json .Config.Volumes}},"onbuild":{{json .Config.OnBuild}},"layers":{{json .RootFS.Layers}}}'
    info=json.loads(subprocess.check_output(argv+['image','inspect','--format',fmt,IMAGE],timeout=10))
    expected=info.pop('layers')
    info['volumes']=len(info['volumes'] or {}); info['onbuild']=len(info['onbuild'] or [])
    prepare.require(info==dict(image_id=IMAGE,architecture='amd64',os='linux',volumes=0,onbuild=0),'exact public cached base')
    layers={}; config=False; total=0
    process=subprocess.Popen(argv+['image','save',IMAGE],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    timer=threading.Timer(45,process.kill); timer.start()
    raw=HashReader(process.stdout)
    try:
        with tarfile.open(fileobj=raw,mode='r|') as archive:
            for count,row in enumerate(archive,1):
                prepare.require(count<=256 and 0<=row.size<=96*1024**2,'cached image outer cap')
                if not row.isfile(): continue
                name=PurePosixPath(row.name).name
                if row.name.endswith('/layer.tar') or 'sha256:'+name in expected:
                    f=archive.extractfile(row)
                    with f: layer=layer_inventory(f)
                    key='sha256:'+layer['sha256']
                    prepare.require(key in expected and key not in layers,'cached layer diffID binding')
                    layers[key]=layer
                elif name==IMAGE.split(':')[1] or row.name==IMAGE.split(':')[1]+'.json':
                    f=archive.extractfile(row)
                    with f: data=f.read(65537)
                    prepare.require(len(data)<=65536 and hashlib.sha256(data).hexdigest()==IMAGE.split(':')[1],'image config digest')
                    obj=json.loads(data)
                    prepare.require(obj['rootfs']['diff_ids']==expected,'ordered layer config binding')
                    config=True
        while raw.read(1048576): pass
        prepare.require(process.wait(timeout=5)==0 and config and set(layers)==set(expected),'complete cached image stream')
    finally:
        timer.cancel()
        if process.poll() is None: process.kill()
        process.wait(timeout=5); process.stdout.close()
    files={}
    for key in expected:
        layer=layers[key]
        for prefix in layer['deleted']+layer['opaque']:
            files={name:pin for name,pin in files.items() if name!=prefix and not name.startswith(prefix+'/')}
        files.update(layer['files'])
    return dict(schema='issue3-cached-base-observation-v1',base=info,endpoint=ENDPOINT,
        files=files,layers=expected,image_config_verified=True,stream_bytes=raw.size,
        bytes_extracted=0,container_created=False,runtime_executed=False,
        ready=False,missing=['engine-specific emulator identity and binding','readonly extracted complete toolchain transport'],
        observed_unix=time.time())
