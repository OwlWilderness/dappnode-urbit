#!/usr/bin/env python3
"""Assemble a NEW exact-baseline planet context/SDK assets. Never builds/runs.

No default target or host UDP port. Existing output refuses. The stock official
Dockerfile/descriptors are untouched; this is an explicit separate selection.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile

PACKAGE = 'issue3-planet.public.dappnode.eth'
VERSION = '0.1.0'
INPUTS = {
    'urbit': (42399776, '58d07af97926e04bc17184bc18f53e5fb11d84fed63bd9daf2fe4ceb04c86698'),
    'source-materials.tar.gz': (220821885, '8ed4fc8a6b4c1acba3e4e89860a4059e490feb3efaf2a818805770f24f65654f'),
    'candidate.json': (2045, '84f825a7ee511c9b4547bfd3b3f67b3fdff1ef769bec1a971bb2c932b6150991'),
    'inputs.json': (2067, '01c83a954542c6b7470f6e91fc6cf24069582563cc1d282d5046be4e98d81006'),
}


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024**2), b''): h.update(chunk)
    return h.hexdigest()


def verify_inputs(root):
    result = {}
    for name, (size, expected) in INPUTS.items():
        path = root/name
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size != size or digest(path) != expected:
            raise ValueError('Selected baseline input mismatch: ' + name)
        result[name] = {'bytes': size, 'sha256': expected}
    return result


def dockerfile(root):
    original = (root/'build/Dockerfile').read_text()
    second = original.index('\nFROM ', original.index('FROM ') + 1)
    recipe = '''FROM alpine@sha256:d56c381f961d307a21b3ca004cf1e3910f106644aefb1f43e654c8a56c4fd395 AS vere-release
COPY --chown=0:0 candidate/urbit /out/urbit
RUN echo '58d07af97926e04bc17184bc18f53e5fb11d84fed63bd9daf2fe4ceb04c86698  /out/urbit' | sha256sum -c - && chmod 0555 /out/urbit
''' + original[second:]
    recipe = recipe.replace('python3=3.14.8-r0', 'python3=3.14.10-r1')
    recipe = recipe.replace('# Preserve the accepted candidate\'s dependency pins; no runtime upgrade here.',
        'LABEL io.uvm.candidate="issue3-real-planet" io.uvm.distribution-cleared="false"\n# Exact retained ELF; platform Python source/notice review remains a release gate.')
    needle = 'COPY --chown=0:0 tools/browser-importer/web/index.html'
    recipe = recipe.replace(needle, '''COPY --chown=0:0 tools/browser-importer/planet.py /opt/importer/planet.py
COPY --chown=0:0 tools/browser-importer/planet_service.py /opt/importer/managed_service.py
COPY --chown=0:0 candidate/source-materials.tar.gz candidate/candidate.json candidate/inputs.json candidate/selection.json /usr/share/doc/uvm/candidate/
COPY --chown=0:0 candidate/notices/ /usr/share/doc/uvm/candidate/notices/
RUN echo '8ed4fc8a6b4c1acba3e4e89860a4059e490feb3efaf2a818805770f24f65654f  /usr/share/doc/uvm/candidate/source-materials.tar.gz' | sha256sum -c -
''' + needle)
    recipe = recipe.replace('EXPOSE 8443/tcp', 'EXPOSE 8443/tcp\nEXPOSE 9444/tcp')
    return recipe


def descriptors(root, identity, host_udp, public_origin=''):
    if public_origin:
        match = (re.fullmatch(r'https://([a-z0-9.-]+)', public_origin)
                 if isinstance(public_origin, str) else None)
        if not match:
            raise ValueError('A canonical HTTPS public origin without an explicit port is required.')
        # Match package_service.parse_origin's DNS contract, but never allow a port.
        host = match.group(1)
        labels = host.split('.')
        if (len(host) > 253 or len(labels) < 2 or
                any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                    for label in labels)):
            raise ValueError('A canonical DNS public hostname is required.')
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError('A DNS hostname is required.')
    if (not isinstance(identity, str) or not re.fullmatch(r'~[a-z]{6}-[a-z]{6}', identity) or
            type(host_udp) is not int or not 1024 <= host_udp <= 65535 or host_udp in (34343, 34344)):
        raise ValueError('An exact public planet literal and explicitly allocated non-star/non-UVM UDP port are required.')
    manifest = json.loads((root/'dappnode_package.json').read_text())
    manifest.update(name=PACKAGE, version=VERSION, shortDescription='Isolated issue3 planet trial',
                    description='Local-only upgraded embedded OpenSSL real-planet trial with authenticated one-shot fresh boot and issue19/20 lifecycle recovery. Not distribution-cleared or in-place upgrade qualified.')
    manifest['warnings']['onInstall'] = 'Separate trial only. No existing star/UVM volume. Networking key intake only through authenticated private owner UI. Never reset/retry interrupted creation. Image, TLS/DNS and source delivery require qualification before installation.'
    manifest['links']['admin'] = 'https://issue3-planet.public.dappnode.private:8443'
    manifest['links']['landscape'] = 'https://ship.issue3-planet.public.dappnode.private:8443'
    compose = (root/'docker-compose.yml').read_text()
    compose = compose.replace('ship.uvm.public.dappnode.eth:0.1.3', 'ship.'+PACKAGE+':'+VERSION)
    compose = compose.replace('ship_data', 'planet_trial_data')
    compose = compose.replace('uvm.public.dappnode.private', 'issue3-planet.public.dappnode.private')
    compose = compose.replace('      IMPORTER_BOOTSTRAP_SHA256:', '      URBIT_PLANET: '+json.dumps(identity)+'\n      URBIT_PUBLIC_SHIP_ORIGIN: '+json.dumps(public_origin)+'\n      IMPORTER_BOOTSTRAP_SHA256:')
    compose = compose.replace('      - "8443/tcp"', '      - "8443/tcp"\n      - "9444/tcp"')
    compose = compose.replace('    expose:', '    ports:\n      - "'+str(host_udp)+':34343/udp"\n    expose:')
    return {'dappnode_package.json': manifest, 'docker-compose.yml': compose}


def assemble(root, artifact, output, identity, host_udp, public_origin=''):
    assets = descriptors(root, identity, host_udp, public_origin)
    assets['setup-wizard.yaml'] = (root/'setup-wizard.yaml').read_text().replace(
        'uvm.public.dappnode.private', 'issue3-planet.public.dappnode.private')
    bindings = verify_inputs(artifact)  # no output before authentication/config validation
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    context = output/'context'; context.mkdir()
    # Fixed production closure only; never copy runtime volumes, private task
    # records, arbitrary repository files or the older issue3 runtime.py.
    paths = set(json.loads((root/'build/notice-files.json').read_text())['files'])
    paths |= {'build/notice-files.json', 'build/docker-entrypoint.sh', 'build/volume_guard.py',
              'build/vere-release.json', 'build/install_vere.py'}
    recipe = dockerfile(root)
    for line in recipe.splitlines():
        if line.startswith('COPY --chown=0:0 tools/'):
            paths.update(line.split()[2:-1])
    for name in sorted(paths):
        source = root/name
        if source.is_symlink() or not source.is_file(): raise ValueError('Source closure refused: '+name)
        target = context/name; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    (context/'build/Dockerfile').write_text(recipe)
    (context/'.dockerignore').write_text((root/'.dockerignore').read_text() + '\n!candidate/\n!candidate/**\n!tools/browser-importer/planet.py\n!tools/browser-importer/planet_service.py\n')
    candidate = context/'candidate'; candidate.mkdir()
    for name in INPUTS:
        shutil.copyfile(artifact/name, candidate/name)
        if digest(candidate/name) != bindings[name]['sha256']: raise ValueError('Copy changed selected input')
    (candidate/'urbit').chmod(0o555)
    notice_root = candidate/'notices'; notice_root.mkdir()
    # Export notice bytes from the authenticated corresponding-source archive;
    # never tar.extract(), follow links or execute source/build tools.
    with tarfile.open(candidate/'source-materials.tar.gz') as archive:
        for member in archive:
            name = PurePosixPath(member.name)
            if (name.is_absolute() or '..' in name.parts): raise ValueError('Unsafe source member')
            base = name.name.upper()
            if member.isfile() and any(base.startswith(t) for t in ('LICENSE', 'COPYING', 'COPYRIGHT', 'NOTICE', 'AUTHORS', 'THANKS')):
                if member.size > 4*1024**2: raise ValueError('Oversized notice')
                target = notice_root/str(name)
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source, target.open('xb') as dest:
                    shutil.copyfileobj(source, dest)
    selection = {'selection': 'retained-amd64-curl-baseline', 'architecture': 'linux/amd64',
                 'files': bindings, 'distribution_cleared': False,
                 'platform_source_review_required': 'Python 3.14.10-r1 and final image packages',
                 'owner_target': identity, 'host_udp': host_udp, 'public_ship_origin': public_origin}
    (candidate/'selection.json').write_text(json.dumps(selection, indent=2)+'\n')
    for name, value in assets.items():
        (output/name).write_text(json.dumps(value, indent=2)+'\n' if isinstance(value,dict) else value)
    # SDK asset context points to the assembled subdirectory, not a live repo.
    compose=output/'docker-compose.yml'
    compose.write_text(compose.read_text().replace('context: .', 'context: ./context'))
    if (root/'avatar.png').is_file(): shutil.copyfile(root/'avatar.png', output/'avatar.png')
    inventory = {str(p.relative_to(output)): {'bytes': p.stat().st_size, 'sha256': digest(p)}
                 for p in sorted(output.rglob('*')) if p.is_file()}
    (output/'assembly.json').write_text(json.dumps({'selection': selection, 'files': inventory,
        'image_built': False, 'ship_run': False, 'install_qualified': False}, indent=2)+'\n')
    return output


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--planet', required=True)
    parser.add_argument('--host-udp', type=int, required=True)
    parser.add_argument('--public-ship-origin', default='',
                        help='Optional approved HTTPS origin; empty keeps the public backend disabled')
    args=parser.parse_args()
    assemble(Path(__file__).resolve().parents[1], args.artifact_root, args.output, args.planet, args.host_udp, args.public_ship_origin)
    print('New context and SDK assets assembled; no image build or ship execution performed.')

if __name__=='__main__': main()
