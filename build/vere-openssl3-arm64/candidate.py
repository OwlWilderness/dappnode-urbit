"""Pinned, build-only Vere candidate. Never invokes Vere or accesses a pier.

--source-check only verifies/extracts public inputs and applies source changes.
--build is for the separately authorized isolated builder, not the host package.
Every output directory is single-use, including failed or interrupted attempts.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import shutil
import subprocess
import tarfile
import time
import urllib.request

HERE = Path(__file__).resolve().parent
CAPACITY_CHECK_BYTES = 8 * 1024**2
COPY_CHUNK_BYTES = 1024**2


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify_input(data, item):
    if len(data) != item['bytes'] or sha(data) != item['sha256']:
        raise ValueError('input hash/size mismatch')


def check_member(member, root):
    path = PurePosixPath(member.name)
    if (path.is_absolute() or '..' in path.parts or not path.parts or
            path.parts[0] != root or not (member.isfile() or member.isdir())):
        raise ValueError('unsafe source archive member')


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('source preimage mismatch (not a retryable patch)')
    return text.replace(old, new, 1)


def patch_build(text):
    text = replace_once(text, 'const VERSION = "4.6";',
                        'const VERSION = "4.6-uvm-openssl3.5.9";')
    start = text.index('    // Parse short git rev\n')
    end = text.index('    // Binary version\n', start)
    return text[:start] + '    const git_rev = "8ddc4b7";\n\n' + text[end:]


def patch_report(text):
    return replace_once(text,
        '  printf("openssl: %s\\n", SSLeay_version(SSLEAY_VERSION));',
        '#if OPENSSL_VERSION_MAJOR != 3 || OPENSSL_VERSION_MINOR != 5 || OPENSSL_VERSION_PATCH != 9\n'
        '#error "UVM candidate requires the pinned OpenSSL 3.5.9 headers"\n'
        '#endif\n'
        '  printf("openssl: %s\\n", OpenSSL_version(OPENSSL_VERSION));\n'
        '  printf("openssl-headers: %s\\n", OPENSSL_VERSION_TEXT);')


def patch_allocator(text):
    return replace_once(text,
        '  /* Initialize OpenSSL with loom allocation functions. */\n#ifndef U3_URTH_MASS',
        '  /* OpenSSL 3 retains TLS/provider state beyond temporary road lifetimes.\n'
        '   * Keep its default process-lifetime allocator; do not change GMP here. */\n'
        '#if !defined(U3_URTH_MASS) && OPENSSL_VERSION_NUMBER < 0x30000000L')


def object_adapter(members):
    """Rearchive actual generated objects, never put an archive inside another."""
    lines = ['const std = @import("std");', 'pub fn build(b: *std.Build) void {',
             '    const target = b.standardTargetOptions(.{});',
             '    const optimize = b.standardOptimizeOption(.{});',
             '    if (target.result.cpu.arch != .aarch64 or target.result.os.tag != .linux or target.result.abi != .musl)',
             '        @panic("UVM OpenSSL candidate supports only aarch64-linux-musl");']
    for lib in ('crypto', 'ssl'):
        names = members[lib]
        if not names or len(names) != len(set(names)) or any(
                not re.fullmatch(r'[A-Za-z0-9_.+-]+\.o', name) for name in names):
            raise ValueError('unsafe or duplicate OpenSSL object member')
        lines += [f'    const {lib} = b.addLibrary(.{{ .name = "{lib}", .linkage = .static,',
                  '        .root_module = b.createModule(.{ .target = target, .optimize = optimize }) });',
                  f'    {lib}.linkLibC();',
                  f'    {lib}.installHeadersDirectory(b.path("prebuilt/include/openssl"), "openssl", .{{}});']
        for name in sorted(names):
            lines.append(f'    {lib}.addObjectFile(b.path("prebuilt/{lib}/{name}"));')
        if lib == 'ssl':
            lines.append('    ssl.linkLibrary(crypto);')
        lines.append(f'    b.installArtifact({lib});')
    return '\n'.join(lines + ['}', ''])


def vere_build_command(zig):
    # Keep the CPU-query default used by Vere's exact target whitelist.
    return [zig, 'build', '-Dtarget=aarch64-linux-musl',
            '-Drelease=true', '-Dpace=once', '-j2', '--summary', 'all', '--verbose-link']


def image_build_command(context, export, attempt_id):
    """For a fresh authorized supervisor only; does not launch or grant a retry."""
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,80}', attempt_id):
        raise ValueError('invalid fresh attempt ID')
    return ['docker', 'buildx', 'build', '--platform=linux/arm64', '--progress=plain',
            '--target=evidence', '--build-arg', 'UVM_BUILD_ATTEMPT_ID=' + attempt_id,
            '--output=type=local,dest=' + str(export), '--file=' + str(context / 'Dockerfile'), str(context)]


def tree_hashes(root):
    """Bind cached generated source, headers and archives, not merely versions."""
    if not root.is_dir() or root.is_symlink():
        raise ValueError('OpenSSL cache tree missing or linked')
    hashes = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError('OpenSSL cache contains a non-regular entry')
        if path.is_file():
            with path.open('rb') as file:
                digest = hashlib.sha256()
                for chunk in iter(lambda: file.read(1024**2), b''):
                    digest.update(chunk)
            hashes[str(path.relative_to(root))] = digest.hexdigest()
    return hashes


class CapacityGuard:
    """Sample at bounded byte/time intervals, not once per gzip header/write."""
    def __init__(self, output):
        self.output = output
        self.last_check = float('-inf')
        self.pending_bytes = 0

    def check(self, written=0, force=False):
        self.pending_bytes += written
        now = time.monotonic()
        if not force and self.pending_bytes < CAPACITY_CHECK_BYTES and now - self.last_check < 5:
            return
        used_kib = None
        for attempt in range(3):
            try:
                used_kib = int(subprocess.check_output(
                    ['du', '-sk', str(self.output)], timeout=15,
                    stderr=subprocess.PIPE).split()[0])
                break
            except subprocess.CalledProcessError as exc:
                lines = (exc.stderr or b'').decode(errors='replace').splitlines()
                prefixes = tuple('du: ' + str(self.output / cache / 'tmp') + '/'
                                 for cache in ('zig-local-cache', 'zig-cache'))
                transient = (exc.returncode == 1 and lines and all(
                    line.startswith(prefixes) and line.endswith(': No such file or directory')
                    for line in lines))
                if not transient or attempt == 2:
                    raise
                time.sleep(0.1)
        assert used_kib is not None
        if used_kib > 6 * 1024**2 or shutil.disk_usage(self.output).free < 8 * 1024**3:
            raise RuntimeError('builder capacity limit reached')
        self.last_check = time.monotonic()
        self.pending_bytes = 0

    def copy_file(self, source, destination):
        with source.open('rb') as reader, destination.open('xb', buffering=0) as writer:
            shutil.copyfileobj(reader, GuardedWriter(writer, self), length=COPY_CHUNK_BYTES)


class GuardedWriter(io.BufferedIOBase):
    def __init__(self, writer, guard):
        self.writer = writer
        self.guard = guard

    def write(self, data):
        self.guard.check()
        written = self.writer.write(data)
        self.guard.check(written=written)
        return written

    def tell(self):
        return self.writer.tell()


class BuildStopped(BaseException):
    """SIGTERM is a stopped attempt, not a compiler error or a retry grant."""


def stop_on_sigterm(signum, frame):
    raise BuildStopped('SIGTERM')


class StageDiagnostics:
    """Bounded public build telemetry; never inspect cmdline, env or ship data."""
    def __init__(self, attempt, log_path, cwd, interval=30, quiet_seconds=120):
        self.attempt, self.log_path, self.cwd = attempt, log_path, cwd
        self.interval, self.quiet_seconds = interval, quiet_seconds
        self.offset = 0
        self.stream_limit = 2 * 1024**2
        self.last_sample = float('-inf')
        self.last_activity = time.monotonic()
        self.previous = None
        self.capped = False

    @staticmethod
    def process_sample(pgid, proc=Path('/proc')):
        if not proc.is_dir():
            return dict(cpu_ticks=None, processes=None)
        ticks, count = 0, 0
        for directory in proc.iterdir():
            if not directory.name.isdigit():
                continue
            try:
                # stat fields 3 onwards; comm may itself contain parentheses.
                fields = (directory / 'stat').read_text().rsplit(')', 1)[1].split()
                if int(fields[2]) == pgid:
                    ticks += sum(int(v) for v in fields[11:15])
                    count += 1
            except (OSError, ValueError, IndexError):
                continue  # A sampled process may exit during enumeration.
        return dict(cpu_ticks=ticks if count else None, processes=count)

    def object_sample(self):
        count = size = scanned = 0
        fingerprint = hashlib.sha256()
        deadline = time.monotonic() + 1
        complete = True
        for directory, dirs, files in os.walk(self.cwd, followlinks=False):
            scanned += 1
            if scanned > 100000 or time.monotonic() > deadline:
                complete = False
                break
            dirs[:] = sorted(d for d in dirs if d != '.git')
            for name in sorted(files):
                scanned += 1
                if scanned > 100000 or time.monotonic() > deadline:
                    complete = False
                    break
                if not (name.endswith(('.o', '.a', '.bin')) or name == 'urbit'):
                    continue
                path = Path(directory) / name
                try:
                    if path.is_symlink():
                        continue
                    stat = path.stat()
                except OSError:
                    continue
                count += 1
                size += stat.st_size
                fingerprint.update(f'{path.relative_to(self.cwd)}:{stat.st_size}:{stat.st_mtime_ns}\n'.encode())
            if not complete:
                break
        return dict(object_files=count, object_bytes=size, object_scan_complete=complete,
                    object_metadata_sha256=fingerprint.hexdigest())

    def update(self, pgid, force=False):
        size = self.log_path.stat().st_size
        if self.offset < min(size, self.stream_limit):
            with self.log_path.open('rb') as log:
                log.seek(self.offset)
                data = log.read(min(32768, self.stream_limit - self.offset))
            self.offset += len(data)
            self.attempt.event('compiler-output', text=data.decode(errors='replace'))
        if size > self.stream_limit and not self.capped:
            self.capped = True
            self.attempt.event('compiler-stream-capped', limit_bytes=self.stream_limit,
                               detail='Full log is inside the build filesystem only; metrics and final tail continue')
        now = time.monotonic()
        if not force and now - self.last_sample < self.interval:
            return
        sample = dict(log_bytes=size, **self.process_sample(pgid), **self.object_sample())
        signature = (size, sample['cpu_ticks'], sample['object_metadata_sha256'])
        if signature != self.previous:
            self.last_activity = now
        self.previous, self.last_sample = signature, now
        quiet = round(now - self.last_activity, 3)
        self.attempt.event('activity', quiet_seconds=quiet,
                           assessment='possibly-stalled' if quiet >= self.quiet_seconds else 'observing',
                           stall_proven=False, **sample)

    def tail(self):
        if self.log_path.is_file():
            with self.log_path.open('rb') as log:
                log.seek(max(0, log.seek(0, 2) - 12000))
                self.attempt.event('compiler-tail', text=log.read().decode(errors='replace'))


class Attempt:
    def __init__(self, output):
        # Exclusive creation is the replay interlock; never remove on failure.
        output.mkdir(mode=0o700, parents=False, exist_ok=False)
        self.output = output
        self.current = 'admitted'
        self.event('admitted')

    def event(self, status, *, mirror=None, **values):
        entry = dict(stage=self.current, status=status, **values)
        for path in [self.output / 'events.jsonl'] + ([mirror] if mirror else []):
            with path.open('a') as log:
                log.write(json.dumps(entry, sort_keys=True) + '\n')
                log.flush()
                os.fsync(log.fileno())
        print(json.dumps(entry, sort_keys=True), flush=True)

    def run(self, stage, argv, cwd, env, timeout=1800):
        self.current = stage
        self.event('entered', argv=argv)
        before = time.monotonic()
        guard = CapacityGuard(self.output)
        stopped = False
        def request_stop(signum, frame):
            # Latch rather than raise during Popen: even a signal arriving
            # during launch must leave us with the child's process-group ID.
            nonlocal stopped
            stopped = True
        previous = signal.signal(signal.SIGTERM, request_stop)
        process = None
        diagnostics = StageDiagnostics(self, self.output / (stage + '.log'), cwd)
        try:
            # Public compiler output only, never ship output/environment dumps.
            with (self.output / (stage + '.log')).open('xb') as log:
                process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=log,
                                           stderr=subprocess.STDOUT, start_new_session=True)
                while True:
                    if stopped:
                        raise BuildStopped('SIGTERM')
                    diagnostics.update(process.pid)
                    if process.poll() is not None:
                        break
                    if time.monotonic() - before > timeout:
                        raise subprocess.TimeoutExpired(argv, timeout)
                    if env.get('UVM_BUILD_CAPACITY_GUARD') == '1':
                        guard.check()
                    try:
                        process.wait(timeout=0.2)
                    except subprocess.TimeoutExpired:
                        continue
                if stopped:
                    raise BuildStopped('SIGTERM')
        except BaseException as error:
            try:
                if process is not None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass  # The group already exited; still reap our child.
                    process.wait(timeout=5)
            finally:
                self.event('stopped', limit_seconds=timeout, reason=type(error).__name__,
                           child_reaped=process is not None and process.poll() is not None)
                diagnostics.tail()
            raise
        finally:
            signal.signal(signal.SIGTERM, previous)
        self.event('returned', exit_code=process.returncode,
                   elapsed_seconds=round(time.monotonic() - before, 3))
        diagnostics.update(process.pid, force=True)
        if process.returncode:
            # Only public compiler output. Expose a bounded useful failure tail
            # even if BuildKit cannot export a failed layer's evidence directory.
            diagnostics.tail()
            raise RuntimeError(stage + ' failed; inspect the retained build log')


def prepare(attempt, lock, input_dir):
    trees = {}
    materials = attempt.output / 'materials'
    materials.mkdir()
    for name, item in lock['inputs'].items():
        attempt.current = 'input-' + name
        filename = {'vere': 'vere-8ddc4b7.tar.gz', 'openssl': 'openssl-3.5.9.tar.gz',
                    'zig': 'zig-aarch64-linux-0.15.2.tar.xz'}[name]
        if input_dir is None:
            with urllib.request.urlopen(item['url'], timeout=90) as response:
                if not response.geturl().startswith('https://'):
                    raise ValueError('insecure input redirect')
                data = response.read(item['bytes'] + 1)
        else:
            with (input_dir / filename).open('rb') as source:
                data = source.read(item['bytes'] + 1)
        verify_input(data, item)
        archive_path = materials / filename
        archive_path.write_bytes(data)
        with tarfile.open(archive_path) as archive:
            members = archive.getmembers()
            for member in members:
                check_member(member, item['root'])
            # All members were restricted to regular files/directories within root.
            archive.extractall(attempt.output, members=members)
        trees[name] = attempt.output / item['root']
        attempt.event('verified', sha256=item['sha256'])
    source = trees['vere']
    for name, expected in lock['source_preimages'].items():
        if sha((source / name).read_bytes()) != expected:
            raise ValueError('Vere source preimage hash mismatch: ' + name)
    main = source / 'pkg/vere/main.c'
    if sha(main.read_bytes()) != '01e9f2de08464b136c46e2c1ec395161c64c7be4ce01f49072344ae62e2f1781':
        raise ValueError('Vere report source preimage hash mismatch')
    build = source / 'build.zig'
    build.write_text(patch_build(build.read_text()))
    main.write_text(patch_report(main.read_text()))
    manage = source / 'pkg/noun/manage.c'
    manage.write_text(patch_allocator(manage.read_text()))
    # Keep the package identity; remove the obsolete OpenSSL/nasm/SDK graph.
    (source / 'ext/openssl/build.zig.zon').write_text(
        '.{ .name = .openssl, .fingerprint = 0x773a47f1ba90827f,\n'
        '   .version = "3.5.9", .dependencies = .{}, .paths = .{ "" } }\n')
    # Refuse accidental builds until the actual generated objects are available.
    (source / 'ext/openssl/build.zig').write_text(
        '@compileError("Run the authorized candidate builder to generate OpenSSL objects");\n')
    # Dead mirrors are changed only at the URL. Zig must still verify the
    # original package-content hashes; an alternate URL is not identity proof.
    for relative, old, new in (
        ('ext/gmp/build.zig.zon',
         'https://ftp.fr.openbsd.org/pub/OpenBSD/distfiles/gmp-6.3.0.tar.xz',
         'https://ftp.gnu.org/gnu/gmp/gmp-6.3.0.tar.xz'),
        ('ext/sigsegv/build.zig.zon',
         'https://ftp.fr.openbsd.org/pub/OpenBSD/distfiles/libsigsegv-2.14.tar.gz',
         'https://ftp.gnu.org/gnu/libsigsegv/libsigsegv-2.14.tar.gz'),
        ('ext/natpmp/build.zig.zon',
         'http://deb.debian.org/debian/pool/main/libn/libnatpmp/libnatpmp_20230423.orig.tar.gz',
         'https://deb.debian.org/debian/pool/main/libn/libnatpmp/libnatpmp_20230423.orig.tar.gz'),
    ):
        file = source / relative
        file.write_text(replace_once(file.read_text(), old, new))
    manifests = {str(p.relative_to(source)): sha(p.read_bytes())
                 for p in sorted(source.rglob('build.zig.zon'))}
    (attempt.output / 'dependency-manifests.json').write_text(json.dumps(manifests, indent=2) + '\n')
    shutil.copyfile(HERE / 'inputs.json', attempt.output / 'inputs.json')
    shutil.copyfile(HERE / 'candidate.py', attempt.output / 'candidate.py')
    attempt.current = 'source-preparation'
    attempt.event('passed', compiled=False, vere_executed=False)
    return trees


def compile_candidate(attempt, lock, trees, *, openssl_only=False, openssl_cache=None):
    if os.uname().sysname != 'Linux' or os.uname().machine != 'aarch64':
        raise ValueError('build requires the pinned Linux ARM64 builder')
    if shutil.disk_usage(attempt.output).free < 14 * 1024**3:
        raise ValueError('builder admission requires 6 GiB budget plus 8 GiB reserve')
    # Snapshot builder-resident inputs before compilation; validate and deliver
    # these exact bytes, never a later host-side copy of the recipe or APK DB.
    evidence = {'Dockerfile': (HERE / 'Dockerfile').read_bytes(),
                'builder-apks.json': (HERE / 'builder-apks.json').read_bytes(),
                'builder-apk-db.txt': Path('/lib/apk/db/installed').read_bytes()}
    for name, content in evidence.items():
        (attempt.output / name).write_bytes(content)
    tools = json.loads(evidence['builder-apks.json'])
    installed = {}
    for block in evidence['builder-apk-db.txt'].decode().split('\n\n'):
        fields = dict(line.split(':', 1) for line in block.splitlines() if ':' in line)
        if 'P' in fields:
            installed[fields['P']] = fields
    for package in tools['packages']:
        if any(installed.get(package['P'], {}).get(key) != value for key, value in package.items()):
            raise ValueError('builder package identity mismatch: ' + package['P'])
    zig = str(trees['zig'] / 'zig')
    source, openssl = trees['vere'], trees['openssl']
    temporary = attempt.output / 'tmp'
    temporary.mkdir()
    env = dict(os.environ, LC_ALL='C', TZ='UTC', SOURCE_DATE_EPOCH='1782999240',
               TMPDIR=str(temporary), UVM_BUILD_CAPACITY_GUARD='1',
               ZIG_GLOBAL_CACHE_DIR=str(attempt.output / 'zig-cache'),
               CC=zig + ' cc -target aarch64-linux-musl -mcpu=baseline',
               AR=zig + ' ar', RANLIB=zig + ' ranlib')
    cache_binding = {name: sha((attempt.output / name).read_bytes()) for name in
                     ('inputs.json', 'candidate.py', 'Dockerfile', 'builder-apks.json', 'builder-apk-db.txt')}
    cache_digest = None
    if openssl_cache is not None:
        cache_bytes = (openssl_cache / 'openssl-cache.json').read_bytes()
        cached = json.loads(cache_bytes)
        openssl = openssl_cache / lock['inputs']['openssl']['root']
        if (cached.get('bindings') != cache_binding or cached.get('status') != 'compiled' or
                cached.get('tree_sha256') != tree_hashes(openssl)):
            raise ValueError('OpenSSL cache identity/content mismatch')
        for name in ('libcrypto.a', 'libssl.a'):
            if name not in cached['tree_sha256']:
                raise ValueError('OpenSSL cache lacks compiled archive')
        trees['openssl'] = openssl
        cache_digest = sha(cache_bytes)
        (attempt.output / 'openssl-cache.json').write_bytes(cache_bytes)
        # Carry original public compiler diagnostics into the final delivery.
        cache_logs = attempt.output / 'openssl-cache-evidence'
        cache_logs.mkdir()
        guard = CapacityGuard(attempt.output)
        for path in sorted(openssl_cache.glob('openssl-*.log')):
            guard.copy_file(path, cache_logs / path.name)
        guard.copy_file(openssl_cache / 'events.jsonl', cache_logs / 'events.jsonl')
        attempt.current = 'openssl-cache'
        attempt.event('verified', cache_sha256=cache_digest, compiled_here=False)
    else:
        attempt.run('openssl-configure', ['perl', 'Configure', 'linux-aarch64',
                    'no-shared', 'no-module', 'no-tests', 'no-apps', 'no-docs',
                    '--prefix=/opt/uvm-openssl3', '--openssldir=/opt/uvm-openssl3/ssl',
                    '--libdir=lib', '-fPIC'], openssl, env)
        attempt.run('openssl-build', ['make', '-j2', 'build_libs'], openssl, env)
        attempt.run('openssl-configuration', ['perl', 'configdata.pm', '--dump'], openssl, env)
    if openssl_only:
        if openssl_cache is not None:
            raise ValueError('OpenSSL cache stage cannot consume another attempt')
        hashes = tree_hashes(openssl)
        if not all(name in hashes for name in ('libcrypto.a', 'libssl.a')):
            raise ValueError('OpenSSL cache lacks compiled archive')
        (attempt.output / 'openssl-cache.json').write_text(json.dumps(
            dict(status='compiled', bindings=cache_binding, tree_sha256=hashes,
                 vere_executed=False), indent=2) + '\n')
        CapacityGuard(attempt.output).check(force=True)
        attempt.current = 'openssl-cache'
        attempt.event('passed', vere_compiled=False, vere_executed=False)
        return
    prebuilt = source / 'ext/openssl/prebuilt'
    prebuilt.mkdir()
    shutil.copytree(openssl / 'include', prebuilt / 'include')
    members = {}
    archive_hashes = {}
    for lib in ('crypto', 'ssl'):
        archive = openssl / ('lib' + lib + '.a')
        names = subprocess.check_output([zig, 'ar', 't', str(archive)], env=env, text=True).splitlines()
        # Validate names and duplicates before extraction (no filesystem escapes).
        object_adapter({'crypto': names, 'ssl': names})
        destination = prebuilt / lib
        destination.mkdir()
        attempt.run('openssl-extract-' + lib, [zig, 'ar', 'x', str(archive)], destination, env)
        members[lib] = names
        archive_hashes[lib] = sha(archive.read_bytes())
    (source / 'ext/openssl/build.zig').write_text(object_adapter(members))
    (attempt.output / 'openssl-archives.json').write_text(json.dumps(
        dict(sha256=archive_hashes, members=members), indent=2) + '\n')
    attempt.run('vere-build', vere_build_command(zig), source, env)
    binary = source / 'zig-out/aarch64-linux-musl/urbit'
    data = binary.read_bytes()
    if data[:6] != b'\x7fELF\x02\x01' or int.from_bytes(data[18:20], 'little') != 183:
        raise ValueError('candidate is not Linux ARM64 ELF')
    if b'OpenSSL 3.5.9' not in data or b'OpenSSL 1.1.1w' in data:
        raise ValueError('candidate embedded OpenSSL version marker rejected')
    attempt.current = 'candidate-output'
    guard = CapacityGuard(attempt.output)
    guard.check(force=True)
    guard.copy_file(binary, attempt.output / 'urbit')
    (attempt.output / 'urbit').chmod(0o555)
    changed = ['build.zig', 'pkg/vere/main.c', 'pkg/noun/manage.c', 'ext/openssl/build.zig',
               'ext/openssl/build.zig.zon', 'ext/gmp/build.zig.zon',
               'ext/sigsegv/build.zig.zon', 'ext/natpmp/build.zig.zon']
    receipt = dict(candidate=lock['candidate'], executable_sha256=sha(data),
                   executable_bytes=len(data), architecture='linux/arm64',
                   source_changes={name: sha((source / name).read_bytes()) for name in changed},
                   inputs_sha256=sha((attempt.output / 'inputs.json').read_bytes()),
                   recipe_sha256=sha((attempt.output / 'candidate.py').read_bytes()),
                   dockerfile_sha256=sha(evidence['Dockerfile']),
                   builder_apks_sha256=sha(evidence['builder-apks.json']),
                   builder_apk_db_sha256=sha(evidence['builder-apk-db.txt']),
                   openssl_cache_sha256=cache_digest,
                   static_version_marker=True, dependency_runtime_report=False,
                   vere_executed=False, image_bound=False, lifecycle_passed=False,
                   reproducibility_verified=False, distribution_cleared=False)
    (attempt.output / 'candidate.json').write_text(json.dumps(receipt, indent=2) + '\n')
    delivery = attempt.output / 'delivery'
    delivery.mkdir()
    for file in attempt.output.iterdir():
        if file.is_file():
            guard.copy_file(file, delivery / file.name)
            if file.name == 'urbit':
                (delivery / file.name).chmod(0o555)

    # Preserve exact archives, patched source, generated headers/configuration,
    # and fetched dependency source. Build caches/objects are not source delivery.
    def source_filter(member):
        parts = PurePosixPath(member.name).parts
        if '.zig-cache' in parts or 'zig-out' in parts or member.name.endswith(('.o', '.a')):
            return None
        return member
    with (delivery / 'source-materials.tar.gz').open('xb', buffering=0) as raw:
        with tarfile.open(fileobj=GuardedWriter(raw, guard), mode='w:gz') as archive:
            for folder in (attempt.output / 'materials', source, openssl, attempt.output / 'zig-cache/p',
                           attempt.output / 'openssl-cache-evidence'):
                if folder.is_dir():
                    archive.add(folder, arcname=folder.name, filter=source_filter)
    # Include the archive trailer/close and every delivery copy in the final
    # capacity decision. No success is emitted for partial evidence.
    guard.check(force=True)
    attempt.event('passed', mirror=delivery / 'events.jsonl', **receipt)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--source-check', action='store_true')
    mode.add_argument('--build', action='store_true')
    mode.add_argument('--openssl-only', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--input-dir', type=Path)
    parser.add_argument('--openssl-cache', type=Path)
    parser.add_argument('--attempt-id')
    args = parser.parse_args()
    if args.openssl_cache and (not args.build or not args.attempt_id):
        parser.error('--openssl-cache requires --build and a fresh --attempt-id')
    if args.attempt_id and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,80}', args.attempt_id):
        parser.error('invalid fresh attempt ID')
    lock = json.loads((HERE / 'inputs.json').read_text())
    attempt = Attempt(args.output.resolve())
    if args.attempt_id:
        attempt.event('authorization-label', attempt_id=args.attempt_id)
    previous = signal.signal(signal.SIGTERM, stop_on_sigterm)
    try:
        trees = prepare(attempt, lock, args.input_dir)
        if args.openssl_only or args.openssl_cache:
            compile_candidate(attempt, lock, trees, openssl_only=args.openssl_only,
                              openssl_cache=args.openssl_cache)
        elif args.build:
            compile_candidate(attempt, lock, trees)
    except BuildStopped:
        attempt.event('stopped', reason='SIGTERM')
        raise SystemExit(128 + signal.SIGTERM)
    except Exception as error:
        attempt.event('failed', error_type=type(error).__name__, detail=str(error))
        raise SystemExit(1)
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == '__main__':
    main()
