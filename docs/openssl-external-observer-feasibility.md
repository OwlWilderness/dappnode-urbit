# External execution observer: read-only feasibility and next probe

Status: **CONDITIONAL / NOT EXECUTED.** Owner selected read-only external-observer
feasibility, with an exact probe scope returned before execution. No observer,
tracer, debugger, compiler or runtime has been installed or started. No source
producer has been implemented and no retention integration is claimed.

## Current selected-field observations

Read-only commands: uname, command -v, df, sysctl hw.memsize, Docker info with
selected fields, Docker ps, Docker system df, and exact-image inspect with selected
fields. No engine-internal filesystem, private environment, logs or pier access.

- Host: Darwin 24.6.0 arm64; physical memory 17179869184 bytes.
- Docker server: 24.0.6, aarch64 Linux, 10 CPUs, 8225546240 memory bytes.
- Docker ps returned no active containers at the observation.
- Image `sha256:333864be7b25a51c4daf25156ced45424c1dfbfd27273e1aa2b320d95a356f8b`
  exists locally: linux/amd64, 127727419 bytes. Service entrypoint is
  `["sh", "/usr/local/bin/docker-entrypoint.sh"]`; declared volume `/urbit`.
- The historical synthetic-memory receipt establishes `/usr/bin/python3` in
  this image; no new image execution was used to recheck it.
- Host scratch filesystem free sample: 21298982912 bytes, 19.836223602294922 GiB.
- Docker storage summary: images 4.715GB, containers 1.051MB, local volumes
  9.662GB, build cache 8.674GB. These are usage reports, NOT guest free-space
  measurements or permission to reclaim anything.
- command -v found Docker but not host strace/gdb. A host macOS debugger would
  not by itself establish observation of the Linux guest compiler.

Neither Docker architecture nor the retained lifecycle's process names identify
QEMU versus Rosetta. No translator identity is asserted. No engine settings were
read or changed to try to identify it.

## Primary-source findings

Primary documentation consulted (URLs recorded for reproducibility):

```text
https://www.qemu.org/docs/master/user/main.html
https://strace.io/
https://man7.org/linux/man-pages/man1/strace.1.html
https://man7.org/linux/man-pages/man2/ptrace.2.html
https://sourceware.org/gdb/current/onlinedocs/gdb.html/Forks.html
https://sourceware.org/gdb/current/onlinedocs/gdb.html/Set-Catchpoints.html
https://sourceware.org/gdb/current/onlinedocs/gdb.html/Events-In-Python.html
https://sourceware.org/gdb/current/onlinedocs/gdb.html/Inferiors-In-Python.html
https://docs.docker.com/engine/security/seccomp/
```

1. QEMU user-mode documentation explicitly says guest ptrace is unimplemented,
   so ordinary strace does not work there. QEMU_STRACE is itself an incomplete
   diagnostic. This is a conditional blocker if that translator is in use, not
   proof of this engine's translator or observed failure.
2. strace relies on ptrace. Its textual syscall diagnostics are not an existing
   end-to-end structured argv/cwd/response-file producer for this recipe. Do not
   substitute a new text parser and claim the capture contract is solved.
3. GDB supports fork/exec catchpoints, retaining forked inferiors, Python stop and
   exit events, and byte-oriented `Inferior.read_memory`. These are usable building
   blocks, NOT a ready-made verified capture pipeline. `Inferior.arguments` is a
   shell-quoted string, not authoritative raw executed argv; do not parse it as one.
4. Linux ptrace documents same-parent TRACEME, memory/register reads and exec/exit
   events. Those prerequisites can be probed on a fresh synthetic child without
   installing GDB. A failure under translation/policy must remain a blocker.
5. Docker seccomp/capability policy can affect tracing. EPERM alone does not
   identify the translator. Do not respond by enabling privileged mode, host PID
   access, adding capabilities, unconfined seccomp or changing the engine.

No primary-source guarantee for Rosetta child-execution tracing was established.
No external observer is currently accepted. Native ARM tracing of translator host
syscalls is not automatically exact guest Zig argv/response provenance and is not
an approved workaround. QEMU remote-stub activation or a new native AMD64 engine
would be additional scopes, not transparent substitutions.

## Smallest useful next probe — proposed, requires approval and capacity

Purpose: determine whether guest ptrace prerequisites work at all in the current
AMD64-on-ARM topology before installing a debugger or building capture tooling.
This is synthetic capability characterization, NOT Zig/link capture acceptance.

### Exact resource/operation envelope

- One fresh, uniquely named/labeled retained container, one attempt, no retries.
  Freeze script/controller hashes and a fresh authorization/spent record first.
- Use only the exact already-local image ID above with explicit linux/amd64 and
  pull disabled. Override entrypoint with `/usr/bin/python3`; never invoke the
  service entrypoint, Vere, Zig, OpenSSL, curl, a package manager or build command.
- Read-only root; network none; no published ports; logging none; no auto-remove;
  UID/GID 65534; all capabilities dropped; no-new-privileges; retain default
  seccomp. No host PID namespace, Docker socket, engine mounts or existing volumes.
- Empty 1 MiB tmpfs over `/urbit` to prevent automatic anonymous-volume creation;
  4 MiB tmpfs `/tmp`. Bind only the frozen public probe script directory read-only.
- Limit 512 MiB memory and memory+swap, one CPU, 32 PIDs, core dumps disabled.
- At most 60 seconds active probe time, followed by at most 15 seconds to stop
  and verify the exact new container. Host watchdog may stop/kill ONLY that
  container on deadline/capacity failure; preserve it and all evidence afterward.
- Bound captured public output to 1 MiB; overflow fails the probe. No environment,
  maps, broad memory dump or unrelated process capture.
- Reuse the existing synthetic-probe admission: host free >=21 GiB, hard floor
  16 GiB and at most 128 MiB observed host growth. No threshold reduction is
  proposed. CURRENT SAMPLE FAILS ADMISSION. Recheck immediately before approval
  and again before create/start; do not infer Docker VM free space from host df.
- No image pull/build/install, cleanup, publication, private state or retained
  artifact alteration. Do not reuse any historical controller/spent attempt.

### Proposed probe behavior and evidence

A small Python stdlib/ctypes harness would create exactly one synthetic child.
Only that child calls PTRACE_TRACEME and stops itself. Parent uses bounded waits,
sets exec/exit/exit-kill options, reads a known short synthetic memory marker at
an address passed over a private pipe, and requests the guest general register
set. No broad process scan, attach to existing processes or memory write.

Then the child execs the same image's Python with a fixed harmless exit-7 program.
Require a successful exec event and matching final exit status, and retain only
bounded event metadata, API return values/errno and synthetic marker equality.
A negative errno, missing event, unsupported register layout, unexpected stop,
timeout or capacity failure ends the attempt without privilege escalation.

Implementation must explicitly test all-ones PEEKDATA/errno handling, architecture
and pointer widths, child reaping and timeout paths before any approved container
run. No script has been created or run under the read-only feasibility authority.

Read back the exact new container's image ID, platform, mounts, security/resource
settings and final exit/PID/OOM state; compare before/after selected resource
inventories. Require no new volume and no remaining active probe process. Preserve
existing resources unchanged. Parent API errors and child exit-7 must not be
confused with whole-container success or failure.

### Interpretation and subsequent boundary

PASS establishes only guest tracing prerequisites under this container policy.
It does not prove fork/vfork/clone coverage, complete argv/cwd/executable capture,
response-file retention, capture limits, final output association or preservation
of compiler behavior. FAIL blocks this local observer route under tested settings;
it does not justify changing translators/security policy or retrying automatically.

Only after a prerequisite PASS should a separate proposal pin a GDB build/package
and Python producer, cover execve/execveat plus all relevant child creation, capture
byte-safe argv/cwd/executable identity, and snapshot response bytes while the
selected child is stopped before it can complete. Parent/sibling scheduling,
response mutation, path namespaces and successful exit correlation need explicit
coverage. Unsupported response paths may instead be refused, but fallback must be
observed and cannot be hidden by logical verbose output. No same-version or
historical cache substitution.

A further bounded test against the exact pinned Zig binary must then demonstrate
actual capture including fallback/refusal and missing/cached/no-link cases before
recipe retention integration. None of these later gates are authorized by the
proposed capability probe. Header-graph design remains as recorded separately;
full parity, actual-library, new build, TLS, lifecycle, native and public release
acceptance remain open.
