# OpenSSL b04 build and report milestone

Status as of October 31, 2026, for issue #3. **The b04 build, static checks and
exact-binary dependency report passed; runtime, package and release qualification
remain open.** This is a sanitized summary of retained build/report evidence and
subsequent source/host preparation, not a release or installation procedure.

## Verified artifact and report

One owned AMD64 build completed on October 30, 2026, with build-client exit 0,
complete artifact export and settled execution. The exported executable is:

| Property | Recorded value |
| --- | --- |
| Size | 42467624 bytes |
| Mode | `0555` |
| SHA256 | `f2eba68682650ab6d9712017781612f4dbc3c01411c1ba5c7c4ecbb0f186b6b5` |
| Format | ELF64, little-endian AMD64; no `PT_INTERP` or `PT_DYNAMIC` |

Static/source readback passed the required owning-arena, shutdown and GMP symbol
checks, frozen recipe/source bindings and retained library/configuration hashes.
The report qualification additionally checked callback-address registration,
startup reachability, GMP registration and normal libc exit-cleanup calls.
These checks do not prove complete shutdown call-flow or dynamic allocation and
consumer lifetimes. The 128 MiB arena is experimental, not production sizing.

The exact executable ran **once with `-R`** on October 30, 2026,
21:16:51.154–21:16:51.212 EDT (October 31, 01:16:51 UTC). It exited 0; independent
readback recorded exited, PID 0 and no OOM kill. Its hash matched before and after
execution. Linked and compiled-header reports agreed on **OpenSSL 3.5.9** and
**curl 8.23.0**. Execution was AMD64 on an AArch64 engine, not native AMD64
Dappnode acceptance. **No ship or pier was started.** `-R` returns before ship
startup and is not a crypto/TLS workload test. Build and report grants are closed;
this milestone grants no retry or further execution authority.

Retained original and Zig-adapted library archives are distinct artifacts.
Their verified hashes and matching version reports are **not authenticated
final-link inputs or actual compile-header provenance**. A retained-library probe
can provide useful bounded evidence without resolving that mapping, but cannot
be promoted to authenticated final-executable acceptance. Additional provenance
capture is not, by itself, a reason to repeat the successful dependency build.

## Preparation completed, execution still open

The b04-specific package binding, package plan/stage/independent-verification
implementation and recipient source-companion assembler/build-relink guidance
are implemented and host-tested. Plans and synthetic fixtures are preparation,
not actual ELF staging, companion delivery, source sufficiency or distribution
clearance. The real executable has not been staged into a package context, and
no b04 image build or selected-file/APK readback has run. Packaging source changes
alone do not supply the missing staged executable or a qualified image.

The bounded crypto/TLS probe and its outer CLI/transport, independent settlement,
Linux bootstrap, artifact channel and selective controller/toolchain staging are
also implemented and host-tested. These are not missing runner implementations.
Real Linux controls and actual-library crypto/TLS cases remain unexecuted. The
next experiment needs daemon-specific AMD64 handler provenance (or a separately
reviewed engine-managed-platform/native AMD64 alternative), approved physical
staging, fresh profiles/admissions and separate exact compile/run grants. The
handler-binding gap is not proof that AMD64 execution cannot work. Preparation
does not require a new compiler download or full dependency rebuild.

## Remaining qualification gates

- Execute bounded crypto vectors, SSL/BIO/CA failure-ownership cases, TLS 1.2/1.3,
  wrong-host and untrusted-root cases against the explicitly bound inputs.
- Qualify real allocator/consumer lifetimes and shutdown, interruption behavior,
  and workload-based arena capacity; host fixtures do not establish these.
- Separately authorize actual package ELF staging and source-companion assembly;
  reconcile runtime APK availability/versions and exact build scope, then build
  and independently read back the b04 image, selected files and APKs.
- Exercise recipient baseline build, modified-library relink and source access;
  resolve applicable source, notice and distribution obligations.
- Run isolated synthetic ship bootstrap, clean stop and same-state reopen, then
  native AMD64/Dappnode acceptance under their own approved scopes.
- Keep public release/signing/publication, owner deployment and personal-pier
  import/Start separate. Earlier baseline-image acceptance does not qualify b04.

No issue completion, release clearance, installed-image update or deployment is
claimed. See the [distribution review](distribution-review.md) for the separate
public-distribution questions and the [README](../README.md) for baseline limits.
