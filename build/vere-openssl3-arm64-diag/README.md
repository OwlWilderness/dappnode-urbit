# Issue 3 native ARM64 diagnostic recipe

Status: implementation prepared; NOT FROZEN, NOT BUILT, NOT RUN.

This directory is the only modified scope. It derives from the separate
`../vere-openssl3-arm64/` recipe without modifying that recipe or prior attempts.
The candidate identifier is diagnostic-specific; all archive, APK and base-image
pins remain inherited unchanged. No additional builder packages are required.

## Required parent-owned final inputs before freezing

Place reviewed final versions of all six instrumentation files beside the helper:

- `vere.patch`
- `spawn.patch` (registration continuation applied after `vere.patch`)
- `target-build.patch`
- `openssl.patch`
- `musl.patch`
- `uvm_issue3_diag.h` (final registration-capable header)

No interim proposal is copied automatically. Missing inputs fail closed.
The Dockerfile COPY, dependency cache bindings and delivered recipe include all
six inputs plus `diagnostic.py`.

## Wiring

After the inherited pinned-source preparation, the helper copies the complete
fresh pinned Zig library into Vere `issue3-zig-lib`. It resolves the allowlisted
unified diffs entirely in memory before writing changed sources. It requires
exact, unique full hunk contexts and declared hunk counts, refusing fuzz,
whitespace normalization, unexpected paths and unsupported diff formats.
Original hunk positions may shift because the inherited report patch changes
main.c earlier in the file; no shortened-context matching is permitted.

Vere receives `vere.patch`, then `spawn.patch`, then `target-build.patch`.
OpenSSL receives only its patch. Musl changes only the private library copy.
The same header bytes are installed beside Vere, OpenSSL and private musl C
sources. The helper adds no diagnostic global definitions; these remain the
responsibility of the final target-main patch.

The existing per-executable build patch selects the private library only for
urbit. OpenSSL and host build tools retain the ordinary pinned compiler library.
Graph-wide ZIG_LIB_DIR is removed from the child environment. Local/global Zig
cache directories are private to each exclusive attempt. The two-stage OpenSSL
producer/Vere consumer layout remains; the new recipe and complete diagnostic
bindings cannot accept an old uninstrumented receipt.

`--verbose-cc` is supported in the retained pinned Zig 0.15.2
`lib/compiler/build_runner.zig` (option handler inspected). The helper also
checks the freshly extracted runner for that support before building. Verbose
C/link output uses the existing public compiler telemetry and retained logs.
This requests evidence; it does not prove patched musl object selection.

## Delivery and remaining acceptance

The preparation manifest records helper/instrument hashes, before/after changed
source hashes, all header copies, and complete ordinary/private Zig library
manifests. It is bound into the OpenSSL cache receipt and final candidate receipt.
Top-level delivery includes the helper, instrumentation and manifest; the source
archive includes the entire private Zig library without the ordinary object
exclusions. Existing APK identity verification, telemetry, generated OpenSSL
archive/member reporting, source export and ARM64 ELF checks remain intact.

The final receipt explicitly leaves diagnostic binary coverage unverified.
After the separately controlled build, acceptance still needs actual changed
musl/OpenSSL object compilation evidence, selected archive/member/link evidence,
disassembly of exit/abort/OPENSSL_cleanup/OPENSSL_die, unique definitions of each
diagnostic global in the final ELF, and ordinary-libc/no-diagnostic-dependency
proof for host tools. Source manifests and strings alone are not that proof.

No compiler, container, build, runtime, old supervisor or broad test was started
while preparing this recipe. Patch-tool syntax checks returned OK. An additional
read-only source-application check was not executed because its tool approval
expired; therefore final input application is not claimed verified. The parent
must review final input integration before freezing a fresh attempt.
