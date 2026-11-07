# Retained native legacy recovery source

This directory preserves the **actual native File Manager recovery path used for
issue #19**, not merely the stricter predecessor `legacy015_recovery.py` library.
It is an isolated, source-only legacy implementation. It does not change the
repository's default package build or deploy anything on load.

Read [the portable operator runbook](../../docs/native-recovery.md) before use.
Run the bounded offline checks from a clean checkout:

```sh
python3 -B tools/native-recovery/run-focused.py
```

Requirements: Python 3.10+ on a POSIX filesystem with `fcntl`, directory file
descriptors, no-follow opens and directory fsync; Node.js 18+ for wire fixtures.
No pip/npm dependencies, ignored directories, sibling checkouts, private image,
local Hermes skill, browser profile or saved appliance receipts are needed for
these checks. Temporary fixtures use the resolved platform temporary directory
(the macOS `/var` symlink is not allowed by the production directory walker).

## Source map

- `service/managed_service.py` -> `native_file_channel.main()` is the exercised
  service entrypoint; `package_service.py` wraps it with the existing TLS/Nginx
  supervisor. It must be idle at boot.
- `service/native_file_channel.py`: root-protected command/receipt validation,
  generation/sequence binding, repair, separate Start/Stop and explicit reconcile.
- `service/trusted_admin_journal.py`: the actual delegated journal transaction,
  retained originals, atomic STOPPED replacement and physical revalidation.
- `service/permanent_recovery.py`: inherited durable state/launcher/server support.
  Its alternative generic controller/mTLS API is **not** the exercised authority.
- `service/legacy015_recovery.py`: unchanged stronger predecessor authority
  contract, retained because inherited state helpers import it. Do not substitute
  its generic authority claim for the native delegated policy.
- Other Python modules and `service/web/`: complete local import/static-file
  dependency closure from the retained installed candidate. `controller_server.py`
  is retained reference support, not a required daemon or a usable native bridge.
- `native-controller.js`: explicit authenticated `my.dappnode` browser operations;
  no actions on load. Includes corrected structured upload receipt admission and
  lost-ack fencing.
- `receipt-invocation.js`: prepare install arguments from owner-selected Files and
  independently reviewed artifact digest/length. No network or install on load.
- `maintenance-wire.js`: corrected single-object RPC wrapping, system update
  pause/restore readbacks and narrowly gated original management-idle boot.
- `source-parity.json`: reference/public hashes and exact portability changes.
  This is source provenance, **not** live authority, evidence or a signed release.
- `../../tests/native-recovery/`: synthetic owned-filesystem transition checks
  and modeled native wire tests. These deliberately do not fake root metadata or
  claim real Docker/native cessation.

## Packaging boundary

All local Python dependencies are included and imported by the focused runner.
Production execution additionally requires the legacy supported Linux runtime,
service UID/GID 10000, root-owned `/opt/importer`, Nginx, OpenSSL CLI, the exact
compatible official Vere binary selected by `service/runtime.py`, existing
service-owned private `/urbit/{pier,uploads,control}` and evidence directories,
and owner-provisioned TLS/auth material. Do not use test fixtures as these inputs.

The installed thin derivative inherited those external executables and supporting
filesystem layout from a retained legacy image. That image is not a portable
public build input. We intentionally do **not** ship its Dockerfile, archive,
owner-specific compose, certificates or a misleading build recipe. This commit
is a runnable source/test closure, not a reproducible replacement image or a
change to package version/runtime selection. A clean-checkout image integrating
this path with the qualified upgraded OpenSSL/Vere candidate is tracked in #20;
#3 and #17 remain independent. Source availability does not clear distribution
or runtime qualification gates. New contributions follow the repository's
GPL-3.0-only terms; preserve inherited notices and third-party terms.
