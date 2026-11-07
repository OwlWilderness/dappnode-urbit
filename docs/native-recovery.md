# Native retained-pier recovery: portable runbook

## Scope and actual delivery

Issue #19's exercised repair used the native Dappnode manager's File Manager
channel and trusted administrator maintenance policy. Its implementation and
local dependencies are in `tools/native-recovery/`; the generic predecessor
library alone is not that implementation. No personal agent skill is required.
This runbook is not permission to touch an appliance, reset storage, reimport,
replace a working ship or replay any historical operation.

The owner-approved November 7, 2026 operation completed repair as
`COMPLETE / REPAIRED`, then one separate Start as `COMPLETE / WRITER_ADMITTED`,
with the runtime journal `RUNNING`. System update settings were restored; UVM and
My-packages updates remained off. The owner subsequently started the tunnel.
These are historical operation outcomes, not fresh observations of today's
appliance. There is no fresh public-health proof here. No reboot/full-restart
or sustained P2P qualification is claimed; the original broad issue #19
acceptance was not exhaustively rerun. Issue closure is an owner-directed scope
settlement, not evidence that all its original criteria passed.

**The Admin UI control gap remains:** TLS/login/status exist, but
`NativeOnlyHandler` rejects every POST except login/logout, including Start,
Stop and Recover. Removing that restriction alone would bypass the intended
authority. Owner-facing admin controls, durable duplicate/lost-ack handling and
combined upgraded OpenSSL/Vere acceptance are tracked in #20. The qualified #3
runtime candidate must be integrated and tested, not assumed present here.
#3 (embedded OpenSSL upgrade) and #17 (deferred allocator hardening) retain their
own scope; this work does not require an additional allocator-arena campaign.

## Authority and limits

The policy is `TRUSTED_NATIVE_ADMIN_MAINTENANCE_V1`, **not** a universal host
exclusion lease or the generic library's stronger `NativeAuthority` contract.
The authenticated external administrator must settle prior installs/rollbacks,
stop the exact original container, observe it exited, complete the acknowledged
replacement where needed, prevent concurrent install/rollback/start/rename/file
changes, and rule out other instances. Ordinary container confinement and no
escaped writer are explicit assumptions. Disabling updates is not an installer
drain. Native package listing checks only managed consumers, not all escaped or
host processes. The worker authenticates root-delivered delegation and local
journal/inode bindings; it cannot independently repeat native lifecycle actions.

Do not use this policy under hostile root, unknown competing writers, missing
receipts, ambiguous journal state or unaccounted replacement. Supplemental locks
are cooperating-writer locks, not cessation proof. Image version tags are not
immutable image identity proofs. Preserve every refusal and UNCERTAIN fence.

## Prepare privately (read-only first)

1. Obtain explicit owner scope and current source/other-instance cessation
   confirmation. Separate package installation, journal repair, ship Start and
   update-setting changes; none is implied by viewing status.
2. Retain the original **full** container ID, exact named volume/mount, original
   runtime/job bytes and hashes, installed source hashes, durable sequence and
   generation, and original update settings. Keep records private. Never copy
   pier contents, credentials, `.env`, TLS keys, live operation IDs or raw native
   receipts into Git or issue comments.
3. Confirm the real legacy journal format: runtime is a one-key `state` object;
   a completed import is `READY_LOCKED` with the exact committed counters/schema.
   A non-STOPPED persisted intent with no admitted process can be fenced as
   `RECOVERY_REQUIRED`; do not rewrite it manually. The repair preserves original
   runtime/job bytes and the committed job, and does not modify the pier.
4. Authenticate the reviewed source/package and all external runtime inputs.
   The source closure is runnable locally, but this repository addition does not
   supply a public legacy base image or qualify a new production package.
   Installation is disruptive and separate; prefer the already-installed feature.
5. Save update restoration obligations before any pause. Restore flags by exact
   fresh readback; re-enabling a flag does not restore a cleared queued schedule.

## Portable browser API inputs

Review/load `native-controller.js` only in the owner's authorized `my.dappnode`
browser origin. No fetch or mutation occurs merely by loading it. The public
factory now requires the independently retained target bindings formerly fixed
to the repaired owner machine:

```js
// Values come from reviewed private original capture, NEVER current-state inference.
const target = {originalContainerId, runtimeSha256, jobSha256};
const controller = createNativeFileRecovery(expectedSources, acceptance, target);
```

All three target values must be exact lowercase 64-hex strings. The constructor
captures its own immutable copy. `expectedSources` must contain exactly the six
worker source names declared in `native_file_channel.SOURCES`, each with its
actual installed SHA-256. Compute from the **public** reviewed worker files
when making a successor; the sanitized worker has a new hash. Do not reuse old
source hashes, old generations or saved authority commands. Package name,
service name, volume and paths remain fixed to the UVM legacy package; this is
not a generalized arbitrary-path or arbitrary-container tool.

`acceptance` must exactly equal the controller's published `ACK` text, after the
administrator has actually accepted and established its changed trust model.
The exact Start confirmation is now the non-owner-specific literal:
`Start the retained pier after native legacy015 repair`. Worker and controller
still perform exact equality checks; this does not automatically grant Start.
This portability change does not alter the already-installed historical worker.

For a separately authorized, qualified replacement, use
`prepareNativeReceiptInstall({manifestFile, composeFile, stagedReceiptFile,
artifactSha256, expectedArtifactSizeBytes})`. Supply the artifact digest/length
from an independently authenticated build, not from the upload receipt itself.
The structured upload finish receipt must bind the **entire** 64-hex image ID,
digest, byte length and unexpired lifetime. Missing/malformed/mismatched/expired
input refuses before Stop. Do not transcribe or shorten upload IDs. The install
helper only prepares arguments; `stopAndInstall(args)` is a separate explicit
mutation. Never substitute a legacy `imageFileId` when receipt authority is absent.

`createNativeMaintenanceWire({originalContainerId})` requires the same independently
retained full original ID. `readUpdates()` is read-only; `setSystemUpdates(bool)`
changes only the system row with `applyToAll:false`, then verifies all three flags.
`startOriginalIdle()` is only a separately authorized management boot of the
exact exited original 0.1.5 container under reviewed installed-source and idle
startup prerequisites. It is not ship Start or a repair fallback; it cannot
supply a real Stop receipt for an already-exited process by assertion.

## Guarded sequence (not an automatic script)

- A fresh install controller may explicitly `stopAndInstall`, preserving a real
  positive native Stop receipt and exited readback before install, then `bootIdle`.
  Package boot starts only the maintenance worker, never Vere. Full native IDs,
  unchanged retained volume, disabled target/system updates, source hashes and
  original journal hashes must match throughout. Failure permanently fences that
  controller; no retry, hidden rollback or proof synthesis.
- For the existing retained recovery service, `attach()` is read-only. It verifies
  the current exact replacement, installed sources and prior durable outcome.
  Attachment does **not** authorize Start. Supported explicit
  `reconcileAfterNativeStop()` performs its own real current-container native Stop,
  exited readback, management boot and fresh generation, preserving prior command,
  receipt and state evidence. It is not a manual phase reset or permission to
  reconcile arbitrary replacement/evidence loss. An already-exited observation
  is not a successful new Stop acknowledgement.
- Only the eligible idle generation may explicitly `repair()`. The worker first
  durably spends the sequence, retains original bytes/evidence, atomically writes
  STOPPED and verifies unchanged job/pier bindings. Successful repair must be
  `COMPLETE / REPAIRED`, with a stopped journal and retained evidence. It must not
  launch Vere. Partial repair remains fenced, not automatically resumable.
- A separate explicit `start(exactConfirmation)` is allowed only after this
  generation's acknowledged repair. The worker durably spends admission before
  constructing the runtime. Issue it **once** and retain its promise/result and
  durable command hash. On lost acknowledgement or timeout, observe the retained
  operation/status; never resend Start, reinstall or fabricate a new receipt to
  recover the UI. Fresh native Stop/reconcile is a distinct disruptive operation
  requiring applicable owner authority, not a timeout retry.
- `stopOwned()` is for the runtime owned by the admitted controller generation.
  Do not infer native cessation from a stopped journal alone. On uncertainty,
  retain package, volume, original journals, commands/receipts and repair evidence;
  keep the fence. Do not delete evidence or restore an old image over new state.
- Restore approved temporary update settings and read them back. Leave an
  owner-authorized successfully started ship running; do not stop it merely to
  complete an unrequested test. A later owner tunnel start supersedes an older
  stopped-tunnel observation; do not start it again without current need/authority.

## Proof levels and focused verification

Separate: container running; durable Start `COMPLETE / WRITER_ADMITTED`; runtime
journal RUNNING; expected ship HTTP response; sustained Vere/P2P health. Cloudflare
error pages are not readiness, and none of these individual levels proves all
others. No live appliance access is performed by the checks below:

```sh
python3 -B tools/native-recovery/run-focused.py
```

The runner verifies public source hashes, compilation, complete local imports,
owned-filesystem repair/preservation/replay/reopen/refusal paths, durable admission
before a **modeled** launcher, root-reader refusal and an available actual
root-owned healthy file, Admin POST rejection, and browser-wire fixtures for
receipt admission, exact native identity/volume, Stop acknowledgement ordering,
RPC object wrapping, update restoration, duplicate/lost-ack fences and read-only
attachment. A missing portable root-owned healthy control is reported as a skip;
root UID10000 delivery/native cessation are not mocked into a pass.

These tests do not requalify native delivery, the installed Linux package, reboot,
all single-writer scenarios, public ingress, a combined #3 runtime, or owner-facing
admin controls. No broad historical suites, rebuilds or live operations are
required to check this source-only preservation commit. `source-parity.json`
records exact byte parity except explicit target/confirmation/artifact
parameterization and portable synthetic test inputs; it contains no operational
journals or private receipts. Runtime import/type checking and production
qualification remain distinct: this preservation is not a type-clean rewrite.
