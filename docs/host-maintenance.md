# Host maintenance companion (issue19; source contract, not installed acceptance)

The package keeps **the existing `ship_data:/urbit` named-volume layout and
`restart: unless-stopped`**. Recovery is a root-host operation, not a UID10000
container API. Modules copied into the image do not install a host service.
The host companion is exported separately from the same source freeze:

```sh
python3 -B tools/prepare-maintenance-host.py --output /absolute/new/host-companion
```

This command is engine-free and only writes public source plus a hash manifest.
It neither installs anything nor registers existing storage. The final release
must bind that manifest, the actual built image/archive, Compose and source
hashes together. Source tests or an earlier overlay image are not release PASS.

## Required host integration, not a stock Dappmanager feature

A trusted host orchestrator must implement **create without start -> register ->
run**, before first package initialization/provisioning/import. Its package-update,
replacement and maintenance operations must serialize with the same authority.
The host must provide local rootful Linux Docker at `/usr/bin/docker`, no userns
remap, stable exclusive local storage, Python 3, persistent root-only
`/var/lib/uvm-maintenance`, and the reviewed companion under a root-owned immutable
release directory outside `/urbit` (example `/opt/uvm-maintenance/RELEASE/`). Install
all five core Python files from `tools/browser-importer/` together; do not mix
releases. The export additionally binds the matched managed-service, supervisor,
HTTP/TLS/frontend source and volume-guard/entrypoint bytes in its manifest; their
presence is source provenance, not host installation. Use the host's Python, not
Python inside the scope being destroyed.

**There is no such hook in the shipped stock Compose descriptor.** A normal
Dappmanager install starts the container directly. This source supplies the host
provider interface and supports its current volume/restart settings, but does not
supply or claim an installed Dappmanager interception/plugin. Before claiming
recoverable default installations, the host integrator must provide and qualify
a pre-first-start create/registration hook plus an update/replacement interlock.
If the host platform cannot hold creation before its first start, this is the
precise blocking capability: virgin-inception registration cannot be established
by this package alone. Do not quietly switch to a bind/no-restart deployment or
call a bespoke fixture proof of that missing integration.

Existing installations that have already written data without this registration
remain **PRIOR_SCOPE_UNPROVABLE**. New modules, a stopped container, a reboot,
`unless-stopped`, an empty alternate authority, or a successful disposable test do
not retroactively prove that history. No installed changes are authorized here.

## Storage and scope admission

- The container is UID10000, unprivileged, caps-drop ALL, no added capabilities or
  devices, no-new-privileges, private PID namespace and exactly one writable
  `/urbit` mount. Exact bind storage remains supported. A named volume must use
  Docker's local driver, local scope, **no driver options**, and its daemon-reported
  mountpoint must exactly equal the selected host `--storage` path. Remote,
  bind-via-driver-options, extra mount, shared/cross-host and unknown aliases are
  not supported. No volume rename, copying or layout conversion is performed.
- Virgin storage contains exactly private UID10000 `pier`, `uploads`, `control`
  directories, all empty. The image initializes this volume directory structure;
  the host integration must ensure it exists without starting package writers.
  Registration requires a never-started `created` container and no other consumer.
  When a host orchestrator preinitializes the volume before container creation,
  it must use Docker's `volume-nocopy` mount option (Compose long syntax
  `volume: {nocopy: true}`). The opt-in `host-maintenance.compose.yml` overlay
  provides precisely that mount override; combine it with `docker-compose.yml`
  only in the separately controlled create-without-start host flow. It does not
  install the hook, initialize storage, enroll a container, or authorize Start.
  This is a **host Docker Compose input**, not an SDK package descriptor: pinned
  Dappnode SDK 0.3.55's volume validator rejects long-volume objects. Do not feed
  this overlay through the SDK release preparer or claim stock Dappmanager
  compatibility. The ordinary descriptor remains SDK-validated independently.
  The stock descriptor retains its existing copy-up behavior for ordinary
  installations; it is **not** the preinitialized host-managed descriptor. The
  host-managed descriptor and its initialization hook must be qualified together.
  Do not enable nocopy on an unprepared empty volume: this UID10000 image cannot
  repair a root-owned volume. No layout/ownership repair is performed by recovery.
- All production Provider entrypoints enforce **one fixed canonical authority**:
  `/var/lib/uvm-maintenance`. The retained CLI `--authority` argument is compatibility
  syntax, not permission to choose another root. Other values refuse before
  opening storage. A flock on the held **underlying storage directory inode**
  additionally excludes simultaneous provider handles even across authority paths.
  The authority/registry and storage must not be replaced or rolled back. Do not
  remove locks, recreate the authority or use a second release-specific authority.
- The trusted host controller must prevent out-of-band Compose create/start/rm,
  auto-updates and external mounts/writers. Daemon restart of the **same registered
  ACTIVE container** is permitted: ACTIVE is persisted before initial start and
  remains active after launcher death, container exit or daemon/host reboot.
  There is no automatic recovery or boot-ID clearance.

The enforced lease/registry guards protect cooperating host orchestration from
accidental parallel controllers; this is not a sandbox against malicious root,
Docker-socket access, hostile service-code filesystem edits or whole-storage
rollback. A root administrator can bypass any local Python gate. Do not claim
otherwise.

## Runnable host interface

The following is an interface specification for a separately installed and
qualified host integration, **not instructions to execute on the existing
installation**. `STORAGE` must be the exact curated daemon-reported volume
mountpoint (or exact bind source); `CID`/`NEXT` are full 64-hex container IDs. Do
not acquire broad inspect/Env/log output to discover them. Commands below use the
same root-owned release source directory throughout:

```sh
P=/opt/uvm-maintenance/RELEASE/tools/browser-importer/maintenance_provider.py
# Host orchestrator has created, never started, the descriptor's container.
python3 -B "$P" --storage "$STORAGE" enroll --container "$CID"
python3 -B "$P" --storage "$STORAGE" run
# Later, host orchestrator has created but not started an exact same-volume
# successor; this ONE call holds canonical admission through the whole handoff.
python3 -B "$P" --storage "$STORAGE" recover --successor "$NEXT"
# Without a successor, recover only migrates metadata and leaves no container.
python3 -B "$P" --storage "$STORAGE" recover
```

`enroll` durably records virgin inception, returns `ENROLLED_NO_START`, and does
not launch anything. `run` requires that registered never-started scope, durably
records ACTIVE, applies/verifies the scope's admitted restart policy (`no` or
`unless-stopped`), then starts the package and holds admission during observation.
The package still requires explicit authenticated ship Start. A launcher exit or
failure does not clear ACTIVE. `SCOPE_EXITED_RECOVERY_REQUIRED` is not settlement.

`recover` checks exact prior scope/storage and all consumers, disables prior
restart with `docker update --restart=no`, positively stops the exact container,
and verifies **restart=no AND private-namespace init exited**. It persists
QUIESCED before removal, removes only that container **without `-v`**, verifies
absence, then persists DESTROYED. Missing ACTIVE containers are not proof. A
saved QUIESCED state makes a crash after acknowledged cessation/removal retryable.
It then takes cooperating writer locks, read-only preflights the intact committed
import and preserves original job/journal bytes in root-host transaction evidence
before paired STOPPED migration. Interrupted/uncertain imports remain refused.

With `--successor`, the same live handle admits only the created exact-volume
successor as an additional consumer, then enrolls/runs it after STOPPED migration.
The successor's descriptor-provided `unless-stopped` policy is restored/applied
only after its new durable ACTIVE intent; the removed prior scope is **never**
restarted or re-enabled. All disable/stop/inspect/remove/recovery/enroll/start
operations are under continuous canonical admission. There is no window where
restoring restart policy lets the old writer race migration. A failed maintenance
operation leaves restart disabled/intent unresolved; do not manually re-enable
or start the old scope. Resume through the provider, preserving evidence.

## Interrupted owner writes and refusal evidence

Runtime owner staging now occurs in same-filesystem `control/.runtime-<uuid>`,
not the exact-layout pier root. The pending file is fsynced, renamed to the target,
then the target directory and (if different) staging directory are fsynced.
Process loss can leave a pending staging file, or a mismatched paired record;
positive host recovery preserves pending bytes, preserves original paired records
in transaction evidence and writes a new STOPPED generation. Pending staging
files are **not authority** and are never used as proof or deleted by recovery.
Start checks current ship inode against the established STOPPED generation before
writing STARTING intent or launching anything; a replacement requires recovery.

An **old-version pier-root** `.runtime-<uuid>` with no independent durable
provenance remains an unknown extra pier entry and is refused unchanged. A name,
well-formed JSON or alleged origin is not proof; moving/deleting it manually is
not this API. This fix prevents that old ambiguity for new writes; it does not
claim to authenticate arbitrary historical staging residuals. Unrelated/unsafe
pier entries, missing established ownership, incomplete imports and foreign
consumers continue to refuse. Preserve them for separately reviewed recovery.

## Qualification and rollback

Engine-free filesystem/subprocess tests model Docker/host boundaries; they do
not prove real Docker namespace cessation, host hook integration, named-volume
behavior on Dappnode, abrupt host crash recovery or installed provenance. The
assigned disposable execution owner must qualify the actual companion/image
freeze's affected CLI + default named-volume/restart handoff. Imported `main()`
is not standalone CLI qualification. Retain C's findings and all earlier false
receipts as historical evidence; never turn their overall FAIL into PASS.

The old baseline image cannot read v3 ownership/layout. Do not downgrade it onto
new state, remove owner records or roll back storage to manufacture provenance.
A rollback needs a separately qualified compatible image or evidence-preserving
restore under positive full-scope cessation; no rollback is authorized here.
