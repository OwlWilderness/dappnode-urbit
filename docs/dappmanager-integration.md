# Source-only Dappmanager lifecycle integration

This document describes a source candidate for issues #20 and #14. It does not
install a manager, create a host service, modify a live package, authorize a
runtime transition, or qualify a deployment. All examples use placeholders;
no owner-specific paths, runtime identifiers, receipts, or private material are
part of this source publication.

## Upstream provenance

The integration patch targets the official
[`dappnode/DNP_DAPPMANAGER`](https://github.com/dappnode/DNP_DAPPMANAGER)
release tag `v0.2.129`, commit
`a21bab295d4c68c3b6115498b18a8efaf89d52a0`. Upstream declares the code
GPL-3.0. The derivative patch is retained at:

- `tools/host-integration/upstream-dappmanager.patch`
- SHA-256: `c7149f6b0923b013c354e89e43e02378c15e0bf7fe52c7671eeb693090ecbd50`

The patch applies to that exact commit and adds
`packages/dockerApi/src/uvmLifecycle.mjs` while changing fifteen existing
upstream paths. The repository does not vendor a reconstructed upstream tree,
image, package archive, credential, or private runtime artifact.

`tools/host-integration/prepare_manager_candidate.py` verifies the pinned
source and patch before constructing a fresh source-only staging tree. Its
receipt records source, patch, and tree hashes and explicitly marks the result
`image-pending` and `installable: false`.

`tools/host-integration/assemble_manager_candidate.py` verifies a separately
provided image archive and host-companion manifest before assembling a local
candidate. Assembly is validation, not publication or installation. It does
not approve a host plan or turn the source candidate into a release.

## Why the adapter is required

The stock manager owns several mutation paths that can create, start, stop,
replace, remove, restore, or write into package containers and volumes. A safe
UVM handoff cannot guard only one installer call. The patched source therefore
places the protected package behind one lifecycle boundary:

1. Route protected activation and recovery to a root-host Unix broker before
   stock Compose creation.
2. Prevent stock rollback from restarting or deleting a protected predecessor
   after an uncertain broker acknowledgement.
3. Refuse protected Compose and direct-container mutations, protected volume
   removal, writable copy/archive operations, backup restore, and installer
   file uploads.
4. Preserve ordinary package behavior outside the protected identity.
5. Freeze stock manager self-replacement in this source variant so a successor
   cannot silently remove the guards.

These are cooperating source guards, not a security boundary against a hostile
Docker owner, root process, unreviewed plugin, or external raw Docker client.
Every newly introduced upstream mutation path requires another review.

## Host-side source

The host side remains separate from the manager source:

- `tools/host-integration/dappmanager_lifecycle.py` implements admission,
  virgin storage preparation, create-only Compose integration, provider
  enrollment, and acknowledged start.
- `tools/host-integration/dappmanager_broker.py` implements a root-Linux-only
  Unix broker with pinned request and plan validation.
- `tools/browser-importer/runtime.py` provides the owned-child and process
  lifecycle used by the source candidate.
- `tools/browser-importer/maintenance_provider.py` provides bounded
  maintenance admission and status behavior.

No file here installs a daemon, creates a socket, mounts a host directory,
changes a running manager, or grants runtime authority.

## Lifecycle contract

Every activation, recovery, and admitted maintenance request must hold the
same nonblocking integration lock before any protected volume is created. The
provider's registry and storage locks are then held continuously through the
operation.

Initial activation is:

```text
integration admission
  -> prove the named volume absent
  -> create and verify an empty local volume
  -> prepare the private package layout
  -> acquire provider admission
  -> Compose create --no-recreate (never up/start)
  -> enroll the never-started container
  -> persist ACTIVE before applying restart policy and starting
  -> verify the exact confined scope and return the ACTIVE receipt
```

Replacement first performs a read-only committed-import eligibility check.
Missing readiness metadata, an incomplete committed layout, retained uploads,
or unsafe paths refuse without stopping or replacing the predecessor. A
positive eligibility result is not itself cessation proof; the provider still
performs its full recovery and storage validation.

No socket, malformed receipt, timeout, or lost acknowledgement falls back to
stock startup or rollback. An uncertain acknowledgement remains uncertain and
must not be treated as permission to retry destructively.

## Broker and plan boundary

The broker accepts only an immutable, separately reviewed plan and host
Compose document. A plan has this shape:

```json
{
  "volume": "<approved-protected-volume>",
  "compose_path": "/opt/uvm-maintenance/<release>/host-compose.json",
  "compose_file_sha256": "<sha256-of-exact-host-compose-bytes>",
  "manager_compose_sha256": "<sha256-of-canonical-manager-compose-json>"
}
```

Plan and Compose leaves must be root-owned mode `0600`, single-link regular
files with no symlink ancestors or writable untrusted parents. The host
Compose document admits one protected service, one external local volume, a
digest-pinned image, fixed identities and explicit reviewed fields. Builds,
hooks, extra mounts, PID sharing, env-files, interpolation, and arbitrary host
paths are refused.

The root-only runtime directory and mode `0600` socket must be provided to the
patched manager by a separately qualified host service. The broker refuses an
unexpected existing socket and never unlinks an unknown endpoint.

## Bounded Compose invocation

The broker invocation requires all of these values:

```text
python3 -B /opt/uvm-maintenance/<release>/tools/host-integration/dappmanager_broker.py \
  --plan /opt/uvm-maintenance/<release>/plan.json \
  --endpoint <original-monotonic-endpoint> \
  --compose-sha256 <exact-compose-plugin-sha256>
```

The endpoint is a finite `time.monotonic()` value in the same host and boot
clock domain. It is not a duration and is never refreshed per request.

The Compose plugin path is fixed by the reviewed source. Its opened target is
hashed and its identity is checked around acquisition and immediately before
spawn. This is pathname execution, not an fd-bound execution guarantee. The
trusted admission owner must prevent concurrent replacement of the invocation,
target bytes, parent paths, and configuration until child execution. Refuse
live admission when that continuing-authority premise cannot be established.

The child environment is fixed and does not inherit manager-selected plugin,
credential, or path configuration. The private configuration directory must
already be empty, nonsymlinked, mode `0700`, and owned by the caller.

## Public certificate transfer

The patched File Manager routes protected writes to the broker before creating
a temporary file or invoking `docker cp`. Only two public X.509 leaves are
admitted under the fixed public-certificate directory:

- `root-ca.pem`
- `server.pem`

Private keys, CSRs, bundles, arbitrary control paths, traversal, and oversized
payloads are refused. The host accepts one canonical, parseable public PEM
certificate and never logs or reflects the uploaded bytes. Publication uses a
private staging leaf, flush and fsync, fixed read-only mode, and a no-replace
rename. Existing or uncertain state is never overwritten automatically.

The broker receipt acknowledges storage only. The unchanged package-side TLS
consumer separately validates trust, names, validity, purpose, and private-key
matching before publishing readiness.

## Deliberate limits

- This is source publication, not an installed manager or release package.
- No live Docker engine, package, ship, owner account, or private storage is
  contacted by the source test suite.
- Existing unknown or unregistered volumes refuse; the source does not invent
  bootstrap provenance or perform destructive repair.
- Stock package retry, rollback, and backup restore are not recovery escape
  hatches for the protected identity.
- A separately reviewed host service, socket mount, immutable plan, pinned
  image, and deployment acceptance remain required.
- Cross-host storage, storage rollback, malicious root, and external raw Docker
  mutation remain outside the trust model.
- The issue-#3 runtime line contains separate recovery behavior. This candidate
  is based on the published issue-#20 source and does not overwrite or claim to
  include the issue-#3 runtime implementation.

## Source verification

Use a pristine checkout of the pinned upstream tag and a short, private test
scratch directory:

```text
export UVM_DAPPMANAGER_CHECKOUT=<patched-upstream-checkout>
export UVM_MANAGER_PRISTINE_SOURCE=<pristine-upstream-checkout>
export IMPORTER_TEST_SCRATCH=<existing-private-scratch-directory>
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p 'test_*.py'
node --test tests/*.test.mjs
```

Focused review should verify the patch against the exact upstream commit, run
the repository's manager, broker, lifecycle, runtime, and connection-code
suites, run the upstream integration tests against the patched source, and
perform a final diff/privacy scan. Passing source tests does not qualify a
build, image, deployment, or live recovery operation.
