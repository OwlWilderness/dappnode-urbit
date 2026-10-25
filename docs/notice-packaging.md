# Local notice-packaging preparation

Status: **source preparation only; final notice-bearing image unbuilt**.
No build, container/ship execution, release export, publication, signing or target
contact is performed by this preparation. Accepted artwork/descriptors and prior
TLS/official-Vere lifecycle results are reused, not regenerated or rerun.

## Implemented source contract

`build/Dockerfile` copies the reviewed `THIRD_PARTY` tree, contribution declaration,
full GPLv3 text and linked public review documents beneath `/usr/share/doc/uvm`.
Files are root-owned; `chmod -R a=rX` makes documentation traversable/readable and
non-writable by the service. These are build instructions, not observed final
image ownership or permissions.

`build/notice-files.json` selects exact repository-relative public files and
SHA-256 values. The generated final block in `.dockerignore` opens only their
required directories and exact filenames; it does not broadly admit arbitrary
new files under `THIRD_PARTY`. Existing application inputs remain allowlisted.
The manifest is copied separately as `/usr/share/doc/uvm/notice-files.json`.
No private state, secret setup page, development dependency tree or operational
checkpoint is added to the build context.

Run the file-only check from the repository root:

```sh
python3 -B scripts/verify-notice-packaging.py
```

It verifies selected source bytes and the exact context block. It does not call
Docker, build, run upstream code, regenerate descriptors or establish license
coverage. It refuses altered hashes, symlinks and context exceptions outside the
fixed notice block. This is for a quiescent owner-controlled source checkout,
not a hostile concurrent filesystem writer.

For a separately authorized future PUBLIC image-filesystem extraction, pass
`--image-root` to the same verifier. That branch verifies the selected installed
documentation bytes and copied manifest against the trusted source manifest.
Synthetic host fixtures exercise it now; no actual final-image extraction or
acceptance has occurred. It is not permission to inspect a container volume or
owner state. The actual Docker ignore matcher still needs its authorized build
check; host source tests are not that matcher test.

## Inventory and prepared source materials

- [Retained public image](../THIRD_PARTY/platform/image-baseline/README.md):
  36 installed APKs, 23 source origins/commit-pinned Alpine recipes, ten ordered
  layers. This predates the renamed/notice-bearing image. Five packages lack
  full applicable notices; other mappings are partial, not exhaustive.
- [Nested selected-file follow-up](../THIRD_PARTY/vere/followup/README.md):
  additional picotls, scrypt, Ed25519 and other notices; nine selected BLAKE3
  files compared, including three retained diffs. Source declarations and file
  comparisons do not prove official binary membership.
- [Source-delivery preparation](../THIRD_PARTY/SOURCE_DELIVERY.md): actual pinned
  Vere source archive, exact source/patch locks and historical wrapper snapshot.
  A final local public-context snapshot can be prepared separately from the
  historical snapshot after integration. Its binding inventory stays outside
  the snapshot/notice tree to avoid a self-referential archive/manifest hash.
  None of these partial materials constitutes complete corresponding-source
  delivery or a written offer.

## Local testing versus public delivery

Public-release notice/source questions are not a reason to keep expanding this
audit instead of testing a local build. The bounded
[five-package follow-up](../THIRD_PARTY/platform/followup/README.md) is complete;
remaining questions are recorded as distribution gaps, not runtime defects.

1. Separately authorize and build the local candidate with its exact inputs.
2. Inspect **that image**: final package inventory, complete selected notice
   bytes/permissions, copied application bytes and unchanged pinned Vere hash.
   Exercise its actual entrypoint through stopped/pending readiness and restart
   persistence, without a ship operation. Reuse unchanged accepted TLS evidence.
3. A separately authorized disposable fake-ship boot can test the actual final
   image; earlier exact-executable lifecycle evidence is not that result. The
   next recommended scope stops after local testing, with no export or target.
4. Before public delivery, resolve the selected Vere distribution basis and
   applicable notice/source obligations. Missing evidence is not proof of
   upstream noncompliance. Do not repeat the exception search or change crypto.
   Only under separate export authority, verify archive tag, image/config
   identity, architecture and binding to the already accepted descriptor assets.
5. Owner signs locally; distribution, scoped release-trust changes, installation
   and stopped-target certificate transfer/enrollment require their own explicit
   authority. Existing HTTPS CA remains unchanged. No agent wallet or Safe.

A prior exact-Vere ship lifecycle PASS is **not** a ship-boot result for this final
image. No final-build ship boot has been run or authorized in this source scope.
If a fresh disposable final-image ship boot is selected as an acceptance
requirement, authorize and perform it before delivery—not on the target first.
Personal import and ship Start remain outside stopped-target acceptance.
