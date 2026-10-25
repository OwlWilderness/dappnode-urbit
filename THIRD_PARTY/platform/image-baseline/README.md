# Retained public image: installed APK baseline

**Complete installed-APK enumeration; partial notices only.** This directory is
new evidence for retained public image
`sha256:eacbb5f0b1b9e21df26e7d4b4d63d89b27985fecc4f3580f2dfac44c5243786a`
(`amd64`; the parent had separately verified `linux/amd64`). It is not a final
image, complete image SBOM, legal clearance, source-delivery acceptance or a
runtime test. The image predates the renamed/notice-inclusive package.

## Entry points

- `installed-notices/inventory.json`: current enumeration of **36 unique APKs,
  23 source origins/commits and 10 ordered RootFS layers**, including precise
  installed Python notice metadata. `installed-notices/installed-apk-db.txt` is
  the unmodified installed database, SHA-256
  `48ce241ed8e8e7a108b11b1bda4b2806667f54700acb36b5299aadfd767a7b23`.
- `inventory.json` and `installed-apk-db.txt`: preserved first database-only
  pass, before recognition of Python's public library-directory LICENSE.
- `PACKAGES.md` and `coverage.json`: every exact installed package, original APK
  license declaration, exact Alpine recipe and bounded notice mapping.
- `recipes.json` and `recipes/`: **23 APKBUILDs** from each installed record's
  source commit, with recipe `pkgver/pkgrel` matching every installed APK pin.
- `source-delivery-references.json`: pinned Alpine source-tree URLs,
  unexecuted source expressions and declared SHA-512 checksums. These are
  references, **not a delivered complete corresponding-source set**.
- `source-notices.json`, `additional-notices.json`, `notices/` and
  `sources-ledger.json`: source retrieval provenance, failures and unchanged
  upstream texts/public source headers. There are **35 new source notice/header
  files**, plus one actual installed Python LICENSE. Four previously collected
  root licenses are referenced in `../licenses/`, not re-downloaded.

Thirteen new exact upstream source archives supplied named notices after their
SHA-512 matched the commit-pinned Alpine recipe. An additional exact
ca-certificates source archive matched its recipe but supplied no named notice
file under the bounded selection rule. No source archive was retained.
GCC 15.2.0 and ncurses 6.6-20260516 version tags were resolved to upstream commits;
the selected notice files are pinned to those commits, not claimed to match an
unavailable/source-uncompared archive. Exact Alpine musl-utils and ssl_client
public source files retain their own copyright/license headers.

The installed `usr/lib/python3.14/LICENSE.txt` is byte-identical to the existing
CPython 3.14.8 license (`b0e25a78cffb43f4d92de8b61ccfa1f1f98ecbc22330b54b5251e7b6ba010231`).

## Unresolved notice/source gaps

Partial exact-version notice evidence maps to **31 packages / 19 origins**.
No complete applicable notice text was collected for these **five packages /
four origins**; their installed license labels and exact recipes remain explicit:

- `alpine-release=3.24.2-r0` (`alpine-base` origin)
- `alpine-baselayout=3.7.2-r1` and `alpine-baselayout-data=3.7.2-r1`
- `alpine-keys=2.6-r0`
- `ca-certificates-bundle=20260909-r0`

The exact ca-certificates archive had no named LICENSE/COPYING/COPYRIGHT/NOTICE
file; its attempted version-tagged README URL returned 404. Embedded trust-data
and MPL-2.0/MIT notice applicability remain unresolved. The ncurses recipe's
snapshot archive URL returned 404; its exact upstream snapshot-tag COPYRIGHT was
collected instead (`COPYING`), without asserting archive equivalence. Readline
8.3.3 is represented by the recipe's 8.3 base plus three patch references; only
base COPYING is collected, not the full patched corresponding-source set.

**All** mappings remain partial: nested/per-file notices, patch/support inputs,
actual binary membership, package/signature verification, source/binary
correspondence, GCC runtime-exception applicability, source delivery/written-offer
obligations, and final artifact inclusion are not accepted. Non-APK COPY inputs
and the separate Vere inventory are not re-enumerated here. Existing Vere
libsigsegv/older-OpenSSL distribution-basis questions are unchanged.

## How the no-container inspection was exercised

`../../../scripts/inventory-public-image.py` uses only selected image
`Id`, `RootFS.Layers` and `Architecture` fields, then a `docker image save`
**pipe solely for filesystem inspection**. This is not a release export: no
image/export archive or temporary layer archive is written. Config and legacy
layer-JSON payloads are skipped, never extracted, parsed, retained or printed.
The manifest's config **filename** binds the selected image ID; ordered raw layer
SHA-256 hashes independently match the selected RootFS layer list. The stream
necessarily passes/discards unselected bytes; those payloads are not exposed as
selected evidence. Whiteouts, opaque directories and layer overwrites are
applied before the final APK database is parsed. Symlinks/hardlinks/special files
at selected paths are refused, not followed; filesystem extraction is never used.

The parser supports only the exercised legacy Docker-save tar format; other
formats, ambiguous/missing layers, malformed identities, duplicate packages and
resource-limit violations refuse without publishing a successful inventory.
Limits: 512 MiB total stream, 256 MiB per layer, 8 MiB per selected public file,
16 MiB retained selected contents, 64 layers/notice paths, 100,000 layer members,
1,024 outer members, 120-second producer timer and exclusive no-symlink output.
Only the installed database and the exact Python LICENSE were selected in live
passes. No container create/run/start/exec/cp, build/pull/load, engine changes,
configuration/log/volume/private-state reads, retained cleanup or target contact
occurred.

Example (choose a **new** evidence directory; this command does not run the image):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/inventory-public-image.py \
  --image sha256:eacbb5f0b1b9e21df26e7d4b4d63d89b27985fecc4f3580f2dfac44c5243786a \
  --notice-path usr/lib/python3.14/LICENSE.txt \
  --output /approved/private/scratch/new-inventory
```

Host-only synthetic tests are `tests/test_public_image_inventory.py`. The parent
owns inclusion decisions; these new files do not change Dockerfile, context
allowlists, existing inventories, canonical docs or package descriptors.
