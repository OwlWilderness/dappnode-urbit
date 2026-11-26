# Exact source locations and companion contract

The selected artifact is the retained maintained OpenSSL 3.5.9 / curl 8.23.0
baseline, not b04 and not the canonical official OpenSSL 1.1.1w package. See
BUILD-RELINK.md and bindings/selection.json. All manifest locations are public
repository-relative source references. No scratch/private input is required.

## Layout

| Recipient path | Actual retained content |
|---|---|
| sources/source-materials.tar.gz | Unchanged archive SHA256 8ed4fc8a6b4c1acba3e4e89860a4059e490feb3efaf2a818805770f24f65654f, 220821885 bytes. Bound in manifest, not needlessly copied into this directory. |
| recipe/ | Frozen original candidate.py, builder Dockerfile/APK database/locks, candidate/source-change receipts and curl overlays. |
| package-context/ | Exact retained historical manager/UI, normal entrypoint, volume guard, fixed baseline adapter, package Dockerfile/licence/context indexes. Baseline ELF is bound but deliberately not duplicated here. |
| bindings/ | Selected baseline lock, historical package binding, actual saved selected-image inventory and installed APK database. Not current engine observations. |
| notices/archive/ | Verbatim conventional licence/notice files read from the exact archive, including nested and optional source branches. |
| notices/texts/ | Already retained exact baseline licence texts and literal source-header grants. No new election or relicensing. |
| notices/supplementary/ | Retained per-file H2O/picotls/urcrypt attribution and BLAKE3 differences/applicability evidence. |
| platform/ | Already retained Alpine recipes, notices and bounded source/support followups; exact selected-image matching is calculated separately. |
| archive-inventory.json | Every archive member, type, byte count and every regular member's SHA256; source symlink targets retained as data, never followed. |
| image-source-requirements.json | Every selected installed APK grouped by source origin/commit, matching-old-recipe indicator and concrete missing source requirements. |
| modifications.json | Exact changed baseline source members and hashes; archive timestamps are not invented actual modification dates. |

Inside the archive: `materials/vere-8ddc4b7.tar.gz`,
`materials/openssl-3.5.9.tar.gz`, `materials/zig-x86_64-linux-0.15.2.tar.xz`;
`vere-8ddc4b786979574dbfcb655e3db1b634f658d0de/` (patched application and adapters);
`openssl-3.5.9/` (generated configuration/source/headers); `p/` (24 package trees);
`openssl-cache-evidence/` (original public library build diagnostics). Generated
OpenSSL object/archive files were filtered out of source delivery; regenerate
through the frozen recipe rather than pretending to recover the original link.

## Machine contract for the package worker

`build/baseline-release-notices.json` is the only integration seal. Read only its
final path, never `.pending`. It is deterministic sorted-key JSON with integer
`schema_version: 1` and status
`SEALED_RETAINED_BASELINE_COMPANION_WITH_EXPLICIT_GAPS`.

- `selected_baseline` binds saved image ID, exact ELF, source archive, adapter,
  revision/target and dependency versions.
- Each `entries[]` row has a canonical safe relative `recipient_path`, `bytes`,
  lowercase `sha256`, `role` and `source`.
- `source.kind=repository_file`: copy exactly `source.path` relative to repo root.
- `source.kind=archive_member`: verify selected archive first, locate exactly
  `source.member` in archive at `source.path`, require unique regular member and
  copy its bytes, never extract a tree or follow links.
- `completeness.missing_requirements` is part of the delivery, not optional prose.
  Assembly completion must not be converted to source sufficiency/legal clearance.
- Counts are generated from actual inventories. File hashes are identities, not
  upstream signature verification. No final release version, source URL/CID or
  final successor image is fabricated.

`assemble.py` verifies the sealed inventory without builds/network/engine/private
state. Its optional new-directory materialization is a distinct explicit operation;
no cleanup/overwrite/retry behavior is provided. `generate.py` regenerates the
small assembly and publishes the manifest only after file-only verification.

## Recipient availability is still unassigned

The local relative source references are an assembler input contract, **not** a
claim that an external recipient can retrieve them. A supplying release must
provide the archive plus manifest-listed companion files together, specify exact
binary/source locations adjacent to one another, and independently retrieve/hash
the offered files. No written source offer or availability period is issued here.
