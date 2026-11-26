# Issue 3 source-preservation queue

This branch preserves the remaining reviewed, public-safe issue-3 source families that were absent from all prior live Git heads. It layers on `feat/3-maintained-openssl-source-candidate` and does not replace or merge a runtime.

Included material is limited to coherent build/source recipe families, focused source tests, source-delivery/license material, and technical design/review records. Byte-identical files needed at multiple recipe paths remain at each required path and are identified in the machine-readable manifest.

Excluded material remains in the independent migrated originals with an exact disposition record: machine-specific paths, credential-shaped fixtures, raw operational diagnostics, build/package/ship harness history, generated inventories, superseded variants, and unrelated project records.

## Source-only verification

All eight newly preserved Python files parsed successfully. Focused host-only checks recorded 31 passed tests for the ARM64 recipe and link-capture source plus two explicit fixture-dependent skips. The retained ARM64 package-image test recorded one pass and three errors because the current published browser-importer verifier does not match its historical preimage. That mismatch is preserved as an issue-3 packaging blocker; it is not repaired or hidden by this source snapshot.

No Vere/image/package build, installation, deployment, ship operation, runtime acceptance, merge, or issue closure is claimed. Runtime and packaging acceptance remain on issue #3.
