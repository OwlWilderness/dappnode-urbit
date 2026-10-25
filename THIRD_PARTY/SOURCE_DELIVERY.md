# Source-delivery preparation — not fulfillment

**RELEASE BLOCKED / FINAL NOTICE-BEARING IMAGE UNBUILT.** No written offer has
been issued. This is **not complete corresponding-source delivery** and does
not clear the selected executable's unresolved distribution basis.

The authoritative machine-readable entry is [source-delivery.json](source-delivery.json).
All JSON `path` fields are **repository-relative** unless explicitly labeled
otherwise; a source-tree path is not a promise that the file exists in installed
documentation. Internal links within this `THIRD_PARTY` collection are local.

## Prepared materials

| Material | What is actually present | Limit |
| --- | --- | --- |
| [Exact Vere source archive](vere/followup/materials/vere-8ddc4b786979574dbfcb655e3db1b634f658d0de.tar.gz) | Public pinned Git revision, reconstructed locally, with every regular-file blob checked against retained primary tree evidence | Not upstream tarball bytes; external dependencies/toolchain and authenticated official build provenance are missing |
| [Archive member index](vere/followup/archive-members.json) | Every included Vere file's Git blob, SHA-256 and size | Source identity, not official executable membership |
| [Exact build/patch inputs](vere/followup/source-inputs.json) | 65 Zig/manifest/workflow/Nix/reference files and all five patch replacement files | Windows libuv replacement is not an AMD64 Linux input; h2o klib/test replacements are not all final-link inputs |
| [Build contract](vere/followup/build-contract.json) | Source-declared Zig version, workflow commands, full archive script index and explicit gaps | No build or reproduction performed; workflow declarations are not historical build attestation |
| [Dependency lock](vere/followup/dependency-lock.json) | Literal declarations, revisions, URLs, Zig hashes and previously collected archive hashes | Dependency source archives not included; hashes not recomputed; three mirror identities unresolved |
| [Wrapper source snapshot](vere/followup/materials/uvm-wrapper-source-snapshot.tar.gz) and [lock](vere/followup/wrapper-source-lock.json) | Actual public package/wrapper source and package-lock bytes | Historical pre-integration dirty snapshot; **must refresh after parent Dockerfile/context/notice-inclusion integration**, not a final source freeze |
| [Nested notice supplement](vere/followup/NOTICES.txt) and [review](vere/followup/README.md) | Exact extracted per-file notice blocks plus preserved full source evidence | Bounded selected-file review, not exhaustive vendored audit or binary SBOM |

The parent's intended documentation destination is
`/usr/share/doc/uvm/THIRD_PARTY`; inclusion and copied-image verification belong
to the parent packaging gate and are not accepted here. Original executable and
artwork bytes are unchanged. Retained earlier image/lifecycle results are not a
build or boot result for the final notice-bearing package.

## Missing delivery inputs and decisions

1. **Exact final artifact binding:** finish parent packaging, regenerate the
   wrapper snapshot/lock from its actual final public inputs, bind final image
   and source artifact digests, and verify delivery availability and inclusion.
   Do not replace the immutable executable merely to close documentation gaps.
2. **Dependency sources:** acquire/preserve the exact source packages, applicable
   build scripts, patches and generated-source inputs needed for the distributed
   components. The lock records what to obtain; it does not supply them. Existing
   collection archives were not retained; no repeated archive download occurred.
   GMP, libsigsegv and natpmp upstream-versus-mirror identities remain unproven.
3. **Applicable GPL/LGPL delivery and installation/relink materials:** select and
   document the actual applicable distribution route after component/binary
   reconciliation. Read the collected full terms, not just labels. In particular,
   GPLv2 section 3, GPLv3 sections 1/6, LGPLv2.1 sections 4/6, and LGPLv3 section 4
   are review inputs. For a combined work, determine and supply any required
   library/application/relink or installation materials; none are claimed
   fulfilled by source URLs, a source lock, or this partial archive set. This is
   an engineering checklist, not a legal determination or a written offer.
4. **Notice applicability:** keep the supplementary ISC-style picotls and Colin
   Percival scrypt helper notices with applicable distributed material. BLAKE3
   modification provenance/notice handling and broader per-file coverage remain
   bounded gaps; see [applicability](vere/followup/applicability.json).
5. **Platform package coverage:** the [retained-image baseline](platform/image-baseline/README.md)
   now enumerates 36 APKs with 23 commit-pinned source recipes. Its
   [source references](platform/image-baseline/source-delivery-references.json)
   record exact recipe sources/checksums; these are not delivered source archives.
   The [five-package follow-up](platform/followup/README.md) documents netbase
   source notices and the pinned CA source notice/generation path. Package-wide
   applicability/attribution gaps remain explicit; this is not complete source
   delivery. Final-image package/patch/source reconciliation remains open.
6. **Distribution basis:** the existing selected Vere libsigsegv/older-OpenSSL
   evidence question remains unresolved. Missing evidence is not a finding of
   noncompliance. No renewed exception search, upstream contact or legal-advice
   engagement was performed or authorized here.

## Terms and verification

Collected terms for review: [GPLv2](vere/licenses/gmp/COPYINGv2),
[GPLv3](vere/licenses/gmp/COPYINGv3),
[LGPLv3](vere/licenses/gmp/COPYING.LESSERv3), and
[LGPLv2.1](vere/licenses/avahi/LICENSE). The repository contribution declaration
and artwork/distribution review files are **source-tree-only references** at
`LICENSE.md`, `LICENSES/GPL-3.0-only.txt`, `docs/artwork.md`, and
`docs/distribution-review.md`; the parent is separately arranging their installed
layout. No hyperlink here assumes those repository-relative paths will resolve
beneath installed `THIRD_PARTY`.

[Verification results](vere/followup/verification.json) cover actual hashes,
archive contents, parsed JSON, source-edge assertions and local documentation
links. To recheck the owned material, from the repository root run
`python3 THIRD_PARTY/vere/followup/verify.py`. This is file-only verification:
no downloads, Docker, descriptor generation, builds, runtime execution, signing
or publication. Completeness remains false even when verification succeeds.
