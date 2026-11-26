# Source-delivery and notice checklist

**Draft preparation only.** Proposed route: separate corresponding-source download under GPLv3 §6(d), plus §6(e) information when peer-to-peer distribution applies; no automatic written offer.[8]
Source need not be installed in the container.[8]

The accepted archive already has substantial real sources. Do not repeat the old conclusion that all dependency sources are missing. This checklist names what is retained, what still needs assembly/reconciliation, and what constitutes closure. It is not a new build/runtime authorization.

| ID | Status | Concrete material / responsible role | Closure evidence |
| --- | --- | --- | --- |
| S01 | VERIFIED LOCAL | Licensing prep: exact accepted executable and source archive | Rehashed executable `58d07af97926e04bc17184bc18f53e5fb11d84fed63bd9daf2fe4ceb04c86698` and archive `8ed4fc8a6b4c1acba3e4e89860a4059e490feb3efaf2a818805770f24f65654f`; frozen recipe/input hashes recorded. |
| S02 | INVENTORIED, NOT FULL SUFFICIENCY | Source maintainer: reuse patched Vere tree, OpenSSL generated tree, original inputs and 24 package-cache trees | `source-cache-inventory.json` maps source declarations to archive membership; only macOS SDK URL declarations lack a package cache. Verify necessary generated headers/data/build scripts and all actual build paths, not merely names. |
| S03 | ASSEMBLY OPEN | Release/source maintainer: add exact frozen `candidate.py`, Dockerfile, input/dependency locks, curl overlays, package recipe and readable invocation/order/environment instructions beside source | Use the accepted artifact's recipe, not today's hardened recipe. Document target x86_64-linux-musl, Zig 0.15.2, compiler/config flags, cache placement, external prerequisites and ordered changes. Ensure paths do not depend on unpublished developer scratch state. |
| S04 | OPEN | Release/source maintainer: bind wrapper/manager/package source to the actual image | Reconcile the exact accepted package context or final successor against a public source snapshot; historical wrapper archives and prior official-image bindings are not proof for the replacement. Reuse matching retained snapshots rather than regenerate gratuitously. |
| S05 | OPEN | Licence/release maintainer: full source/relink usability | Confirm source and utilities permit recipient rebuilding/relinking with a modified LGPL library. If complete source is sufficient, application .o files are not automatically required. If source delivery is insufficient, supply missing corresponding application material; no private inputs. An eventual authorized focused build/relink exercise is engineering evidence, not a universal bit-identical rebuild requirement. |
| S06 | CONDITIONAL ALTERNATIVE | Owner/reviewer: approve actual version/alternative choices before release | Review proposes libsigsegv/GMP/D-Bus GPLv3 and Avahi LGPLv3; preserve original grants. Any LGPLv2.1 §3 conversion would require appropriate notice edits in the distributed copy and is not enacted by this checklist.[10] |
| S07 | DRAFT TEXTS PREPARED; INCLUSION OPEN | Notice/release maintainer: select exact new component notices | Stage OpenSSL 3.5.9 and curl 8.23.0 rather than old 1.1.1w/8.9.1 texts. Keep MIT, GPL/LGPL, Avahi GLib attribution, upstream disclaimers and relevant nested notices. Prepare a new selected-input manifest only for the final release; do not mutate the accepted manifest/image. |
| S08 | OPEN | Source/release maintainer: modification notices and dates | Map each actual changed source/adapter to its original revision, change purpose, actual date and hash. Include proposed hardening/SHA changes only if the newly bound artifact contains them. Preserve original MIT attribution for covered urcrypt/Vere code.[8][11] |
| S09 | OPEN, BOUNDED | Licence reviewer: nested source notices | Dispose of retained BLAKE3 modified-file attribution/applicability and relevant H2O/picotls/scrypt/Ed25519 notices using existing follow-up receipts; do not redownload notices already held. Header-only Avahi scan is not all-file licence coverage. |
| S10 | OPEN | Image/source maintainer: exact final base/APK sources and patches | Reconcile installed package database against final image, including Python 3.14.10-r1 versus old 3.14.8-r0 baseline. Reuse matching Alpine origin recipes/source locks; inventory required patches and missing source archives. Resolve existing Alpine attribution/CA-bundle applicability residuals without pretending missing root notices negate declared grants. |
| S11 | CONDITIONAL | Owner + reviewer: installation-information facts | Determine whether GPLv3 §6 User Product transfer conditions apply; if so provide necessary recipient modified-version installation information. LGPLv3 §4(e) applies only as stated. Do not infer a need to expose wallet/CA/ship secrets.[8][9] |
| S12 | NOT PUBLISHED | Authorized release operator: source and binary equivalent availability | Put clear complete-source directions adjacent to the binary; supply §6(e) peer information for IPFS/P2P. Independently fetch the exact published source companion and verify digest/members. Keep availability for the required period; do not rely on a source homepage or promise.[8] |
| S13 | SEPARATE RELEASE GATE | Owner/release worker: actual Public-tab discovery, signing and native AMD64 target acceptance | `../public-release-preparation.md` owns these gates. Local legal preparation does not register a package, sign a release, install it, establish TLS behavior or approve publication. |

## Minimum source companion layout to assemble, not a claim it exists

- A release-binding inventory **outside** the source archive: actual executable/image/package hashes, source-companion hash and exact version.
- Exact patched application/library source and original or reconstructible modifications; full relevant licence/notice files.
- Frozen recipe/locks, integration adapters and generated inputs or complete generation instructions; required data/utilities.
- Final package/wrapper/manager public source and necessary installation/build scripts.
- Exact applicable base-package sources/patches/recipes, with selected transport and recipient directions.
- A concise BUILD/RELINK guide tested against the actual delivered paths when separately authorized; missing tools/material must remain explicit.

Do not include piers, keys, private certificates, login codes, cookies, private logs, derived private authorization records or broad operational workspaces.[8]
Do not require unrelated macOS SDK/developer-only source merely because an optional manifest mentions it.[8]
Toolchain/runtime components actually incorporated in the work still require applicable notices/source analysis; the general-purpose-tool exclusion is not an automatic exclusion for copied runtime code.[8]

## LGPL route detail

LGPLv3 §4(d)(0) allows Corresponding Application Code as source and/or object code, together with Minimal Corresponding Source and needed utilities, under terms allowing recombination with a modified library.[9]
Preserve prominent use notices, licence copies and reverse-engineering permissions.[9]
A frozen source archive can contribute substantially, but source membership alone does not demonstrate usable relinking.[9]

If using LGPLv2.1 instead, §6(a)/(d) provides a source/object-and-equivalent-access route with complete library source and the work-that-uses-the-library, plus required data/utilities; do not claim §6(b)'s shared-library route for this static executable.[10]

Exact accepted OpenSSL/curl static archive recovery is blocked in the technical TLS task. That block does not mandate an object-only legal delivery choice, nor does this checklist turn an unrun TLS test into a pass.

## Sources

[8] https://www.gnu.org/licenses/gpl-3.0.html — GPLv3 exact license text retained in GMP
[9] https://www.gnu.org/licenses/lgpl-3.0.html — LGPLv3 exact license text retained in GMP
[10] https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html — LGPLv2.1 exact license text retained in Avahi
[11] https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz — OpenSSL 3.5.9 exact license
