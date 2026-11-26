# OpenSSL candidate: distribution licence review

**Review and draft preparation complete; public distribution NOT cleared.**
Snapshot: October 28, 2026. This is a bounded technical/licensing evidence review, not a legal opinion, an enacted licence election, a third-party exception, or publication authority. The intended release remains the DappStore **PUBLIC** tab, not merely a private installation or a GitHub source upload.

## Outcome

The original concern was the in-process combination of GPL-2.0-or-later libsigsegv 2.14 and **OpenSSL 1.1.1w's older OpenSSL/SSLeay terms**, not the separately installed Alpine OpenSSL.[1]
The recovered historical review did not establish an applicable linking exception.[1]
OpenSSL's primary policy explicitly distinguishes those older releases from Apache-2.0 releases starting at 3.0.[1]

The accepted replacement described below instead uses **OpenSSL 3.5.9**, with its exact Apache-2.0 text retained in the accepted source delivery.[2][11]
Apache's own guidance permits Apache-2.0 code in GPLv3 works, but does not regard Apache-2.0 as GPLv2-compatible.[2][11]

**Conditional conclusion:** choosing GPLv3 under libsigsegv's existing “or later” grant supplies a supported general compatibility route for this particular OpenSSL/libsigsegv pairing.[2][4]
An invented OpenSSL exception is not needed for that route.[2][4]
This is not retroactive clearance of the old official executable, not a GPLv2 route, and not certification that every other source, notice, dependency and delivery obligation is fulfilled.[2][4]

Concrete preparation now includes exact-version licence copies, MIT attribution, a proposed component-choice table, scoped runtime/build-tool exception evidence, a source-cache inventory, draft recipient notices and an actionable source/relink checklist. All live production licence declarations and accepted artifact inputs remain unchanged.

## Artifact scope and local evidence

Workspace branch inspected: `fix/3-maintained-openssl`, HEAD `1e64ae302011990fe10af30a940c64a3b0a24024`. Existing unrelated tracked/untracked changes were preserved.

| Binding | Exact value / meaning |
| --- | --- |
| Accepted artifact directory | `build_issue3_amd64_curl_build_02/artifact` |
| Vere upstream revision | `8ddc4b786979574dbfcb655e3db1b634f658d0de` (v4.6 plus recorded local changes) |
| Accepted executable SHA-256 | `58d07af97926e04bc17184bc18f53e5fb11d84fed63bd9daf2fe4ceb04c86698` |
| Source delivery SHA-256 | `8ed4fc8a6b4c1acba3e4e89860a4059e490feb3efaf2a818805770f24f65654f` |
| Recorded accepted image | `sha256:333864be7b25a51c4daf25156ced45424c1dfbfd27273e1aa2b320d95a356f8b` |
| Frozen recipe SHA-256 | `d41db22cdbe63d524b517fdf1039a3d9a8c464b430863a31a449b5903e5b6256` |
| Frozen input lock SHA-256 | `01c83a954542c6b7470f6e91fc6cf24069582563cc1d282d5046be4e98d81006` |
| Embedded versions recorded by exact-binary report | OpenSSL 3.5.9; curl 8.23.0 |

This review independently rehashed the executable and complete public source archive, read `candidate.json`, frozen `inputs.json`, dependency manifests and selected archived source/build files. Image and runtime outcomes are **reused saved evidence**, not a new image inspection or execution: see `openssl-amd64-curl-result.md`. The later report/lifecycle supersedes early `candidate.json` flags saying no report/image/lifecycle at its build-time checkpoint. This does not supersede `distribution_cleared: false`.

The archived source graph links libsigsegv/OpenSSL into noun, and GMP/curl/OpenSSL/Avahi into Vere; Avahi's adapter links D-Bus and Expat. Link declarations and selected source headers are not an exhaustive object-membership attestation. The saved static verification plus source graph support treating this as a static combined executable for preparation, not as independently replaceable shared libraries.

`openssl-allocation-hardening-result.md` is a **future source-only candidate**, including HTTP-context changes and a urcrypt SHA replacement. Its reported 59 host tests do not update the accepted executable above. A later hardened release requires its own binary/source/image binding, change notices and acceptance. No new build or runtime is authorized or performed by this review. `openssl-tls-artifact-recovery.json` records four exact-library TLS cases still unrun and no verified export of the accepted static library/object bytes. That is a technical acceptance/recovery gap, not automatically a legal requirement for object-only delivery.

Historical docs recovered from the older product checkout: `release-license-decisions.md`, `release-compliance-checklist.md`, and `vere-license-compatibility-result.md`. Their separate-source-companion approach is reused. Their old official executable `47ad302e8934271dfc00dcdab1d553c6d6460b105e3099ff47e0e4e4231bb26d`, old image/export, older source gaps, and optional-registry conclusion are **not** bindings or final-goal guidance for this replacement.

## Proposed component choices — not enacted

Each proposal concerns this distribution only. Preserve original grants/attributions; do not rewrite upstream “or later” permissions into “only” grants. The JSON companion contains the same core rows.

| Component | Exact version / revision | Observed grant | Proposed use for this combined distribution |
| --- | --- | --- | --- |
| Vere | 4.6 / `8ddc4b786979574dbfcb655e3db1b634f658d0de` | MIT | Preserve MIT and copyright 2015 Urbit; combined executable conveyed under GPLv3 conditions, without declaring Vere source exclusively GPL.[12] |
| libsigsegv | 2.14 | GPL-2.0-or-later | Exercise GPLv3 option; preserve upstream grant and notices.[4] |
| OpenSSL | 3.5.9 | Apache-2.0 | Preserve Apache licence, applicable notices and modification markings; combine through GPLv3-compatible route.[2][11] |
| curl | 8.23.0 | curl permission notice | Preserve exact 1996–2026 Daniel Stenberg/contributors notice and permission text; do not substitute the retained 8.9.1 notice.[3][13] |
| GMP | 6.3.0 | LGPL-3.0-or-later OR GPL-2.0-or-later | Proposed GPLv3 option under the GPL alternative; keep original dual grant. LGPLv3 is a valid alternate preparation route but has combined-work conditions.[5][9] |
| Avahi | 0.8 | LGPL-2.1-or-later in main selected source headers | Proposed LGPLv3 via later-version permission, satisfying §4 source/relink route; preserve original LGPL notices. No §3 conversion notice edits enacted.[6][9][10] |
| Avahi GLib-derived `avahi-common/utf8.c` | file in exact 0.8 cache tree | Literal notice says GNU **Lesser** GPL “version 2 ... or ... any later version” | Preserve literal wording and Tom Tromey/Red Hat attribution; proposed later-version LGPLv3 route, with wording/applicability explicitly recorded rather than silently normalized.[6] |
| D-Bus library | source 1.14.8 | AFL-2.1 OR GPL-2.0-or-later; some tools GPL-only | Proposed GPLv3 via GPL alternative, not AFL for this combined route. Standalone programs need their own file terms.[7] |

D-Bus's frozen adapter sets `VERSION` to 1.14.8 but generates a `DBUS_VERSION` header value of **1.14.10**. Source archive selection remains 1.14.8; do not silently change the component version to match the generated header. Reconcile this provenance discrepancy in release documentation (implementation belongs to the other worker).

Additional permissive/alternative choices are retained from `THIRD_PARTY/COMPONENTS.md`, `vere/followup/applicability.json` and the exact source caches, not relabelled as a complete linked SBOM: whereami `ba364cd54fd431c76c045393b6522b4bff547f50` — propose MIT rather than WTFPL; urcrypt `6c93535d46adffcd1495f904bac91d43b2d6d555` — keep MIT plus nested terms; Argon2 — propose CC0 rather than Apache where the actual file permits; Monocypher — propose BSD-2-Clause rather than CC0; H2O picohttpparser — preserve the MIT option. These are retained-inventory proposals, not newly enacted or exhaustive per-file elections. BLAKE3 1.5.0-labelled modified vendored files retain the prior exact-applicability/modification-notice residual; a version label alone does not clear that issue. All other recorded component notices remain applicable according to their actual selected files.

The inherited wrapper's literal `GPL v3`, owner-controlled contributions/artwork's existing GPL-3.0-only declaration, and the historical README's MIT attribution are separate from this combined-binary analysis.[8]
The whole container and all repository history are **not** being relicensed.[8]
Independent aggregate programs keep their own terms; GPLv3 §5's aggregate rule is not an exception for a statically linked program.[8]

## libsigsegv: runtime grant versus build-tool exceptions

The exact accepted archive contains the GPLv2-or-later runtime headers, not just a top-level COPYING file.[4]
The reviewed five translation units are `dispatcher.c`, `handler.c`, `leave.c`, `stackvma.c`, and `version.c`.[4]
The pinned Linux adapter additionally selects `handler-unix.c`, `leave-nop.c`, `stackvma-none.c`, `fault-linux-i386.h`, `fault-none.h`, and `signals.h`; `fault.h` and `sigsegv.h.in` were also checked.[4]
The retained receipt lists each inspected member and digest.[4]
No runtime OpenSSL-linking exception was established in these headers.[4]

There **are** special permissions in `build-aux/config.guess`, `config.sub`, `compile`, `missing`, `ltmain.sh`, and Autoconf macros such as `m4/bold.m4`.[4]
Their wording grants scoped permission for **that file** in an Autoconf/Libtool-built program or library.[4]
Those permissions do not purport to relicense the libsigsegv runtime implementation or authorize linking GPL runtime code with old OpenSSL.[4]
This is the concrete reason a keyword hit on “exception” does not answer the original question.[4]

This closes the bounded runtime/build-tool distinction, not every imaginable private grant or every architecture's implementation. The accepted replacement uses the GPLv3/Apache route instead. No third-party exception was authored; no maintainer was contacted.

## Static-link compliance options and selected draft route

### Proposed normal route: complete source, not object-only delivery

For the GPLv3 combined executable, prepare the corresponding source needed to generate/install/run/modify it, including interface files and controlling scripts; the licence excludes qualifying System Libraries and unmodified general-purpose tools.[8]
Do not demand every build tool's source or a bit-identical reproducibility project as a universal legal requirement.[8]

For Avahi under the proposed LGPLv3 choice, §4(d)(0) calls for Minimal Corresponding Source and Corresponding Application Code in a form allowing recombination/relinking with a modified library.[9]
The definition expressly permits **object code and/or source code**.[9]
Include required data/utilities, licence copies, prominent library/use notices, and terms allowing the covered modifications and reverse engineering for debugging them; include applicable runtime copyright notices if displayed.[9]

Thus absence of recovered `libssl.a`, `libcrypto.a`, `libcurl.a` or application `.o` files does **not by itself** make compliant delivery impossible.[8][9]
Complete usable corresponding source/build inputs can be the route.[8][9]
A source URL list or a tarball with untested/missing instructions is not proof that this route is fulfilled.[8][9]
Exact-library recovery remains a separate TLS test requirement in the technical worker's plan.[8][9]

### Other options, not silently substituted

- Keeping Avahi under LGPLv2.1 invokes §§4/6: library source including modifications, and for a static executable the complete work-that-uses-the-library as object **and/or** source with required data/utilities, permitting modification/relinking; §6(d) supplies the equivalent-download route.[10]
- LGPLv2.1 §3 allows conversion of a given library copy to ordinary GPL (including a newer published GPL version), but requires changing the relevant notices and makes the conversion irreversible for that copy. This is an available alternative, **not performed here** and not interchangeable with merely documenting a proposal.[10]
- GMP may instead stay on LGPLv3 with §4 compliance. Proposed use of its GPL alternative avoids inventing a second relicensing grant.[5][9]
- LGPL shared-library mechanisms under v2.1 §6(b) or v3 §4(d)(1) require an actual suitable replaceable runtime link. The accepted static artifact cannot claim that route just because the container also contains shared libraries.[9][10]
- D-Bus's AFL/GPL alternatives are choices, not an AND requirement. The GPL option is the proposed route here; no conclusion that AFL's different conditions have been satisfied is made.[7]

### Delivery and installation information

Use the previously selected **separate source companion**: GPLv3 §6(d) allows equivalent access alongside binary downloads, with clear adjacent directions if hosted on another server, at no further charge.[8]
Recipients need not download source with the installer.[8]
For peer-to-peer/IPFS delivery, address §6(e) as well: inform peers where the binary and source are publicly available at no charge under §6(d).[8]
A local archive or repository homepage alone is not recipient availability.[8]

No written offer is issued by these drafts.[8]
Do not publish one unless deliberately selecting and fulfilling that different route.[8]
Keep source availability and its version binding under the distributor's control rather than depending solely on upstream URLs.[8]

GPLv3 §6 Installation Information is conditional on the stated User Product and transfer-transaction facts; LGPLv3 §4(e) follows that trigger and its own necessity limit.[8][9]
This review establishes no hardware-possession transfer.[8][9]
The Public-tab software-download goal alone does not establish every triggering fact.[8][9]
If later distribution is bundled with qualifying hardware/transactions, assess a recipient-installable modified-build path.[8][9]
Do not read or publish wallet keys, CA keys, ship secrets or pier data; no such requirement is assumed here.[8][9]

## Actual materials versus missing work

**Already present and reused:** accepted `source-materials.tar.gz` contains the patched Vere tree, generated OpenSSL 3.5.9 tree, original Vere/OpenSSL/toolchain archives, and **24 package-cache trees**. A parsed inventory of URL/hash pairs in archived Vere `build.zig.zon` manifests found only macOS SDK declarations missing from that cache; those are not Linux inputs. This is more than the old partial source snapshot and supersedes a blanket claim that GMP/libsigsegv/curl/Avahi/D-Bus sources are absent. It is archive-membership evidence, not an independent Zig-content-hash recomputation or proof that every build step is documented.

The changed GMP/libsigsegv manifests now select GNU primary archive URLs and retained cache hashes. The old mirror-identity concern cannot simply be copied as a blocker for this candidate. Exact member notices were read from this accepted archive. Required build adapters and changes remain in the patched tree and frozen recipe; the original old OpenSSL notice in production THIRD_PARTY is not a replacement for the new licence.

**Not complete:** final recipient companion assembly and usable recipe instructions; final wrapper/manager source-to-image binding for this replacement; exact final image package/source/notice reconciliation (Python package changed from the historical baseline); nested attribution dispositions; final notice selection/inclusion for new versions; hardened-candidate rebinding if selected; recipient retrieval after separately authorized publication. See `license-preparation/source-delivery-checklist.md` for owners, evidence and closure tests.

**Concrete unresolved questions:**

1. Will the release select this accepted pre-hardening artifact or a newly qualified hardened one? New source-only changes cannot inherit its binary hash or acceptance.
2. Does the assembled source companion, including frozen recipe, package caches, generated configuration and scripts, actually let recipients build/relink modified library code without missing private or transient inputs? No build/relink was run in this no-build scope.
3. Which exact final APK versions, patches and source materials/notices accompany the release image, including the Python update? The older 36-APK baseline is not proof for every new package byte.
4. Have modified BLAKE3/nested notices and the recorded Alpine grant/CA-bundle applicability residuals received supported dispositions? Preserve affirmative grants; missing paperwork is not proof of no permission.
5. Is the literal Avahi UTF-8 LGPL-version wording and proposed later-version treatment adequately documented, and are all its original notices preserved? Do not replace its actual text with a guessed SPDX identifier.
6. Do the actual distribution transaction and recipient installation mechanism trigger additional Installation Information obligations? Reassess if the release model changes.

These are specific source, notice, artifact-selection and conditional legal questions, not requests for a generic FOSS distribution permit. Qualified licensing review is appropriate for any disputed interpretation before claiming clearance.

## Retrieval, scope and verification limits

The resumed review reused the prior citation ledger and successful primary OpenSSL/Apache/curl page bodies rather than fetching them again.[4][13]
Direct current GNU website requests timed out.[4][13]
The configured native search backend reported search-only extraction unavailable; a search fallback returned primary GNU/Apache results, but snippets were **not** used as full licence texts.[4][13]
Full GPL/LGPL terms were instead read from hash-bound upstream source members already in the accepted delivery.[4][13]
Sources [4]–[13] therefore identify primary origins/official canonical licence pages; the ledger is not a claim that every URL was newly downloaded today.

`license-preparation/evidence-receipts.json` gives exact archive members, hashes, scope and text-copy identities. `source-cache-inventory.json` and `selected-source-notices.json` record bounded programmatic checks. The latter includes conditional Windows .c declarations for completeness of the source-list scan; it is not a claim that those objects are linked on Linux. The source ledger uses stable IDs and short mechanically verified evidence quotes.

Only this review, its JSON companion and new files under `docs/license-preparation/` were written. No production licence, README, THIRD_PARTY, recipe or hardening file was edited. No build, runtime, private-state/log/key access, cleanup, Docker operation, external contact, signing, publication, transaction, commit or push occurred. Preparation done does not mean publication cleared.

## Sources

[1] https://www.openssl.org/source/license.html
[2] https://www.apache.org/licenses/GPL-compatibility.html
[3] https://curl.se/docs/copyright.html
[4] https://ftp.gnu.org/gnu/libsigsegv/libsigsegv-2.14.tar.gz — libsigsegv 2.14 runtime grant and build-tool permissions
[5] https://ftp.gnu.org/gnu/gmp/gmp-6.3.0.tar.xz — GMP 6.3.0 alternative grants
[6] https://github.com/lathiat/avahi/releases/download/v0.8/avahi-0.8.tar.gz — Avahi 0.8 source grant
[7] https://dbus.freedesktop.org/releases/dbus/dbus-1.14.8.tar.xz — D-Bus 1.14.8 alternative grants
[8] https://www.gnu.org/licenses/gpl-3.0.html — GPLv3 exact license text retained in GMP
[9] https://www.gnu.org/licenses/lgpl-3.0.html — LGPLv3 exact license text retained in GMP
[10] https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html — LGPLv2.1 exact license text retained in Avahi
[11] https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz — OpenSSL 3.5.9 exact license
[12] https://codeload.github.com/urbit/vere/tar.gz/8ddc4b786979574dbfcb655e3db1b634f658d0de — Pinned Vere MIT license
[13] https://curl.se/download/curl-8.23.0.tar.gz — curl 8.23.0 permission notice
