# ca-certificates-bundle 20260909-r0: pinned source/notice follow-up

**Outcome: the missing README/source notice was recovered; generated-bundle applicability is narrowly classified, not cleared.** The literal installed and recipe declaration remains **MPL-2.0 AND MIT**. This addition does not change existing coverage records, package manifests or the final image.

## Exact revision and recovery

The retained [APKBUILD](../../image-baseline/recipes/ca-certificates-APKBUILD) is from Alpine aports `eb7078df3a16d666e8f7723f94bb92e00d4b9236`. The official [tag API response](evidence/tag.json) binds version `20260909` to commit `5aaf4043e057e23cc8e0dd5cfbe4f9ceba41ca3b`; `target` is the annotated tag object `b692f78f98ec478f01266e8962d197480bae6360`, **not** the source commit. [VERSION](source/VERSION) agrees. [Recursive commit tree](evidence/tree-commit.json) and [tag tree](evidence/tree-tag.json) are identical; all collected upstream files match their listed Git blob IDs. The API response contained 14 entries (13 blobs and one directory), below the requested 100-entry page; README.md is present, README and named root license files are not.

The previous `.../raw/20260909/README` HTTP 404 remains recorded in [additional-notices.json](../../image-baseline/additional-notices.json). It was not retried: the correct [README.md](source/README.md) was obtained by the official API at the resolved commit. The previously checked archive was **not fetched again**. Historical recipe-checksum verification is referenced, not promoted to a new archive/per-file byte comparison. Search discovery did not establish the pin; the retained API and file bytes did.

## Bundle path and applicability

[Makefile](source/Makefile) runs `perl mk-ca-bundle.pl -n -w 64 cert.pem`, so it consumes the bundled public [certdata.txt](source/certdata.txt) without downloading replacement certificate data. The tool defaults to `SERVER_AUTH:TRUSTED_DELEGATOR`; its [embedded notice](source/mk-ca-bundle.pl) selects SPDX `curl` and references a COPYING file absent from this tree. [split-ca-bundle.sh](source/split-ca-bundle.sh) takes the blocks following certificate-name separators through END CERTIFICATE into individual `.crt` files; general bundle headers are outside those blocks. The retained recipe sorts/concatenates those `.crt` files, adding a newline per file, into `etc/ssl/certs/ca-certificates.crt`.

`bundle()` moves **only** that generated file and creates the three compatibility links: `etc/ssl/cert.pem -> certs/ca-certificates.crt`, `etc/ssl1.1/certs -> /etc/ssl/certs`, and `etc/ssl1.1/cert.pem -> /etc/ssl/cert.pem`. The retained installed APK database enumerates exactly those four paths. This is a source packaging trace, not newly verified installed bytes.

The pinned certdata.txt lines 2–4 expressly attach **MPL v2.0** to that Source Code Form. The [complete official Mozilla MPL v2.0 text](licenses/MPL-2.0.txt) was retrieved only after checking the existing repository for reusable full text; the versioned text is bound by this actual notice, not guessed from a package label. The unchanged public source is delivered here with its notice intact. This establishes an express source-file grant, not an assessment of copyrightability of individual CA data or satisfaction of every generated-bundle obligation.

[c_rehash.c](source/c_rehash.c) carries Timo Teräs's copyright and an explicit MIT license reference. It and [update-ca.c](source/update-ca.c) compile into utilities installed by the main package; the bundle subpackage does not move them. The manpage [authorship notice](source/update-ca-certificates.8) is also retained as unshipped documentation evidence. The Makefile, split script, updater C source and [version helper](source/scripts/update-version.sh) do not supply an express embedded per-file grant. The recipe's comment about an unshipped GPL script is preserved as historical recipe evidence: the retrieved generator actually says `curl`, so that comment alone cannot establish a current GPL file. No license declaration was deleted or rewritten.

## Delivery and limits

[Inventory](inventory.json) lists exact URLs, bytes and SHA-256 values; [notice bindings](notice-bindings.json) identify actual embedded notices; [source-delivery references](source-delivery-references.json) bind the source paths, recipe and archive history. The latter is a recipient-facing source locator, **not** a complete corresponding-source acceptance. The complete upstream tree is enumerated but CI/ignore/renovation metadata is not copied.

Package-wide `applicable_grant_established` remains false conservatively: the explicit MPL source-file grant is separately true in notice-bindings.json, while the precise generated-payload scope and mixed MIT declaration need review. Missing source/notice discovery is no longer an unknown-root-license problem; the residual is generated-bundle notice/source-delivery applicability and integration. Parent notice/context manifests and the final image still need independent selection/readback. Complete coverage, complete corresponding source and legal clearance remain false.

Only public upstream source was read. No local trust store, user certificates, keys, CA operations, build, boot, Docker, archive redownload, export, signing, publication, target access, cleanup, commit, push or upstream engagement occurred.
