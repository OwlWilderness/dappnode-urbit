# Nested notices and source inputs: bounded follow-up

**Source-level applicability review only. Release remains blocked and unbuilt.**
No legal clearance, final-image SBOM, verified binary membership, written offer,
or complete corresponding-source delivery is asserted.

Start with [source delivery](../../SOURCE_DELIVERY.md), the
[machine-readable manifest](../../source-delivery.json), and
[applicability records](applicability.json). Existing inventories are unchanged.

## Concrete findings

- **BLAKE3:** the pinned urcrypt copy is a modified 1.5.0-derived selected source
  set, not a byte-identical upstream release. Of the nine AMD64 source/header
  files compared, six are identical Git blobs. The other three are captured as
  exact [diffs and blob identities](blake3-comparison.json): `blake3.c` adds
  `blake3_hasher_init_raw`; `blake3.h` declares it; `blake3_impl.h` differs only
  in whitespace in this comparison. Four AMD64 Unix assembly implementations,
  dispatch and portable implementation match upstream. This narrows the old
  header-only uncertainty; it does not establish whole-directory equivalence,
  grant rights over modifications, or authenticate the official executable.
  The already-collected [upstream license](../licenses/urcrypt/blake3/LICENSE)
  remains identified as the upstream reference. Modification attribution and
  applicable notice delivery still require reconciliation.
- **Picotls is not uniformly MIT:** the explicitly selected `asn1.c` and
  `pembase64.c` carry Christian Huitema's ISC-style permission/disclaimer.
  Their complete notices are preserved in [supplementary notices](NOTICES.txt)
  and the [full per-file evidence](notice-review-inputs.json). MIT-bearing
  picotls files retain their distinct holders. This supplements, rather than
  silently changing, the earlier picotls MIT summary.
- **Cifra:** selected `curve25519.c` directly includes
  `curve25519.tweetnacl.c` on the non-Cortex branch relevant to AMD64. The
  included file identifies TweetNaCl and a public-domain origin. Selected
  `poly1305.c` retains its CC0 dedication. These are source edges, not linked
  binary proof. Existing [Cifra CC0 text](../licenses/h2o/deps/picotls/deps/cifra/COPYING)
  and [micro-ecc BSD text](../licenses/h2o/deps/picotls/deps/micro-ecc/LICENSE.txt)
  remain relevant source notices.
- **Klib:** disabling the standalone klib link does not exclude headers. The
  adapter adds its include directory; explicitly selected `lib/common/cache.c`
  includes `khash.h`. The additional retained `kvec.h` and `kstring.h` remain
  header candidates, not independently established include paths here. Preserve
  applicable header notices. The four h2o replacement
  files already collected remain source/build material; the klib library's
  direct link is commented out, while the patched picohttpparser implementation
  is explicitly selected and linked.
- **Urcrypt:** the selected scrypt implementation and SHA-256 helper carry
  Colin Percival's BSD-2-Clause notices, distinct from the top-level scrypt
  notice. Argon2's selected BLAKE2 files and optimized implementation carry
  the dual CC0/Apache notice. The selected Ed25519 SHA-512 file identifies
  LibTomCrypt origin and a literal “free for all purposes” grant, not an explicit
  public-domain dedication in that file. It should not be reduced to the parent
  directory's Zlib label or silently assigned a standard license identifier.
  Preserve these per-file declarations.

## Materials delivered, and limits

[Source-input lock](source-inputs.json) records the selected revision's Zig
adapters/manifests, workflows and patch replacement files. An actual local
[public Vere source archive](materials/vere-8ddc4b786979574dbfcb655e3db1b634f658d0de.tar.gz)
was reconstructed from retained Git objects, without fetching source archives or
running code. Every regular file was matched to the already-retained upstream
Git tree. It is **not** the byte stream of an upstream release tarball.
The [archive member index](archive-members.json) supplies every included path
and content hash.

The [wrapper snapshot](materials/uvm-wrapper-source-snapshot.tar.gz) contains
actual public package/wrapper inputs, not a placeholder. Its
[lock](wrapper-source-lock.json) pins each byte stream. It is a point-in-time
**dirty, historical pre-integration** source snapshot; it **must be refreshed**
after the parent's Dockerfile/context/notice-inclusion integration. Its recorded
Dockerfile and `.dockerignore` hashes are archive-history checks, not a final
source freeze. Tests/docs and dependency source archives
are not comprehensively included. The original executable and artwork were
not changed or executed.

[Dependency lock](dependency-lock.json) preserves all 95 literal declarations
and 30 primary component records from the existing inventory, including all
26 unique source-archive URLs. SHA-256 archive values are inherited collection
records, **not** fresh verification of unavailable archives. No dependency
archive has been redownloaded. GMP, libsigsegv and natpmp mirror identity gaps
remain unresolved, and Zig package hashes have not been recomputed.

[Retrieval ledger](retrievals.json) records only genuinely missing pinned
public per-file/tree evidence, including response limits, URLs, hashes and
sizes. Full fetched files use a `.txt` suffix as inert evidence. Some notices
were recovered from retained Git rather than fetched. No private state or
logs were inspected. No upstream inquiry or legal engagement occurred; the
existing libsigsegv/older-OpenSSL distribution-basis question was not reopened.

[Verification](verification.json) checks JSON, local links, content hashes,
archive members and source-edge assertions. It is not a build, runtime,
installer, final-image or source-delivery-completeness test.
