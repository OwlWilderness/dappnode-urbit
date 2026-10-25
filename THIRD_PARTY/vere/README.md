# Vere 4.6: source-pinned licenses and notices

Pinned Vere revision: `8ddc4b786979574dbfcb655e3db1b634f658d0de`.
The upstream `vere-v4.6` tag resolves to that commit.[1]

`inventory.json` is the machine-readable entry point: component versions/revisions,
manifest declarations, upstream URLs, archive SHA256 values, full-text paths,
file SHA256 values, platform/build scope, and unresolved items. `licenses/` holds
full license texts; `notices/` holds complete notice-bearing source/readme files;
`evidence/` holds the pinned tree and build declarations. Original file bytes are
preserved; the saved Vere tree is explicitly reformatted JSON.

## Coverage

63 component records (30 primary/in-tree entries and 33 nested/internal entries); 26 distinct archive URLs from the inspected manifests, including the followed zlib wrapper dependency. 56 license-directory files, 25 notice-directory files, and 61 evidence files. Counts describe collected source material, **not shipped components**.

The source declarations include h2o and urcrypt nested libraries. macOS SDK,
AArch64-only sse2neon use, build-time NASM, and optional developer Tracy are
explicitly distinguished from AMD64 runtime candidates. Auxiliary tools,
examples, and documentation licenses do not establish binary inclusion.[2][3][4]

## Limits and unresolved items

- **Not a binary SBOM or legal clearance.** No binary download, build, execution,
  or link-map verification was performed. Declared dependencies are not proof
  that every component is linked into the release.
- Zig hashes are preserved, not recomputed. Primary-host replacements for the
  GMP, libsigsegv and libnatpmp mirror URLs have recorded SHA256 values but no
  independently established equality to the manifest-mirror archives.
- The macOS SDK was intentionally not fetched. BLAKE3's version-matched upstream
  license is retained as a reference: the vendored 1.5.0 header differs from
  upstream, so source equivalence and exact applicability remain unresolved.
- This bounded collection is not an exhaustive audit of all nested sources,
  toolchains, examples, system libraries, or individual file attributions.
- The known libsigsegv GPL-2.0-or-later/OpenSSL 1.1.1w original-terms distribution
  question remains open. Collecting notices does not create an exception or
  establish permission to distribute a combined work.[5][6]

The copied C/header files are documentary evidence, not a standalone compilable
source distribution. See each component's `unresolved` field and the top-level
`limitations` list before using this collection in a distribution.

## Sources

[1] https://api.github.com/repos/urbit/vere/git/ref/tags/vere-v4.6
[2] https://raw.githubusercontent.com/urbit/vere/8ddc4b786979574dbfcb655e3db1b634f658d0de/build.zig
[3] https://raw.githubusercontent.com/urbit/vere/8ddc4b786979574dbfcb655e3db1b634f658d0de/ext/h2o/build.zig
[4] https://raw.githubusercontent.com/urbit/vere/8ddc4b786979574dbfcb655e3db1b634f658d0de/ext/openssl/build.zig
[5] https://ftp.gnu.org/gnu/libsigsegv/libsigsegv-2.14.tar.gz
[6] https://github.com/openssl/openssl/releases/download/OpenSSL_1_1_1w/openssl-1.1.1w.tar.gz

All individual source URLs, archive member names and file digests are recorded
in `inventory.json`; URLs above are primary provenance, not a request to execute
or install anything.
