# Component license index

Readable index of the collected source notices. These are **declared/source
components, not a verified list of binaries shipped in the image**. Read full
texts and the linked inventories for exceptions, attribution and coverage gaps.

**Supplements:** [nested selected-file review](vere/followup/README.md) adds
picotls ISC-style, scrypt helper and Ed25519 SHA-512 notices and narrows BLAKE3's
modified-source provenance. Its supplementary texts take precedence over the
older short summaries below for the reviewed files. The
[retained-image package table](platform/image-baseline/PACKAGES.md) enumerates
all 36 baseline APKs, not merely the four direct pins below. Neither supplement
establishes exhaustive notice coverage, final-image inclusion or distribution
clearance. See [prepared source delivery](SOURCE_DELIVERY.md).

## Vere and primary declared dependencies

| Component | Version / revision | Recorded terms | Full texts | Scope / gaps |
| --- | --- | --- | --- | --- |
| aes_siv | 9681279cfaa6e6399bb7ca3afbbc27fc2e19df4b | Apache-2.0 | [COPYING](vere/licenses/aes_siv/COPYING) | declared-runtime-candidate; actual release linkage not verified |
| avahi | 0.8 | LGPL-2.1-or-later | [LICENSE](vere/licenses/avahi/LICENSE) | declared-runtime-candidate; actual release linkage not verified |
| backtrace | 4ead348bb45f753121ca0bd44170ff8352d4c514 | BSD-3-Clause | [LICENSE](vere/licenses/backtrace/LICENSE) | declared-runtime-candidate; actual release linkage not verified |
| curl | 8.9.1 | curl | [COPYING](vere/licenses/curl/COPYING) | declared-runtime-candidate; actual release linkage not verified |
| dbus | 1.14.8 | AFL-2.1 OR GPL-2.0-or-later; standalone tools may differ | [COPYING](vere/licenses/dbus/COPYING)<br>[COPYING-CMAKE-SCRIPTS](vere/licenses/dbus/cmake/modules/COPYING-CMAKE-SCRIPTS) | declared-runtime-candidate; actual release linkage not verified |
| ent | 8ddc4b786979574dbfcb655e3db1b634f658d0de | MIT | [LICENSE](vere/licenses/ent/LICENSE) | declared-runtime-candidate; actual release linkage not verified |
| expat | 2.5.0 | MIT | [COPYING](vere/licenses/expat/COPYING) | declared-runtime-candidate; actual release linkage not verified |
| gmp | 6.3.0 | LGPL-3.0-or-later OR GPL-2.0-or-later | [COPYING](vere/licenses/gmp/COPYING)<br>[COPYING.LESSERv3](vere/licenses/gmp/COPYING.LESSERv3)<br>[COPYINGv3](vere/licenses/gmp/COPYINGv3)<br>[COPYINGv2](vere/licenses/gmp/COPYINGv2) | declared-runtime-candidate; actual release linkage not verified; Fetched matching release from original upstream rather than manifest mirror; Zig package hash not recomputed; archive identity against manifest mirror not independently proven. |
| h2o | 3bbfe369a5c31d38cc1717e5281ca6af89ecf787 | MIT; nested component terms separate | [LICENSE](vere/licenses/h2o/LICENSE)<br>[LICENSE](vere/licenses/h2o/deps/brotli/LICENSE)<br>[COPYING](vere/licenses/h2o/deps/libyrmcds/COPYING)<br>[LICENSE](vere/licenses/h2o/deps/mruby-input-stream/LICENSE)<br>[LICENSE](vere/licenses/h2o/deps/neverbleed/LICENSE)<br>[COPYING](vere/licenses/h2o/deps/picotls/deps/cifra/COPYING)<br>[LICENSE.txt](vere/licenses/h2o/deps/picotls/deps/micro-ecc/LICENSE.txt)<br>[LICENSE](vere/licenses/h2o/deps/ssl-conservatory/LICENSE)<br>[LICENSE](vere/licenses/h2o/deps/yaml/LICENSE) | declared-runtime-candidate; actual release linkage not verified |
| libuv | 1.50.0 | MIT; LICENSE-extra and documentation terms separate | [LICENSE](vere/licenses/libuv/LICENSE)<br>[LICENSE-docs](vere/licenses/libuv/LICENSE-docs)<br>[LICENSE-extra](vere/licenses/libuv/LICENSE-extra) | declared-runtime-candidate; actual release linkage not verified |
| lmdb | 40d3741b7d40ba4c75cb91dd9987ce692d376d71 | OLDAP-2.8 | [COPYRIGHT](vere/licenses/lmdb/libraries/liblmdb/COPYRIGHT)<br>[LICENSE](vere/licenses/lmdb/libraries/liblmdb/LICENSE) | declared-runtime-candidate; actual release linkage not verified |
| macos_sdk | 14.5 | UNRESOLVED; not fetched | Not collected | excluded: macOS-only SDK; Excluded macOS-only SDK; archive not fetched (size boundary; not AMD64 Linux). |
| murmur3 | 8ddc4b786979574dbfcb655e3db1b634f658d0de | public-domain dedication (source header) | [murmur3.c](vere/licenses/murmur3/murmur3.c) | declared-runtime-candidate; actual release linkage not verified |
| nasm | 2.16.1-4 (Vere manifest) | BSD-2-Clause | [LICENSE](vere/licenses/nasm/LICENSE) | excluded: build-time assembler in Windows branch of ext/openssl/build.zig |
| natpmp | 20230423 | BSD-3-Clause | [LICENSE](vere/licenses/natpmp/LICENSE) | declared-runtime-candidate; actual release linkage not verified; Fetched matching release from original upstream rather than manifest mirror; Zig package hash not recomputed; archive identity against manifest mirror not independently proven. |
| openssl | 1.1.1w | OpenSSL and original SSLeay terms; auxiliary tools separate | [LICENSE](vere/licenses/openssl/LICENSE)<br>[COPYING](vere/licenses/openssl/external/perl/Text-Template-1.46/COPYING)<br>[copyright.pm](vere/licenses/openssl/util/perl/OpenSSL/copyright.pm) | declared-runtime-candidate; actual release linkage not verified |
| pdjson | 67108d883061043e55d0fb13961ac1b6fc8a485c | Unlicense | [UNLICENSE](vere/licenses/pdjson/UNLICENSE) | declared-runtime-candidate; actual release linkage not verified |
| secp256k1 | 0.5.1 | MIT | [COPYING](vere/licenses/secp256k1/COPYING) | declared-runtime-candidate; actual release linkage not verified |
| sigsegv | 2.14 | GPL-2.0-or-later | [COPYING](vere/licenses/sigsegv/COPYING) | declared-runtime-candidate; actual release linkage not verified; Fetched matching release from original upstream rather than manifest mirror; Zig package hash not recomputed; archive identity against manifest mirror not independently proven. |
| softblas | cbffb33f19ea02f9ffbd184d445123c57929ec53 | MIT | [LICENSE](vere/licenses/softblas/LICENSE) | declared-runtime-candidate; actual release linkage not verified |
| softfloat | 5c06db33fc1e2130f67c045327b0ec949032df1d | BSD-3-Clause | [COPYING.txt](vere/licenses/softfloat/COPYING.txt) | declared-runtime-candidate; actual release linkage not verified |
| sse2neon | 1.5.1 | MIT | [LICENSE](vere/licenses/sse2neon/LICENSE) | excluded: aarch64-only include paths in ext/h2o/build.zig |
| tracy | 0.12.2 | BSD-3-Clause; examples and nested terms separate | [LICENSE](vere/licenses/tracy/LICENSE)<br>[license.md](vere/licenses/tracy/examples/ToyPathTracer/license.md)<br>[LICENSE](vere/licenses/tracy/public/libbacktrace/LICENSE) | optional developer profiler; disabled by default; not asserted shipped |
| unwind | 7cc4c20fbcf65a9c855fb9d950fad8d0e29b092e | MIT | [COPYING](vere/licenses/unwind/COPYING)<br>[LICENSE](vere/licenses/unwind/LICENSE) | declared-runtime-candidate; actual release linkage not verified |
| urcrypt | 6c93535d46adffcd1495f904bac91d43b2d6d555 | MIT; nested component terms separate | [LICENSE](vere/licenses/urcrypt/LICENSE)<br>[LICENSE](vere/licenses/urcrypt/argon2/LICENSE)<br>[license.txt](vere/licenses/urcrypt/ed25519/license.txt)<br>[LICENSE](vere/licenses/urcrypt/ge-additions/LICENSE)<br>[LICENSE](vere/licenses/urcrypt/scrypt/LICENSE) | declared-runtime-candidate; actual release linkage not verified |
| vere | 4.6 | MIT | [LICENSE.txt](vere/licenses/vere/LICENSE.txt) | declared-runtime-candidate; actual release linkage not verified |
| wasm3 | be8cbeafa8b2301350484ecb494ed0288589d985 | MIT | [LICENSE](vere/licenses/wasm3/LICENSE) | declared-runtime-candidate; actual release linkage not verified |
| whereami | ba364cd54fd431c76c045393b6522b4bff547f50 | MIT OR WTFPL-2.0 | [LICENSE.MIT](vere/licenses/whereami/LICENSE.MIT)<br>[LICENSE.WTFPLv2](vere/licenses/whereami/LICENSE.WTFPLv2) | declared-runtime-candidate; actual release linkage not verified |
| zlib | 1.3.1 | Zlib; bundled contrib notices retained | [LICENSE](vere/licenses/zlib/LICENSE)<br>[LICENSE_1_0.txt](vere/licenses/zlib/contrib/dotzlib/LICENSE_1_0.txt) | declared-runtime-candidate; actual release linkage not verified |
| zlib-build-wrapper | 61e7df7e996ec5a5f13a653db3c419adb340d6ef | MIT | [LICENSE](vere/licenses/zlib-build-wrapper/LICENSE) | build-only Zig integration, not a linked zlib library |

## Nested and internal source components

| Component | Version / revision | Recorded terms | Full texts | Scope / gaps |
| --- | --- | --- | --- | --- |
| dbus/cmake-scripts | 1.14.8 (vendored snapshot) | BSD-style | [COPYING-CMAKE-SCRIPTS](vere/licenses/dbus/cmake/modules/COPYING-CMAKE-SCRIPTS) | excluded from AMD64 shipped claims: auxiliary/developer/documentation source |
| h2o/brotli | 3bbfe369a5c31d38cc1717e5281ca6af89ecf787 (vendored snapshot) | MIT | [LICENSE](vere/licenses/h2o/deps/brotli/LICENSE) | source archive only; no shipped claim |
| h2o/cifra | 3bbfe369a5c31d38cc1717e5281ca6af89ecf787 (vendored snapshot) | CC0-1.0 | [COPYING](vere/licenses/h2o/deps/picotls/deps/cifra/COPYING) | declared-runtime-candidate |
| h2o/cloexec | 3bbfe369a5c31d38cc1717e5281ca6af89ecf787 (vendored snapshot) | MIT | [cloexec.c](vere/notices/h2o/deps/cloexec/cloexec.c) | excluded from shipped claims: direct link commented out |
| h2o/golombset | 3bbfe369a5c31d38cc1717e5281ca6af89ecf787 (vendored snapshot) | MIT | [golombset.h](vere/notices/h2o/deps/golombset/golombset.h) | header include candidate |
| h2o/klib | 3bbfe369a5c31d38cc1717e5281ca6af89ecf787 (vendored snapshot) | MIT | [khash.h](vere/notices/h2o/deps/klib/khash.h) | header include candidate; direct library link commented out |
| h2o/libgkc | 3bbfe369a5c31d38cc1717e5281ca6af89ecf787 (vendored snapshot) | MIT | [gkc.c](vere/notices/h2o/deps/libgkc/gkc.c) | declared-runtime-candidate |
| h2o/libyrmcds | 3bbfe369a5c31d38cc1717e5281ca6af89ecf787 (vendored snapshot) | BSD-2-Clause | [COPYING](vere/licenses/h2o/deps/libyrmcds/COPYING) | excluded from shipped claims: direct link commented out |
| h2o/micro-ecc | 3bbfe369a5c31d38cc1717e5281ca6af89ecf787 (vendored snapshot) | BSD-2-Clause | [LICENSE.txt](vere/licenses/h2o/deps/picotls/deps/micro-ecc/LICENSE.txt) | declared-runtime-candidate |
| h2o/mruby-input-stream | 3bbfe369a5c31d38cc1717e5281ca6af89ecf787 (vendored snapshot) | MIT | [LICENSE](vere/licenses/h2o/deps/mruby-input-stream/LICENSE) | source archive only; no shipped claim |
| h2o/neverbleed | 3bbfe369a5c31d38cc1717e5281ca6af89ecf787 (vendored snapshot) | MIT | [LICENSE](vere/licenses/h2o/deps/neverbleed/LICENSE) | source archive only; no shipped claim |
| h2o/picohttpparser | 3bbfe369a5c31d38cc1717e5281ca6af89ecf787 (vendored snapshot) | MIT or Perl terms; MIT text retained | [picohttpparser.h](vere/notices/h2o/deps/picohttpparser/picohttpparser.h) | declared-runtime-candidate; Vere patch retained separately |
| h2o/picotls | 3bbfe369a5c31d38cc1717e5281ca6af89ecf787 (vendored snapshot) | MIT | [picotls.h](vere/notices/h2o/deps/picotls/include/picotls.h) | declared-runtime-candidate |
| h2o/ssl-conservatory | 3bbfe369a5c31d38cc1717e5281ca6af89ecf787 (vendored snapshot) | MIT | [LICENSE](vere/licenses/h2o/deps/ssl-conservatory/LICENSE) | excluded from shipped claims: declaration/link commented out |
| h2o/yaml | 3bbfe369a5c31d38cc1717e5281ca6af89ecf787 (vendored snapshot) | MIT | [LICENSE](vere/licenses/h2o/deps/yaml/LICENSE) | source archive only; no shipped claim |
| h2o/yoml | 3bbfe369a5c31d38cc1717e5281ca6af89ecf787 (vendored snapshot) | MIT | [yoml.h](vere/notices/h2o/deps/yoml/yoml.h) | header include candidate |
| libuv/documentation | 1.50.0 (vendored snapshot) | CC-BY-4.0 | [LICENSE-docs](vere/licenses/libuv/LICENSE-docs) | excluded from AMD64 shipped claims: auxiliary/developer/documentation source |
| openssl/copyright.pm | 1.1.1w (vendored snapshot) | Apache-2.0 source header | [copyright.pm](vere/licenses/openssl/util/perl/OpenSSL/copyright.pm) | excluded from AMD64 shipped claims: auxiliary/developer/documentation source |
| openssl/Text-Template | 1.1.1w (vendored snapshot) | GPL-2.0 text; tool-specific grant not fully traced | [COPYING](vere/licenses/openssl/external/perl/Text-Template-1.46/COPYING) | excluded from AMD64 shipped claims: auxiliary/developer/documentation source |
| pkg/c3 | 8ddc4b786979574dbfcb655e3db1b634f658d0de | Vere root MIT; third-party terms remain separate | [LICENSE.txt](vere/licenses/vere/LICENSE.txt) | internal Vere package; not independently versioned |
| pkg/noun | 8ddc4b786979574dbfcb655e3db1b634f658d0de | Vere root MIT; third-party terms remain separate | [LICENSE.txt](vere/licenses/vere/LICENSE.txt) | internal Vere package; not independently versioned |
| pkg/past | 8ddc4b786979574dbfcb655e3db1b634f658d0de | Vere root MIT; third-party terms remain separate | [LICENSE.txt](vere/licenses/vere/LICENSE.txt) | internal Vere package; not independently versioned |
| pkg/ur | 8ddc4b786979574dbfcb655e3db1b634f658d0de | Vere root MIT; third-party terms remain separate | [LICENSE.txt](vere/licenses/vere/LICENSE.txt) | internal Vere package; not independently versioned |
| pkg/vere | 8ddc4b786979574dbfcb655e3db1b634f658d0de | Vere root MIT; third-party terms remain separate | [LICENSE.txt](vere/licenses/vere/LICENSE.txt) | internal Vere package; not independently versioned |
| tracy/libbacktrace | 0.12.2 (vendored snapshot) | BSD-3-Clause | [LICENSE](vere/licenses/tracy/public/libbacktrace/LICENSE) | excluded from AMD64 shipped claims: auxiliary/developer/documentation source |
| tracy/ToyPathTracer | 0.12.2 (vendored snapshot) | Unlicense | [license.md](vere/licenses/tracy/examples/ToyPathTracer/license.md) | excluded from AMD64 shipped claims: auxiliary/developer/documentation source |
| urcrypt/argon2 | 6c93535d46adffcd1495f904bac91d43b2d6d555 (vendored snapshot) | CC0-1.0 OR Apache-2.0 | [LICENSE](vere/licenses/urcrypt/argon2/LICENSE) | declared-runtime-candidate; actual release linkage not verified |
| urcrypt/blake3 | 1.5.0; vendored at urcrypt 6c93535d46adffcd1495f904bac91d43b2d6d555 | CC0-1.0 OR Apache-2.0 (version-matched upstream license) | [README.md](vere/notices/urcrypt/blake3/README.md)<br>[blake3.h](vere/notices/urcrypt/blake3/blake3.h)<br>[LICENSE](vere/licenses/urcrypt/blake3/LICENSE) | declared-runtime-candidate; actual release linkage not verified; Upstream 1.5.0 license supplied as version-matched reference only. Vendored header says 1.5.0 but does NOT byte-match upstream; complete source/version equivalence and exact license applicability remain unresolved. |
| urcrypt/ed25519 | 6c93535d46adffcd1495f904bac91d43b2d6d555 (vendored snapshot) | Zlib | [license.txt](vere/licenses/urcrypt/ed25519/license.txt) | declared-runtime-candidate; actual release linkage not verified |
| urcrypt/ge-additions | 6c93535d46adffcd1495f904bac91d43b2d6d555 (vendored snapshot) | BSD-3-Clause | [LICENSE](vere/licenses/urcrypt/ge-additions/LICENSE) | declared-runtime-candidate; actual release linkage not verified |
| urcrypt/keccak-tiny | 6c93535d46adffcd1495f904bac91d43b2d6d555 (vendored snapshot) | CC0-1.0 (notice; full CC0 in argon2/LICENSE) | [README.markdown](vere/notices/urcrypt/keccak-tiny/README.markdown)<br>[keccak-tiny.c](vere/notices/urcrypt/keccak-tiny/keccak-tiny.c)<br>[LICENSE](vere/licenses/urcrypt/argon2/LICENSE) | declared-runtime-candidate; actual release linkage not verified |
| urcrypt/monocypher | 6c93535d46adffcd1495f904bac91d43b2d6d555 (vendored snapshot) | BSD-2-Clause OR CC0-1.0 | [monocypher.c](vere/notices/urcrypt/monocypher/monocypher.c)<br>[LICENSE](vere/licenses/urcrypt/argon2/LICENSE) | declared-runtime-candidate; actual release linkage not verified |
| urcrypt/scrypt | 6c93535d46adffcd1495f904bac91d43b2d6d555 (vendored snapshot) | BSD-2-Clause | [LICENSE](vere/licenses/urcrypt/scrypt/LICENSE) | declared-runtime-candidate; actual release linkage not verified |

## Direct platform packages and historical material

| Component | Declared version | Recorded terms | Full text |
| --- | --- | --- | --- |
| zlib | 1.3.2-r1 | Zlib | [License](platform/licenses/zlib-LICENSE.txt) |
| python3 | 3.14.8-r0 | PSF-2.0 (plus historical agreements and included notices; see full LICENSE) | [License](platform/licenses/python3-LICENSE.txt) |
| openssl | 3.5.9-r0 | Apache-2.0 | [License](platform/licenses/openssl-LICENSE.txt) |
| nginx | 1.30.6-r0 | BSD-2-Clause | [License](platform/licenses/nginx-LICENSE.txt) |
| Historical jmnsf/urbit-docker README | `32fc5f843adf5b9f67b7e5a71f2370bc0cb53c67` | MIT | [License](platform/licenses/jmnsf-readme-LICENSE.txt) |

## Explicitly incomplete coverage

- Exact base/transitive versions, including musl and BusyBox, are now in the linked retained-image baseline; final-image inventory and complete notice sets remain unverified.
- Exact upstream platform licenses are collected; Alpine package revisions, patches and all nested platform components are not thereby verified.
- Vere inventory includes mirror-identity and BLAKE3 modification/attribution gaps, narrowed by the linked selected-file follow-up, plus intentionally excluded platform/developer dependencies. No binary linkage is asserted.
- No full corresponding-source bundle or applicable libsigsegv/older-OpenSSL distribution basis is established by this index.

Details: [Vere inventory](vere/inventory.json), [platform inventory](platform/inventory.json), [overall scope](README.md).
