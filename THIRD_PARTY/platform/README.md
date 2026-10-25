# Platform and inherited README notices

This is a bounded source-notice collection, **not a complete SBOM, complete
license coverage, legal clearance, or proof of what an image contains**.
`inventory.json` records exact inputs from `build/Dockerfile`, content hashes,
retrieval URLs, failed requests and remaining gaps. No runtime/package pins
were changed and no image, container, build or package installation was used.

## Full texts collected

| Declared APK pin / historical input | Preserved full upstream text | Evidence |
| --- | --- | --- |
| `zlib=1.3.2-r1` | `licenses/zlib-LICENSE.txt` — Zlib | [1] |
| `python3=3.14.8-r0` | `licenses/python3-LICENSE.txt` — full CPython license, historical agreements and included notices | [2] |
| `openssl=3.5.9-r0` | `licenses/openssl-LICENSE.txt` — Apache 2.0 | [3] |
| `nginx=1.30.6-r0` | `licenses/nginx-LICENSE.txt` — BSD 2-Clause | [4] |
| `jmnsf/urbit-docker` commit `32fc5f843adf5b9f67b7e5a71f2370bc0cb53c67` | `licenses/jmnsf-readme-LICENSE.txt` — MIT; Copyright (c) 2021 João Ferreira | [5] |

All four exact upstream version tags returned full root license texts. Their
resolved commit URLs returned identical bytes; tag/ref response evidence and
SHA-256 hashes are preserved. These are upstream-version texts, **not a claim
that Alpine's exact APK revision or every bundled file has been audited**.
The historical README is preserved in `evidence/jmnsf-readme-source.md`; it is
provenance evidence, not current deployment instructions. No line-by-line
mapping of inherited passages is claimed.

## Pin evidence versus gaps

The sampled Alpine `edge/main/x86_64` listings matched zlib, OpenSSL and nginx's
literal APK pins.[6][8][9] The Python listing instead showed `3.14.9-r2`, not
`3.14.8-r0`.[7] A subsequent all-branch query returned HTTP 404; that failure is
recorded, not interpreted as proof that the pinned package never existed.
The exact upstream Python 3.14.8 license was successfully retrieved.[2]
No current-version license was silently substituted for an unavailable pin.

The base remains the declared
`alpine@sha256:d56c381f961d307a21b3ca004cf1e3910f106644aefb1f43e654c8a56c4fd395`.
Its manifest and installed-package database were not inspected. **musl and
BusyBox require inventory**: neither exact shipped versions nor their full
applicable notice sets are guessed here. Other base/transitive packages,
optional modules, packaging patches and subcomponent notices remain incomplete.
Obtain installed-package metadata and corresponding exact source/notice sets
before making distribution-completeness claims. No release signatures,
package signatures, source/binary correspondence, corresponding-source delivery
or written-offer obligations have been verified.

Selected Vere binary dependencies are covered by a separate collection and
are not duplicated here. SDK 0.3.55 is development-only, outside the runtime
COPY allowlist, and not expanded into a node_modules license dump.

## Evidence layout

- `inventory.json`: declarations, coverage status, computed counts, all retrievals.
- `licenses/`: five unmodified full license texts (UTF-8 bytes preserved).
- `evidence/`: historical README, raw public Alpine listings and upstream tag/ref JSON.
- `sources-ledger.json`: mechanically registered citation URLs.
- `verification.json`: local file/hash/count checks; not runtime verification.

Raw fetched evidence is retained as data; do not execute it. SHA-256 identifies
retrieved bytes, not authenticity or a signature verification.

## Sources

[1] https://raw.githubusercontent.com/madler/zlib/v1.3.2/LICENSE
[2] https://raw.githubusercontent.com/python/cpython/v3.14.8/LICENSE
[3] https://raw.githubusercontent.com/openssl/openssl/openssl-3.5.9/LICENSE.txt
[4] https://raw.githubusercontent.com/nginx/nginx/release-1.30.6/LICENSE
[5] https://raw.githubusercontent.com/jmnsf/urbit-docker/32fc5f843adf5b9f67b7e5a71f2370bc0cb53c67/LICENSE
[6] https://pkgs.alpinelinux.org/packages?name=zlib&branch=edge&arch=x86_64
[7] https://pkgs.alpinelinux.org/packages?name=python3&branch=edge&arch=x86_64
[8] https://pkgs.alpinelinux.org/packages?name=openssl&branch=edge&arch=x86_64
[9] https://pkgs.alpinelinux.org/packages?name=nginx&branch=edge&arch=x86_64
