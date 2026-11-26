# Draft recipient notices — REVIEW ONLY, NOT ENACTED

Do not copy this file into a release unchanged. Resolve all `UNSET` fields, approve the proposed version choices, reconcile the exact release files and preserve full upstream notices. This is neither a written source offer nor blanket relicensing.

## Release identification

- Release/version/CID: **UNSET — no publication performed**.
- Reviewed pre-hardening executable: SHA-256 `58d07af97926e04bc17184bc18f53e5fb11d84fed63bd9daf2fe4ceb04c86698`.
- Corresponding accepted local source archive: SHA-256 `8ed4fc8a6b4c1acba3e4e89860a4059e490feb3efaf2a818805770f24f65654f`.
- Recipient-accessible complete source companion and SHA-256: **UNSET — local source completeness/assembly and publication remain open**.
- Directions alongside the binary and, where applicable, to IPFS peers: **UNSET**.

A later hardened binary must replace these bindings only after its own qualification. The accepted hash does not include the later HTTP-context/SHA hardening changes.

## Proposed combined-work statement

Subject to final review, this modified Vere executable would be conveyed as a combined work under GNU GPL version 3, exercising available later-version/alternative permissions for libsigsegv, GMP and D-Bus.[4][5][7]
This proposed statement does not remove original component permissions, claim ownership of third-party work, or change every repository file to GPL.
The proposed compatibility basis is Apache-2.0 code combined with GPLv3, not GPLv2.[2]

Vere v4.6 covered source retains the **MIT License, Copyright (c) 2015 Urbit**, reproduced in `texts/Vere-MIT.txt`; distribute its full permission and warranty notice, not only this credit.[12]

Owner-controlled UVM contributions/artwork retain their existing bounded GPL-3.0-only declaration. Preserve inherited androolloyd attribution and the literal inherited `GPL v3` declaration. Historical copied README material retains the original João Ferreira MIT notice; `texts/historical-readme-MIT.txt` is a staged copy, not a new grant for the whole package.

## Component notice wording for review

- **libsigsegv 2.14:** includes upstream GPLv2-or-later material; proposed distribution exercises GPLv3.[4]
  Preserve the original copyright and grant, including Bruno Haible, Paolo Bonzini, Eric Blake and Free Software Foundation notices where applicable.[4]
  Build-script exceptions are not a runtime linking exception.[4]
- **OpenSSL 3.5.9:** Apache License 2.0; include `texts/OpenSSL-3.5.9-LICENSE.txt` and preserve relevant source attribution/modification notices.[11]
  Apache §4 requires applicable NOTICE content when supplied.[11]
  No top-level `NOTICE` member was present in the inspected accepted OpenSSL tree (local archive-membership check); this does not settle nested notice applicability.
- **curl 8.23.0:** include the exact copyright/permission text in `texts/curl-8.23.0-COPYING.txt`; preserve Daniel Stenberg and contributors' notice.[13]
  The older retained curl 8.9.1 text is not the exact candidate-version text (local notice comparison).
- **GMP 6.3.0:** upstream provides LGPLv3-or-later or GPLv2-or-later alternatives.[5]
  Proposed use is the GPLv3 option; preserve the upstream dual grant and component/file attribution.[5]
- **Avahi 0.8:** the archived build graph selects Avahi facilities; proposed use is LGPLv3 through the original later-version permission.[6]
  Supply GPLv3 and LGPLv3 texts, original notices, complete library source and corresponding application material in a form permitting modified-library recombination/relinking; do not prohibit the covered modifications or reverse engineering for debugging them.[9]
- **Avahi's GLib-derived UTF-8 file:** preserve Copyright (C) 1999 Tom Tromey and Copyright (C) 2000 Red Hat, Inc.[6]
  Its original header literally says GNU Lesser GPL version 2 or later; retain that wording rather than silently changing its source notice.[6]
  See `texts/avahi-utf8-header.txt` and the review's proposed later-version treatment.
- **D-Bus library source 1.14.8:** proposed GPLv3 option under its GPLv2-or-later alternative, not the AFL option for this combined route.[7]
  Preserve per-file notices; do not extend the dual-choice assertion to standalone GPL-only tools.[7]
- **urcrypt and nested components:** retain the exact accepted-source `texts/urcrypt-MIT.txt` and all applicable nested notices. A later local SHA replacement needs applicable original attribution and an accurate change notice; it is not included in the accepted binary merely because its source exists.

Other dependencies and independent image programs retain their actual terms. The old component index is a starting inventory, not the release's completed SBOM. Finalize modified BLAKE3, nested H2O/crypto, toolchain runtime and exact APK coverage before selecting the notices for an image.

## Changes notice to finalize against the release

Record the actual modifications and relevant dates, their source paths, original revision and resulting hashes.[8][11]
For the reviewed accepted executable these include OpenSSL/curl adapters/manifests, version reporting, the allocator-hook change, and the `30L` curl-option correction, as recorded in frozen `candidate.json`.[8][11]
Do not mark unchanged upstream sources as authored locally.[8][11]
Do not claim source-only HTTP-context/SHA hardening is in this executable.[8][11]
GPLv3 §5 requires prominent modification/date notices; Apache §4 separately requires modified files to carry change notices.[8][11]

## Source delivery statement — not yet publishable

**Do not assert availability until independently retrieved.** Final release language should identify the complete, version-bound source companion, build/install/relink instructions, and equivalent no-additional-charge access alongside the binary.[8]
For peer-to-peer distribution, tell peers where the binary and corresponding source are publicly available under the selected GPLv3 §6(d)/(e) route.[8]

This preparation issues no written offer. No private ship data, wallet or certificate keys, login credentials, authentication cookies or private operational logs belong in the source material.

## Sources

[2] https://www.apache.org/licenses/GPL-compatibility.html
[4] https://ftp.gnu.org/gnu/libsigsegv/libsigsegv-2.14.tar.gz — libsigsegv 2.14 runtime grant and build-tool permissions
[5] https://ftp.gnu.org/gnu/gmp/gmp-6.3.0.tar.xz — GMP 6.3.0 alternative grants
[6] https://github.com/lathiat/avahi/releases/download/v0.8/avahi-0.8.tar.gz — Avahi 0.8 source grant
[7] https://dbus.freedesktop.org/releases/dbus/dbus-1.14.8.tar.xz — D-Bus 1.14.8 alternative grants
[8] https://www.gnu.org/licenses/gpl-3.0.html — GPLv3 exact license text retained in GMP
[9] https://www.gnu.org/licenses/lgpl-3.0.html — LGPLv3 exact license text retained in GMP
[11] https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz — OpenSSL 3.5.9 exact license
[12] https://codeload.github.com/urbit/vere/tar.gz/8ddc4b786979574dbfcb655e3db1b634f658d0de — Pinned Vere MIT license
[13] https://curl.se/download/curl-8.23.0.tar.gz — curl 8.23.0 permission notice
