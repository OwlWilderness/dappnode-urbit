# Distribution provenance review

Status: owner-controlled contribution/artwork terms selected and applied locally;
**not legal clearance or publication authority**. No upstream contact, runtime
replacement or release occurred.
This review does not invalidate accepted local runtime/TLS behavior or call for
another ship boot. It identifies what remains before public distribution.

## Package source and artwork

The inherited manifest at commit
`38a9dfaa95c55e7e45532a3eca8c033fcfc2f1c5` explicitly declares `GPL v3` and
attributes androolloyd. The preceding initial commit is
`c51f77c0d99c02abb8ce740b14b172481a7c3ef5`. Parent inspection of both local Git
trees found no root license file. That absence is **not evidence that no license
was granted**; preserve the affirmative manifest declaration rather than
silently converting it to `GPL-3.0-or-later` or an unrelated license.

The historical README derives from `jmnsf/urbit-docker`, whose pinned license
is MIT, copyright 2021 João Ferreira. This is provenance for that copied
material, not a replacement license for the entire package. The obsolete
instructions have been removed from the current README; Git history remains.

The inherited `avatar-urbit.png` was present in the initial package tree, with
no asset-specific permission established. It remains in Git history but is no
longer selected: the working-tree file now contains original geometric UVM
artwork. See `artwork.md` for its SVG, generator and GPL-3.0-only terms.

The owner approved GPLv3-only for contributions they control, retaining all
inherited and third-party terms. `../LICENSE.md` applies that bounded declaration
and includes the full license in `../LICENSES/GPL-3.0-only.txt`. It does not
override bundled component licenses or supply a third-party linking exception.

## Pinned Vere and linked dependencies

The GitHub tag API resolves `vere-v4.6` to commit
`8ddc4b786979574dbfcb655e3db1b634f658d0de`. Its root `LICENSE.txt` is MIT,
copyright 2015 Urbit. Preserve the corresponding notice when distributing it.
The selected archive and executable checksums remain in
`build/vere-release.json`; this review did not execute or replace the binary.

Parent source inspection at that commit confirmed:

- `pkg/noun/build.zig:141–144` links OpenSSL and, outside Windows, libsigsegv.
- `pkg/noun/build.zig.zon` maps those dependencies to `ext/openssl` and
  `ext/sigsegv`.
- `ext/openssl/build.zig.zon` selects OpenSSL **1.1.1w**, whose license retains
  the older OpenSSL/SSLeay conditions, not the Apache-2.0 terms of OpenSSL 3.
- `ext/sigsegv/build.zig.zon` selects libsigsegv **2.14**. The official GNU
  source archive's README specifies GPLv2-or-later. Parent retrieved it in
  memory only: 464658 bytes, SHA256
  `cdac3941803364cf81a908499beb79c200ead60b6b5b40cad124fd1e06caa295`.

**Unresolved compatibility question:** the GPL-covered library and older
OpenSSL terms are a known license-mixing concern. Curl's primary-source
license-mixing guidance describes this combination as requiring a suitable
exception. We have not established an applicable exception or other distribution
basis for this exact Vere artifact. This is an evidence gap and reason to defer
binary publication—not a definitive legal conclusion about upstream compliance.
The source build declarations are not a new forensic attestation of every byte
linked into the published binary.

A bounded follow-up checked the exact GNU archive above against its SHA256 and
read the five translation-unit files selected by the pinned Vere
`ext/sigsegv/build.zig`: `dispatcher.c`, `handler.c`, `leave.c`, `stackvma.c` and
`version.c`. Their headers carry GPLv2-or-later notices. No OpenSSL/linking
exception was found in those five files or the archive README; the pinned Vere
root license is MIT. This is not an exhaustive exception search, a binary
composition attestation or legal clearance. It leaves the distribution-basis
question open; do not repeat the same source checks as another release gate.

Do not solve this by silently changing the runtime, reviving a custom crypto
build, adding an exception on behalf of third-party authors or repeating the
accepted lifecycle. Resolve the distribution basis for the selected artifact
with authoritative licensing evidence or qualified advice. Any upstream contact
requires owner approval.

## Remaining distribution work

1. Contribution declaration and original replacement artwork are applied locally.
2. Establish the selected Vere artifact's applicable license-mixing basis.
3. A source-pinned collection now exists in `../THIRD_PARTY/README.md`, with a
   readable component table, full license texts and verified provenance hashes.
   The retained image now has a 36-APK baseline and exact Alpine recipes; the
   selected-file follow-up adds missing nested notices and prepared source
   archives/locks. Complete remaining notice/source-delivery gaps and reconcile
   against the actual final image. Dockerfile/context inclusion is implemented
   at source level, not built or verified in an image. See
   [notice packaging](notice-packaging.md). This is not a complete final-image
   SBOM, corresponding-source delivery or clearance.
4. Owner signing is the selected route: the owner retains the wallet and signs
   locally; no agent wallet or Safe is needed. The public signer address, scoped
   target trust entry and explicit publication authority remain unestablished.
   No Association cooperation is a prerequisite. Local descriptor preparation
   does not satisfy these gates.

A fresh descriptor-only output may include the replacement avatar. Its artwork
terms do not clear the whole distribution: it still has no bound image or
signature and must not be uploaded as a release.

## Evidence references

- Inherited manifest: `git show 38a9dfaa95c55e7e45532a3eca8c033fcfc2f1c5:dappnode_package.json`.
- Historical trees: `git ls-tree -r --name-only` at both commits above.
- jmnsf license: `https://raw.githubusercontent.com/jmnsf/urbit-docker/32fc5f843adf5b9f67b7e5a71f2370bc0cb53c67/LICENSE`.
- Vere tag: `https://api.github.com/repos/urbit/vere/git/ref/tags/vere-v4.6`.
- Vere source base: `https://raw.githubusercontent.com/urbit/vere/8ddc4b786979574dbfcb655e3db1b634f658d0de/`.
- OpenSSL license: `https://raw.githubusercontent.com/openssl/openssl/OpenSSL_1_1_1w/LICENSE`.
- libsigsegv: `https://ftp.gnu.org/gnu/libsigsegv/libsigsegv-2.14.tar.gz`, `libsigsegv-2.14/README:132–141`.
- Curl guidance: `https://raw.githubusercontent.com/curl/curl/3b8bbbbd1609c638a3d3d0acb148a33dedb67be3/docs/LICENSE-MIXING.md`, OpenSSL section.

Retrieval limits: the pinned libsigsegv OpenBSD mirror returned 404; the official
GNU archive above was readable. GNU's license-list page timed out during parent
verification; the parent used the exact upstream licenses and Curl's published
guidance instead. No guessed successful fetch is recorded.
