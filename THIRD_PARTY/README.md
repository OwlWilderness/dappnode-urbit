# Third-party licenses and notices

**Start with the [component-by-component license table](COMPONENTS.md).**
The collection contains 61 license-text files plus notice-bearing source and
provenance evidence. It indexes 63 Vere-related source component records, four
direct platform package pins and the historical README license. Counts describe
the original collection, not the exact contents of a shipped image. New
[nested notice/source materials](vere/followup/README.md) supplement that
collection. The [retained-image APK baseline](platform/image-baseline/README.md)
enumerates 36 installed packages and records additional exact-version notices.
The [five-package follow-up](platform/followup/README.md) adds narrower source
and notice closures; residual public-distribution questions remain recorded.

Parent verification checked saved hashes, pinned Vere Git blob identities,
fresh upstream platform license bytes and local links; see `verification.json`.

This directory collects third-party license texts and source references for UVM.
It does not replace the terms of any component or claim that every license in a
bundled executable has been identified. Component-specific notices take
precedence over a short label in a table.

**Scope:** source-pinned notices plus a retained public-image package baseline.
This is not a final-image SBOM, a complete
corresponding-source bundle, proof of the exact linked contents of the official
Vere executable, or clearance of the unresolved license-mixing question.

## Where to find the terms

| Material | License information |
| --- | --- |
| Owner-controlled UVM contributions and original artwork | [UVM declaration](../LICENSE.md), [full GPLv3 text](../LICENSES/GPL-3.0-only.txt) |
| Inherited Dappnode wrapper | Preserve the manifest's literal `GPL v3` declaration and androolloyd attribution; do not silently reinterpret its historical version choice |
| Official Vere v4.6 and its declared source dependencies | [Vere notices and inventory](vere/README.md) |
| Direct Alpine/runtime package pins and historical README provenance | [Platform notices and inventory](platform/README.md) |
| Prepared source materials and missing delivery inputs | [Source delivery](SOURCE_DELIVERY.md) |
| Source packaging and verification boundaries | [Notice packaging](../docs/notice-packaging.md) |
| Remaining distribution questions | [Distribution review](../docs/distribution-review.md) |

The component inventories record retrieved source URLs, selected versions or
revisions, local notice paths and content SHA-256 values. An unavailable license
or unknown version must remain an explicit gap rather than being filled with a
license from an unrelated/current release. Declared build dependencies are not
necessarily all present in the released Linux AMD64 executable.

## Distribution layers

1. **UVM source and artwork.** The owner-approved declaration applies only to
   rights the contributor controls. Existing third-party notices are preserved.
2. **Official Vere executable.** `build/vere-release.json` pins the selected
   release archive and executable. Vere's root MIT license is not a substitute
   for the notices and terms of its linked dependencies.
3. **Final Alpine image.** `build/Dockerfile` pins the base image and direct APK
   packages. The retained pre-rename image has an exact 36-APK baseline, including
   base/transitive packages and 23 commit-pinned Alpine source recipes. Notice
   mappings remain partial, with five packages lacking full applicable notice
   text. Re-inventory the actual final image after a separately authorized build;
   this baseline is not final-image coverage.
4. **Development tooling.** The Dappnode SDK and its npm dependencies are
   development-only in `package.json`, not copied into the runtime Dockerfile.
   The lockfile is retained. Redistributing a toolchain or `node_modules` would
   need a separate inventory; do not describe these as shipped runtime packages.

## Before distributing a binary

- Reconcile these notices against the exact final image and linked-component
  evidence, including base/transitive APK packages and nested vendored code.
- Resolve the selected Vere libsigsegv/older-OpenSSL distribution-basis question.
  Merely copying both license texts does not document an applicable exception.
  No exception is granted on third-party authors' behalf here.
- Complete applicable source delivery for the exact shipped components. The
  [prepared Vere archive and source locks](SOURCE_DELIVERY.md) are real materials,
  but dependency archives, delivery/relink obligations and final artifact binding
  remain incomplete. No written offer is issued.
- The Dockerfile now wires the explicitly inventoried notice/source tree and
  contribution terms to `/usr/share/doc/uvm`, root-owned and service-readable.
  **No notice-bearing image has been built:** source/host checks do not verify
  copied-image inclusion. The descriptor preparer's fixed assets are unchanged;
  accepted descriptors remain image-unbound, unsigned and unpublished.

No runtime replacement, build, ship boot, publication or target installation is
performed by adding this documentation. Preserve accepted lifecycle/TLS evidence.
