# Source-candidate provenance

This branch is a sanitized source derivative of a preserved local review corpus.
It is based on `feat/20-recovery-source-closeout` commit
`5399ee0c1aba07db8dd861afd7e1421441b77ef9`; it is not based on, merged into,
or overlaid onto the issue-#3 runtime line or the default branch.

The input review contained 67 entries resolving to 55 unique paths plus seven
tracked dependencies. This source candidate deliberately excludes 23 historical
issue-19 operational harness paths and two issue-2 public-ingress paths. Those
inputs remain in the preservation corpus but are not represented as publishable
product source here.

The privacy review found 22 personal absolute-path references across eight input
files. Twelve references were confined to six excluded historical harness files.
The remaining ten references were removed from the two included derivatives
listed below. Three additional included tests used generic home-relative scratch
defaults; those defaults were also replaced with explicit environment inputs or
the platform temporary directory. The published candidate must contain no
personal absolute path, owner binding, credential, private runtime artifact, or
operational receipt.

## Sanitized derivatives

| Path | Preserved input SHA-256 | Published derivative SHA-256 | Transformation |
| --- | --- | --- | --- |
| `docs/dappmanager-integration.md` | `a6c14e79b811f12768bc6867ae42ae4cdfc6b2589b60083376c5933edff994f8` | `01d6eda8ba4fa25a7f8503b1768798b4af6ea9e1cd6df51a30c911a856e3437d` | Rewritten as a source-only design and provenance document; removed owner/local checkpoints, receipts, live-status observations, artifact paths, and machine-specific history while retaining the technical contract and limitations. |
| `tests/browser-importer/test_legacy015_recovery.py` | `8ef235cc663fe6674e540fe891c77bd477ab76649085b83ac93fd6114e8ec7ba` | `17558d64ac5808747a9b6ff8d66d6c6e1826c1ddc60c5bec0c94f4e3038cbfa0` | Replaced the personal scratch location with `IMPORTER_TEST_SCRATCH`, falling back to the platform temporary directory. |
| `tests/dappmanager-upstream-integration.test.mjs` | `306fa7ef87aa8f8bc87b99ea18601b15c5aa8c32ac21bb5757d11f91735f96cc` | `03b65a6ae6301763ea68af2bcc75aa863abc4abc77dd8b01c7c740adc5b84171` | Replaced the home-relative scratch fallback with `os.tmpdir()` while retaining `IMPORTER_TEST_SCRATCH` precedence. |
| `tests/test_dappmanager_integration.py` | `24257d69004ef24574736b560ad031275ecc5b980a55bfdbe2fe075ff9e8b325` | `03b24bb51ddd378023380d7489015facb648c3fd652cfbe28134445140aa02d9` | Replaced the home-relative scratch fallback with the platform temporary directory. |
| `tests/test_prepare_manager_candidate.py` | `e90bd67d439f6f5af6ae7fe72462eeeaca2be3678cf5dd2d973b6b8321f0a59c` | `9d20aeea396e6baf20ed3950632504404477b29fde9e2ccbab8166cea8d5b09a` | Accepts the pristine upstream input through `UVM_MANAGER_PRISTINE_SOURCE`, skips clearly when absent, and uses `IMPORTER_TEST_SCRATCH` or the platform temporary directory. |
| `tools/browser-importer/maintenance_provider.py` | `6c3ea7ddf8a4ae91193432844d8eadffac7bb126a4d89be4113eda6928904d18` | `3c48eedd9c3e449b4c3dba22c406224fdc7313cd90f12cadd34178583e9e2f54` | Removed one extra blank line at end of file; behavior is unchanged. |

The upstream derivative patch remains byte-identical to the reviewed input:

- Path: `tools/host-integration/upstream-dappmanager.patch`
- SHA-256: `c7149f6b0923b013c354e89e43e02378c15e0bf7fe52c7671eeb693090ecbd50`
- Upstream: `https://github.com/dappnode/DNP_DAPPMANAGER`
- Tag: `v0.2.129`
- Commit: `a21bab295d4c68c3b6115498b18a8efaf89d52a0`
- Declared upstream license: GPL-3.0

Unified-diff context lines are required to begin with a space, including blank
context. The repository's narrow `.gitattributes` rule disables outer-diff
whitespace diagnostics only for `tools/host-integration/*.patch`; it does not
alter or conceal whitespace findings in product source.

This provenance record is source-review metadata. It does not approve a build,
image, install, deployment, host plan, runtime transition, or portfolio closure.
