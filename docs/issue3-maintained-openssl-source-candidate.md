# Issue 3 maintained OpenSSL source candidate

This branch preserves the source-side maintained-OpenSSL candidate that remained outside the published Git heads.

## Provenance

- Base: `fix/3-maintained-openssl` at `9ebe8d5686fe9642c27abac7f4b613ab9918fcc7`
- Preserved source root: `build/vere-openssl3/`
- Preserved focused tests:
  - `tests/test_openssl_candidate.py`
  - `tests/test_openssl_binary_verifier.py`
  - `tests/test_openssl_link_inputs.py`
  - `tests/test_openssl_source_companion.py`

The files were copied byte-for-byte from the independently preserved issue-3 worktree. The branch does not include generated executables, build caches, runtime logs, owner data, credentials, or machine-specific paths.

## Verification boundary

The focused source tests exercise admission/refusal behavior, binary receipt validation, retained-link-input validation, and source-companion validation without building Vere or starting a ship. They do not establish image qualification, package installation, DAppNode deployment, ship lifecycle, production workload sizing, or runtime acceptance.

Those acceptance stages remain with issue #3.
