# Issue #3 portable source-preservation derivatives

This branch preserves 86 previously actionable source/test files: 60 byte-exact portable files and 26 machine-neutral derivatives. The JSON manifest maps every original path and SHA-256 to its published path and SHA-256.

Sanitization is intentionally narrow: personal scratch roots become synthetic `/tmp` fixture paths, the personal Docker Desktop socket becomes `/var/run/docker.sock`, and the personal checkout root becomes `/workspace/dappnode-urbit`. The two probe tests use resolved `tempfile.gettempdir()` guards so macOS `/tmp` symlink resolution remains portable. `b04_lifecycle/config.json` is explicitly synthetic and `UNBOUND`; its image and input bindings remain null/empty, so effectful entry points refuse before Docker.

Source-only verification parsed all Python files. Ten independently portable unit modules ran 152 tests with 152 passes. `host_cleanup_fixture.c` passed `cc -fsyntax-only`; the two probe translation units reached the expected local prerequisite boundary because this host has no `openssl/crypto.h`. Dependency reconciliation also exercised the other candidate tests; tests requiring absent historical evidence, superseded modules, runtime-bound inputs, or host-permission assumptions were not published on this branch and have exact per-file results in the final 159-entry receipt.

No operational harness, host-verification record, owner-bound ship harness, VM, ship, image build, deployment, package installation, network mutation, or merge is included or accepted here. Runtime acceptance remains with issue #3.

`git diff --check` reports only a historical blank line at EOF in each of `tools/issue3_crypto_tls_probe/timeout_observer/observer.py` and `tools/issue3_observed_compile/timeout_observer.py`. Those two files are byte-exact source preservation, so their original bytes were not normalized.
