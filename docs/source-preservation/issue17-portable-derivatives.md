# Issue #17 portable source-preservation derivatives

This branch preserves 2 machine-neutral derivatives from the remaining issue #17 queue. The JSON manifest maps each original path and SHA-256 to its published path and SHA-256.

Personal scratch roots were replaced with synthetic `/tmp` fixtures. Source-only verification parsed both Python files, and `tests.test_openssl_arena_metrics` ran four tests with four passes. Nine other candidate tests were retained only in the migrated original because their import/suite failed without intentionally local source snapshots, operational evidence, or host-bound dependencies; each has an exact result and dependency record in the final receipt.

No allocator integration, package/runtime acceptance, operational harness, VM, ship, image build, deployment, network mutation, or merge is claimed. Runtime acceptance remains with issue #17.
