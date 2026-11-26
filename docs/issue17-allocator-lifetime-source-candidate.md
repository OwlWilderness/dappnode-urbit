# Issue 17 allocator/lifetime source candidate

This branch preserves the isolated allocator/lifetime experiment separately from issue #3's maintained OpenSSL source. It is intentionally blocked and is not a production selection.

## Provenance

- Base: `fix/3-maintained-openssl` at `9ebe8d5686fe9642c27abac7f4b613ab9918fcc7`
- Preserved experiment: `tools/issue3_allocator_lifetime/`
- Preserved review/test material:
  - `tests/test_openssl_allocator_lifetime.py`
  - `docs/openssl-original-allocator-candidate.md`
  - `docs/openssl-original-allocator-lifetime-review.md`

The tool and probe files were copied byte-for-byte from the independently preserved issue-3 worktree. The test was publication-sanitized only to remove a workstation-specific scratch path, accept an explicit `ISSUE3_ALLOCATOR_LIFETIME_ARCHIVE`, and skip when the pinned public Vere source archive is unavailable. The candidate documentation's test command was similarly made machine-neutral.

## Safety boundary

`overlay.py` deliberately inserts `ORIGINAL_VERE_ALLOCATOR_BLOCKED`; it cannot yield a buildable production candidate. Its own blockers remain authoritative:

- child-road allocations are not proven to survive ordinary road rewind;
- curl, CA, TLS, and other consumer teardown/thread quiescence are not established;
- mock invalidation is not evidence of real OpenSSL storage lifetime.

The pinned source archive is not committed. `sources.json` records its immutable SHA-256 and the exact public-member pins needed to rerun the full extracted tests. Without that archive, the test module reports explicit skips rather than inventing source bytes.

No build, image, package installation, deployment, ship operation, or runtime acceptance is claimed. Remaining allocator/lifetime qualification stays with issue #17; maintained runtime qualification stays with issue #3.
