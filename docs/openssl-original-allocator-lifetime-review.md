# Original OpenSSL allocator: parent source-lifetime review

## Status

Source inspection only; implementation worker remains active. The independent review subagent stopped at a provider safety filter before delivering a report or host probes. Its partial transcript is not an accepted review. Parent took over the normal allocation/teardown source inspection; no replacement request was dispatched to bypass the filter.

No production recipe, allocator selection, accepted binary/image or historical attempt changed. No Docker, target/library build, Vere runtime, private-state access or historical cleanup occurred. Existing baseline verification remains 189 tests in 50.602 seconds, exit 0, no skips; no new lifetime host-test result is claimed here.

## Exact public inputs inspected

Archive `build_issue3_amd64_curl_build_02/artifact/source-materials.tar.gz` was streamed and checked against SHA-256 `8ed4fc8a6b4c1acba3e4e89860a4059e490feb3efaf2a818805770f24f65654f`. Metadata was inspected before unique regular bounded selected members were read. Root is `vere-8ddc4b786979574dbfcb655e3db1b634f658d0de/`.

| Member | SHA-256 |
|---|---|
| pkg/noun/manage.c | 2b06d6a006595ea7440690b325e8c994505a6040a97087e877a19c5e0c46d321 |
| pkg/noun/allocate.c | be6089c91a3d566c2dd8f0b3dd102d0861fef49268b79a5bbe4e3aa2993f7336 |
| pkg/noun/palloc.c | 7e6ac278d3082052d049f21b2a4b23ebb9c749ecfeaa4a33c9d7680dfac00d57 |
| pkg/noun/events.c | b800b97d5b10e5254321be45d15c5a8bf9e3db62c58bfcca3aeeb0482c24af4a |
| pkg/noun/jets/e/aes_siv.c | 1e44e524ba7a67d4c2250ccaf1b4a5dc870c8bc6cd253237c83742e3ae43df56 |

## Findings and corrections

1. **Shutdown ordering is a candidate intervention, not an established cause.** Archived `_mars_flush` saves, closes the disk/decoder/trace path, calls `u3m_stop`, then `exit(0)`. `u3m_stop` invokes `u3t_sstack_exit`, `u3e_stop` and `u3je_secp_stop`. This gives an explicit source insertion point for cleanup-before-stop, but the earlier observed abort does not identify which retained allocation was invalid.
2. **Do not describe u3m_stop as a demonstrated full-loom unmap.** `events.c:1510–1518` conditionally calls `_ce_toss_pages` then closes/unlinks backing-file handles. `_ce_toss_pages:1367–1377` computes a page count from two bounds/count arguments and calls `madvise(..., MADV_DONTNEED)`. It is not a `munmap` call. No target observation here establishes that this call invalidated the particular OpenSSL bytes. The prior simplified explanation overstated what final teardown alone had been shown to do.
3. **Normal road reclamation is separate.** `manage.c:u3m_fall` updates the parent's cap and switches `u3R`; `u3m_love:1350–1387` copies selected noun/cache state then rewinds cap/ear. `allocate.c:u3a_drop_heap:93–105` itself only poisons under ASAN and is otherwise a no-op; logical reuse follows the road-pointer updates, not a mandatory OS deallocation at that helper.
4. **The original callbacks do not retain their region.** `_cm_malloc_ssl`, `_cm_realloc_ssl`, `_cm_free_ssl` simply call `u3a_malloc/realloc/free`. `allocate.c` includes `palloc.c`; its BASE/HEAP macros default to the current `u3R` road. `_ifree:870ff` and `_irealloc:894ff` interpret storage using the current heap's directory and range. Restoring these callbacks does not by itself pin a child road or introduce a general owner-road lookup.
5. **There are real configured native-operation callers to inspect.** SIV jets in `jets/e/aes_siv.c:116,152` call the urcrypt implementation while noun evaluation can be active. Earlier public-source review traced that implementation into EVP cipher/provider machinery. That supports an earlier-lifetime question; it is not a measurement of a specific OpenSSL allocation escaping a particular event, nor proof that a provider cache caused the historical abort.
6. **The original sibling positive is useful but narrower.** `docs/u07-allocator-init.md` and `docs/u07-crypto-vectors.md` used original callbacks with a live loom, explicit cleanup-before-stop, and deliberate home-road provider warming. Do not convert that controlled positive into whole-runtime lifetime acceptance.

## Integration disposition

An isolated original-callback/cleanup-before-stop overlay is a legitimate implementation artifact for comparison. It must preserve ordinary frees/reallocs, quiesce library consumers, and cover direct worker/king/utility exit paths rather than an unreachable main cleanup tail. Its tests should distinguish observed call ordering from mocked memory invalidation.

Production restoration is **not cleared by source ordering alone**. The owner requirement includes keeping still-live OpenSSL storage valid throughout its lifetime, including normal road returns. If the staged implementation only moves final cleanup, report that narrower result honestly and keep the working default-heap baseline unchanged until the contract is resolved/exercised. No speculative process-global current-road switching, no-op free, whole-road retention or custom allocator replacement was authorized as an unreviewed shortcut. A14/native-lock recovery is a separate obligation.
