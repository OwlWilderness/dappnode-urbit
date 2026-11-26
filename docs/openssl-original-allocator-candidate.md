# Original Vere allocator: isolated ordering candidate, blocked on lifetime

## Verdict

A concrete source transformation and extracted-function host probes exist in
`tools/issue3_allocator_lifetime/` and `tests/test_openssl_allocator_lifetime.py`.
They restore the original OpenSSL allocator registration and exercise explicit
`OPENSSL_cleanup()` before **`u3e_stop()`**, within the common `u3m_stop()` path.

**This is not a retention fix, not a buildable candidate, and not production
selection.** The transformed translation unit deliberately starts with:

```c
#error "ORIGINAL_VERE_ALLOCATOR_BLOCKED: road retention and consumer quiescence are unqualified"
```

There is no enable flag or environment bypass. Tests extract the exact function
bodies separately from this guard, compile them against mocked boundaries, and
also verify the complete translation-unit prefix refuses preprocessing. Removing
this guard merely because the host tests pass would be incorrect: several tests
explicitly demonstrate remaining unsafe cases.

The requested stronger property—retain all OpenSSL-reachable original-allocator
objects until full teardown, and clean up only after all users/threads settle—is
**not established or implemented** by this narrow ordering intervention. A literal
per-caller full cleanup before entering `u3m_stop()` is also not implemented; the
experiment places it inside the shared stop function, before storage shutdown.
No speculative persistent arena, home-road pointer switching, no-op free,
`NO_ATEXIT`, forced-exit bypass, or allocator replacement was introduced.

## Exact API, input and composition

```python
transform_manage(data: bytes) -> bytes
apply(root: pathlib.Path) -> dict[str, str]
```

`apply` changes only `root / "pkg/noun/manage.c"`. It rejects symlinked source
paths, nonregular targets, preimage drift, upstream/pristine input, replay,
changed transformation contexts and wrong postimages before a source write.
Use a new, caller-owned disposable source tree without concurrent mutation;
this is not a hostile-filesystem race-proof writer. Its returned mapping is
checked against the bytes actually written in the host tests.

Input `pkg/noun/manage.c` SHA-256:
`2b06d6a006595ea7440690b325e8c994505a6040a97087e877a19c5e0c46d321`.

Output `pkg/noun/manage.c` SHA-256, **including the unconditional refusal**:
`6126a00974035b0495cd5440a532dda49df85d156ec021bf558c672ecd1f9d93`.

The exact returned changed-source mapping is:

```json
{"pkg/noun/manage.c":"6126a00974035b0495cd5440a532dda49df85d156ec021bf558c672ecd1f9d93"}
```

Intended composition is **after** the existing production recipe's
`patch_allocator`, plus the other selected hardening overlays. The accepted
archive's manage.c is **already default-heap-corrected**: do not apply
`patch_allocator` to that member again. A pristine upstream tree instead first
needs that existing patch once. Its pristine manage.c SHA-256 is
`25eaa5384e190067d19a4a731d120efb8174367bb02296e4b2b2d8b53f90fa68`;
this experiment deliberately refuses it rather than guessing composition.
The separately staged A14-terminal manage.c is not a second allowed preimage;
composing that alternative would require a new reviewed transformation and pins.

The source/test ledger is `tools/issue3_allocator_lifetime/sources.json`. Public
input is the accepted `build_issue3_amd64_curl_build_02/artifact/source-materials.tar.gz`,
SHA-256 `8ed4fc8a6b4c1acba3e4e89860a4059e490feb3efaf2a818805770f24f65654f`.
The tests hash the archive, validate uniqueness/type/exact size of **all five
selected public members before reading any selected content**, then validate each
member hash. No archive extraction or historical source modification occurs.

## Actual source changes

- Restore the original `#ifndef U3_URTH_MASS` registration of
  `_cm_malloc_ssl`, `_cm_realloc_ssl`, `_cm_free_ssl`, including OpenSSL >= 3.
  All three callback bodies remain byte-identical and still forward ordinary
  malloc/realloc/free to `u3a_*`; there is no deferred or suppressed free.
- For OpenSSL >= 3, add a process-local one-shot state: cold, registered, terminal.
  A repeated initialization entry through `_cm_crypto` refuses before another
  registration; stop before initialization is a no-op; repeated stop is a no-op.
  The terminal latch is set before cleanup, not after it. This is an owning-thread
  model, **not synchronization for concurrent lifecycle calls**.
- Insert full `OPENSSL_cleanup()` before `u3e_stop()` inside `u3m_stop()`.
  Existing stack, storage and secp stop calls retain their relative order.
- Add the unconditional compiler refusal above.

Tests independently strip only the changed functions, added state and refusal,
then compare every remaining manage.c byte. The allocator callbacks, GMP helper
bodies/registration, `u3m_init`, road return and road rewind remain unchanged.
A composition test seeds actual current CA-hardened main.c and curl-buffer-hardened
king.c, verifies their current lock hashes, applies this overlay and proves both
and mars.c remain byte-identical. No curl/TLS/SHA/CA/H2O/cttp production patch,
recipe, verifier, pin, checkpoint, accepted binary or historical attempt is edited.

## Two different lifetime questions

### Earlier ordinary road lifetime: still unresolved, no retention operation

The original callbacks simply forward to `u3a_malloc/realloc/free`. They do not
pin a region or inform the road system about OpenSSL's retained pointers.
In the selected actual source, `u3m_fall()` changes the parent's cap to the child's
hat, and `u3m_love()` copies the noun product/caches before rewinding cap to ear.
These operations do not discover or preserve arbitrary OpenSSL globals/TLS.
`u3a_drop_heap()` is ASAN poisoning only (a no-op in ordinary builds); it must not
be described as the ordinary reclamation mechanism. Reuse follows road-pointer
rewind, not a promised pin/free protocol.

This overlay deliberately leaves those functions untouched. Therefore a native
object allocated on a child road and retained beyond its return **does not gain
any lifetime guarantee from final shutdown reordering**. Per-object frees on a
different current road also need their own ownership justification; no owner
lookup or cross-road fix is added here. The parent's independent normal-lifetime
review remains separate; the failed review worker supplied no acceptance.

### Final storage-stop order: exercised hypothesis only

The host oracle deliberately treats `u3e_stop()` as making modeled storage
unavailable. It detects missing/late cleanup. **That mock does not prove what the
real function does to any OpenSSL allocation.** This report does not assert
`u3m_stop()` unmaps the loom, that `madvise` covers live OpenSSL bytes, or that final
storage shutdown caused the historical abort. Earlier road reuse and the exact
stale allocation remain separate from this ordering experiment.

## Callers and consumers

The selected current source has ten utility `u3m_stop()` sites in main.c:
`_cw_info`, `_cw_grab`, `_cw_cram`, `_cw_queu`, `_cw_meld`, `_cw_melt`, `_cw_pack`,
`_cw_play`, `_cw_chop`, `_cw_roll`. Mars `_mars_flush` and king `u3_king_done` each
have one more. All twelve would receive the common prefix; only the actual mars
and king caller bodies are compiled/executed here. Utilities are source-inventory
checks, not complete utility executions. Other terminal paths that never invoke
`u3m_stop()` are not changed into a new cleanup framework.

The extracted `_mars_flush` host probe confirms its terminal save/disk/cue/trace/
dump calls still occur before central cleanup/storage stop. This is not proof of
real thread settlement: mocked disk exit is not a join.

The extracted `u3_king_done` host probe confirms it can queue libuv close callbacks
and proceed to storage stop **without a close-completion barrier**. Another case
supplies a deliberately modeled live consumer and detects global cleanup while
that consumer remains live. Queued handles are not themselves proof of a live
OpenSSL user, but neither empty pier linkage nor queued close is a lifetime proof.
King curl globals, the embedded CA stack, H2O/TLS objects, pending callbacks and
helper-thread shutdown still need a real consumer inventory and completion/join
barriers before global cleanup. The original main tail's legacy cleanup does not
provide that barrier for the direct king exit path. No guessed teardown ordering
was integrated. The compiler refusal prevents executing this incomplete change.

## Executed verification

Command from the worktree:

```sh
TMPDIR="${TMPDIR:-/tmp}" PYTHONDONTWRITEBYTECODE=1 \
python3 -m unittest discover -s tests -p test_openssl_allocator_lifetime.py -v
```

Final isolated run: **15 collected, 15 unique, 15 executed; 0 failures, 0 errors,
0 skips; 10.519 seconds; exit 0**. Only its unchanged unrelated sentinel remained
before the owning outer TemporaryDirectory removed itself. This is not a global
historical-scratch sweep.

Observed behavioral RED -> GREEN:

- Archived actual `u3m_stop` and actual `_mars_flush` control: two tests compile,
  both fail with boundary status **61** because cleanup has not run at storage
  stop. The patched extracted paths pass. Final control rerun: 2 tests,
  4.693 seconds, 2 expected failures, exit 1.
- After adding cleanup but before restoring registration, actual `_cm_crypto`
  wrapper exercise fails status **72**; restoring the original hooks passes,
  preserves 19 bytes through resize to 113, and calls ordinary free exactly once.
- Before the state guard: repeat stop **62**, repeat init **81**, restart **82**,
  cold stop **79**; after it, single cleanup/stop or expected refusal **71**.
  Registration-failure refusal remains exercised; abort is mocked to a bounded
  exit so these host cases do not create a real core dump.
- Compiler refusal test first fails because preprocessing succeeds; adding the
  unconditional guard makes preprocessing fail with the named blocked diagnostic.
- Symlink root/parent/file cases first modify only owned test fixtures without
  refusal; after the path guard all refuse before write and preserve the targets.

Expected negative counterexamples remain visible: modeled live-user cleanup exits
**84**, and king emits `king:close-queued-without-drain-barrier`. These are not
successful lifetime/consumer-teardown results. Initial host fixture compile issues
(missing mocked exit enum, unused abort helper in the archived control) were fixed;
only the subsequent compiled behavioral controls are counted above.

## Integration requirements and remaining authority

### Parent independent verification

Parent inspected overlay.py, both C probes, the tests and source ledger. All five
delivered code/ledger/test hashes matched the worker's returned values. All 34
preexisting public recipe/test snapshot files remain byte-identical; no production
allocator selection, shared pin/verifier, accepted binary or unrelated hardening
was reverted. Parent consolidated discovery: **204 collected/unique/executed tests
in 58.084s, exit 0, no failures/errors/skips**. The two archived-order controls
independently failed as intended (both probe status 61, 2 tests in 4.689s,
unittest exit 1). Outer owned scratch retained only its unchanged sentinel after
GREEN and controls before owning cleanup; this is not a global scratch audit.
New-file syntax/whitespace and git diff checks passed.

**Owner's requested safe original-allocator restoration is NOT COMPLETE.** This
artifact is an ordering experiment with an unconditional compiler refusal, not
an implementation of native allocation retention or consumer/thread completion.
Its successful suite includes expected unsafe modeled cases and does not certify
the stronger property. No new target-runtime failure was observed or induced.

Do not select this source as production or remove its compiler refusal without a
separately implemented/reviewed answer for original-allocator road ownership and
all OpenSSL consumers/threads. Simply moving full cleanup earlier cannot preserve
objects already made reusable during ordinary work. If the exact original road
allocator cannot satisfy retained-object lifetimes without broader changes, keep
this experiment blocked rather than claiming a fixed original allocator.

Parent owns production selection, source delivery/verifier/recipe bindings and
checkpoint updates. Full focused-suite integration, exact-header/library/target
qualification, actual OpenSSL/TLS behavior and real application lifetime testing
remain unperformed here. No full/dependency build, Docker (including inspection),
Vere runtime/tracing, engine operation, private state/log/key access, historical
cleanup, deployment/publication, commit or push was performed.
