# Arena budgeting workload protocol — prepared, NOT executed

## Source-only collector/aggregation update

`tools/issue3_arena_measurement/` now implements a dedicated aggregate-only C
collector, a pure post-owned-integration instrumentation stage, and strict
multi-process receipt/population arithmetic. See
`openssl-arena-measurement-result.md` for tests, schema, exact ownership and
remaining integration gates. The independently corrected observational stage is
**selected in the NEW `build/vere-openssl3-owned/` source recipe**; see
`openssl-source-integration-result.md` for final bindings and verification.
Explicit per-process descriptor/identity bootstrap and independently
bound supervisor evidence remain necessary. Unconfigured hooks deliberately emit
nothing; that is NOT a successful measurement. No workload row below was run.

## Scope and instrument

This is a concrete future experiment specification, not runtime/build authority
or a measured budget. The NEW owned recipe now carries
`u3_openssl_arena_snapshot(u3_openssl_arena_metrics *)`. The API takes the existing
owner mutex and does not allocate, log, reset counters or expose payloads. Every
successful engine page acquisition increments the charge; release decrements it
before free-run coalescing. Initialization charges the full fixed metadata prefix
and permanent anchor. The cumulative peak observes **internal** realloc overlap
and staged pages even if the outer request fails and rolls them back.

`charged_bytes` is a conservative, page-granular allocator occupancy charge:
all occupied engine pages, including unused chunk slots, chunk metadata and
headers, plus the full fixed directory/descriptor prefix and anchor. It is NOT
requested live bytes, RSS, mapped extent, exact occupied-byte count, a minimum
viable capacity, or a fragmentation guarantee. It excludes the small static
owner/mutex/Hunk tables outside the mapping (count those in non-arena memory).
The peak never resets during one arena lifetime. `allocation_failures` saturates
and counts nonzero public allocation/resize calls returning NULL while initialized,
including oversize requests, once per public call. Init failures need separate
startup outcome evidence. Zero-size calls are not OOM. No caller file/line or
object/pointer/crypto data is retained.

Snapshot returns 0 and leaves output untouched for NULL/uninitialized output.
Destroy clears metrics. A failed destroy with live blocks preserves them.
Collection must occur **after consumer completion and full OPENSSL_cleanup but
before successful arena destruction**, as well as at phase boundaries. A call
from inside an allocator callback, signal handler, or while holding the arena
mutex is forbidden. This is not async-signal-safe, post-fork recovery, atexit
ordering proof, or longjmp/lock recovery.

## Prerequisites before any experiment

1. Independently verify the final frozen recipe, exact executable SHA256, actual
   library/header/link provenance, explicit trial capacity and target/ABI. Build
   grant, exact-link sequencing, fresh bound controller, engine resource limits,
   capacity/space admission and disposable-resource retention scope are separate
   owner approvals. No existing spent attempt may be reused.
2. Source-integrate and host-test a **public aggregate-only collector** at startup,
   named phase barriers, and the pre-destroy boundary above, in EVERY arena-owning
   process (king, workers, applicable utilities and no-loom fetch). The snapshot
   API is selected in source; the collector/instrumentation stage is now
   implemented, host-tested and **selected by the NEW frozen recipe**.
   Configure each owning process explicitly after fork/exec and before owned
   OpenSSL startup. A runner-entry `application` checkpoint is not `ready` or a
   successful workload barrier. Invoke the named phase API at actual approved
   ready/workload boundaries; controller bootstrap/barrier wiring is not supplied.
   Use monotonic sequence/run/process-generation labels, not addresses, keys,
   environment dumps or private logs. Retain final shutdown record durably even
   if later destruction fails; a missing final record invalidates completeness.
   Persistence failure must NOT block necessary application cleanup: the selected
   hooks preserve startup status, actual live-block checking, arena destruction
   and backing teardown. Sticky failure/missing final invalidates the measurement
   trial only. Unconfigured hooks do not initialize collector PID/mutex state.
   Bind collector source and schema in the new recipe before building.
3. The owner fixes workload limits: simultaneous piers/workers, inbound/outbound
   TLS connections, request/body sizes, DNS/cancellation rate, event count, cycle
   count, duration/deadline, CPU/memory/PID/storage bounds and public fixtures.
   Record these literal values in the approved run manifest; unset limits refuse
   admission. Do not invent production-looking values from the host 2MiB fixture.
4. Qualify same-accounting-domain memory collection: effective cgroup/container
   limit, peak domain charge, concurrent process population and arena mapping
   accounting. Periodic RSS samples are not guaranteed peaks. If concurrent
   non-arena resident upper bound cannot be established, conservatively use the
   entire domain peak as that bound (double-counting arena is safe but pessimistic),
   or declare the budget inconclusive. Do not subtract unrelated peaks. Capture
   effective limits and OOM/kill events via explicitly allowlisted public metadata,
   never broad engine inspection or private process/config/log dumps.

## Workload matrix and checkpoints

All rows are required only within their separately approved fixture/network scope;
otherwise mark NOT RUN and narrow the claimed workload envelope. No personal ship
or external endpoint is implied. Use the **same exact binary and capacity** for
all rows combined into one observation. Repeat the complete matrix at least three
times in fresh approved disposable states; repetitions are evidence, not proof of
all future workloads. Bound duration/events so the experiment terminates.

| Phase | Actions | Required public checkpoints/outcomes |
|---|---|---|
| Cold startup | Offline fake bootstrap through ready; exercise parent and spawned worker initialization | startup identity/capacity, ready snapshot, bootstrap success, all participating process generations |
| Warm crypto | Public deterministic SHA/SIV/provider vectors through actual selected library | before/after snapshots, vector pass/fail, no allocation failure |
| TLS | Fixture TLS1.2/TLS1.3 success; wrong hostname and untrusted-root rejection; inbound and outbound paths where supported | each case outcome, post-case snapshots, owner-selected bounded concurrency maximum |
| Churn | Repeated connect/request/cancel/close; bounded DNS pending/cancel and TLS failure cases; varied approved body sizes and overlap | cycle barriers, cumulative peak/failure counts, no accidental plaintext fallback; partial coverage explicitly listed |
| Steady bounded load | Approved maximum simultaneous work for approved duration/event count | phase begin/end, population/accounting envelope, cumulative peak/failures; no unbounded soak |
| Orderly completion | Stop admission, complete users/loop, normal globals and OpenSSL cleanup, snapshot, then arena destroy/backing stop | per-process final snapshot with zero live blocks and zero failures, successful destroy/exit, no forced kill |
| Same-state reopen | Different authorized container/process, noncreating reopen, ready/HTTP, repeat load subset and orderly completion | new process generation, exact binary/capacity unchanged, ready and final snapshots/outcomes |
| No-loom utility | Authorized local fixture exercising fetch-style TLS startup and finalization without noun backing | separate startup and pre-destroy snapshot, actual utility outcome; no external download inferred |

A forced stop, missing process final, startup/init failure, nonzero allocation
failures, nonzero final live blocks, mismatched binary/capacity or resource-bound
violation is a failed/incomplete trial, not successful sizing evidence. Expected
TLS authentication failures are not allocator failures. Fatal/OOM capacity-search
trials require a separate explicit grant; never deliberately exhaust production
or infer crash/recovery acceptance from orderly stop/reopen.

## Evidence record and budget decision

Retain only positively allowlisted public aggregate JSON and the approved workload
manifest. Per process generation retain schema, exact binary/recipe/collector
hashes, trial capacity, ordered phase labels, monotonic sequence, snapshot values,
exit/destroy/init outcomes. The supervisor receipt binds those bytes, resource
limits/outcomes, all process generations and workload manifest hash. Self-reported
hashes do not authenticate a run; independent controller/exact-binary binding and
readback are necessary. No raw argv, secrets or private payloads enter metrics.

For each successful exact-binary trial compute the maximum cumulative
`peak_charged_bytes` across all complete snapshots for each process generation.
It may supply a conservatively rounded occupancy bound to the sizing arithmetic
only when its provenance, complete lifecycle and workload are independently
accepted. Retain **successful configured capacity** as a floor: fragmented free
space can refuse an allocation even below peak charge. Do not lower capacity to
the charge peak or select safety margins automatically.

For a shared memory limit, budget ALL concurrently possible process arenas:
`sum(full configured arena capacities for admitted concurrent processes) +
concurrent non-arena upper bound + explicit system headroom <= effective limit`.
Use the owner-admitted maximum concurrent arena-owning population conservatively;
process-generation peaks must not be added as if sequential generations coexist.
The existing `admission.py` still computes only a **single-arena** envelope.
The new `issue3_arena_measurement/aggregate.py` validates a supplied supervisor
start/exit inventory and complete per-process records, rejects population-bound
violations, and multiplies per-role full candidate capacity by all admitted slots.
It does not sum sequential-generation peaks as simultaneous reservations.
It remains conditional arithmetic, not authenticated evidence or a controller.
Do not silently feed a per-process peak into the single-arena helper as
whole-container admission. Independent evidence must bind population, capacities
and the same accounting domain, or refuse the budget.
Arena headroom and system headroom remain independent owner-reviewed inputs.
`production_authorized=false` remains mandatory until separate approval.

## Remaining implementation/authority decision

The immediate source-only next slice is explicitly scoped per-process controller
descriptor/identity/bootstrap and real workload barrier wiring. Independent source
integration and deterministic NEW recipe refresh are complete; the exporter is
not operational without that bootstrap. After that, request a specific trial build/runtime grant
with explicit trial capacity, matrix bounds and exact-link sequencing. An initial
**trial** capacity is needed to obtain workload measurements; that is a distinct
bounded experiment decision, not a circular demand for production sizing before
any measurement and not automatic permission to use 2MiB. This turn ran only host
allocator probes. No workload row, Docker operation, target/library build or Vere
runtime was executed, and no production capacity is selected.
