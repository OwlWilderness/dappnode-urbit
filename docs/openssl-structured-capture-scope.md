# Structured capture: source-only scope decision

Status: header exporter has a source-supported design; executed-link capture is
still unresolved. No capture implementation, recipe integration or new build has
been performed. This supplements `openssl-link-capture-result.md`; it does not
supersede that report's refusal of verbose-link parsing.

## Independent checks this session

- Rechecked branch `fix/3-maintained-openssl` in the issue-3 worktree.
- Reran the handoff's focused command: 91 tests in 18.121 seconds, exit 0,
  no skips; `git diff --check` passed. These remain host/mock/source tests.
- Read-only header investigation returned; parent independently inspected the
  pinned distribution's Compile, Module, Build and main source sections below.
- Existing hardening, historical artifacts, attempts and resource state were not
  changed. No Docker/engine, tracing, recovery, dependency build or runtime call.

## Header graph design — not yet implemented or exercised

Use a custom make-phase step depending on the actual executable Compile step.
Make required install/delivery completion depend on export success. Traverse
`getCompileDependencies(true)` and each root module's `getGraph().modules`.
Resolve existing LazyPaths in make phase; do not search cache basenames.
Select artifacts through graph edges plus owning package identity and registered
headers, rejecting ambiguity. Retain each consumer module's ordered configuration.

Pinned Zig 0.15.2 distribution source references:

- `lib/std/Build/Step/Compile.zig:2150–2179`: linked compile traversal.
- `lib/std/Build/Module.zig:670–709`: make-phase module traversal.
- `lib/std/Build.zig:2428–2492`: resolved LazyPath paths.
- `lib/std/Build/Step/Compile.zig:303–353,556–580`: header registrations,
  copy filters and generated include trees.
- `lib/std/Build/Module.zig:160–195,611–615`: structured ordered include
  argument emission followed by literal macro arguments.
- `lib/std/Build/Module.zig:646–655`: library edges also add include entries.

Do not first call `getEmittedIncludeTree()` during the export callback: that API
can create new graph state. Read trees already wired for actual consumers and
refuse absent expected trees. Header installation defaults to `.h` filtering;
source/copy inventory equality must apply the registered filters.

Manifest obligations: graph/package identities, source registrations and emitted
paths, per-header source/copy hashes, ordered tagged includes (with duplicates),
literal macro arrays, per-source flags/language, target query and resolved target,
CPU/features/optimization, recipe/adapter/toolchain bindings and explicit coverage.
Curl's linked SSL and crypto include entries both remain represented. Preserve
OpenSSL Configure evidence separately from its object-rearchive adapter. Do not
invent curl_config.h.

This proves resolved graph configuration and copied public headers only. It does
not prove actual preprocessor file accesses, implicit/system search paths, builtin
macros, or executed final-link argv. Exporting after compile also does not provide
a new concurrent-mutation guarantee; the isolated-attempt assumption remains.

Minimal proposed implementation: new `header-provenance.zig`, a preimage-checked
root-build staging/hook in `candidate.py`, focused schema/refusal tests, and later
reviewed delivery/lock/Docker/verifier bindings. No adapter changes are presently
shown necessary. Actual graph execution remains a separately scoped test gate.

## Execution capture: explicit decision needed before expansion

Parent inspected `src/main.zig:3023–3027,3410–3413`: the compiler obtains its own
executable path and gives it to Compilation. `src/link/Lld.zig:1615–1723` creates
and waits for its child and handles a NameTooLong response-file fallback.
A PATH wrapper or build-runner compiler-argv export does not observe that child.
No supported exact capture facility was established by this bounded inspection;
this is not a claim that none exists anywhere.

Two further scopes are distinct, and neither is silently authorized here:

1. **External execution-observer feasibility, read-only first.** Evaluate an
   existing Linux facility against this exact AMD64-on-ARM builder topology,
   child exec/argv/cwd/exit coverage, pre-deletion response capture, loss limits
   and permissions. No tracer execution/install, container creation, engine
   changes or custom syscall parser. Return a concrete bounded probe proposal
   or a blocker. This preserves the pinned compiler binary if viable.
2. **Pinned Zig instrumentation, source-only first.** Design/implement a bounded
   structured producer in the exact LLD child-spawn/wait path, with byte-safe argv,
   cwd, spawn/exit outcomes and either captured response bytes or explicit refusal
   before fallback. Bind the source patch and future instrumented compiler
   identity. This changes the toolchain; rebuilding/qualifying that compiler is
   a separate substantial gate, not covered by the existing candidate budget.

Do not wire retention to a proposed producer until its execution contract is
established. Synthetic manifests cannot qualify the producer. Keep absent,
ambiguous, truncated, cached/no-link and unsuccessful captures fail-closed.
Future integration must bind the producer, graph manifest, selected final archives,
output/delivery hashes, retained bytes, capacity guards and final receipt ordering.

No build/runtime approval is requested or implied by this document. Before any
such proposal, inspect current capacity and state, identify exact inputs/resources,
time/storage limits and fresh attempt authorization. Full parity, actual-library,
TLS, lifecycle, native Dappnode and publication gates remain open.
