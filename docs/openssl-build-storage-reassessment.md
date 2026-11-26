# Owned-build storage reassessment — October 30, 2026

## Outcome

**Launcher tests are isolated from live disk capacity; production admission remains
fail-closed. No build, start, pull, cleanup or lower-budget activation occurred.**
Fresh measurements support a smaller **monitored experimental** allowance, not a
claim that compilation fits or that the reserve is a hard quota. Recommend one
attended b02 trial with **6 GiB observed growth, 1 GiB stop headroom, immutable
10 GiB reserve, 17 GiB host AND engine admission** after explicit owner go-ahead
and fresh launch-time checks. Existing defaults remain **18/8/10 GiB**, margin0.

## Measurements and retained b01 accounting

Exact branch `fix/3-maintained-openssl`; existing tracked/untracked work preserved.
Read checkpoint, retry/trial records, minimum-gate assessment, contribution rules,
launcher and compiler/export guards. No applicable AGENTS.md/CLAUDE.md found.
All work stayed in this subagent. The previous “clean first” direction is superseded
by this reassessment request; historical cleanup authority remains consumed.

- **06:28:40–43 EDT:** host free minimum **19,506,323,456 B =18.166679 GiB**;
  engine filesystem free **39,817,297,920 B =37.082748 GiB**. Engine measurement
  was bounded `df -Pk /var/lib/docker` through the already-existing Desktop
  diagnostic socket, not a newly started container. Returned filesystem `/dev/vda1`,
  mount `/var/lib/containerd`. No engine-internal file payload was read.
- **06:38:40 EDT:** host **19,487,858,688 B =18.149483 GiB**, just
  **160,505,856 B above default18 GiB admission**. Thus the old host blocker is
  not continuously present: this is593,145,856 B more free at the first sample
  than the b02 refusal, without agent deletion. Cause of unrelated host variation
  is unknown. Closeout diagnostic-socket rechecks returned no df rows; the engine
  figure remains explicitly the06:28 observation, **not refreshed admission**.
- Worktree, scratch and Docker.raw share the host filesystem. Host available bytes
  have4096 B allocation granularity (statvfs reports1 MiB preferred block size);
  guest `df -Pk` has1 KiB reporting units. Neither counter reserves space or
  excludes concurrent writes. Three short host samples are not a sustained-rate test.
- Docker.raw: **63,999,836,160 B logical capacity**, **20,052,377,600 B allocated
  host blocks**. Neither predicts reclaimable physical space; APFS/sparse extents,
  guest free and host available space are distinct. Do not add host+engine free.
- Selected public API at daemon-advertised **v1.43**, context `desktop-linux`:
  **79 containers,34 volumes,44 unique images,216 cache records**. Logical layer
  accounting4,714,729,362 B; cache-size sum9,337,829,430 B; named-volume sum
  5,382,109,765 B. These can overlap; they are **not additive physical usage or
  deletion/reclaim estimates**.
- Exact b01 container `270dbd4f398e28333c7ed71f1d3fecc26806e20fcd3e1ae7c0fab85c88341dd9`
  remains exited/runningfalse/PID0/OOMfalse. Writable layer **86 B**; state volume
  `buildx_buildkit_issue3-owned-20261029-b010_state` **547,948 logical B**,
  RefCount1, joined to exactly that container. Its247,682,627 B rootfs includes
  the image; do not count it again. BuildKit image247,682,541 B, SharedSize
  8,660,061 B,239,022,480 B image-unique logical difference, **two container
  references**. Removing b01 would not remove that shared image. Nested builder
  cache was not queried with Buildx (which might bootstrap a stopped builder).
  Its volume is small because b01 failed before compilation, not a measured
  successful-build footprint. There is no meaningful measured storage case for
  deleting b01 here; all retained resources remain protected.
- Original public b01 result/spent/build-log hashes unchanged; accepted rollback
  image present. No running containers; exact b02 container/volume absent at closeout.

## Budget decision and limitations

The proposed arithmetic is **10 GiB reserve +6 GiB observed growth +1 GiB
stop/settlement margin =17 GiB admission** on each filesystem. At the final host
sample,6 GiB net growth would leave **12.149483 GiB**, versus **10.149483 GiB**
under8 GiB growth. That is useful extra room, not a measured capacity requirement.
Stop at growth **>=6 GiB** OR sampled free **<11 GiB**, whichever occurs first;
refuse admission below17 GiB. Bytes: growth6442450944, margin1073741824,
reserve10737418240, stop-free11811160064, initial18253611008.

- Outer policy measures **net free-space loss** including sparse-engine growth,
  host exported artifacts/public logs/evidence and unrelated filesystem changes;
  it is not per-build gross-write accounting. Concurrent freeing can mask growth.
  Engine measurement protects guest logical availability separately; host may be
  limiting even when the guest reports37 GiB free.
- Compiler's unchanged14 GiB initial/8 GiB guest-free guards and6 GiB sampled
  attempt-directory guard are **not whole-build quotas**. Two-stage retained
  OpenSSL/compiler cache and snapshots can coexist. Final delivery copies original
  archives/config/emitted archives (bounded256 files/512 MiB), binaries/receipts
  and compressed source; local export adds another host copy while engine state
  remains retained. The source archive has no independent512 MiB total cap.
  All overlap must fit the outer6 GiB net-growth allowance, not be added after it.
  No whole-build successful owned peak or source-export size is available.
- Nominal outer loop sleeps5s and can spend15s in inspect plus10s in sampling:
  roughly30s between observations, plus command/scheduler effects. Settlement is
  nominal60s best effort; it does not keep sampling disk.1 GiB spread over90s
  corresponds to only **11.378 MiB/s**, not an established upper write rate.
  Export/compiler writes or unrelated writes could exceed that. There is **no
  proof that1 GiB bounds overshoot**, no reservation/hard disk quota, and no
  through-daemon/host-loss guarantee. If “never below10 GiB under any failure”
  is required, this launcher cannot establish it at any of these admissions.
- RAM6 GiB/zero swap/2 CPUs are separately configured/read-back cgroup controls
  in the prior attempt, **not freshly verified for nonexistent b02**. Disk/time
  stopping is monitoring, not enforcement like those resource limits. New launch
  still requires fresh control readback.128 MiB arena is trial-only.

**Conclusion:** a6 GiB trial is a reasonable tighter stop envelope with more
reserve headroom than today's8 GiB proposal, but may stop before producing an
ELF. b01's tiny metadata-only growth cannot justify promising a compile fits.
Do not reduce reserve or change defaults to manufacture a passing gate.

## Source changes and verification

- `tools/issue3_fresh_attempt/buildkit_trial.py`: explicit validated
  `--max-growth-bytes`/`--stop-headroom-bytes`, recorded in authorization receipt;
  growth positive integer <=8 GiB, margin nonnegative integer; reserve fixed10 GiB.
  Derive initial floors from reserve+growth+margin, preserve at least14 GiB engine
  admission. Admission and every build sample share the policy; host baseline
  includes setup/evidence growth. Invalid/missing readings refuse. Defaults unchanged.
- `tests/test_openssl_buildkit_trial.py`: mock **disk_usage** only in the existing
  mocked-client test, not production `storage` or admission. Outer unavailable-OS
  provider regression failed before this fix and passes after it. Added default,
  explicit-byte/CLI/validation, host unavailable/low, engine unavailable/low,
  monitored headroom/growth, no-spent/no-client-before-admission tests. Mocked
  negative paths verify exact-owned stop/readback and no delete. A deliberately
  ignored-policy integration control produced the expected1 failure/0 errors;
  real suite then passed. Initial missing-budget/API failures were scaffold RED,
  not standalone proof of all safety branches.
- Focused **23 tests PASS,0.191s,exit0**. Full relevant discovery:
  **344 collected/unique/executed,PASS,136.296s,exit0,zero failures/errors/skips**.
  Outer owned scratch retained only its unchanged sentinel before owner cleanup;
  this is not historical/global cleanup. Host/source/mock/synthetic proof only,
  not target compilation, real-library/TLS, ship or native acceptance.
- Final independent56 recipe bindings match b01 frozen recipe; manifest remains
  `be42b67418b33e5b4e4ba5acd9941187ff0e9ec5a5924d53cca5f17e525b32ef`.
  The changed launcher is outside the bound recipe/helper set; **no recipe refresh
  needed or performed**. Launcher source hash765f5482693581e4005a5e848d2db26f2d2cff4ea2d63cb7368a6925db493cfe.
  `git diff --check` and explicit changed-file whitespace/syntax checks pass.

Durable public receipts in `docs/openssl-candidate-evidence/`:
`storage-reassessment-20261030.json`, `storage-source-tests-20261030.json`,
`storage-closeout-20261030.json`. Scratch retains bounded audit/test/closeout
scripts and full test log. Checkpoint AND copyable prompt synchronized.

## Smallest next approval

**Approve one resumed, attended b02 trial using6 GiB observed growth +1 GiB
stop margin (17 GiB initial/10 GiB reserve), client-process-only
`BUILDKIT_NO_CLIENT_TOKEN=1`, and all other original one-shot limits unchanged.**
Include fresh immediate host/engine admission, cached pin/bindings/effective
6 GiB RAM/zero swap/2 CPUs readback,40min+60s best-effort stop/retain, no automatic
retry, no deletion. Select the new flags explicitly only in that approved invocation.
The b02 invocation remains unspent but its prior stopped execution is closed;
this assessment/source approval is **not launch approval**. No extra cleanup or
research approval is needed. If fresh admission fails, stop and report it; do not
reuse this observation or silently trim the bound. Network candidate is untested.
Compilation is the next product milestone; library/TLS/lifecycle/package/native/
Public/personal-use gates remain subsequent and unqualified.
