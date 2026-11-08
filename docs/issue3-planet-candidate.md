# Isolated issue3 real-planet candidate

This source selection extends recovery base `6041ab135f40ddcc553eaf180d692296210be5a9`.
It is **not an image qualification, installation, distribution clearance or issue3 closure**.
The stock `build/Dockerfile`, official download selection, package identity and volume
remain unchanged. Select this candidate explicitly using `build/assemble_planet.py`.

## Target and authority

The assembler requires an explicitly selected, owner-verified unused planet.
No owner readiness records or target checklist is distributed with this source.
Verify eligibility and absence of another instance independently before any use.
Do not put keys in configuration, environment, arguments, URLs, logs or chat.
Preserve all existing ships and production storage.

The candidate uses separate `issue3-planet.public.dappnode.eth`, image
`ship.issue3-planet.public.dappnode.eth:0.1.0`, and `planet_trial_data:/urbit`.
This is a local trial identity, not a claim of public namespace registration.
The assembler requires an explicit public planet literal and explicitly allocated
host UDP port; it rejects existing UVM/star ports 34343/34344. It does not inspect
or reserve network ports. No host TCP port is published. Internal Ames remains
34343 and ship HTTP remains loopback 8081. Never attach a protected existing volume.
The public backend defaults disabled (`URBIT_PUBLIC_SHIP_ORIGIN=""`).
Only an explicit `--public-ship-origin https://ship.example.com` (replace with
the approved host) enables its descriptor setting
and exposes internal ship-only TLS backend **9444/tcp**, with no host TCP publish.
The inherited frontend retains private manager/ship **8443** and public Host/Origin/SNI
checks, including rejection of an explicitly written default `:443` origin. Only
normal ship loopback 8081 is upstream of 9444; owner management/key intake is not.
The separate future tunnel must verify TLS with this ship's owner CA and private
ship SNI. This descriptor does not create a connector, remote route or DNS record.

Intended private owner route:
`https://issue3-planet.public.dappnode.private:8443`; ship route:
`https://ship.issue3-planet.public.dappnode.private:8443`. These are descriptor
values, **not resolver/TLS/browser-qualified endpoints**. Before installation,
verify both exact DNS names and the existing owner-CA certificate/CSR workflow.
Enrollment/password/CSRF/session safeguards and separate ship/admin origins remain
those of the existing private manager. Do not bypass them with a plaintext upload,
File Manager key handoff, root wrapper or owner shell requirement.

## Exact selection and assembly

Selected AMD64 ELF SHA256:
`58d07af97926e04bc17184bc18f53e5fb11d84fed63bd9daf2fe4ceb04c86698`
(42,399,776 bytes). Matching source archive SHA256:
`8ed4fc8a6b4c1acba3e4e89860a4059e490feb3efaf2a818805770f24f65654f`
(220,821,885 bytes). Retained selection reports OpenSSL 3.5.9, curl 8.23.0,
Vere source `8ddc4b786979574dbfcb655e3db1b634f658d0de`, default process-lifetime
OpenSSL allocation. This is not b04. No older `runtime.py` is copied.

After an operator allocates a nonconflicting UDP port, run the assembler with
`--planet '~sample-planet'`, `--host-udp <allocated-port>`, `--artifact-root` pointing
to the retained `build_issue3_amd64_curl_build_02/artifact`, and `--output` pointing
to a **new** directory whose parent exists. No default identity or port is guessed.
The assembler authenticates four exact inputs, copies the current recovery/source
closure and inherited notices, retains the corresponding-source archive, exports
its notice/license files without extracting executable source, and writes context,
SDK manifest/Compose/wizard/avatar and a hash inventory. It never builds or runs.
The explicit Dockerfile checks ELF/source hashes again. `UpdatedRuntimeAdapter`
checks the ELF inode at every launch; the official adapter still rejects this ELF.

Only this image maps `planet_service.py` to the supervisor's existing
`managed_service.py` entrypoint. No second supervisor or writer is added. The
selected platform Python pin is 3.14.10-r1, matching the retained candidate rather
than claiming old platform-source coverage applies. Distribution review remains
open for that pin, the final image package closure and corresponding-source/relink
requirements. Carrying notices/source is not legal clearance.

## Browser-first one-shot first boot

1. Qualify/install the exact image and private route in a later separately
   authorized phase. Management starts without Vere. Complete the existing
   owner-CA and one-time owner-password enrollment workflow.
2. Sign in to the ordinary private owner page. It displays the configured public
   planet. Verify it matches the independently approved planet. Select the networking keyfile locally
   (1–65,536 bytes), confirm unused/no-other-instance, and initialize once.
3. The authenticated same-origin CSRF-protected binary POST `/api/provision`
   accepts no file path, arbitrary command or alternate identity. It does not echo
   the key or raw failures. The browser clears the file selection before awaiting
   acknowledgement and sends no automatic retry. The server provides only an
   anonymous descriptor to the pinned child (`-k /proc/self/fd/N`); key contents
   never enter argv/environment. On Linux this is a memfd. Source-only portable
   tests use an unlinked private temporary inode. No retained key-upload API exists.
4. Under the existing lifetime locks, persist an exclusive `fresh-planet.json`
   ATTEMPTED record, a fenced job, and STARTING intent **before** creation. Launch
   the verified ELF with `-w <configured-name> -k <fd> -x -c <held-pier-fd>/ship`,
   with all child stdio suppressed. Linux subreaper ownership is the same existing
   boundary. The request returns while the one owned worker waits; the page polls
   status. A lost response is an observation problem, never retry permission.
5. Only natural exit0, no owner Stop/interruption, safe `.urb` layout, no surviving
   owned descendants and successful durable commit produce COMPLETE + ordinary
   READY_LOCKED + STOPPED. **No automatic resume.** Explicit Start then uses the
   existing noncreating lifecycle; Stop/access-code/Recover remain distinct.

Stop during initialization is available but **permanently fences this attempt**,
even if the child acknowledges exit0. Interrupted/failed/ambiguous creation leaves
its pier, attempt and journals preserved. Reopening does not retry or resume it;
import/reset/cancel/Start and lifecycle Recover cannot convert incomplete creation
into a usable pier. There is intentionally no reset/retry/erase endpoint. Preserve
and review that exact attempt; this source does not promise arbitrary pier repair.

## Recovery, upgrade and rollback limits

The issue19 completed-native-history validator, opaque `legacy015-evidence`
admission, original journals, issue20 local recovery and PID1 management-only boot
boundary are retained, not replaced. Completed initialization enters their ordinary
READY_LOCKED lifecycle. Whole-container crash leaves intent fenced until a verified
management boot and explicit Recover; Recover retains original evidence, leaves
STOPPED and never implies Start or Urbit data repair. Unknown writers, pending
native evidence, uncertain ownership and interrupted recovery still refuse.
Exclusive volume/private PID namespace/trusted administrator remain prerequisites.

This trial is **not** authorization or qualification for an existing UVM/star
upgrade. The focused native-history fixture establishes source compatibility, not
physical metadata admission of a live retained volume or Linux container recovery.
A fresh planet cannot prove migration from an older real pier. Any future migration
needs exact stopped backup, source/runtime/layout/evidence bindings and controlled
upgrade admission before writer launch. Do not remove issue19 evidence to force
admission. Never run two copies of the same ship.

Rollback before any candidate writer starts may restore the unchanged predecessor
plus its own unchanged volume. After creation or a candidate write, an older ELF
may not read the advanced pier; no backward-compatibility guarantee is made. Keep
an independent cold pre-upgrade backup and predecessor image/source/evidence.
Restore only the appropriate stopped-state backup under separate authorization;
never silently downgrade against candidate-modified state, clear journals, copy a
live pier or replay creation. A new planet has no pre-creation pier rollback.

## Focused evidence and next phase

Run portable source checks from the repository root:

```sh
python3 -B tests/issue3-planet/test_planet.py
python3 -B tests/issue3-planet/test_assembly.py
node --test tests/issue3-planet/ui.test.mjs
```

The assembly suite reports two explicit integration skips without
`UVM_PLANET_ARTIFACT_ROOT`; these are not build qualification. Set that variable
only to a separately authenticated retained-artifact directory to run those gates.
No test reaches into a personal or sibling checkout automatically.

`tests/issue3-planet/test_planet.py`: committed stopped fresh completion, duplicate
and interrupted/reopened refusal, exit0-after-Stop fencing, authenticated HTTP/CSRF/
Origin/no-secret-reflection, and one completed-native-history compatibility fixture.
`test_assembly.py`: retained-input hashes, actual disposable context assembly and
source/notice closure, isolated descriptors, existing-output refusal, and the real
selected ELF read through the adapter with Popen replaced (no ELF execution).
`ui.test.mjs`: owner form binary submission, clearing, no retry/auto-Start and
initialization Stop availability. These are source/controller tests, **not rendered
browser, Linux memfd/creation, image, TLS/DNS or real-ship qualification**.

Next: allocate UDP, assemble the actual selected descriptor set, build one AMD64
root image from that sealed context, inspect final layers/runtime/source/notices and
SDK bindings, and exercise only the changed composition through real private TLS
and browser access. Then the parent handles private owner key intake and real
`~sample-planet` boot/network/TLS/reopen/recovery acceptance. No real ship, image
build, installation, wallet action, publication, commit or push occurred in this
implementation phase. Issue3 stays open until its actual criteria are verified.
