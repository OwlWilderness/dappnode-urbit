# b04 recipient source layout, build and modified-library relink

**Preparation, not a tested recipient build.** No real companion assembly,
extraction, compiler, relink or library modification was executed to write this
guide. Host tests exercise small opaque fixtures only. The historical b04 build
and ONE no-state `-R` passed; they do not prove these recipient instructions,
final-link/header authentication, crypto/TLS, package/image or release clearance.
This guide is a new companion document, not a change to the frozen recipe or a
licence election. All execution below is for a separately authorized recipient
workspace; it is not permission to execute in the developer's retained workspace.

## 1. Authenticate, plan, assemble, read back

Read `docs/license-preparation/b04-source-notices-binding.md` and
`docs/openssl-b04-preparation-integration.md` first. The independently reviewed
manifest digest is
`715108b2cecbce58dd4c88a53659862f850b65c2ff4246915ba42beb9617d487`.
The unchanged source archive is 220848835 bytes, SHA-256
`a5f35232abe2aa4d03ff82e06665a465ecf1d6ee0f5399d22b8c7fd6bfcfea54`.
The associated b04 ELF is 42467624 bytes, SHA-256
`f2eba68682650ab6d9712017781612f4dbc3c01411c1ba5c7c4ecbb0f186b6b5`.
The ELF is authenticated at planning, **not copied into this source companion**.

From the developer checkout, set `ARTIFACT` to the retained b04 `artifact/`
directory (its sibling must be `frozen-recipe/`). `DEST_PARENT` must be an existing
owned directory. These commands do not extract or execute source:

```sh
python3 -m tools.issue3_fresh_attempt.b04_source_companion plan \
  --artifact "$ARTIFACT" > "$DEST_PARENT/b04-plan.json"
# Record the resulting plan digest independently of the delivery directory.
python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' \
  "$DEST_PARENT/b04-plan.json"
# Set PLAN_SHA256 to that exact independently retained value.
python3 -m tools.issue3_fresh_attempt.b04_source_companion assemble \
  --artifact "$ARTIFACT" --output "$DEST_PARENT/b04-source" \
  --plan "$DEST_PARENT/b04-plan.json" --plan-sha256 "$PLAN_SHA256"
```

Assembler checks strict notice selection, unchanged archive hash and exact
member inventory, all 56 explicitly inventoried frozen files (including nested
`baseline/` and owned `tools/` helpers), all 34 artifact support/config files,
reviewed evidence, notice copies and these successor documents/tools. It does
not infer completeness from a fixed package-tree count. The original archive
is streamed unchanged; its confined upstream symlinks stay **inside** the opaque
archive. External input/output symlinks, hardlinked leaves, noncanonical and
portable-colliding paths, excess bytes/files, pre-existing output and capacity
shortfall are refused. Default copy bounds: 512 leaves, 224 MiB per leaf,
256 MiB total; 64 MiB free reserve plus remaining bytes and receipt allowance;
120-second checked copy deadline. These are sampled checks, not filesystem
quotas, race-proof hostile-writer isolation, power-loss durability, or hard
end-to-end deadlines. Use an exclusively owned parent; do not race another writer.

An error retains the new incomplete directory; there is no automatic rollback,
cleanup or overwrite. No completion receipt is issued before all copies and
capacity callbacks finish and all destinations are rehashed. Do not reuse a
failed directory. A later readback failure invalidates any existing receipt.

After delivery, with `B04` set to the recipient companion's absolute directory:

```sh
cd "$B04"
python3 tools/issue3_fresh_attempt/b04_source_companion.py validate \
  --output "$B04" --plan "$INDEPENDENT_PLAN" --plan-sha256 "$PLAN_SHA256"
```

The recipient needs the independently retained plan **and its independently
trusted digest**. Editing both a receipt and an untrusted plan cannot establish
authenticity. Successful result is only `ASSEMBLED_NOT_REBUILD_RELINK_VERIFIED`.
No installed repository, developer scratch pathname, ELF, Docker daemon or
network is required for this readback. Do not put the independent plan inside
the companion: exact-inventory validation rejects extra leaves/directories.

## 2. Layout and build inputs

`layout.json` beside this guide is machine-readable. Mapping is relative to
`$B04`, derived from the artifact's **effective** Dockerfile, original recipe,
`local_build.py`, `local_dependencies.py` and `local-build-binding.json`:

| Recipient path | Meaning |
| --- | --- |
| `source-materials.tar.gz` | Original opaque source delivery, byte-for-byte unchanged |
| `recipe/` | Every exact frozen recipe key, including `baseline/`, `tools/`, locks and generation helpers |
| `support/` | Every exact artifact support/config key; final receipts are not substituted for recipe preimages |
| `support/effective.Dockerfile` | Actual late local-dependency builder definition; `recipe/Dockerfile` remains original |
| `support/local-build-binding.json` | Exact hashes of late driver, dependency helper, observer, effective Dockerfile and local dependency receipt |
| `docs/openssl-candidate-evidence/` | Genuine original build and report receipts (not authority to replay a spent controller) |
| `docs/license-preparation/texts/` | The 14 reviewed minimum notice selections, not complete licence disposition |
| `tools/issue3_fresh_attempt/` | New companion validator/assembler and reviewed binding helper |

Do **not** copy `support/h2o-socket.c` over `recipe/h2o-socket.c`: the former is
final-owned output, the latter is the required intermediate pinned preimage.
Likewise, baseline overlay receipts describe intermediate source, not final
owned bytes. `recipe/owned-recipe.json` authenticates recipe/helper completeness.
Keep this companion immutable; all following operations belong in a **separate**
owned `WORK` directory, with no private pier or retained developer cache mounts.

The source archive contains these roots:

- `materials/`: pristine Vere archive (`vere-8ddc4b7.tar.gz`), OpenSSL archive
  (`openssl-3.5.9.tar.gz`), and Linux AMD64 Zig archive
  (`zig-x86_64-linux-0.15.2.tar.xz`). Their sizes/hashes are in `recipe/inputs.json`.
- `vere-8ddc4b786979574dbfcb655e3db1b634f658d0de/`: historical **already patched**
  source, generated owned config and OpenSSL object adapter. Objects/archives
  were deliberately filtered out. Do not apply pristine overlays twice here.
- `openssl-3.5.9/`: historical configured/generated source. This is not the
  original archive, and contains no retained `.o` or `.a` source-delivery payload.
- `p/`: exact archived dependency source trees. Their explicit identities and
  required notices are in the reviewed binding, not established by tree count.
- `openssl-cache-evidence/`: original OpenSSL configure/build diagnostics.

The effective build requires **Linux AMD64**, pinned **Zig 0.15.2**,
`x86_64-linux-musl`, Perl, make, xz, Python and musl build tools. The effective
Alpine base digest and full pinned APK closure are in
`support/effective.Dockerfile`, `recipe/builder-apks.json` and
`support/builder-apk-db.txt`; notably this builder uses Python **3.14.10-r1**.
Those are historical builder facts, not current repository availability or
runtime-image APK verification. No images/APKs are included. Use an isolated
recipient build environment matching them; base/APK retrieval and native target
validation remain untested here. The historical arena value 134217728 is a
**trial**, not a production memory-capacity qualification.

## 3. Extraction and generation order

First validate the opaque companion. After separately admitting disk/memory,
extract it only in an empty recipient-owned directory using Python 3.14's data
filter, not an unrestricted `tar -xf` into existing files. For example, in the
isolated Linux recipient environment:

```sh
export B04 WORK  # absolute, distinct owned directories; WORK already exists
python3 - <<'PY'
import os, pathlib, tarfile
out = pathlib.Path(os.environ['WORK']) / 'retained'
out.mkdir()  # exclusive; never merge into an existing tree
with tarfile.open(pathlib.Path(os.environ['B04']) / 'source-materials.tar.gz') as t:
    t.extractall(out, filter='data')
PY
```

This extraction example is **not exercised** here, and lexical archive inspection
alone is not a safe-extraction proof. Keep the new directory isolated from hostile
writers; no device/special-file or escaping-link permission is implied.

Start a fresh source build from the three `retained/materials/` pristine archives,
not by re-patching the historical Vere tree. The frozen `candidate.prepare()` is
the executable ordering specification and checks pristine archive hashes first:
H2O publication → SHA → allocation hardening → curl → top-level build/report →
CA → curl buffer → baseline allocator → OpenSSL manifest/placeholder → preserved
content-pin mirror replacements → owned integration. The final integration
generates the arena/config, shutdown completion, startup and noun graph, preserving
intermediate receipts separately. `owned-overlay.json` and `candidate.json` carry
final-source maps. No new code generation is performed by the companion assembler.

The OpenSSL placeholder must be replaced **after** compiling the selected
OpenSSL source: copy its generated include tree, list and validate archive members
using pinned Zig `ar`, extract each original archive into `ext/openssl/prebuilt/crypto`
and `/ssl`, and regenerate `ext/openssl/build.zig` with `candidate.object_adapter()`.
Never nest an `.a` inside a new `.a`, retain stale extracted objects, or select a
library by first matching basename. The frozen `compile_candidate()` implements
this order and invokes:

```text
zig build -Dtarget=x86_64-linux-musl -Drelease=true -Dpace=once -j2 --summary all --verbose-link
```

OpenSSL uses pinned Zig `cc -target x86_64-linux-musl -mcpu=baseline`, `ar` and
`ranlib`, `SOURCE_DATE_EPOCH=1782999240`, `LC_ALL=C`, `TZ=UTC`, then:

```text
perl Configure linux-x86_64 no-shared no-module no-tests no-apps no-docs --prefix=/opt/uvm-openssl3 --openssldir=/opt/uvm-openssl3/ssl --libdir=lib -fPIC
make -j2 build_libs
perl configdata.pm --dump
```

## 4. Local dependency route and fresh build

The historical late driver inserted **three naked tarballs** into the same fresh
Zig global cache later used by Vere. They are not standalone files in this
companion: archived `p/` source is not a replacement for their original tar bytes.
The exact public URLs, compressed byte counts/SHA-256s, original `.zon` manifests
and Zig package identities are the literal `PINS` in
`support/local_dependencies.py`. Obtain just those three public archives into
`$WORK/local-deps/{softblas,pdjson,backtrace}.tar.gz`, within those byte bounds,
then run that helper's `verify()`; both compressed hash and independent Zig
package hash must pass. No pin or URL rewriting is needed. If unavailable, report
the exact retrieval failure; do not silently synthesize a different tarball or
pretend the historical cache has been delivered.

Copy `local_build.py`, `local_dependencies.py`, `progress_observer.py` and
`effective.Dockerfile` from `support/` to `$WORK/local-deps/`, preserving their
hashes from `support/local-build-binding.json`. A concrete bounded setup script
for that **new** named context follows. It performs public retrieval only when
a recipient separately runs it; it was not executed by this task. Its helper
verification is host/file-only; `seed()` below is the later compiler invocation.
A failed setup is retained; choose a fresh workspace rather than merging files.

```python
import os, sys, json, hashlib, urllib.request
from pathlib import Path
sys.dont_write_bytecode = True
B04 = Path(os.environ['B04']).resolve()
WORK = Path(os.environ['WORK']).resolve()
local = WORK / 'local-deps'
local.mkdir()  # exclusive new directory
hashes = json.loads((B04 / 'support/local-build-binding.json').read_text())
for name in ('local_build.py', 'local_dependencies.py',
             'progress_observer.py', 'effective.Dockerfile'):
    data = (B04 / 'support' / name).read_bytes()
    if hashlib.sha256(data).hexdigest() != hashes[name]:
        raise ValueError('late helper binding mismatch: ' + name)
    with (local / name).open('xb') as writer:
        writer.write(data)
sys.path.insert(0, str(local))
import local_dependencies
for name, (size, digest, pin, manifest, url) in local_dependencies.PINS.items():
    with urllib.request.urlopen(url, timeout=90) as response:
        if not response.geturl().startswith('https://'):
            raise ValueError('insecure dependency redirect')
        data = response.read(size + 1)
    if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError('original dependency archive mismatch: ' + name)
    with (local / (name + '.tar.gz')).open('xb') as writer:
        writer.write(data)
local_dependencies.verify(local)  # compressed identities AND Zig package hashes
```

The original effective Dockerfile uses `recipe/` as build context and
`issue3deps=$WORK/local-deps/` as a **named**
context. It copies the original `recipe/Dockerfile` into `/recipe`; do not replace
that file with the effective one or change frozen `.dockerignore`/manifest pins.
The original `local_build.py` first verifies the exact old OpenSSL cache hashes;
it is **not a modified-OpenSSL driver** and its developer cache was not delivered.

For a source rebuild without that cache, use the frozen recipe API directly.
The following is a recipient script outline with concrete companion-relative
paths; save it outside the immutable companion, then review and execute **only
under separately scoped resource/network/settlement controls** in the pinned
Linux environment. It is not run by this task. It deliberately compiles OpenSSL
from pristine source (no `--openssl-cache` fallback). Remaining dependencies may
use their original public `.zon` URLs; this is not an established offline build.

```python
import os, sys, json
from pathlib import Path
B04 = Path(os.environ['B04']).resolve()
WORK = Path(os.environ['WORK']).resolve()
sys.dont_write_bytecode = True  # do not add __pycache__ to the immutable companion
sys.path[:0] = [str(B04 / 'recipe'), str(WORK / 'local-deps')]
import candidate, local_dependencies, progress_observer
candidate.owned.validate_recipe(B04 / 'recipe')
local_dependencies.verify(WORK / 'local-deps')
lock = json.loads((B04 / 'recipe/inputs.json').read_text())
candidate.StageDiagnostics = progress_observer.StageDiagnostics
attempt = candidate.Attempt(WORK / 'rebuild')  # must not exist, even after failure
# Explicit recipient-only late timeout adapter. Original default is 1800 s;
# historical b04 used 3300 s. This does not impose an outer OS/container ceiling.
original_run = attempt.run
def run(stage, argv, cwd, env, *args, **kwargs):
    if stage == 'vere-build':
        if args or kwargs:
            raise ValueError('ambiguous timeout override')
        kwargs['timeout'] = 3300
    return original_run(stage, argv, cwd, env, *args, **kwargs)
attempt.run = run
# 128 MiB was the historical trial setting, NOT production sizing.
trees = candidate.prepare(attempt, lock, WORK / 'retained/materials',
                          arena_bytes=134217728)
# Optional modified-library step described in section 5 belongs HERE.
local_dependencies.seed(WORK / 'local-deps', trees['zig'] / 'zig',
                        attempt.output, trees['vere'])
candidate.compile_candidate(attempt, lock, trees)  # no retained-cache argument
```

`seed()` requires a fresh `work/rebuild/zig-cache`, checks the original URL/pin
strings, runs pinned Zig `version` and `fetch`, and verifies the resulting package
paths. Do not prepopulate that fresh path with unverified extracted `p/` trees;
Zig trusts existing cache entries. The compile environment sets that **same**
global cache plus `work/rebuild/zig-local-cache`. The frozen recipe's disk guards,
APK checks and command timeouts remain; this outline adds no enforced RAM/CPU,
PID/network/disk quotas or crash settlement. Historical full build memory/time
figures are not independent fresh admission. No controller grant is replayed.

Expected output path (not an observed new output):
`$WORK/rebuild/vere-8ddc4b786979574dbfcb655e3db1b634f658d0de/zig-out/x86_64-linux-musl/urbit`.
`$WORK/rebuild/delivery/` is build evidence, not an installable runtime image.
Do not invoke the old `source_companion.py` or `package_image.py` as b04 delivery
or image acceptance tools. Compare fresh source/recipe/archives/config/ELF hashes
and retain logs; byte-identical reproduction is unproven, not assumed.

## 5. Modified-library rebuild and recombination

Use a **different fresh** `WORK` and record the change as a recipient variant,
not b04. At the marked point after `prepare()`, modify the selected library's
source in `trees['openssl']`, or for another library the corresponding pristine
source/adapter dependency. For OpenSSL, keep the compatible public API/ABI and
required 3.5.9 marker unless deliberately reviewing the version gates too. Record
an explicit patch, modification date/purpose, original and modified hashes,
configuration, headers and test expectations in a new recipient-side receipt.
A pause for an editor can be inserted at that point; do not edit the preserved
archive, pinned manifest, original cache JSON or reviewed helper pins.

Then continue the **no-cache** `compile_candidate()` route: Configure and
`make build_libs` rebuild OpenSSL, generated headers and archives feed fresh
validated object extraction, the generated Zig adapter feeds the ordinary Vere
build, and the application is relinked from source. Existing final objects in
the archive are not required for this source route. Do not simply edit
`ext/openssl/build.zig` while leaving historical prebuilt object/header bytes.
For a library fetched through a Zig content pin, modify a new local source copy
and explicitly adjust the **recipient variant** dependency path/graph rather
than corrupting a directory that still claims the original package hash.

`local_dependencies.verify_openssl()` and original-cache bindings intentionally
reject changed libraries. **Do not disable them and call it an authenticated b04
cache hit.** Bypassing that route by an explicit source rebuild is a distinct
variant; its fresh receipts must say so. The outline has not tested application
objects, modified-library recombination, function behavior, final-link execution
capture or actual preprocessor consumption. A baseline reproduction and one
meaningful modified-library change must be independently compiled/relinked and
read back, then separately qualified with bounded vector/TLS/application tests.
Retained original versus Zig-adapted SSL/crypto archives are different identities;
this assembler includes neither large library set and silently selects neither.

## 6. Minimal remaining recipient verification scope

1. Independently retain/authenticate the plan, admit capacity, perform ONE real
   unchanged-archive assembly and recipient-side exact readback/retrieval. This
   task only plans the large real delivery and exercises small-copy fixtures.
2. In an isolated pinned Linux AMD64 environment, scope safe extraction and
   original URL/base/APK access, verify all generated helper paths, then ONE
   baseline source build with explicit resource/time/settlement controls. Record
   source/config/archive/ELF identities and failures honestly. No offline or
   byte-identical-build success is pre-certified.
3. Separately authorize ONE compatible, meaningful library change, source rebuild
   and application relink using the variant route; retain its patch and evidence,
   prove changed library bytes reach the new executable, and test that executable.
   Actual final-link/header authentication remains a separate unresolved fact.
4. Reconcile actual runtime image/wrapper/manager/build-script and APK scope,
   modification notices, nested notice dispositions and equivalent recipient
   source access before any distribution decision. Preserve the recorded
   D-Bus source/generated-version discrepancy, literal Avahi wording and nested
   BLAKE3 residuals. No GPL/LGPL alternative is elected here; no written offer,
   source sufficiency, runtime acceptance or publication clearance is invented.
