# Retained baseline — BUILD / RELINK

This companion selects the original maintained baseline, **not b04**. The static
ELF is `58d07af97926e04bc17184bc18f53e5fb11d84fed63bd9daf2fe4ceb04c86698`
(42,399,776 bytes); saved image identity is
`sha256:333864be7b25a51c4daf25156ced45424c1dfbfd27273e1aa2b320d95a356f8b`.
These are historical bindings, not observations of an available engine/image.

## Obtain and check the material

The sealed manifest is `build/baseline-release-notices.json` in the supplying
checkout. It maps every recipient file to exact public retained bytes. Run:

```sh
python3 docs/license-preparation/baseline-recipient/assemble.py \
  --repo-root . --manifest build/baseline-release-notices.json --verify-only
```

There is no implicit download. If separately authorized to make a recipient copy,
use `--output NEW_DIRECTORY` instead of `--verify-only`. The directory must not
exist. This copies the unchanged 220,821,885-byte archive once to
`sources/source-materials.tar.gz`; no archive is duplicated in this repository.
The assembler copies only manifest entries and never executes a build or extracts
an archive tree. It also writes the seal as `companion-manifest.json`. From the
recipient directory, verify independently of the supplying checkout:

```sh
python3 assemble.py --recipient-root . --manifest companion-manifest.json --verify-only
```

Recipient file paths
are relative to the new directory, not paths on the original developer's host.
`SOURCE-LOCATIONS.md`, `archive-inventory.json`, `image-source-requirements.json`,
and `MISSING-INPUTS.md` identify retained sources and remaining inputs.

## Authoritative recipe and host prerequisites

Use **recipe/candidate.py**, **recipe/inputs.json**, **recipe/Dockerfile**,
**recipe/builder-apks.json**, the two **recipe/curl-build.zig*** overlays, and
**recipe/candidate.json** delivered here, not today's repository candidate.py.
The recipe's exact successful build used Linux AMD64, Zig 0.15.2, target
`x86_64-linux-musl`, ReleaseFast (`-Drelease=true`), pace once, `-j2` and
`--verbose-link`. `builder-apk-db.txt` records the build environment. The Dockerfile
pins its Alpine base by digest and build tools by exact versions, but invokes
networked APK installation and source acquisition: it is **not** an already
qualified offline image recipe. Availability of those exact APKs/base is not
promised. No build, compiler or tool installation was run for this assembly.

The archive contains the original pinned Vere/OpenSSL/Zig archives under
`materials/`, the patched Vere tree, generated OpenSSL source/configuration and
headers, and 24 Zig package-source trees under `p/`. Inspect inventory before
unpacking into an isolated build directory. The archive includes source symlinks;
use a vetted extraction policy in an empty isolated workspace, not extraction over
an existing source tree or privileged filesystem. The assembler intentionally
keeps the original archive opaque rather than claiming safe tree extraction.

## Reconstruct the build without changing the historical recipe

1. In a separately admitted Linux AMD64 build workspace, safely unpack the source
   archive to `retained/`. Safely unpack `retained/materials/zig-x86_64-linux-0.15.2.tar.xz`
   to obtain the compiler. Verify each original input against recipe/inputs.json;
   archive-inventory.json also binds each member. Install/provide the exact tools
   from builder-apks.json using an independently supplied exact tool/base source.
2. Set a fresh **nonexistent** absolute output path (`OUT`) whose parent exists,
   choose an actual fresh build attempt label, and set `INPUTS` to the unpacked
   `retained/materials` and `CACHE` to unpacked `retained/p`. There must be no old
   attempt/cache mixed into OUT. The recipe refuses reused output directories.
3. The following is the ordered invocation expressed through the frozen recipe's
   real API. Run only under a separately authorized bounded build supervisor.
   A network-denied sandbox must enforce offline operation; this snippet does not
   install a network sandbox. Missing cached packages must fail, not be fetched.

```python
# Run with Python in recipient root; OUT/INPUTS/CACHE are public build paths.
import importlib.util, json, os, shutil
from pathlib import Path
spec = importlib.util.spec_from_file_location('baseline_recipe', 'recipe/candidate.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
lock = json.loads(Path('recipe/inputs.json').read_text())
a = r.Attempt(Path(os.environ['OUT']))
trees = r.prepare(a, lock, Path(os.environ['INPUTS']))
# prepare() validates original archives, applies curl overlays and all original
# baseline patches. Do NOT apply these patches again to the already-patched tree.
shutil.copytree(Path(os.environ['CACHE']), a.output / 'zig-cache' / 'p')
r.compile_candidate(a, lock, trees)
```

The original CLI alternative is `python3 recipe/candidate.py --build --output OUT
--input-dir INPUTS`; it does not offer a pre-compile package-cache seeding flag.
Do not describe that CLI alone as an offline build. The API sequence above seeds
the retained source cache before compilation and does not import a prior compiled
OpenSSL cache. Regenerating OpenSSL avoids depending on absent retained `.a/.o`.

OpenSSL is configured by the recipe as `linux-x86_64 no-shared no-module no-tests
no-apps no-docs --prefix=/opt/uvm-openssl3 --openssldir=/opt/uvm-openssl3/ssl
--libdir=lib -fPIC`, then `make -j2 build_libs`. CC is Zig cc targeting musl with
`-mcpu=baseline`; AR/RANLIB are Zig tools. The recipe supplies LC_ALL=C, TZ=UTC,
SOURCE_DATE_EPOCH=1782999240, per-attempt TMPDIR/local/global Zig caches. It extracts
actual generated OpenSSL object members and regenerates ext/openssl/build.zig
before the Vere build. Do not attempt to use the archived generated object adapter
without regenerating those objects: `.o/.a` are deliberately absent from source.

## Relink with a modified LGPL library

Use the same complete application sources and build utilities, not an object-only
route. Copy the relevant `p/<package-hash>` source tree to a new writable local
source directory, modify it, and change the corresponding dependency in the
prepared Vere tree's `ext/avahi/build.zig.zon` (or other affected manifest) from
its URL/hash dependency to Zig's local `.path` dependency. Keep the dependency
name and required build adapter interface. Do not overwrite original hash-addressed
cache contents and then claim their old identity. For Avahi the retained tree is
`p/N-V-__8AAOLVeQDfYsiL0A86OXqDtfyLSrZXiEu8RSplOJJ5`; D-Bus and Expat are separate
entries in the same adapter manifest. `source-cache-inventory.json` maps every
retained dependency declaration. Then run the frozen compile_candidate against
the prepared `trees` after making the dependency edit, with a fresh admitted build
workspace. This is a modified build: record new source/ELF hashes, preserve library
notices and permit debugging/reverse engineering of covered modifications.

This is a concrete source-route procedure, **not a successful recipient rebuild or
modified-library relink result**. Required focused exercise remains open. No
application object files are asserted necessary or available; an object-only
fallback would need its own concrete missing-material assessment.

## Package / install boundary

`package-context/` contains the exact historical normal entrypoint, manager/UI,
fixed matching runtime adapter, package Dockerfile and source licence. It does
not contain the executable; a separately authorized package operation must place
the exact baseline ELF at `package-context/candidate/urbit` and bind the final
context/notices/base/image. `bindings/` contains the historical context binding
and saved selected-image inventory/database. Historical notice indexes can refer
to old upstream versions; the selected notices in this companion are separate.

A newly composed manager/private-delivery package is a successor to this historical
context and needs its own public source snapshot. No package/version/CID is
assigned here. Installing a modified package, platform signature/trust policy and
any applicable installation information remain explicit release inputs; do not
request or distribute owner wallet, CA, auth or ship secrets.
