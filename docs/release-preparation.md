# Local release descriptor preparation

This is portable source guidance, not an operational acceptance receipt.
Canonical package descriptors remain at **0.1.3**, with image tag
`ship.uvm.public.dappnode.eth:0.1.3`. Separately qualified private thin derivatives
**0.1.4** (owner-code UI) and **0.1.5** (public backend), plus a separate **0.1.0**
named cloudflared connector, have been installed on the reference installation.
The owner confirmed private Reveal/login, public ship login and relying-app
EAuth. Public HTTP 200 with strict TLS and the persisted route's private CA,
SNI and exactHost settings were verified. These scoped results do not qualify a
clean build of this checkout, another target or a binary/Dappstore release.
Source tests and descriptor preparation do not establish a clean image build,
image binding, signature, publication or Dappnode acceptance. Retain existing
accepted images, exports and receipts separately; these instructions do not
authorize rebuilding, runtime attempts, target changes or publication.

## Public-access artifact boundary

Public source publication is separate from binary publication or a Dappstore
release. Do not bump canonical descriptors to match private derivatives or
retag the accepted baseline merely because their features are now in source.
The descriptor preparer below still describes canonical **0.1.3**, not an
export of the installed 0.1.4/0.1.5 derivatives or the separate connector.

The optional `URBIT_PUBLIC_SHIP_ORIGIN` defaults to empty. The reference design
uses an explicit origin such as `https://ship.example.com`, a dedicated 9444
HTTPS backend forwarding to Eyre at `127.0.0.1:8081`, and unchanged private
8443 administration. The named connector uses only the public CA certificate
for backend trust, no pier mounts and no host ports; its owner-managed token is
private. See [public access](public-access.md) for ship-only routing and EAuth
acceptance. Do not include personal domains, target details, tokens, pier state
or operational receipts in public artifacts.

## Prerequisites

Use Node >=20, Python 3 and the locked Dappnode SDK **0.3.55**. Set
`DAPPNODE_SDK_ROOT` to an existing installation's `@dappnode/dappnodesdk`
directory; the loader checks its version. No dependency installation is part
of the commands below. A fresh checkout without the SDK cannot run the Node
suite or descriptor preparer until dependencies are separately provisioned.
The synthetic owner-TLS tests also require OpenSSL 3.

Set `IMPORTER_TEST_SCRATCH` to an existing, private, explicitly approved scratch
directory outside the checkout. Set `RELEASE_TEST_SCRATCH`, `ARCHIVE_TEST_SCRATCH`
and `TMPDIR` to that same directory and `PYTHONDONTWRITEBYTECODE=1`. Keep secret-bearing environment
variables out of the test process, including `SSLKEYLOGFILE`. Fixtures use
synthetic inputs, not an owner's credentials or pier. Descriptor fixtures are
retained, and the command prints their paths.

## Source-only checks

From the checkout root, with the prerequisites above configured:

```sh
npm test
python3 -B -m unittest discover -s tests -p 'test_*.py'
python3 -B -m unittest discover -s tests/manager -p 'test_*.py'
python3 -B scripts/verify-notice-packaging.py
python3 -B THIRD_PARTY/vere/followup/verify.py
python3 -B scripts/render-avatar.py --check
```

These are source/fixture checks, not Docker, real-ship or target acceptance.
The public tree omits host-specific local-export/boot/native-browser controllers
and their paired tests; those gates are not represented by these suite results.
Do not use `npm run validate` for a no-Docker check: that separate command invokes
Docker Compose configuration validation through the SDK. File-only preparer
validation does not require Docker.

## Run locally

Set `RELEASE_OUTPUT` to an absolute, **not-yet-existing** directory outside the
source checkout. Its parent must already exist. Use canonical paths without
symlink ancestors and keep source and output directories quiescent.

```sh
npm run prepare:release -- --output "$RELEASE_OUTPUT"
```

This command reads only four selected public source inputs, uses the pinned SDK
parsers and file-only validation rules, and writes:

```text
<output>/
  inventory.json
  assets/
    dappnode_package.json
    docker-compose.yml
    setup-wizard.json
    avatar.png
```

The inventory stays outside `assets`. It records source/output SHA-256 values,
package/version, SDK version, expected image tag, architecture and archive
filename. Its status is `DESCRIPTORS_ONLY_IMAGE_UNBOUND` and `image_binding` is
`null`. No image digest, CID, signature or installability is invented.

Manifest, Compose and wizard use deterministic JSON serialization. JSON is also
valid YAML syntax, so release Compose remains `docker-compose.yml`. The parsed
source wizard becomes JSON under the SDK release name `setup-wizard.json`;
the SDK's YAML-only **source** reader must not reload that release filename.
The selected raster is copied under the SDK's `avatar.png` release name. See
[artwork provenance and checks](artwork.md); verify each prepared asset against
its own inventory rather than relying on a host-specific historical receipt.

Build instructions are removed from exported Compose only. Source files are
not edited. Existing output, symlink inputs/ancestors, source-descendant outputs
(including case aliases), and wrong package/service/version/architecture/tag
are refused. A write failure retains partial output; it never deletes or reuses
that directory. Hostile concurrent path replacement is not qualified.

Descriptor tests cover fixed-input reads, no preparation subprocess, schema and
identity mismatch refusal, path/overwrite boundaries, partial-write preservation,
CLI behavior, output-only build removal, SDK release names, semantic round-trip,
input/output hashing and byte determinism. The preparer does not invoke Docker,
SDK build/upload tasks, signing or network publication.

## Notice materials and release boundaries

[Notice packaging](notice-packaging.md) documents image COPY wiring and the exact
public-file hash allowlist. Preserve both public source archives listed there:
the pinned Vere source and the historical UVM wrapper snapshot. They are notice
and provenance inputs, not private pier backups. The wrapper snapshot is not a
current source freeze; source-delivery metadata explicitly requires refresh
before final release binding. Do not remove either archive merely because it is
compressed, or rewrite historical provenance as current acceptance.

See [distribution review](distribution-review.md) and
[source-delivery scope](../THIRD_PARTY/SOURCE_DELIVERY.md) for unresolved runtime
licensing and source-delivery questions. Contribution terms and original artwork
do not settle the selected runtime's distribution basis. Namespace control,
signing/trust policy, explicit publication approval and exact artifact/target
qualification remain separate gates. Installation, TLS trust, owner enrollment,
import, explicit Start and browser login must be checked separately.

The pinned Vere runtime's embedded OpenSSL maintenance risk remains unresolved;
newer frontend TLS libraries and successful public HTTPS do not repair it.
Installed private derivatives and owner-confirmed EAuth do not clear this risk
or the licensing/source-delivery gates for public binary distribution.

The expected archive filename is
`uvm.public.dappnode.eth_0.1.3_linux-amd64.txz`; a filename is not proof that an
archive exists or is accepted. Do not upload a descriptor-only directory as a
release. Neither passing source tests nor an old accepted image proves that a
clean build of this source tree is reproducible or deployable.
