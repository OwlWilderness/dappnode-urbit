# UVM — Urbit Vere Manager

**One ship. Private access. Explicit control.**

UVM is a Dappnode package for managing one Urbit ship with the official Vere
runtime. It pairs persistent pier storage with a private management interface,
owner-controlled HTTPS and explicit ship Start/Stop controls.

> **Private custom/dev package, not a signed public/Dappstore release.**
> Start with the [owner operator guide](docs/operator-guide.md) for the existing-pier
> workflow. Initial installation needs a compatible Dappmanager and an approved
> image/descriptor bundle—not merely this checkout. This is not an approved
> in-place upgrade of the historical Urbit package.

Package identity: `uvm.public.dappnode.eth`. UVM means **Urbit Vere Manager**
here; it is not the separate Urbit Virtual Machine blockchain project.

## What UVM manages

One persistent ship, separate private manager/ship HTTPS origins, owner enrollment
and explicit Start/Stop. The image contains pinned Vere, a Python supervisor and
Nginx; ship HTTP remains on loopback inside the container. Starting the package
or importing a pier does not automatically start Vere. UVM does not accept boot
keys, create identities or adopt arbitrary pier directories.

## Private interfaces

| Interface | Configured HTTPS origin | Purpose |
| --- | --- | --- |
| Manager | `https://uvm.public.dappnode.private:8443` | Owner enrollment and ship management |
| Ship | `https://ship.uvm.public.dappnode.private:8443` | The running ship's web interface |

The Compose service is `ship`. Separate hostnames keep management and ship
authentication cookies isolated. These are configured endpoints, not a claim
that target DNS, browser trust or installation has passed acceptance.

## Feature availability

| Feature | Availability |
| --- | --- |
| Private HTTPS, enrollment, browser ZIP import, explicit Start/Stop | Private 0.1.3 baseline; verify configuration on each installation |
| Ship web login | Requires a responsive running ship and the owner's Urbit access code |
| **Reveal access code** in UVM | **SOURCE ONLY. Not in the installed 0.1.3 baseline; validation and controlled update are in progress, not deployment acceptance** |
| Fresh identity / boot-key provisioning | Not implemented; use a stopped existing pier |
| Automatic ship start after import, restart or update | Not supported; Start is separate |
| Public ship web access | Not configured; never expose UVM administration |
| Signed public release / Dappstore listing | Separate release gates; not supplied here |

A version label alone does not identify which source changes are in an image.
Keep the accepted image/export until a replacement is qualified.

## Get a ship running

1. **Check prerequisites:** compatible AMD64 Dappnode, private browser access,
   capacity, an approved custom/dev bundle and a verified stopped existing pier.
2. **Configure owner trust:** prepare enrollment authority locally; supply only
   its digest, the public owner-CA fingerprint and exact origins in configuration.
3. **Provision HTTPS:** download the public CSR through trusted Dappmanager,
   sign locally with the owner CA, upload only public certificates and verify
   warning-free HTTPS. Reuse established CA trust; never bypass a warning.
4. **Enroll and import:** create a distinct UVM password and upload the stopped
   pier through UVM's ZIP transfer, not Dappmanager File Manager.
5. **Start explicitly:** READY_LOCKED means imported, not running. Confirm every
   other instance is stopped and select **Start ship explicitly**. RUNNING is
   process state; verify the ship login page separately.
6. **Log in to the ship:** use its Urbit access code, not the UVM password. If you
   lack the code, baseline 0.1.3 cannot reveal it through UVM yet.

The [operator guide](docs/operator-guide.md) gives exact wizard fields, public
certificate filenames, enrollment, archive requirements, interrupted-upload
recovery, login, stop/update/resume and troubleshooting. No SSH is required for
that owner workflow; custom bundle delivery and owner-local CA signing must be
arranged. Never share keys, codes, passwords or pier contents with an agent.

**No domain or ENS purchase is needed for private custom/dev installation.**
Private installation, public ship web exposure and package publication are
separate operations. The package name does not create public ship reachability.

For an owned domain and multiple hosted projects, see the
[domain and hosting findings](docs/domain-hosting-findings.md). This is research
and pending setup guidance, not a configured public ingress.

## Storage and existing ships

The Compose volume key is `ship_data`, mounted at `/urbit`. The managed layout
contains `pier`, `uploads` and `control` directories. A **pier** is the ship's
persistent state; **ship** names the service and its browser endpoint.

UVM uses a new package namespace. Retaining `ship_data:/urbit` **does not adopt an
old package's volume**. Legacy, partial or unknown layouts are refused rather
than overwritten. Do not rename directories or force-bind an existing volume to
bypass that refusal, and never run two copies of the same ship.

Read [migration and data-preservation boundaries](docs/migration.md) before
using existing storage. The supported owner path is stopped-archive import into
separate managed storage, not automatic legacy-volume adoption.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) and
[local release preparation](docs/release-preparation.md) for contributor and
artifact-preparation workflows. Descriptor preparation is not an image build,
publication, installed-image update or ship start.

## Runtime and release limits

Local image/lifecycle evidence and the private custom/dev baseline do not imply
public distribution clearance or validate unbuilt source changes. Namespace
control, signing, publication and distribution terms remain separate gates.
There is no general automatic recovery, certificate renewal, fresh-key boot or
legacy volume-adoption workflow.

The copied runtime is pinned to Vere 4.6. Its embedded OpenSSL maintenance risk
remains unresolved; the frontend's newer TLS library does not repair it. Private
use does not remove that risk.

Use [release preparation](docs/release-preparation.md) for portable descriptor
and source-check instructions, and the [distribution review](docs/distribution-review.md)
for remaining public-release questions. This source tree does not include
host-specific operational receipts or establish a clean image build, private
candidate deployment, or target acceptance. Canonical descriptors remain at
0.1.3; private 0.1.4 candidate work is not a release of this source tree.
Installation, enrollment, import, Start and browser login are distinct checks.
No automatic publication workflow is installed.

## Attribution and licensing

This fork modernizes androolloyd's original Urbit Dappnode package. It preserves
upstream history and original author attribution; the repository
name is unchanged. Historical quick-start commands and `releases.json` describe
the upstream package, not a release or installation procedure for UVM.

The inherited manifest's `GPL v3` declaration is preserved. Owner-controlled new
UVM contributions are now declared **GPL-3.0-only** in [LICENSE.md](LICENSE.md),
without overriding inherited or third-party terms. The selected avatar is
[original UVM artwork](docs/artwork.md), replacing the inherited image whose
provenance remains unresolved in Git history. This is not complete binary
distribution clearance.

[Third-party licenses and notices](THIRD_PARTY/README.md) collects component
license texts, pinned-source evidence and explicit coverage gaps. Consult the
[notice-packaging record](docs/notice-packaging.md) for artifact scope; notice
inclusion alone is not complete binary distribution clearance.

The [distribution provenance review](docs/distribution-review.md) records the
inherited declaration and a separate unresolved license-mixing question in the
pinned Vere dependencies. A new UVM license alone would not resolve that question.
