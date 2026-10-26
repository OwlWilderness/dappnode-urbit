# Run one ship with UVM

This guide covers the **private custom/dev package and an existing, stopped pier**.
It is not a Dappstore release announcement or a new-identity boot guide. No SSH,
appliance shell or browser agent is required for the owner workflow. Initial
custom-package delivery still needs a compatible Dappmanager and an approved
image/descriptor bundle; there is no universal one-click installer in this repo.

## Feature availability

| Capability | Availability | Limits |
| --- | --- | --- |
| Owner-CA HTTPS and one-time owner enrollment | Available | Requires private DNS, public certificate exchange and browser trust |
| Browser ZIP import of one stopped existing pier | Available | Imports into managed empty storage; does not start the ship |
| Explicit Start / Stop | Available | RUNNING is process state, not proof of healthy boot or network reachability |
| Ship web login with an owner-held Urbit access code | Available once the ship serves its login page | Separate from UVM login |
| **Reveal access code** in UVM | Installed and owner-confirmed in the qualified private 0.1.4 thin derivative | Not in historical 0.1.3; private manager reauthentication required |
| Fresh planet/identity provisioning or boot-key upload | Not supported | No first-boot key form; obtain a stopped existing pier through a separately supported owner workflow |
| Automatic start after import, package restart or update | Not supported | Explicit Start is required; uncertain prior runtime state can require recovery |
| Public ship HTTPS / relying-app EAuth | Owner-confirmed on the reference installation with private 0.1.5 derivative and separate 0.1.0 connector | Optional ship-only ingress; never expose UVM administration; other targets need their own acceptance |
| Signed public package / Dappstore distribution | Not delivered by this guide | Separate licensing, namespace, signing and publication gates |

A version string alone does not identify which source changes are in an image.
Use the accepted artifact's feature record before relying on a new button.
Canonical source descriptors remain **0.1.3**; the installed private derivatives
are separately qualified artifacts, not a binary/Dappstore release of this tree.

## 1. Check prerequisites

- A Dappnode matching the package's `linux/amd64` architecture, with sufficient
  available memory, disk space and inodes for the ship, archive and extraction.
  Current importer defaults cap uploads at **8 GiB**, expansion at **64 GiB**,
  and reserve **1 GiB** of free space. These are limits, not sizing guarantees.
- Authenticated access to Dappmanager over your established private route, and
  private DNS resolution for both package aliases below. Remain connected to that
  private network/VPN while using UVM and the private ship page.
- An approved custom/dev image plus matching package descriptors, supplied through
  the supported installer path for your Dappmanager version. Confirm package,
  service, architecture and actual persistent-volume mapping before installation.
- A local owner CA with a known public-certificate fingerprint and a local signing
  workflow. UVM does **not** create an owner CA or provide a CA-signing UI. If you
  already established this trust, reuse it; do not create another root. A new
  owner must arrange local signing and browser trust before enrollment.
- One verified stopped-state backup of the intended existing pier, under owner
  control. Reuse an already verified backup when still appropriate; do not repeat
  backup preparation just to repeat setup. Recheck that every other instance is
  stopped immediately before import and Start.
- An owner-held Urbit access code or a qualified installed Reveal build for web
  login. Historical 0.1.3 can run the ship but cannot reveal the code in UVM; see
  [login](#6-open-the-ship-and-sign-in).

**One identity, one running instance.** A local runtime lock cannot prevent a
second copy on another machine from running. Keep the original host stopped,
including any automatic restart mechanism, after migration.

## 2. Install privately and set the wizard values

Private package installation, public ship web access, and package publication
are three different operations. **No domain or ENS purchase is needed for this
private custom/dev installation.** The package name `uvm.public.dappnode.eth`
does not itself publish a release or create public DNS for the ship.

Use your compatible Dappmanager's supported custom/dev installation path with
the approved bundle. The underlying installer accepts a local Docker image
archive and matching manifest/Compose/wizard descriptors without IPFS; the
archive must carry the exact service/package/version tag. For the baseline that
is `ship.uvm.public.dappnode.eth:0.1.3`. Do not substitute a source checkout,
historical `releases.json`, an arbitrary local image tag, or a public-store search.

The reviewed Dappmanager UI shows an installed dev package under **My custom
packages**; that tab appears only when a dev package exists. It is not an upload
wizard. If your installation method is not already available, obtain compatible
bundle-delivery instructions from the maintainer before proceeding—do not upload
the image or pier through the general File Manager or disable release checks.

Prepare enrollment using the repository's self-contained offline
[`bootstrap-authority.html`](../src/manager/bootstrap-authority.html)
on your own computer. Keep the generated authority in your password manager;
provide **only its digest** to the wizard. Configure these exact fields (or their
corresponding package configuration values in the approved custom install):

| Wizard field | What to supply |
| --- | --- |
| Importer enrollment authority digest | Offline page's 64-character lowercase SHA-256 digest, not the authority/password/key |
| Owner CA public certificate fingerprint | Independently obtained SHA-256 of the root certificate's DER bytes, lowercase without colons; not a fingerprint supplied by an untrusted server |
| Private importer HTTPS origin | `https://uvm.public.dappnode.private:8443` |
| Private ship HTTPS origin | `https://ship.uvm.public.dappnode.private:8443` |

The two hostnames must differ. Origins have no trailing slash, path, query or
fragment, and the package listener uses port 8443. Do not invent alternative
names without first arranging matching private DNS and certificates.

Installation starts the **package**, not the ship. Fresh storage creates the
managed `pier`, `uploads` and `control` directories in `ship_data:/urbit`.
A new package namespace does not adopt an older package's volume. Unknown,
partial or symlinked layouts are refused; do not force-bind or rename them.
See [migration boundaries](migration.md).

## 3. Establish private HTTPS using public files only

Until certificates are accepted, `AWAITING_CERTIFICATE` means no HTTPS listener
and no ship has started. Use the **already trusted Dappmanager File Manager**,
selecting `uvm.public.dappnode.eth`, service **ship**, for these small public files:

| File Manager action | Exact container filename |
| --- | --- |
| Download the public CSR | `/urbit/control/owner-tls-public/request.pem` |
| Upload the public owner root certificate | `/urbit/control/owner-tls-public/root-ca.pem` |
| Upload the signed public server certificate | `/urbit/control/owner-tls-public/server.pem` |

Enter the complete filename, not a directory. Do not use prefilled download
links, download `/urbit/control`, or transfer private TLS keys or auth records.

1. Download only `request.pem` through that authenticated management channel.
2. On your own computer, verify the CSR and sign it with your existing owner CA
   using your established signing tool. Keep the CA private key local. The leaf
   must match the CSR's public key, be directly signed by that root, be valid for
   server authentication (`serverAuth`, `CA:FALSE`), and have exactly these DNS SANs:
   `uvm.public.dappnode.private` and `ship.uvm.public.dappnode.private`.
3. Upload the root and leaf to their exact filenames. Each file contains exactly
   one public PEM certificate, not a key or multi-certificate bundle. The root
   must match the independently configured fingerprint.
4. Let the package validate them; it polls while waiting. A valid first activation
   normally needs no manual package restart. On refusal, correct the public-file
   delivery with the maintainer rather than changing private state or permissions.
5. Trust the independently verified owner root in your browser/OS as appropriate
   to your existing setup. Open the manager origin and require warning-free HTTPS
   with the correct hostname. **Never bypass a certificate warning to enroll.**

The stopped ship may not yet serve an application; its absence is not a reason
to reset TLS. Certificate renewal/replacement is not an automatic file-overwrite
workflow: the package retains a validated identity. Arrange a qualified renewal
procedure before expiry; do not delete its private TLS directories.

## 4. Enroll and sign in to UVM

At the verified manager origin, **Enroll importer access** asks for **One-time
owner authority** and **New importer password**. Use the offline authority, not
its digest; choose a distinct manager password of at least 12 characters. Select
**Enroll access**. Enrollment consumes that authority and causes a service
replacement; after it returns, sign in as `owner` using the new **Importer
password**. Verify that the normal login works. Enrollment never starts a ship.

| Item | Purpose / handling |
| --- | --- |
| Dappmanager login | Appliance administration; does not authenticate you to UVM |
| Bootstrap enrollment authority | One-time permission to create the UVM owner login; only its digest belongs in configuration |
| UVM manager / importer password | Repeated UVM sign-in and reauthentication for Reveal in qualified builds; not an Urbit password |
| Urbit access code | Login to the ship's web interface; not a wallet key or UVM enrollment authority |
| Ship boot/network keys and wallet secrets | Identity/provisioning authority; never enter them in UVM's wizard or importer |
| Owner CA private key | Local certificate signing only; never upload to the package |

Keep all secrets out of chat, tickets, screenshots and source control. Do not
send a pier archive to an agent. UVM has its own session; Dappmanager cookies do
not replace it. Lost manager access is not repaired by reinstalling or deleting
`control`; request a preservation-first recovery plan.

## 5. Import the stopped pier, then explicitly Start

If an import is already committed, skip upload and inspect its state. Otherwise:

1. Stop the source ship cleanly and preserve its original storage. Archive the
   stopped pier locally, including hidden `.urb` data, as **one top-level pier
   directory**. This is a private backup, not a source artifact. Do not archive a
   running database or include unrelated directories or loose boot-key files.
2. Use a single-volume, unencrypted ZIP with stored/deflated entries; ordinary
   ZIP64 is supported. The importer rejects symlinks, special files, unsafe paths,
   ambiguous trees and unsupported ZIP metadata. On macOS, inline `._*` metadata
   is rejected; use an archive layout matching the
   [extractor's documented macOS policy](../src/manager/archive.py).
   Archive validation is not proof of identity, database health or bootability.
3. In UVM's **Local ZIP transfer**, select **Pier ZIP**. Set **Maximum expanded
   size (GiB)** high enough for the complete expanded pier but within the 64 GiB
   ceiling. Review displayed capacity; archive and extracted data need space
   together. A retained upload keeps its original budget.
4. Confirm the source is stopped and no other instance is running. Select
   **Upload / resume**. Wait through upload, validation and commit. UVM uses bounded
   chunks; do not use Dappmanager's File Manager for the pier.
5. **READY_LOCKED means the import is committed, not that the ship is running.**
   For the managed package, wait for runtime **STOPPED** and Start availability.
   Reconfirm every other instance is stopped, tick the Start confirmation, and
   select **Start ship explicitly** once. Refresh status before any retry.
6. Runtime **RUNNING** confirms an owned process, not a healthy boot. Verify that
   the private ship origin reaches its login page, and that owner login works.
   Do not treat a redirect, running container badge or process status as sufficient.

**Pause** retains the upload. After reload, interruption or session expiry, sign
in again, reselect the exact original ZIP, reconfirm stopped state and select
**Upload / resume**. Retained bytes are verified before continuation; do not edit
or recreate the ZIP mid-upload. **Cancel incomplete import** applies only to an
uploading/failed job, not a committed pier or a recovery state.

## 6. Open the ship and sign in

Open `https://ship.uvm.public.dappnode.private:8443` over the private connection.
Use your **Urbit access code**, not the manager password. Keep the code in your
own password manager and enter it only at the intended ship origin.

**Historical baseline 0.1.3 has no Reveal button.** If that is your installed
artifact and you lack the code, obtain an owner-supported recovery path or a
separately qualified manager update.
Do not reset the identity, import a key, inspect private logs or run a second copy
of the pier to retrieve it.

The qualified private 0.1.4 owner-code derivative has been installed, and the
owner confirmed Reveal and private ship login on the reference installation.
On a qualified Reveal build, while RUNNING, re-enter the manager password and
select **Reveal access code**; manually use the displayed value, then **Hide**.
Display automatically clears after 30 seconds. Keep this operation on the
private manager; do not share the displayed code or capture it in diagnostics.

Private access alone does not configure public access. The reference installation
now has separately qualified **ship-only** public HTTPS: private 0.1.5 adds the
public backend, and a separate 0.1.0 named cloudflared connector supplies ingress.
Public HTTP 200 with strict TLS and persisted private-CA/SNI/exactHost route
settings were verified. The owner confirmed public ship login and relying-app
EAuth, for example from `https://app.example.com` to `https://ship.example.com`.
These example names do not identify the private installation.

`URBIT_PUBLIC_SHIP_ORIGIN` is optional and empty by default. When explicitly
configured, the dedicated 9444 HTTPS backend forwards only to Eyre at
`127.0.0.1:8081`; private 8443 remains unchanged. The connector uses only the
public CA certificate for backend trust, no pier mounts and no host ports; its
owner-managed token stays private. Do not publish the manager origin, its
`/api/*` routes or the entire 8443 frontend. See [public access](public-access.md)
for the separate configuration and acceptance boundary. Reference-installation
success does not prove other DNS/router setups or Ames reachability.

## 7. Stop, update and resume without a second instance

1. Select **Stop managed ship** and refresh until runtime reports **STOPPED**.
   If shutdown is uncertain, stop here; do not copy, replace or restart state on
   the assumption that clicking Stop succeeded.
2. Before a package update, preserve the existing verified stopped-state backup
   and confirm whether it is current enough for recovery. Do not take a new
   backup merely because this guide repeats the prerequisite; changed state may
   require refreshing it. Keep the old accepted artifact until the update passes.
3. Use only a separately qualified update with the same intended package/storage
   mapping. Preserve `ship_data`, enrollment and HTTPS identity. Do not reset,
   remove volumes, force-adopt legacy storage or reinstall to add a source-only
   feature. A container image rollback does not reverse changes to pier state.
4. After replacement, verify warning-free private HTTPS, UVM login, committed
   import status and runtime **STOPPED**. No repeat enrollment, certificate setup
   or import should be necessary for a normal preservation update.
5. Confirm the single-instance rule and explicitly Start, then verify ship login
   again. If runtime reports **RECOVERY_REQUIRED**, do not clear journals or force
   Start. Interrupted/uncertain prior runtime state needs operator recovery.

A package restart is not a ship resume command. The Compose restart policy can
restart the supervisor, but does not authorize automatic Vere start.

## Troubleshooting

| Symptom | Safe next action |
| --- | --- |
| No My custom packages tab | It appears only after a dev install. Confirm compatible installation/delivery with the maintainer; this is not evidence of a public release. |
| Manager unreachable; certificate pending | Check private connection/DNS, exact origin/port, wizard values and public-file exchange. Waiting for certificates intentionally has no listener. |
| Certificate warning or wrong name | Stop before entering secrets. Verify owner root trust, both exact SANs and origin. Never use an exception or public proxy as a workaround. |
| `VOLUME_LAYOUT_REFUSED` / exit 78 | Preserve storage. Unknown/partial layouts are refused; use the migration plan, not directory renaming or reset. Exit 78 can also represent other startup refusals. |
| Enrollment refused / already consumed | Use normal owner login if enrolled. Refresh after replacement. Do not regenerate authority or delete auth/TLS records to bypass refusal. |
| Upload fails or exceeds capacity | Refresh status; check upload/expanded limits and free space/inodes. Preserve the backup. Cancel only an eligible incomplete job before a corrected attempt. |
| `READY_LOCKED`, no running ship | Expected after import. Check managed runtime STOPPED, Start availability and the explicit stopped-instance confirmation. |
| `BLOCKED_EMBEDDED_OPENSSL` persists after sign-in | A standalone locked importer is not the managed package. Confirm the accepted image/entrypoint; do not bypass the gate. |
| `RUNNING` but ship page unavailable | Process state is not health. Check the exact private ship route and allow boot time; report only nonsecret status. Never start another copy. |
| Missing Reveal button / no access code | Expected on historical 0.1.3; use an owner-held code or obtain a qualified update. Verify the installed artifact rather than assuming current source was deployed. |
| `FAULT` or `RECOVERY_REQUIRED` | Preserve pier/control/upload state and stop routine retries. Request a reviewed recovery procedure; no journal deletion, forced adoption or second instance. |
| External app cannot reach the ship | Verify the optional ship-only public route and EAuth separately using [public access](public-access.md); private HTTPS alone and reference-installation success do not qualify your route or Ames reachability. Never expose UVM admin. |

When asking for help, share package/build identity, sanitized state labels and the
failing step—not private logs, credentials, archive names, pier contents or
personal network details. No generic destructive recovery command is provided.

## Source and risk boundaries

The workflow follows the actual [wizard](../setup-wizard.yaml),
[Compose service](../docker-compose.yml), [volume guard](../build/volume_guard.py),
[HTTPS supervisor](../src/manager/package_service.py),
[owner TLS validator](../src/manager/owner_tls.py),
[importer UI](../src/manager/web/index.html) and
[runtime controller](../src/manager/runtime.py).

Dappmanager UI/installer instructions were checked against official source at
commit `a21bab295d4c68c3b6115498b18a8efaf89d52a0`:
`packages/installer/src/calls/packageInstallDev.ts`,
`packages/admin-ui/src/pages/packages/components/PackagesNavigator.tsx`, and
`packages/admin-ui/src/pages/packages/components/FileManager/{From,To}.tsx`.
That source establishes the supported dev mechanism and public-file controls,
not a universal browser archive-install button or compatibility with every release.

The package pins Vere 4.6; its embedded OpenSSL maintenance risk remains
unresolved. A newer Nginx/Python TLS library does not repair the runtime's embedded
library. Private installation does not remove this risk. Public source publication
is not binary/Dappstore release clearance. Public binary distribution
still needs the maintained [provenance review](distribution-review.md),
[third-party notices](../THIRD_PARTY/README.md), namespace/signature and publication
gates. Historical evidence documents describe their own scopes, not current
operator instructions or permission to update an installed ship.
