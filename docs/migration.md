# Existing installations and data preservation

This is **not an approved in-place upgrade** of the original package.
Keeping a volume key does not establish appliance upgrade compatibility.
For private custom/dev onboarding, follow the [operator guide](operator-guide.md):
import an owner-verified stopped archive into separately provisioned managed
storage. This does not qualify automatic legacy-volume adoption.

## What stays and what changes

- The package identity is now `uvm.public.dappnode.eth`, not
  `urbit.public.dappnode.eth`. This is an independent package, not an automatic
  update of the old identity. Preserve the old package's storage untouched.
- The Compose volume key remains `ship_data`, mounted at `/urbit`, but the
  platform's package/project namespace changes the actual named volume. Do not
  assume it reuses an existing volume or force-bind the old volume to bypass
  migration. Confirm actual named mounts through target metadata before install.
- The Compose service is `ship`; the original upstream service was
  `urbit.public.dappnode.eth`. Check the selected custom package's actual mount
  mapping; service-name similarity is not migration.
- The administration/ship certificate names are now `uvm.public.dappnode.private`
  and `ship.uvm.public.dappnode.private`. An old leaf certificate is not valid
  for the new names. Keep the existing owner root; issue the new package's leaf
  from its own authenticated CSR only after target provisioning is authorized.
  Do not edit persisted TLS settings or reuse old private TLS state.
- The new managed layout has `pier`, `uploads` and `control` directories.
- An empty volume gets those three private directories before enrollment can
  begin, so a pending-enrollment restart has the complete layout.
  An empty volume or exactly those three real directories can reach the
  supervisor. Unknown entries, partial layouts, symlinks and inaccessible
  roots cause exit 78 before the supervisor runs.
- The guard reads directory metadata only. It never reads keys or pier payloads,
  chooses the first directory, moves data, changes ownership or starts a ship.
- This guard is an accidental-layout protection, not proof of pier health or
  a complete migration mechanism. The importer/runtime retain their own checks.

## Safe import and update boundary

1. Do not install UVM over the original package or force it onto that volume.
2. Stop the original writer and preserve a verified owner-operated stopped-state
   backup outside the repository. Reuse an established backup when appropriate;
   refresh it if later state must be protected. Keep the original volume intact.
3. Import the stopped ZIP through the private UVM manager into separately
   provisioned managed empty storage. Do not manually rename directories, erase
   the original volume, or use the general File Manager to transfer the pier.
4. READY_LOCKED is a committed import, not a running ship. Installation, private
   HTTPS, enrollment, import, explicit Start and successful ship login are distinct
   checks. Never run two copies of the same ship.
5. For later updates within UVM, stop the managed ship and verify STOPPED first.
   Preserve the volume, enrollment and HTTPS identity; use only a qualified
   replacement artifact. Resume explicitly and verify login. An image rollback
   does not roll back pier changes. RECOVERY_REQUIRED needs operator recovery,
   not deletion of journals or another import.

The old manifest's generic `/urbit` backup entry is intentionally not carried
forward: it did not establish a stopped, consistent LMDB backup. A backup
workflow must preserve the actual writer-stop and restore guarantees.

## Separate release boundary

Private custom/dev installation is not signed public distribution. Each new
installation still needs compatible artifact delivery, checked storage mapping,
private DNS/HTTPS and owner verification. Before public distribution, resolve
licensing/attribution, package namespace control, publication and accepted
release-signature trust. Fork ownership is not package-registry ownership or
release-signature acceptance. Source-only features are not installed updates;
see the [feature availability table](operator-guide.md#feature-availability).
