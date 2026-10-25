# Public ship HTTPS and EAuth

## Status and boundaries

A reference private/dev installation has completed public ship login and an
external application's EAuth round trip, both confirmed by the owner. Independent
checks verified the public login page, valid TLS and persisted strict origin
settings. This is not a signed public package or acceptance for every ship/app.
Personal hostnames, credentials, certificates and operational receipts are not
part of this public guide. Names below are examples only.

Canonical UVM source descriptors still say **0.1.3**. The reference installation
used qualified private thin derivatives: **0.1.4** for owner access-code reveal,
then **0.1.5** for the optional public backend and manager branding. The separate
connector was **0.1.0**. Do not equate source version labels, tested image contents
and installed artifacts. A source checkout is not an installable bundle.

The connector is a separate Dappnode package, `uvm-tunnel.public.dappnode.eth`,
maintained in [dappnode-urbit-ship-tunnel](https://github.com/OwlWilderness/dappnode-urbit-ship-tunnel).
Keep connector credentials and installation-specific build inputs out of either
repository. Source availability is not a published binary or Dappstore release.

## Topology

```text
Browser → HTTPS ship.example.com:443 → Cloudflare named Tunnel
        → separate cloudflared connector on Dappnode
        → verified HTTPS ship.uvm.public.dappnode.private:9444
        → Eyre HTTP 127.0.0.1:8081

Private UVM manager and ship access: unchanged on 8443
Existing Dappnode HTTPS/PWA services: unchanged
New inbound host-port publications: none
```

The ship stays on Dappnode. Registrar, DNS provider and application host are
separate roles. The reference setup retained its registrar and moved authoritative
DNS to Cloudflare after preserving existing records. The tunnel avoids waiting
for inbound router forwarding; it does not remove dependence on the home Internet
connection. Other project subdomains need their own deliberately scoped routes.

The dedicated backend has only a fixed ship upstream, not a manager fallback.
Never route public traffic to the shared private 8443 listener. Keep UVM enrollment,
access-code retrieval, lifecycle controls and Dappnode administration private.

## Prepare and activate

1. Reuse accepted backup, identity, enrollment and owner-CA preparation. Preserve
   the named volume and both private origins. Qualify a matching image/descriptor
   bundle before installing; do not rebuild consumed artifacts merely for evidence.
2. Configure `URBIT_PUBLIC_SHIP_ORIGIN=https://ship.example.com` in the approved
   UVM deployment descriptor. It defaults to empty/disabled; CLI equivalent is
   `--public-ship-origin`. Use a canonical HTTPS origin with no path, query or
   fragment. Omit the default `:443`; explicit `:9443` is supported for a separately
   qualified direct-edge topology, not required by the named tunnel.
   Current source rejects explicit `:443` before filesystem/TLS work to avoid
   browser Host/Origin serialization mismatches. This validation hardening was
   added after the tested private 0.1.5 image; the accepted installation already
   uses the canonical no-port origin and was not rebuilt or redeployed for it.
3. Obtain approval for the controlled update and have the owner Stop the ship.
   Preserve `ship_data:/urbit`, existing enrollment and TLS identity; read back
   package/version and actual named-volume metadata. Package startup does not
   start Vere. The owner explicitly Starts and verifies the ship afterward.
4. Qualify the separate connector with the pinned official cloudflared image and
   **only the existing public CA certificate** at `/etc/cloudflared/origin-ca.pem`.
   Never copy its private signing key, pier or manager state. The connector has
   no host ports, pier mounts, Docker socket or administration UI.
5. Create a named tunnel and let the owner supply `TUNNEL_TOKEN` privately in
   Dappnode configuration. A blank token prevents connection and the configured
   restart policy can produce a restart loop. Never put the token into source,
   chat, screenshots, issue comments or agent-visible commands. Environment-based
   provisioning is administrator-readable, not a secret vault.
6. Verify a healthy connected replica and the dedicated backend's strict TLS and
   responsive ship login page. A healthy tunnel alone does not prove origin DNS,
   network reachability, certificate validation or application authentication.
7. Add exactly one Published application route with the settings below. Read back
   the saved settings; a populated form is not proof they were persisted.

| Setting | Example value |
| --- | --- |
| Public hostname | `ship.example.com` |
| Path | Empty |
| Service URL | `https://ship.uvm.public.dappnode.private:9444` |
| HTTP Host Header | `ship.example.com` |
| Origin Server Name | `ship.uvm.public.dappnode.private` |
| CA Pool | `/etc/cloudflared/origin-ca.pem` |
| Disable TLS certificate verification | Off |
| Match SNI to host | Off |

Do not add a wildcard hostname, plaintext fallback, wildcard CORS or a public
manager route. The backend enforces exact SNI/Host/Origin and replaces forwarding
headers with its configured public HTTPS authority. Only GET/HEAD may omit Origin;
other methods require the exact configured public Origin. Non-browser API clients
and arbitrary apps require their own compatibility qualification.

## Acceptance and troubleshooting

Keep these checks separate:

- **Installed:** expected package versions/image tags and original named volume.
- **Connected:** tunnel has a healthy replica; no credentials inspected.
- **Transport:** public `/~/login` returns 200 with valid TLS and the saved backend
  configuration still verifies the private CA and hostname.
- **Isolation:** public manager-path probes must not return UVM management data.
  In the reference installation these paths redirected as unauthenticated ship
  requests; they were not manager responses. An unrelated Origin returned 403.
- **Public login:** owner signs in locally at the exact public ship hostname,
  preferably testing independently of the private network. Never share the code.
- **EAuth:** the relying application discovers the ship, authorization occurs on
  the owner's ship, and the owner returns authenticated to the application. A
  reachable login page alone does not establish EAuth success.

The owner confirmed both public login and EAuth in the reference installation,
including an EAuth attempt in a private browser session. Do not infer that private
browsing must be disabled because an attempt briefly spins. Distinguish discovery,
redirect, approval and return stages before changing configuration. Do not reset
identity, relax Origin/TLS policy or start another ship to troubleshoot a delay.

A running manager container is not proof that Vere is running. A strict-TLS 502
can indicate the ship upstream is unavailable; check owner-controlled runtime
status and boot readiness before changing certificates or routes.

Cloudflare is a trusted TLS terminator in this topology, not an opaque relay for
browser HTTPS. Keep that trust boundary explicit when handling ship login traffic.
Enter access codes only on the verified owner ship origin; a relying application's
page must not collect the ship code, boot keys or wallet secrets.

## Withdrawal, renewal and remaining qualifications

Disable the public route or connector first when withdrawing access. DNS deletion
alone is not immediate isolation. Preserve private manager/ship access, volume,
CA and enrollment. A package rollback is separate and does not reverse pier data.
If an EAuth-origin override was explicitly changed, restore its recorded prior
value rather than blindly clearing it. No manual EAuth override was needed for
the accepted reference flow.

The following remain separate work, not implied by successful login:

- Exercised public edge certificate renewal and private origin certificate renewal,
  replacement/reload, including coordinated CA-pool changes where needed.
- Effective managed catch-all configuration readback: the inspected route UI did
  not expose it. Do not claim a verified `http_status:404` catch-all from defaults.
- Broad app/API compatibility, sustained streaming, failure recovery and direct
  Ames/UDP reachability. A successful EAuth flow is not a complete network audit.
- Canonical clean-build qualification and binary distribution, signing, namespace
  and licensing gates. The embedded Vere OpenSSL maintenance issue remains open.

See the [operator guide](operator-guide.md), [domain findings](domain-hosting-findings.md)
and [release boundaries](release-preparation.md). Public source publication does
not publish a connector credential, certificate, image or Dappstore entry.
