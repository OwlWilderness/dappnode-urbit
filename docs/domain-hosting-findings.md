# Domain and multi-project hosting findings

## Status

The reference installation now has working public ship HTTPS and relying-app EAuth. The owner confirmed private Reveal/login, public ship login and relying-app EAuth. Public HTTP 200 with strict TLS and the persisted route's private CA, SNI and exactHost settings were independently verified. This is reference-installation acceptance, not a claim about arbitrary DNS/router configurations or Ames reachability. See [public access](public-access.md).

Canonical source descriptors remain 0.1.3. Separately qualified private thin derivatives 0.1.4 (owner-code UI) and 0.1.5 (public backend), and a separate 0.1.0 connector, have been installed. Public source publication is not a binary/Dappstore release; runtime OpenSSL and licensing/distribution gates remain unresolved.

The research sections below originated on October 25, 2026, before this setup was completed. That research used public primary sources through fallback retrieval; it did not contact the target or verify the installed HTTPS service. Treat its provider comparisons and direct-ingress options as background, not current quotes or the deployed design.

## Tested ship-only route

The optional `URBIT_PUBLIC_SHIP_ORIGIN` defaults to empty. An enabled example is `https://ship.example.com`, with a relying application at `https://app.example.com`. A named cloudflared connector routes to the dedicated 9444 HTTPS backend, which forwards to Eyre at `127.0.0.1:8081`. Private 8443 and private manager/Reveal access remain unchanged.

The connector uses only the public CA certificate for backend trust, has no pier mounts or host ports, and keeps its owner-managed token private. Persisted backend private-CA trust, SNI and exactHost settings are part of the verified route; do not disable TLS verification or publish the entire private frontend. These results do not establish that router changes are needed, available or tested on another installation.

## Recommended direction

Use one owner-controlled domain with separate subdomains for individual projects, for example `app.example.com` and `ship.example.com`. These are illustrative names, not selections or availability claims.

Use a dedicated application reverse proxy to route those names to individual services. Keep Dappnode management, UVM enrollment/administration and access-code retrieval on their existing private routes. Do not share parent-domain authentication cookies between projects.

A domain registration is separate from DNS hosting, TLS certificates, public reachability, reverse-proxy configuration and application deployment. Buying a domain completes none of the other steps.

## Dappnode source findings

- The package manifest supports multiple `exposable` entries, with service, port and optional subdomain fields.
- Inspected public HTTPS source constructs a hostname from `mapping.from` and `dappnodeDomain`, and uses Dappnode certificate paths. This does not establish arbitrary custom-domain support. A CNAME alone does not configure custom-host routing, matching certificates or application Host handling.
- The inspected proxy template forwards to `http://` upstreams and preserves the incoming Host header. UVM's private-CA HTTPS frontend and exact Host checks are not a verified drop-in upstream. Do not expose the entire UVM frontend or weaken its checks to make a mapping work.
- Mappings have optional Basic Auth and private-source restrictions for nonexternal routes. Basic Auth clears the forwarded Authorization header, which can conflict with application authentication. A public mapping alone does not establish user authentication.
- Published Compose source binds host ports 80 and 443. A separate application ingress needs a verified coexistence design rather than competing for those ports. Router public-port translation to a dedicated ingress port is only a candidate where supported.
- These findings concern inspected public source, not proven equivalence with the installed HTTPS service.

## Registration and DNS options

The research recommendation was Porkbun for authoritative-DNS-provider flexibility; Cloudflare Registrar is an alternative if its mandatory Cloudflare nameserver requirement is acceptable.

| Option | Findings to verify at purchase |
| --- | --- |
| Porkbun | Publishes registration and renewal prices separately; DNS API, DNSSEC and privacy for eligible TLDs; permits changing nameservers. |
| Cloudflare Registrar | Advertises registry/ICANN cost without markup; DNS API, DNSSEC and redaction where permitted; requires Cloudflare authoritative DNS while registered there. |

Do not select on first-year promotional price alone. Compare the chosen name's renewal price, premium status, fees and transfer conditions. This public document includes no exact-name quote or availability result. Registrar and DNS provider can be separate, subject to the registrar's restrictions.

## Internet access and TLS: background alternatives

- Direct ingress is an alternative, not the tested connector design. If evaluating it for another installation, check reachable public addressing, router control, ISP restrictions, inbound forwarding and IPv4/IPv6 separately.
- A changing public address can be handled with dynamic DNS; it does not inherently require a tunnel.
- Investigate CGNAT rather than assuming it; private/shared WAN addresses warrant topology/ISP investigation. No personal network topology is recorded here.
- An outbound tunnel is an alternative when inbound access is unavailable or deliberately avoided. It introduces a connector/provider dependency and does not itself authenticate application users.
- HTTP-01 certificate validation needs inbound port 80. DNS-01 can validate domain control without a public web listener and supports wildcard certificates. Successful certificate issuance therefore does not prove public reachability.
- Earlier local DNS/TLS checks of the existing Dappnode name do not establish off-network access. A public DNS answer also does not prove inbound connectivity.

## Decisions and acceptance for other installations

The tested reference installation has completed its ship HTTPS/login/EAuth checks.
For a different installation or additional application, qualify the following
separately rather than treating that result as transferable:

1. Owner-selected candidate names/TLDs, annual renewal budget and purchase approval.
2. Initial projects and which should be public, authenticated or private.
3. Preference for DNS-provider independence and direct ingress versus tunnel tradeoffs.
4. Authorized read-only assessment of WAN reachability and existing port use.
5. Version-specific ingress design that preserves private administration and supports each application's Host, WebSocket, forwarding and backend-TLS requirements.
6. Owner-operated registration/account/payment flow; never request credentials or payment details in chat.
7. Explicitly authorized DNS/ingress changes followed by external reachability, TLS and application-login checks.

Public-domain work remains separate from private owner access-code retrieval. Both are working on the reference installation; future ingress changes must preserve private administration and must not implicitly restart the ship.

## Primary references reported by the research worker

- Dappnode manifest: https://docs.dappnode.io/docs/dev/references/manifest
- HTTPS name construction: https://raw.githubusercontent.com/dappnode/DNP_HTTPS/master/src/nginx/templater.ts
- HTTPS proxy template: https://raw.githubusercontent.com/dappnode/DNP_HTTPS/master/templates/default.ssl.conf.ejs
- HTTPS listeners: https://raw.githubusercontent.com/dappnode/DNP_HTTPS/master/docker-compose.yml
- Porkbun prices: https://porkbun.com/products/domains
- Porkbun DNS: https://porkbun.com/products/dns_management
- Porkbun privacy: https://porkbun.com/products/whois_privacy
- Porkbun nameservers: https://kb.porkbun.com/article/22-how-to-change-nameservers
- Cloudflare Registrar: https://raw.githubusercontent.com/cloudflare/cloudflare-docs/production/src/content/docs/registrar/index.mdx
- Cloudflare registration: https://raw.githubusercontent.com/cloudflare/cloudflare-docs/production/src/content/docs/registrar/get-started/register-domain.mdx
- Dynamic DNS: https://raw.githubusercontent.com/cloudflare/cloudflare-docs/production/src/content/docs/dns/manage-dns-records/how-to/managing-dynamic-ip-addresses.mdx
- Cloudflare Tunnel: https://raw.githubusercontent.com/cloudflare/cloudflare-docs/production/src/content/docs/tunnel/index.mdx
- ACME challenges: https://letsencrypt.org/docs/challenge-types/
- Shared address space: https://www.rfc-editor.org/rfc/rfc6598.txt

Mutable source URLs are research references, not deployment pins. No domain-specific account information, personal hostnames, IP addresses or secrets are included here.
