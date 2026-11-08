# UVM read-only connector — isolated, not activated

This is executable standard-library Python source, not a replacement backend.
It exposes one MCP stdio tool, `uvm_status`, with an empty object input and no
other tools. No Hermes profile/configuration, installed package, or live runtime
has been modified. No target requests or browser/session extraction were made.

## Contract

The only outbound request implemented is `GET /api/status`, verified HTTPS to
`issue3-planet.public.dappnode.private:8443`, with its exact Host header. There is
no URL, hostname, port, path, method, action, expression, credential, header, CA,
or filesystem argument in the tool schema. Runtime dispatch also rejects every
extra tool argument before constructing a connection. No proxy/environment URL
handling, redirects, retries, public listener, login, or lifecycle writes exist.
`http.client.HTTPSConnection` connects directly; this is not authorization to
use it against the currently denied private target.

Successful output is exactly:

- `manager`: authenticated status response received (not independent health).
- `ship_process`: bounded runtime state enum or UNKNOWN.
- `initialization`: ATTEMPTED / COMPLETE / UNKNOWN, from provisioning evidence;
  STOPPED/RUNNING never imply completion.
- `job_state`: bounded job state enum or UNKNOWN.
- `recovery_outcome`: PENDING / COMPLETE / REFUSED / UNKNOWN, retained result,
  not current health. No operation ID or evidence bodies.
- `recovery_reported_available`, `start_reported_available`: strict booleans
  reflecting server flags, NOT authorization, execution, or inferred safety.
- `ship_http_readiness`: always UNKNOWN_NOT_MEASURED. This API does not measure
  ship HTTP readiness; the connector does not probe the ship.

CSRF values, identities, session IDs, passwords, keys, access codes, operation
IDs, paths, free text, raw diagnostics, logs, and unknown fields are discarded.
Unknown enum values become UNKNOWN; malformed JSON, duplicate keys, non-finite
numbers, wrong types, oversized/truncated bodies and unexpected framing fail
closed. HTTP responses must be JSON with Content-Length, no Transfer-Encoding,
and at most 65,536 bytes. Error bodies are never read/returned for non-200.
MCP request lines are at most 16,384 bytes; overlong/incomplete framing closes
stdio. No tracebacks or raw errors are intentionally logged.

The stdio server implements the narrow legacy MCP initialize / initialized /
ping / tools/list / tools/call subset; supported versions are 2025-11-25,
2025-06-18, 2025-03-26, 2024-11-05. It intentionally accepts integer request IDs
only and strictly empty tool arguments. No resources, prompts, tasks, sampling,
elicitation, HTTP MCP, or 2026 stateless discovery is implemented. Compatibility
with the actual installed Hermes client remains to be verified through supported
managed connection discovery; do not represent the offline protocol test as that
integration. Current official Hermes docs retain legacy handshake support.

## Existing backend authentication: facts, not a new token design

Inspected original `tools/browser-importer/server.py`:

- lines 89–123: exact Host; exactly one session cookie, server-side expiry.
- lines 143–151: authenticated GET status, includes CSRF (discarded here).
- lines 153–164: writes require exact Origin and session CSRF. Unchanged.
- lines 298–325: existing password JSON login; random 32-byte token_urlsafe
  session ID, `__Host-import_session`, Secure/HttpOnly/SameSite=Strict/Path=/,
  900-second expiry, at most eight sessions, five login attempts/minute.
- no server-enforced read-only role, bearer token, API key, OAuth, or scoped
  status credential is supplied by this connector.

A session cookie remains a FULL-PRIVILEGE backend credential. This connector's
interface is read-only; the backend credential is NOT read-only. GET status
itself contains CSRF, so a compromised connector process could recover write
capability. Its source restriction is not a sandbox, OS/network policy, or a
substitute for server-enforced authorization. Backend status may also perform
its existing observation/session housekeeping. Trusted local operator and
same-UID/root integrity are assumed. These limits must be accepted explicitly
before using an owner session; otherwise stop and separately design/authorize a
server-enforced scoped credential (OUTSIDE this source-only task).

No password/login function is implemented. A later, separately authorized,
owner-operated trusted authentication client would need to call the EXISTING
`POST /api/login` with exact configured Host/Origin, JSON Content-Type and a
securely supplied password, receive a NEW dedicated session, and write ONLY the
43-character session ID to a new connector-only credential file. Do not extract
or reuse browser cookies; do not reuse another bot/profile's credentials. Do not
send passwords/cookies/CSRF through chat, source, argv, tool arguments, transcripts,
or logs. No supported secure session-issuance/handoff mechanism has been
established here: this is a concrete live-activation GAP, not an implemented
login workflow. Existing browser sign-in alone cannot activate this source.
The connector never renews sessions, retries login, logs out, or resets state;
expiry requires a fresh dedicated owner-authenticated session through that
separately approved mechanism. Clearing the local file does not revoke a server
session; revoke through the owner's existing approved path or let it expire.

## Activation prerequisites — all remain required

1. Independently approve and establish a SUPPORTED trust/network route from
   Hermes's intended local stdio process to this exact private manager. Resolve
   the existing private-address denial through its normal supported process;
   neither this source nor changing an environment variable resolves that denial.
   No alternative transport, public admin tunnel, guard weakening, or disguised
   URL is authorized. Do not attempt target requests until this is satisfied.
2. Owner must verify that the running manager's configured origin/netloc is
   exactly this pinned host and port, and DNS/routing reach the intended manager.
   This binding comes from the intended planet checkpoint, NOT live verification.
   The checked-out generic docker-compose default still names an older UVM host;
   do not silently generalize the connector or assume that default is installed.
   On mismatch, stop for reviewed source/config scope, not alternate-URL input.
3. Verify normal hostname-authenticated TLS for that host using the existing
   public CA. The published `credentials.py` is a fail-closed trust template:
   `PUBLIC_CA_SHA256` is empty and every certificate is refused. A separately
   reviewed installation must replace that constant with the independently
   authenticated public-root DER SHA-256. No tool/environment trust override
   exists. Only one public PEM is accepted, with hostname verification and
   minimum TLS 1.2; no system roots, private key or insecure flag is used.
   No owner certificate, CA fingerprint or private path is distributed here.
   Live certificate/route acceptance remains untested.
4. Establish the secure dedicated-session issuance/handoff described above and
   explicitly accept full-privilege-session risk, OR keep activation blocked.
   File must be absolute, single-linked, regular, current-user owned, mode 0600,
   inside a current-user mode-0700 directory with canonical nonsymlink parent.
   Final symlinks, links, extra bytes/newlines, unsafe modes and malformed IDs
   fail closed. No existing auth/verifier/digest file is read. File loader paths
   are OPERATOR settings, never tool parameters. Hostile same-UID/root races are
   outside this cooperative process boundary.
5. Through the SUPPORTED managed Hermes connection/owner approval path, review
   adding the local stdio command `/usr/bin/python3` with args `-B` and absolute
   `mcp_stdio.py` path. No installation is required for the connector itself.
   No MCP/config/profile changes have been made. Do not hand-edit MCP config.
   Actual custom-server registration/approval availability must be established;
   do not invent catalog registration or unsupported `manage_connections` fields.
   Inspect supported management/CLI schemas at that time. Advertise ONLY uvm_status;
   disable unnecessary resources/prompts/sampling/events and parallel execution.
6. Only AFTER the previous gates, explicitly pass these nonsecret operator
   environment settings through the approved managed process:
   `UVM_CONNECTOR_PUBLIC_CA_FILE` (public PEM path),
   `UVM_CONNECTOR_SESSION_FILE` (dedicated protected file path), and
   `UVM_CONNECTOR_ENABLE=approved-status-only`. The last value is a local off-by-
   default latch, NOT proof of approval or a policy exception. Never set it now.
   Discovery/default-disabled execution opens neither CA nor session files and
   makes no network request. Do not put credential values in these settings.
7. Verify actual session-visible tool discovery/schema, then ONE authorized
   status read and sanitized result. Keep current init/Start state untouched;
   no writes can be dispatched by this tool. Do not infer that COMPLETE or Start
   occurred from the owner's reported STOPPED/HTTPUNKNOWN state.

## Offline tests and evidence

Run from this isolated directory:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B test_connector.py
```

Tests use only owned in-memory synthetic handlers, including the real stdlib
HTTP request serializer/response parser, temporary owned synthetic session files
under the operator-selected temporary directory, and an actual stdio subprocess with network-denying audit
hooks. The parent test process also denies connect/DNS/bind/sendto. No test binds
a socket or contacts any target. Audit hooks are cooperative test tripwires,
not an installed policy mechanism. The fixture secret `SECRET` and `A` session
are invented adversarial markers, not fabricated target observations.

Private verification receipts and the machine-bound `verify_source.py` are
not distributed. The portable suite does not load any actual CA or session input.
Its successful result is offline source acceptance, not installed trust binding.
Tests cover allowed end-to-end read, blocked URL/path/actions/secret arguments
before request construction, strict projection, unknown readiness, malformed
responses, redirects, invalid session framing, TLS verification flags, private
file refusal, protocol limits/notification refusal, and default-disabled stdio.
They do NOT prove live routing, TLS handshake, authentication, Hermes-client
integration, or private-address-policy resolution.

## Primary protocol references reviewed

- https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
- https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle
- https://modelcontextprotocol.io/specification/2025-11-25/server/tools
- https://hermes-agent.nousresearch.com/docs/user-guide/features/mcp
- https://hermes-agent.nousresearch.com/docs/reference/mcp-config-reference

Official docs were retrieved via search primary-source excerpts; the configured
URL extraction backend returned an extraction-unavailable error. No settings
were changed to obtain documentation. The narrow legacy implementation is an
intentional compatibility target, not a claim to implement the latest MCP era.
