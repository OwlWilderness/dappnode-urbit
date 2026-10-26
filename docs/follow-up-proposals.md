# Local follow-up drafts for issue #8

**Not GitHub issues; no implementation authorized.** Review scope and current issue state before filing. Keep them separate from existing backup [#7](https://github.com/OwlWilderness/dappnode-urbit/issues/7), source layout [#5](https://github.com/OwlWilderness/dappnode-urbit/issues/5), UVM label [#6](https://github.com/OwlWilderness/dappnode-urbit/issues/6), connector label [#1](https://github.com/OwlWilderness/dappnode-urbit-ship-tunnel/issues/1), and embedded OpenSSL [#3](https://github.com/OwlWilderness/dappnode-urbit/issues/3).

## A. Public-certificate preflight and expiry visibility

**Goal:** Reduce wrong-CA/SAN/expiry mistakes without giving the application or agent control of the owner CA.

**Acceptance:** A public-input-only offline/manager view checks the CSR signature and requested names, leaf/CSR public-key equality, root DER SHA-256 against an independently entered pin, strict server chain/purpose, exact two SANs and not-before/not-after; it shows actionable refusal/approaching-expiry states without displaying private paths or materials. Synthetic tests cover wrong pin/name/key, expired/root invalid and malformed PEM. Clear UI says READY identity cannot be replaced in place today. The owner still signs, uploads, trusts and explicitly approves changes.

**Exclusions:** No private signing key ingestion, automatic signing, CA import from an untrusted upload, auto-renewal, live reload, mutation of READY storage, or implied renewal/recovery acceptance. A separate design and owner-approved migration/test plan is required before any renewal implementation.

## B. Route and package preflight

**Goal:** Prevent a correct-looking tunnel or descriptor bundle from being mistaken for a safe installed ship-only route.

**Acceptance:** A read-only checklist/preview reports exact selected artifact/feature record, package/service/version/image binding and target volume mapping before authorized update; distinguishes descriptor-only from built image and STOPPED/RUNNING/login-ready. For the optional route it checks effective saved exact Host/SNI/private CA path/verification/9444 backend, forbids admin 8443, highlights unmatched catch-all not independently read back, and separates tunnel connection, TLS, login and EAuth verification. Synthetic or fixture tests exercise mismatches. Expose only sanitized identifiers in shareable output.

**Exclusions:** No bundle build/upload, token/DNS edits, automatic package change, pier backup, Stop/Start, TLS relaxation, public route creation or auto-login. Coordinate UI labels with #6 and companion #1; do not move source as part of this proposal (#5).
