# Owner certificate exchange: initial provisioning only

Use with [operator guide §3](operator-guide.md#3-establish-private-https-using-public-files-only). This is a **local owner workstation** example for an existing, owner-controlled root CA. It does not create a CA, provision browser/OS trust, renew a READY identity, access the target filesystem or qualify a particular Dappmanager version. Keep the signing key outside the repository, agent workspace, appliance and screenshots. Never paste a key, enrollment authority or access code into chat. Example names below are package defaults; if authorized origins differ, stop and have the maintainer qualify the complete DNS/SAN/descriptor change.

## Before the exchange

- Owner: confirm private Dappmanager authentication, selected package `uvm.public.dappnode.eth`, service `ship`, its expected fresh managed storage and both private DNS names. Reuse an accepted owner root CA where possible. Obtain its **public** certificate (`root-ca.pem`) independently of the target. If the CA/certificate or signing tool is unavailable, stop; do not generate an ad-hoc root in UVM or ask an agent to handle a private key.
- On the owner's computer, use **OpenSSL 3**, not macOS's `/usr/bin/openssl` LibreSSL. Set `OPENSSL` to a verified OpenSSL 3 executable, e.g. `/opt/homebrew/opt/openssl@3/bin/openssl`, and work in a private owner directory outside Git. Commands below assume current directory contains `root-ca.pem`, an owner-held `root-ca.key` accessible only to that owner, and (after download) the public `request.pem`. Do not share command output containing private paths or run with shell tracing. Validate executable with `"$OPENSSL" version` (must start `OpenSSL 3.`).
- **Only for a new owner without a root:** arrange a protected, owner-operated CA and independent OS/browser trust first. One OpenSSL 3 local example, run by the owner in a restricted directory (`umask 077`), is below. Choose the root lifetime and offline backup policy deliberately; losing the signing key blocks future issuance and replacing the trusted root is a separate migration. The encrypted key/passphrase stay on the owner's computer and never go to UVM, a connector, repository or agent. If local interactive signing/trust is unavailable, stop. This example does not install trust on arbitrary OS/browser versions:

```sh
umask 077
"$OPENSSL" req -x509 -newkey rsa:4096 -cipher aes-256-cbc \
  -keyout root-ca.key -out root-ca.pem -days 3650 -sha256 \
  -subj '/CN=UVM owner CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign'
```

Keep an offline owner-controlled backup and import **only** the public root certificate through your OS/browser's trusted-CA management UI. Verify the displayed fingerprint against the independent DER digest below, then confirm warning-free HTTPS later. Exact trust-store UI varies; a browser exception is not trust provisioning.
- Independently compute the lowercase DER root pin and compare it to the wizard value **before** uploading anything:

```sh
"$OPENSSL" x509 -in root-ca.pem -outform DER | "$OPENSSL" dgst -sha256
"$OPENSSL" x509 -in root-ca.pem -noout -ext basicConstraints -dates
"$OPENSSL" verify -x509_strict -check_ss_sig -no-CApath -no-CAstore -CAfile root-ca.pem root-ca.pem
```

The digest line's hex suffix must equal the 64 lowercase hex characters supplied independently to **Owner CA public certificate fingerprint**. If the root is expired, not self-signed or its pin differs, stop. Owner-only OS/browser trust installation is platform-specific; use your approved trust workflow and never click through a warning.

## Download, inspect, sign locally

1. In the trusted Dappmanager File Manager, choose the package and `ship` service, and download **only** `/urbit/control/owner-tls-public/request.pem` to your private workstation directory. `AWAITING_CERTIFICATE` means no UVM HTTPS listener yet; it is not a reason to expose management publicly. Do not download `/urbit/control` or a private key.
2. Inspect the public request. Its signature must verify and requested SANs must be exactly the two names below; confirm the package/service in Dappmanager independently. A CSR alone does **not** authenticate which installation made it.

```sh
"$OPENSSL" req -in request.pem -noout -verify
"$OPENSSL" req -in request.pem -noout -text
```

3. After owner approval, write the following **public extension policy** to `server-ext.cnf` locally. Use a reviewed owner signing process if one already exists; this OpenSSL example writes only a public leaf and OpenSSL-generated serial in your private working directory, never exports the CA key. `-set_serial` avoids a `.srl` state file. Choose a unique random serial and an owner-approved validity shorter than the root's remaining life.

```ini
[server]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:uvm.public.dappnode.private,DNS:ship.uvm.public.dappnode.private
```

```sh
"$OPENSSL" x509 -req -in request.pem -CA root-ca.pem -CAkey root-ca.key \
  -set_serial "0x$("$OPENSSL" rand -hex 16)" -days 90 -sha256 \
  -extfile server-ext.cnf -extensions server -out server.pem
```

The passphrase, if any, must be entered only through the owner's local tool. Do not hand these commands or a CA key to an agent to run. Check the result **before** upload:

```sh
"$OPENSSL" x509 -in server.pem -noout -dates -ext basicConstraints,extendedKeyUsage,subjectAltName
"$OPENSSL" verify -x509_strict -auth_level 2 -check_ss_sig -no-CApath -no-CAstore \
  -CAfile root-ca.pem -purpose sslserver -verify_depth 0 \
  -verify_hostname uvm.public.dappnode.private server.pem
"$OPENSSL" verify -x509_strict -auth_level 2 -check_ss_sig -no-CApath -no-CAstore \
  -CAfile root-ca.pem -purpose sslserver -verify_depth 0 \
  -verify_hostname ship.uvm.public.dappnode.private server.pem
"$OPENSSL" req -in request.pem -pubkey -noout > request-pub.pem
"$OPENSSL" x509 -in server.pem -pubkey -noout > server-pub.pem
cmp request-pub.pem server-pub.pem
```

Expected: CSR signature verifies, each chain/name check prints `server.pem: OK`, public keys compare equal, leaf is currently valid with `CA:FALSE`, serverAuth and **exactly** both DNS SANs. Check extension contents manually; a passing hostname check alone does not prove the SAN set has no extra names. If any check fails, do not upload; correct the local signing inputs. Keep all generated files under owner control. The public CSR/cert may be inspected by a helper only with separate approval; no tool may read the key.

## Upload, verify and stop conditions

4. Upload **one public PEM certificate per filename** using the authenticated File Manager: root to `/urbit/control/owner-tls-public/root-ca.pem`, leaf to `/urbit/control/owner-tls-public/server.pem`. Never upload the private key, a bundle or a pier. The service polls, validates the independent pin, CSR public key, strict chain, purpose and exact names; valid first activation becomes READY without a manual package restart. Partial uploads can remain waiting. On refusal, preserve state and report sanitized state/validation label to the maintainer; don't edit permissions, replace private records or repeatedly restart.
5. In the owner browser with independently trusted root, visit `https://uvm.public.dappnode.private:8443`. Require warning-free HTTPS and correct name before entering enrollment authority/password. Confirm ship origin separately once explicitly started. A healthy package container is not proof of a ready listener or ship.

## Feasibility evidence from this spike

**VALIDATED (synthetic, local only):** OpenSSL 3.5.0 generated a disposable encrypted synthetic root with the owner-new-root example and passed strict self-verification. A disposable synthetic root/CSR also signed the example leaf with the extension policy above, verified the CSR signature, exact requested public-key match and both strict chain/hostname checks; a wrong hostname failed. Public inspection showed the expected SAN, CA:FALSE and serverAuth extensions. The disposable synthetic keys stayed in a private scratch directory for the probe and were not printed or retained. This does **not** verify an owner's CA tool, browser trust, Dappmanager File Manager, actual package READY activation or replacement. **PARTIAL:** initial signing is reproducible with the example, but target-specific trust and delivery require owner checks. **INVALIDATED as a current workflow:** overwriting READY public certificates to renew; current source explicitly refuses changed uploads.

**Expiry and replacement:** the initial READY identity is immutable in current source (`tools/browser-importer/owner_tls.py`): changed public uploads are refused, and no supported in-place leaf/CA renewal, live reload or recovery procedure exists. Calendar the leaf/root expiries with the owner; obtain a separately reviewed renewal design and explicit target approval **before** expiry. Never overwrite public exchange files expecting rotation, delete `control`, reset enrollment, start a second ship or bypass browser trust. If expiry or damaged TLS state blocks access, preserve volume and request preservation-first operator recovery; this runbook cannot promise a rollback. Public tunnel origin trust and browser trust must be coordinated in any future CA change. [Public access](public-access.md#withdrawal-renewal-and-remaining-qualifications) tracks that separate gap.
