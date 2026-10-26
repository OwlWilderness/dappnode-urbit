---
name: uvm-workflow-audit
description: Audit UVM owner workflows without touching private state.
version: 0.1.0
author: Project contributors, Hermes Agent
license: GPL-3.0-only
platforms: [linux, macos]
metadata:
  hermes:
    tags: [uvm, operations, documentation, dappnode]
---

# UVM workflow assistance

Use the repository's human runbooks as authority. This skill does not grant target access, owner authority, release permission, or permission to handle private material.

## When to use
- Auditing a UVM install/update, certificate exchange, existing-pier migration, Dappmanager MCP access or public tunnel procedure.
- Drafting nonsecret preflight/checklists or focused improvements for these workflows.
- Not for executing a production signing, backup, Start/Stop, install, route, token, DNS or publication operation without separately scoped approval.

## Prerequisites
- Read the current issue **and comments** before changing source. Check the default branch and active checkout; create a separate issue branch. Read `CONTRIBUTING.md` and [`docs/workflow-audit.md`](../../../docs/workflow-audit.md).
- Read [`docs/operator-guide.md`](../../../docs/operator-guide.md), [`docs/owner-certificate-runbook.md`](../../../docs/owner-certificate-runbook.md), [`docs/workflow-runbooks.md`](../../../docs/workflow-runbooks.md) and relevant companion [README](https://github.com/OwlWilderness/dappnode-urbit-ship-tunnel#readme). For MCP questions consult [Dappnode's developer guide](https://docs.dappnode.io/docs/dev/package-development/agent-assisted-development/) and current Hermes MCP/profile guidance. The operator can follow these without this skill.
- Before synthetic checks, use only a separately approved private scratch outside the repository; no target files, keys, codes, tokens, cookies, private logs, pier archives or personal receipts. Synthetic keys may be generated within a disposable scoped probe, never read or printed by the agent.

## Procedure
1. Inventory one workflow's actual source/doc/UI path with `read_file`/`search_files`. Record prerequisites, owner-only step, expected result, failure boundary and evidence provenance. Completion: links resolve and historical reference acceptance is separate from this checkout's tests and any target claim.
2. Prefer a runbook patch over a new script. For certificates, the agent may validate **synthetic or owner-approved public** CSR/certificate inputs; owner signs locally and verifies browser trust. For release, descriptor-only checks are not an image; use `docs/release-preparation.md` prerequisites. Completion: no hidden tooling or unsupported renewal/delivery claims.
3. For unclear feasibility, run a small synthetic offline probe with `terminal` and record VALIDATED/PARTIAL/INVALIDATED plus what it cannot prove. Never probe the installed service or start/restart a ship. Completion: observable result and scoped limitations recorded.
4. Draft narrowly scoped follow-ups with impact, risk, acceptance and exclusions. Check existing issues #3/#5/#6/#7 and companion #1 to avoid duplicate ownership. Do not create a remote issue without approval. Completion: each proposed automation leaves high-consequence operations behind explicit owner gates.
5. For MCP access, distinguish Dappmanager's owner-only key and mutating-tools gate from Hermes's profile-specific server and tool selection. Use only nonsecret CLI help/list/status and already authorized discovery; never inspect credentials/config/env, rotate keys, toggle a server/tool or call mutating tools for permission testing. Document unknown live target state as a gap and refer to [the MCP runbook](../../../docs/workflow-runbooks.md#optional-dappmanager-mcp-access).

## Pitfalls
- The source descriptor remains 0.1.3 while installed private derivatives are 0.1.4/0.1.5. No source test proves current target identity.
- `owner_tls.py` treats READY identity as immutable; re-upload is not renewal. Do not propose a silent certificate overwrite.
- No generic installer button, CA trust recipe or pier backup command exists. Never use Dappmanager File Manager for private pier delivery.
- The connector has independent authoritative instructions. Its tunnel health is not backend strict TLS, ship login or EAuth acceptance.

## Verification
- Run non-disruptive link/format checks, `git diff --check`, and focused source tests only if prerequisites exist and changes warrant them. Read back exact modified paths/status. Report passed source checks separately from untested target, renewal, clean build and public release. No commits or remote writes absent authorization.
