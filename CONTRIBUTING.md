# Contributing

## Licensing

Owner-controlled new UVM contributions and the replacement artwork are licensed
under GPL-3.0-only; see `LICENSE.md` and `LICENSES/GPL-3.0-only.txt`. Preserve all
inherited attribution and third-party terms. Do not add a linking exception or
claim that this declaration clears the selected runtime's distribution basis.

## Issues and branches

Use one concise issue for a meaningful change: a short goal, a few completion
criteria, and important exclusions. Avoid detailed task hierarchies.

Branch format: `<type>/<issue-number>-<short-description>`.

- Types: `feat`, `fix`, `docs`, `chore`.
- Use lowercase kebab-case and the actual issue number from this repository.
- Describe the outcome, not the implementation details.
- Branch from the current default branch (`master`); do not work directly on it.
- Reference the issue in the pull request. Close it only when its criteria are met.

Example: `feat/1-modernize-package` tracks issue #1, “Modernize the Urbit Dappnode package”.

## Scope and verification

Preserve upstream attribution and handle existing persistent data deliberately.
Keep private state, keys, credentials and personal operational records out of Git.
Reuse applicable accepted evidence; run focused checks for changed behavior.
State separately what passed locally and what was verified on Dappnode.
