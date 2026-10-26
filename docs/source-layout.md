# Source layout (#5)

Current manager source and bundled web UI live in `src/manager/`; the tracked candidate image verifier lives in `tools/image-validation/verify_image.py`. Manager host tests live in `tests/manager/`. `tools/local-candidate/` is deliberately not moved wholesale: local-only helpers, if present in an existing checkout, remain private and untouched.

The Docker context allowlist and explicit COPY operands now point to `src/manager/`, but copy the same selected files to `/opt/importer/` and `/opt/importer/web/`. The Docker entrypoint, working directory, volume mount `/urbit`, package identity, images, service names and network origins are unchanged. `bootstrap-authority.html` remains source-only and excluded from the image context. This is a source-layout change, not a new built image or installed update.

The historical provenance lock in `THIRD_PARTY/vere/followup/wrapper-source-lock.json` intentionally retains the paths of the original snapshot; editing it would falsify provenance. Existing archived artifacts and private operational records are not rewritten.

Host checks: `npm test`; `PYTHONDONTWRITEBYTECODE=1 IMPORTER_TEST_SCRATCH=<private scratch directory> python3 -B -m unittest discover -s tests/manager -p 'test_*.py'`; `python3 -B -m unittest discover -s tests -p 'test_candidate_image_verifier.py'`. The Docker matcher harness `tests/check_docker_context.py` uses synthetic files but invokes Docker buildx and is a separate, approval-dependent image-build check.
