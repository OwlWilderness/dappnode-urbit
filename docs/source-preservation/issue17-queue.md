# Issue 17 source-preservation queue

This branch layers the issue-17 allocator/lifetime source candidate onto the published issue-3 maintained-source base, then preserves the remaining reviewed public-safe allocator, arena, shutdown, IPC, and integration source families. It is a source-preservation branch, not a runtime integration or production selection.

The owned allocator and shutdown material retains its existing refusal and qualification boundaries. Byte-identical files required inside the owned recipe and at canonical tool paths remain at both paths and are identified in the machine-readable manifest.

Excluded material remains in the independent migrated originals with an exact disposition record: machine-specific paths, credential-shaped fixtures, raw operational diagnostics, working-ship/manager harnesses, build/package/lifecycle execution history, generated results, superseded variants, and unrelated records.

## Source-only verification

The original source-only execution selected eight newly preserved Python files and parsed them successfully. Independent read-only review later statically parsed all 25 Python paths added by queue commit `e49efa80e0316c4c396b4c42b8b62ba46dfcd97b`—20 unique blobs across those paths—with zero parse failures. This is static source coverage, not runtime execution. The host-only arena-sizing checks recorded eight passes. Nineteen source-extraction checks skipped explicitly because the accepted public Vere source input was not supplied; no source bytes or pass result were fabricated.

No build, package/image qualification, installation, deployment, ship operation, runtime acceptance, merge, or issue closure is claimed. Ownership, quiescence, native runtime, package, and lifecycle acceptance remain on issue #17.
