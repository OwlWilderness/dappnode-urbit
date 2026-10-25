# Original UVM artwork

The selected avatar consists of whole mint U and M letters rigidly rotated
in opposite directions, with their bases tangent to a common circle and their
inner baseline corners meeting. Their inner strokes imply a V; there is no
separate V polygon. A mint circular arc replaces the straight underline on dark
blue, mirrored vertically to bow downward beneath the letters. It was authored for this
project without external images, fonts, Urbit logos or Dappnode logos. It does
not claim endorsement by either project.

- Editable vector: `assets/uvm-avatar.svg`.
- Reproducible geometry/raster generator: `scripts/render-avatar.py` (Python
  standard library only; no downloads or runtime dependencies).
- Selected package raster: `avatar-urbit.png`, 256 × 256 RGB PNG. The historical
  source filename is retained to avoid changing the accepted SDK/input contract;
  its current contents are the new UVM design, not the inherited image.
- Release filename: `avatar.png`, copied by the existing descriptor preparer.
- Terms: GPL-3.0-only for owner-controlled rights, as stated in `LICENSE.md`.

Regenerate intentionally with `python3 -B scripts/render-avatar.py`. Verify
without writing with `python3 -B scripts/render-avatar.py --check`. Raster bytes
are compared using the current Python/zlib implementation; cross-zlib byte
reproducibility is not claimed.

The inherited artwork is preserved in Git history, not selected for a new
release. Its historical permissions remain unestablished. Replacing it changes
an actual descriptor input, so a fresh descriptor output is required. Preserve
older prepared outputs as historical evidence; do not overwrite them or claim
the new descriptors have an image binding, signature or publication status.

For each prepared output, compare `assets/avatar.png` with the selected source
raster and verify its digest against that output's inventory. Run the generator's
`--check` mode before preparation. These source checks do not establish an image
binding, a clean build, deployment or acceptance of any particular output.
Host-specific artwork and descriptor receipts are not part of this source tree.
