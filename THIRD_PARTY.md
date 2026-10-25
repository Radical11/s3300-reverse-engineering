# License boundaries

The root MIT license applies to original project-authored tools, tests,
documentation and creative-look code. It does not license Nikon firmware,
decoded executable bytes, recovered artwork, fonts, language tables, manuals,
personal photographs or third-party packages. Extracted vendor bytes are not
reconstructed open-source C code.

Vendor inputs and generated vendor-derived outputs stay under the existing
ignored `sources/`, `derived/`, `samples/`, `experiments/` and `work/` paths.
An upstream firmware download is an input to the local workflow; it is not
bundled in a source release. Metadata and hashes identify artifacts without
relicensing those artifacts.

Python dependencies and any locally installed Capstone, REA, Node or other
analysis tools retain their own licenses. They are separate dependencies;
this repository's MIT license does not replace their licenses. Do not copy a
virtual environment or `tools/vendor/` into a source release.

This change adds local licensing and development access. Repository visibility
and remote publication are separate operations; no remote setting is changed.
