# Changelog

All notable changes to `hexcore-capstone` will be documented in this file.

## [1.3.2] - 2026-02-14

### Fixed

- **ARM/ARM64 sync/async detail parity** — synchronous disassembly now includes `mem`, `shift`, `vectorIndex`, `subtracted` (ARM) and `mem`, `shift`, `ext`, `vas` (ARM64) fields, matching async output.
- **Error handling** — `numInsns == 0` with `CS_ERR_OK` is now treated as valid empty input instead of error. Added null guard on `cs_free`.
