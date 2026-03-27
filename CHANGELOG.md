# Changelog

All notable changes to `hexcore-capstone` will be documented in this file.

## [1.3.4] - 2026-03-26

### Added
- **Function Boundary Detection** — New `detectFunctions()` async method that scans code buffers for function prologues (x86/x64, ARM64, ARM32, MIPS) and call targets. Returns `FunctionBoundary[]` with start/end addresses, confidence scores, detection method, and thunk flag.
- **BigInt Addresses** — Instruction `address` field now emits BigInt for 64-bit safety. Backward-compatible `addressAsNumber` field added. Base address parameter accepts both BigInt and Number.

### Fixed
- **Async Worker Error Swallowing** — `DisasmAsyncWorker::Execute()` now calls `SetError()` instead of silently storing errors. Promises correctly reject with descriptive Capstone error messages.
- **Detached ArrayBuffer Guard** — Added `IsDetached()` check before dereferencing TypedArray buffers in both sync and async disassembly paths.
- **C++17 Cross-Platform** — Added `CLANG_CXX_LANGUAGE_STANDARD: c++17` for Mac and `/std:c++17` for Windows in `binding.gyp`.
- **target_name Compliance** — Renamed `capstone_native` → `hexcore_capstone` in binding.gyp, main.cpp, and index.js (legacy name kept as fallback).
- **Exception Settings** — Aligned Mac/Windows exception settings with `NAPI_DISABLE_CPP_EXCEPTIONS`.
- **Unhandled Architecture Detail** — `DetailToObject()` returns `archSpecific: null` with warning for unsupported architectures.
- **Copyright Headers** — Replaced Microsoft copyright with HikariSystem in all source files.
- **Async option parity** — `disasmAsync()` now replays remembered Capstone handle options on the worker-side handle instead of preserving only `DETAIL`.
- **Async mode tracking** — `CS_OPT_MODE` updates are now reflected in the wrapper's async execution state.
- **Syntax parity coverage** — added sync vs async ATT syntax consistency coverage to prevent silent divergence between `disasm()` and `disasmAsync()`.

## [1.3.2] - 2026-02-14

### Fixed

- **ARM/ARM64 sync/async detail parity** — synchronous disassembly now includes `mem`, `shift`, `vectorIndex`, `subtracted` (ARM) and `mem`, `shift`, `ext`, `vas` (ARM64) fields, matching async output.
- **Error handling** — `numInsns == 0` with `CS_ERR_OK` is now treated as valid empty input instead of error. Added null guard on `cs_free`.
