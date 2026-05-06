# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What Blutter Does

Blutter is a Flutter/Dart AOT reverse engineering tool. Given an Android APK or `lib/arm64-v8a/` directory (containing `libapp.so` and `libflutter.so`), it:
1. Detects the exact Dart VM version from `libflutter.so`
2. Fetches and compiles that exact Dart SDK version as a static library
3. Builds a C++ executable that links against that Dart VM library
4. Loads the AOT snapshot in-process and walks the Dart heap to produce annotated ARM64 assembly, object pool dumps, IDA Pro scripts, and a Frida instrumentation template

Android arm64 and iOS arm64 are supported. macOS desktop is not yet supported (requires different Dart VM defines and compressed-pointer settings).

## Running Blutter

```bash
# Analyze an APK / IPA or extracted lib directory
python3 blutter.py path/to/app.apk out_dir         # Android APK
python3 blutter.py path/to/app.ipa out_dir         # iOS IPA
python3 blutter.py path/to/lib/arm64-v8a out_dir  # extracted Android dir
python3 blutter.py path/to/Payload/App.app/ out_dir  # extracted iOS app dir

# Test on the included test binaries (tests/ dir has both android/ and ios/ subdirs)
python3 blutter.py tests/android /tmp/out_android
python3 blutter.py tests/ios /tmp/out_ios

# Common flags
python3 blutter.py ... out_dir --rebuild       # force rebuild C++ tool
python3 blutter.py ... out_dir --no-analysis   # skip IL annotation (faster)
python3 blutter.py path/to/libapp.so out_dir --dart-version 3.4.2_android_arm64  # skip auto-detection

# Build Dart VM static library for a specific version
python3 dartvm_fetch_build.py 3.4.2 android arm64
python3 dartvm_fetch_build.py 3.4.2 ios arm64
```

`blutter.py` automatically downloads and builds the correct Dart VM static library on first use — no manual setup needed.

## Build System

The build is two-stage and fully automated by `blutter.py`:

**Stage 1 — Dart VM static library** (`dartvm_fetch_build.py`):
- Sparse-clones `dart-lang/sdk` at the exact version tag into `dartsdk/v<ver>/`
- Generates `sourcelist.cmake` via `scripts/dartvm_create_srclist.py` (parses Dart `.gni` files)
- Instantiates `scripts/CMakeLists.txt`, runs CMake+Ninja
- Installs to `packages/include/dartvm<ver>/` and `packages/lib/libdartvm<ver>_<os>_<arch>.a`

**Stage 2 — blutter executable** (`blutter/CMakeLists.txt`):
- Requires `-DDARTLIB=dartvm<ver>_<os>_<arch>` and version-specific `-D` flags (detected by `find_compat_macro()`)
- Output goes to `bin/blutter_dartvm<ver>_<os>_<arch>`

**`build/` and `dartsdk/` are safe to delete** — only `packages/` and `bin/` need to persist.

## Dependencies

- **Python 3.11+** with `pyelftools` and `requests`; managed by asdf (`.tool-versions`) + direnv (`.envrc` activates `.venv/`)
- **C++20**: g++ ≥ 13 (Linux), Clang ≥ 16 / Apple Clang (macOS), MSVC VS 2022+ (Windows)
- **Build tools**: CMake ≥ 3.20, Ninja
- **Libraries**: `libcapstone`, `libicu4c`
- **macOS < Sequoia**: needs `brew install llvm@16` for `<format>` support

## Testing

There is no test framework. Testing is done by running against the binaries in the `tests/` directory (`tests/android/` and `tests/ios/`) and inspecting output. Both contain Dart 2.19.6 snapshots.

## C++ Architecture

### Entry point: `blutter/src/main.cpp`
`DartApp app(path)` → `app.LoadInfo()` → `CodeAnalyzer::AnalyzeAll()` → `DartDumper` → `FridaWriter`

### Key architectural points

**In-process Dart VM**: blutter links the Dart VM static library and calls `Dart_Initialize` / `Dart_CreateIsolateGroup` to actually load the snapshot. All internal `dart::` namespace types are directly accessible.

**One binary per Dart version**: `find_compat_macro()` in `blutter.py` inspects installed headers and sets preprocessor macros (`OLD_MAP_SET_NAME`, `HAS_TYPE_REF`, `HAS_RECORD_TYPE`, `UNIFORM_INTEGER_ACCESS`, etc.) so a single compiled binary handles one specific Dart version. Different Dart versions produce distinct executables.

**Addresses are base-relative**: `DartFnBase::SetLibBase()` sets the global `lib_base`. `Address()` returns ASLR-independent offsets; `MemAddress()` returns the runtime address.

**ARM64-specific code** lives in `*_arm64.cpp` files. `Disassembler_arm64.h` defines the `A64::Register` enum and all Dart-special register constants (`THR=R26`, `PP=R27`, `HEAP_BITS=R28`, `NULL_REG=R22`, etc.).

**Compressed pointers** differ per platform: Android arm64 uses `DART_COMPRESSED_POINTERS` (30-bit Smis, 4-byte heap refs); iOS arm64 does NOT (62-bit Smis, 8-byte refs). `CSREG_DART_HEAP` (R28) is always defined — it's used for both write barriers and compressed-pointer decompression. Code that handles decompression instructions (`handleDecompressPointer`) is guarded by `#if defined(DART_COMPRESSED_POINTERS)` and is a no-op on iOS.

**iOS Dart VM CMake requires both** `DART_TARGET_OS_MACOS_IOS` and `DART_TARGET_OS_MACOS` — the Dart source checks `DART_TARGET_OS_MACOS` first (see `dart.cc`). `scripts/CMakeLists.txt` sets both for the `ios` target.

**`blutter/src/pch.h`** is the precompiled header — it includes all Dart VM headers and applies version-compatibility shims using the compile-time macros.

### Core classes (all in `blutter/src/`)

| Class | Purpose |
|---|---|
| `ElfHelper` | Maps `libapp.so` / `App`, dispatches to `MachoHelper` for Mach-O, locates the four Dart snapshot sections |
| `MachoHelper` | Parses Mach-O/fat binaries (iOS), locates Dart snapshot symbols via symtab |
| `DartLoader` | Calls Dart C API to load snapshot into in-process isolate |
| `DartApp` | Top-level container: live isolate, all libraries/classes/functions/stubs, object pool, type DB |
| `DartLibrary` → `DartClass` → `DartFunction/DartField` | Dart object model mirrored in C++ |
| `DartTypes` / `DartTypeDb` | Dart type system representation with deduplication registry |
| `Disassembler` / `Disassembler_arm64` | libcapstone wrapper; `AsmInstructions` owns `cs_insn*` array |
| `CodeAnalyzer` | `AnalyzeAll()` iterates every `DartFunction`, runs `asm2il()` (ARM64), attaches `AnalyzedFnData` |
| `ILInstr` hierarchy (`il.h`) | Intermediate language: `Call`, `LoadField`, `StoreField`, `AllocateObject`, `BranchIfSmi`, etc. |
| `VarValue` hierarchy (`VarValue.h`) | Typed value abstraction used during analysis (registers, locals, pool entries, etc.) |
| `DartDumper` | Writes `asm/`, `pp.txt`, `objs.txt`, `ida_script/addNames.py`, `ida_dart_struct.h` |
| `FridaWriter` | Emits `blutter_frida.js` using `scripts/frida.template.js` as template |

## Python Scripts

| Script | Purpose |
|---|---|
| `blutter.py` | Main orchestrator |
| `dartvm_fetch_build.py` | Clone Dart SDK, build static library |
| `extract_dart_info.py` | Parse `libflutter.so`/`Flutter` (ELF or Mach-O) to get Dart version, arch, OS |
| `scripts/dartvm_create_srclist.py` | Parse `.gni` files → `sourcelist.cmake` |
| `scripts/dartvm_make_version.py` | Write `runtime/vm/version.cc` from snapshot hash |
| `scripts/init_env_win.py` | Windows: install capstone + ICU via NuGet |
