#!/usr/bin/env bash
#
# wasmedge/mayhem/build.sh — build WasmEdge's .wasm LOADER+VALIDATOR fuzz target as a sanitized
# libFuzzer binary (+ a standalone reproducer).
#
# Fuzzed surface (see mayhem/harnesses/wasmedge_fuzz_loader.c):
#   WasmEdge_LoaderParseFromBuffer  — binary .wasm decode (the parser).
#   WasmEdge_ValidatorValidate      — structural / type validation of the decoded module.
# This is the attacker-controlled parse surface of upstream tools/fuzz/tool.cpp, MINUS the LLVM
# AOT/JIT codegen tail. We therefore build with WASMEDGE_USE_LLVM=OFF, which:
#   * drops the entire LLVM/lld dependency (no llvm-*-dev apt, no libLLVM*.so to ship), and
#   * keeps the build light (CMake configures fmt/spdlog/simdjson via FetchContent only).
# The loader+validator C API symbols are NOT gated on WASMEDGE_USE_LLVM, so they are always present.
#
# We build the WasmEdge STATIC library (libwasmedge.a) compiled WITH $SANITIZER_FLAGS so the
# loader/validator code itself is instrumented (not just the thin harness), then link the harness
# against it. Build contract (CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/SRC/OUT) comes from the org
# base ENV.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) so an explicit empty --build-arg SANITIZER_FLAGS builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DWARF < 4 required (§6.2 item 10). clang-19 defaults to DWARF-5; -gdwarf-3 pins it explicitly.
# Thread $DEBUG_FLAGS AFTER $SANITIZER_FLAGS on every compile/link so it is always present.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${OUT:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS OUT

SRC="${SRC:-/mayhem}"
cd "$SRC"

HARNESS_DIR="$SRC/mayhem/harnesses"
BUILD="$SRC/mayhem-build"

# ── 1) Configure + build the WasmEdge static library WITH sanitizers, NO LLVM ──────────────────────
# -fsanitize=fuzzer-no-link lets the loader/validator pick up the coverage/cmp instrumentation that
# libFuzzer feeds on, without dragging the libFuzzer main() into the static lib.
SAN_BUILD="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS"

# Baseline x86-64 (NO -march=native) for portable, reproducible targets.
cmake -GNinja -B"$BUILD" -S"$SRC" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_C_FLAGS="$SAN_BUILD" \
  -DCMAKE_CXX_FLAGS="$SAN_BUILD -Wno-error" \
  -DWASMEDGE_USE_LLVM=OFF \
  -DWASMEDGE_BUILD_AOT_RUNTIME=OFF \
  -DWASMEDGE_BUILD_FUZZING=OFF \
  -DWASMEDGE_BUILD_TOOLS=OFF \
  -DWASMEDGE_BUILD_TESTS=OFF \
  -DWASMEDGE_BUILD_SHARED_LIB=OFF \
  -DWASMEDGE_BUILD_STATIC_LIB=ON \
  -DWASMEDGE_BUILD_PLUGINS=OFF \
  -DWASMEDGE_FORCE_DISABLE_LTO=ON

# Build only the static library target (pulls in loader/validator/common/etc. + fmt/spdlog).
# The CMake custom target that produces libwasmedge.a is `wasmedge_static_target`.
ninja -C "$BUILD" -j"$MAYHEM_JOBS" wasmedge_static_target

LIBWASMEDGE="$BUILD/lib/api/libwasmedge.a"
APIINC="$BUILD/include/api"          # generated public header lives here (wasmedge/wasmedge.h)
[ -f "$LIBWASMEDGE" ] || { echo "ERROR: $LIBWASMEDGE not produced" >&2; exit 1; }

mkdir -p "$OUT"

# ── 2) Build the harness twice: libFuzzer target (+ standalone reproducer) ─────────────────────────
# Compile the C harness to objects with $CC, then LINK with $CXX: libwasmedge.a is C++ (and carries
# UBSan vptr instrumentation, so the link must pull the C++ UBSan runtime via clang++ +
# $SANITIZER_FLAGS). -ldl: the loader's shared_library.cpp uses dlopen.
LINK_LIBS="-lpthread -lm -ldl"

$CC $SANITIZER_FLAGS $DEBUG_FLAGS -I"$APIINC" -c "$HARNESS_DIR/wasmedge_fuzz_loader.c" -o "$BUILD/wasmedge_fuzz_loader.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$HARNESS_DIR/standalone_main.c" -o "$BUILD/standalone_main.o"

# libFuzzer target -> $OUT/wasmedge_fuzz_loader
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS \
    "$BUILD/wasmedge_fuzz_loader.o" \
    $LIB_FUZZING_ENGINE "$LIBWASMEDGE" $LINK_LIBS \
    -o "$OUT/wasmedge_fuzz_loader"

# standalone reproducer (no libFuzzer runtime) -> $OUT/wasmedge_fuzz_loader-standalone
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS \
    "$BUILD/wasmedge_fuzz_loader.o" "$BUILD/standalone_main.o" \
    "$LIBWASMEDGE" $LINK_LIBS \
    -o "$OUT/wasmedge_fuzz_loader-standalone"

# ── 3) Build the golden load/validate oracle (for mayhem/test.sh) ──────────────────────────────────
# Built with NORMAL flags (no libFuzzer engine, no -fsanitize=fuzzer) against the SAME static lib so
# test.sh only RUNS it. The sanitizers stay on so the oracle still catches memory bugs on the golden
# inputs. Links the C++ runtime since libwasmedge.a is C++.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -I"$APIINC" -c "$HARNESS_DIR/oracle.c" -o "$BUILD/oracle.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$BUILD/oracle.o" "$LIBWASMEDGE" -lpthread -lm -ldl \
    -o "$BUILD/oracle"
echo "built load/validate oracle -> $BUILD/oracle"

echo "build.sh complete:"
ls -la "$OUT/wasmedge_fuzz_loader" "$OUT/wasmedge_fuzz_loader-standalone" "$BUILD/oracle"
