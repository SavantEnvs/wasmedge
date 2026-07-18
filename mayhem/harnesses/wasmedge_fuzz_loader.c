// SPDX-License-Identifier: Apache-2.0
//
// wasmedge_fuzz_loader — libFuzzer harness over WasmEdge's .wasm LOADER + VALIDATOR.
//
// This mirrors the fuzzed surface of upstream tools/fuzz/tool.cpp (WasmEdge_Driver_FuzzTool)
// MINUS the LLVM AOT/JIT codegen tail: that tail needs the heavy LLVM backend, and the
// attacker-controlled parse surface we care about (binary .wasm decode + static validation) is
// fully exercised by parseModule()+validate(). Scoping to the loader keeps the build LLVM-free.
//
// We drive the STABLE public C API (wasmedge.h) instead of the internal C++ Loader/Validator
// classes so the harness survives upstream refactors:
//   WasmEdge_LoaderParseFromBuffer  — decode the WASM binary into an AST module (the parser).
//   WasmEdge_ValidatorValidate      — type-check / structurally validate the decoded module.
// Both run with the default Configure (all proposals at upstream defaults). The module is freed
// every iteration; nothing is instantiated or executed.
//
// Input = a raw .wasm module body (the bytes a real loader would see). Not valid wasm is the
// common case and is handled as a clean parse error (returns, no crash) — exactly what we fuzz.

#include "wasmedge/wasmedge.h"
#include <stddef.h>
#include <stdint.h>

// Bake detect_leaks=0 into the binary (Mayhem owns the runtime ASAN_OPTIONS; this weak default is
// not overridden by it). WasmEdge's contexts are all explicitly deleted below, but the LSan default
// trips on benign one-time static initializations inside spdlog/fmt.
__attribute__((weak)) const char *__asan_default_options(void) {
  return "detect_leaks=0";
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  // uint32_t buffer length in the C API; clamp oversized inputs rather than truncate-wrapping.
  if (Size > 0x7fffffffu) {
    return 0;
  }

  WasmEdge_ConfigureContext *Conf = WasmEdge_ConfigureCreate();
  if (Conf == NULL) {
    return 0;
  }
  WasmEdge_LoaderContext *Loader = WasmEdge_LoaderCreate(Conf);
  WasmEdge_ValidatorContext *Validator = WasmEdge_ValidatorCreate(Conf);
  if (Loader == NULL || Validator == NULL) {
    if (Loader != NULL) WasmEdge_LoaderDelete(Loader);
    if (Validator != NULL) WasmEdge_ValidatorDelete(Validator);
    WasmEdge_ConfigureDelete(Conf);
    return 0;
  }

  WasmEdge_ASTModuleContext *Module = NULL;
  WasmEdge_Result Res = WasmEdge_LoaderParseFromBuffer(
      Loader, &Module, Data, (uint32_t)Size);

  if (WasmEdge_ResultOK(Res) && Module != NULL) {
    // Only validate a successfully-decoded module (matches the upstream FuzzTool flow).
    WasmEdge_ValidatorValidate(Validator, Module);
  }

  if (Module != NULL) {
    WasmEdge_ASTModuleDelete(Module);
  }
  WasmEdge_ValidatorDelete(Validator);
  WasmEdge_LoaderDelete(Loader);
  WasmEdge_ConfigureDelete(Conf);
  return 0;
}
