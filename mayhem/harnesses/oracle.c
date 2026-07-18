// SPDX-License-Identifier: Apache-2.0
//
// oracle.c — golden functional oracle over WasmEdge's fuzzed load/validate path (the SAME C API the
// fuzz harness drives). It is NOT a no-op stub: it asserts real behavioral invariants of the parser
// and validator, so a patch that breaks (or short-circuits) load/validate fails the build.
//
// Cases:
//   1. A known-good minimal valid module (preamble + an empty Type section) MUST load AND validate.
//   2. A module with the wrong magic ("\0asX") MUST be REJECTED by the loader (parse error).
//   3. A truncated module (bare preamble + a section id with a bogus oversized length) MUST be
//      rejected by the loader.
//   4. The empty input MUST be rejected (no preamble).
//   5. A structurally-decodable but TYPE-INVALID module — a function whose body just executes
//      `i32.add` on an empty stack — MUST load but FAIL validation. This exercises the validator
//      independently of the loader (the part a no-op "return OK" validator patch would break).
//
// Each case prints PASS/FAIL; main returns the number of failures.

#include "wasmedge/wasmedge.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int load_only(const uint8_t *buf, uint32_t len,
                     WasmEdge_ASTModuleContext **out) {
  WasmEdge_ConfigureContext *conf = WasmEdge_ConfigureCreate();
  WasmEdge_LoaderContext *ldr = WasmEdge_LoaderCreate(conf);
  WasmEdge_ASTModuleContext *mod = NULL;
  WasmEdge_Result r = WasmEdge_LoaderParseFromBuffer(ldr, &mod, buf, len);
  WasmEdge_LoaderDelete(ldr);
  WasmEdge_ConfigureDelete(conf);
  int ok = WasmEdge_ResultOK(r) && mod != NULL;
  if (out && ok) {
    *out = mod;
  } else if (mod) {
    WasmEdge_ASTModuleDelete(mod);
  }
  return ok;
}

static int validate_module(WasmEdge_ASTModuleContext *mod) {
  WasmEdge_ConfigureContext *conf = WasmEdge_ConfigureCreate();
  WasmEdge_ValidatorContext *val = WasmEdge_ValidatorCreate(conf);
  WasmEdge_Result r = WasmEdge_ValidatorValidate(val, mod);
  WasmEdge_ValidatorDelete(val);
  WasmEdge_ConfigureDelete(conf);
  return WasmEdge_ResultOK(r);
}

#define CHECK(name, cond)                                                      \
  do {                                                                         \
    if (cond) {                                                                \
      printf("PASS %s\n", name);                                               \
    } else {                                                                   \
      printf("FAIL %s\n", name);                                              \
      ++failures;                                                              \
    }                                                                          \
  } while (0)

int main(void) {
  int failures = 0;

  // Minimal VALID module: preamble + empty Type section (id 0x01, size 0x01, count 0x00).
  static const uint8_t good[] = {0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00,
                                 0x00, 0x01, 0x01, 0x00};
  WasmEdge_ASTModuleContext *gmod = NULL;
  int gload = load_only(good, sizeof(good), &gmod);
  CHECK("good_module_loads", gload);
  CHECK("good_module_validates", gload && gmod && validate_module(gmod));
  if (gmod) WasmEdge_ASTModuleDelete(gmod);

  // Wrong magic -> loader rejects.
  static const uint8_t badmagic[] = {0x00, 0x61, 0x73, 0x58, 0x01,
                                     0x00, 0x00, 0x00};
  CHECK("bad_magic_rejected", !load_only(badmagic, sizeof(badmagic), NULL));

  // Bogus oversized section length -> loader rejects.
  static const uint8_t truncated[] = {0x00, 0x61, 0x73, 0x6d, 0x01, 0x00,
                                       0x00, 0x00, 0x01, 0x7f};
  CHECK("truncated_section_rejected",
        !load_only(truncated, sizeof(truncated), NULL));

  // Empty input -> rejected.
  CHECK("empty_rejected", !load_only((const uint8_t *)"", 0, NULL));

  // Type-invalid module: one type () -> (), one func, code body = i32.add ; end.
  //   Type section:  01 04 01 60 00 00              (size 4: 1 functype, no params, no results)
  //   Func section:  03 02 01 00                    (size 2: 1 function, type 0)
  //   Code section:  0a 05 01 03 00 6a 0b           (size 5: 1 body of size 3 = 0 locals,
  //                                                  i32.add(0x6a), end(0x0b))
  // i32.add on an empty stack is a validation type error -> loads but MUST fail validation.
  static const uint8_t typebad[] = {
      0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,       // preamble
      0x01, 0x04, 0x01, 0x60, 0x00, 0x00,                   // type section
      0x03, 0x02, 0x01, 0x00,                               // function section
      0x0a, 0x05, 0x01, 0x03, 0x00, 0x6a, 0x0b};            // code section
  WasmEdge_ASTModuleContext *tmod = NULL;
  int tload = load_only(typebad, sizeof(typebad), &tmod);
  CHECK("typeinvalid_loads", tload);
  CHECK("typeinvalid_fails_validation", tload && tmod && !validate_module(tmod));
  if (tmod) WasmEdge_ASTModuleDelete(tmod);

  printf("oracle: %d failures\n", failures);
  return failures;
}
