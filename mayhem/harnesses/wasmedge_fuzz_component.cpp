// SPDX-License-Identifier: Apache-2.0
//
// wasmedge_fuzz_component — libFuzzer harness over WasmEdge's Component Model loader + validator.
// Same surface as upstream tools/fuzz/component.cpp: with the Component proposal on, parseWasmUnit()
// routes through the component decoder (AST::Component) and the component validator. It uses the
// internal C++ API because the C API only parses core modules.

#include "common/configure.h"
#include "common/span.h"
#include "loader/loader.h"
#include "validator/validator.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <variant>

extern "C" int __lsan_is_turned_off() { return 1; }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  WasmEdge::Configure Conf;
  Conf.addProposal(WasmEdge::Proposal::Component);

  WasmEdge::Loader::Loader Loader(Conf);
  auto ParseResult =
      Loader.parseWasmUnit(WasmEdge::Span<const uint8_t>(Data, Size));
  if (!ParseResult) {
    return 0;
  }

  auto &Unit = *ParseResult;
  WasmEdge::Validator::Validator Validator(Conf);
  if (auto *Comp =
          std::get_if<std::unique_ptr<WasmEdge::AST::Component::Component>>(
              &Unit)) {
    Validator.validate(**Comp);
  } else if (auto *Mod =
                 std::get_if<std::unique_ptr<WasmEdge::AST::Module>>(&Unit)) {
    Validator.validate(**Mod);
  }

  return 0;
}
