#!/usr/bin/env bash
#
# wasmedge/mayhem/test.sh — RUN the golden load/validate oracle (built by mayhem/build.sh) and emit a
# CTRF summary. exit 0 iff every oracle case passes.
#
# PATCH-grade oracle: mayhem/harnesses/oracle.c drives the SAME public C API the fuzz harness fuzzes
# (WasmEdge_LoaderParseFromBuffer + WasmEdge_ValidatorValidate) and asserts real behavioral
# invariants — a good module loads+validates, bad magic / truncated / empty modules are rejected, and
# a structurally-decodable but type-invalid module loads yet FAILS validation. A no-op / "always OK"
# patch to the loader or validator cannot pass all of these. This script only RUNS the pre-built
# binary; it never compiles.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

SRC="${SRC:-/mayhem}"
cd "$SRC"
ORACLE="$SRC/mayhem-build/oracle"

# emit_ctrf <tool> <passed> <failed> [skipped]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}"
  local tests=$(( passed + failed + skipped ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": 0,
      "skipped": $skipped,
      "other": 0
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":0,"skipped":%d,"other":0}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$skipped"
  [ "$failed" -eq 0 ]
}

if [ ! -x "$ORACLE" ]; then
  echo "missing $ORACLE — run mayhem/build.sh first" >&2
  emit_ctrf "wasmedge-load-validate" 0 1 0; exit 2
fi

echo "=== running load/validate oracle ($ORACLE) ==="
out="$("$ORACLE" 2>&1)"; rc=$?
echo "$out"

PASSED=$(printf '%s\n' "$out" | grep -c '^PASS ')
FAILED=$(printf '%s\n' "$out" | grep -c '^FAIL ')
: "${PASSED:=0}" "${FAILED:=0}"

# If the oracle crashed (sanitizer abort) without printing any PASS/FAIL lines, count it as a failure.
if [ "$(( PASSED + FAILED ))" -eq 0 ]; then
  echo "oracle produced no PASS/FAIL lines (exit $rc)" >&2
  emit_ctrf "wasmedge-load-validate" 0 1 0; exit 1
fi

# A nonzero oracle exit with no FAIL line parsed (e.g. sanitizer abort after some PASSes) is a failure.
if [ "$FAILED" -eq 0 ] && [ "$rc" -ne 0 ]; then
  echo "oracle exited $rc despite no FAIL line — treating as failure" >&2
  emit_ctrf "wasmedge-load-validate" "$PASSED" 1 0; exit 1
fi

emit_ctrf "wasmedge-load-validate" "$PASSED" "$FAILED" 0
