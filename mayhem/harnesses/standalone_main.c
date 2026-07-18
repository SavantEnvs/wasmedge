// SPDX-License-Identifier: Apache-2.0
//
// Standalone run-once driver: reads ONE input file and feeds it to LLVMFuzzerTestOneInput.
// Linked instead of the libFuzzer runtime to build a plain reproducer (./<target>-standalone <file>).
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *pData, size_t size);

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s <input-file>\n", argv[0]);
    return 1;
  }
  FILE *f = fopen(argv[1], "rb");
  if (f == NULL) {
    fprintf(stderr, "failed to open %s\n", argv[1]);
    return 2;
  }
  fseek(f, 0, SEEK_END);
  long size = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (size < 0) { fclose(f); return 3; }
  uint8_t *data = (uint8_t *)malloc((size_t)size + 1);
  if (data == NULL) { fclose(f); return 3; }
  size_t r = (size > 0) ? fread(data, (size_t)size, 1, f) : 0;
  fclose(f);
  if (size > 0 && r != 1) { free(data); fprintf(stderr, "read failed\n"); return 4; }
  LLVMFuzzerTestOneInput(data, (size_t)size);
  free(data);
  return 0;
}
