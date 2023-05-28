#include <stdio.h>

#include "utils.h"

void printHex(const char* s, const uint8_t* data, size_t len) {
  printf("%s: ", s);
  for (size_t i = 0; i < len; i++) {
    printf("%02X", data[i]);
  }
  printf("\n");
}

int printUint8Arr(uint8_t* arr, uint32_t unitSize, uint32_t len) {
  for (uint32_t i = 0; i < len; i++) {
    for (uint32_t j = 0; j < unitSize; j++) {
      printf("%.2x", *(arr + (i * unitSize) + j));
    }
    printf("\n");
  }
  return 1;
}

void xorUint8Arr(const uint8_t* a, const uint8_t* b, uint8_t* out, size_t len) {
  for (size_t i = 0; i < len; i++) {
    out[i] = a[i] ^ b[i];
  }
}

// TODO: hopefully takes care of the endianness
uint8_t getBit(const uint8_t* src, uint32_t idx) {
  // return (*src & (1 << (7 - idx))) >> (7 - idx);
  return (*src >> (7 - idx)) & 1;
}