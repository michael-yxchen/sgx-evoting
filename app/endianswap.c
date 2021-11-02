/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <openssl/bn.h>

#include "app.h"
#include "endianswap.h"

BIGNUM *bignum_from_little_endian_bytes_32(const uint8_t *const bytes) {
  /* Create BIGNUM from raw (little endian) bytes
     without using memcpy (static scanner requirement) */
  uint8_t copied_bytes[32];
  for (size_t i = 0; i < sizeof(copied_bytes); ++i) {
    copied_bytes[i] = bytes[i];
  }

  SWAP_ENDIAN_8X32B(copied_bytes);
  BIGNUM *bn = BN_bin2bn(copied_bytes, sizeof(copied_bytes), NULL);
  return bn;
}
