/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdarg.h>
#include <stdio.h>

#include "enclave.h"
#include <enclave_t.h>

#include "sgx_tgmp.h"
#include <gmp.h>
#include <sgx_quote.h>
#include <sgx_tcrypto.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>

/**
 * This function generates a key pair and then seals the private key.
 *
 * @param pubkey                 Output parameter for public key.
 * @param pubkey_size            Input parameter for size of public key.
 * @param sealedprivkey          Output parameter for sealed private key.
 * @param sealedprivkey_size     Input parameter for size of sealed private key.
 *
 * @return                       SGX_SUCCESS (Error code = 0x0000) on success,
 * some sgx_status_t value upon failure.
 */

#define MPZ_WORDS_MAX 32
#define MPZ_WORDS_ORDER 1      /* Most significant order first */
#define MPZ_WORDS_ENDIANNESS 0 /* Use host endianness */
#define MPZ_NAILS 0            /* Use full words */

sgx_status_t ecall_tally(char *sealedkey, size_t sealed_key_size) {

  // Step 1: Open Context.
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;

  print("\nTrustedApp: TALLY incomplete\n");
  ret = SGX_SUCCESS;

cleanup:
  // Step 4: Close Context.

  return ret;
}
