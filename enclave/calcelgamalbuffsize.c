/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdarg.h>
#include <stdio.h>

#include "enclave.h"
#include <enclave_t.h>

#include <sgx_tcrypto.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>

/**
 * This function calculates the sizes of buffers needed for the untrusted app to
 * store data (public key, sealed private key and signature) from the enclave.
 *
 * @param epubkey_size            Output parameter for size of public key.
 * @param esealedprivkey_size     Output parameter for size of sealed private
 * key.
 * @param esignature_size         Output parameter for size of signature.
 *
 * @return                        SGX_SUCCESS (Error code = 0x0000) on success,
 * some other appropriate sgx_status_t value upon failure.
 */

sgx_status_t
ecall_calc_elgamal_buffer_sizes(size_t *e_elgamal_key_buffer_size,
                                size_t *e_sealed_elgamal_key_buffer_size) {
  *e_elgamal_key_buffer_size = 128;
  *e_sealed_elgamal_key_buffer_size = sgx_calc_sealed_data_size(0U, 128);
  print("\nTrustedApp: Sizes for sealed elgamal key pair "
        "calculated successfully.\n");
  return SGX_SUCCESS;
}
