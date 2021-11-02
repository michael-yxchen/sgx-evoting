/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>

#include "app.h"

bool allocate_elgamal_buffers() {
  printf("[GatewayApp]: Allocating ElGamal buffers\n");
  sealed_elgamal_key_buffer = calloc(sealed_elgamal_key_buffer_size, 1);
  elgamal_key_buffer = calloc(elgamal_key_buffer_size, 1);

  if (sealed_elgamal_key_buffer == NULL || elgamal_key_buffer == NULL) {
    fprintf(stderr, "[GatewayApp]: allocate_elgamal_buffers() memory "
                    "allocation failure\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
  }

  return (sgx_lasterr == SGX_SUCCESS);
}

bool allocate_election_buffers() {
  printf("[GatewayApp]: Allocating ElGamal buffers\n");
  sealed_election_buffer = calloc(sealed_election_buffer_size, 1);

  bulletin_buffer = calloc(bulletin_buffer_size, 1);

  if (sealed_election_buffer == NULL) {
    fprintf(stderr, "[GatewayApp]: allocate_election_buffers() memory "
                    "allocation failure\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
  }

  return (sgx_lasterr == SGX_SUCCESS);
}

void cleanup_elgamal_buffers() {
  printf("[GatewayApp]: Deallocating elgamal buffers\n");

  if (sealed_elgamal_key_buffer != NULL) {
    free(sealed_elgamal_key_buffer);
    sealed_elgamal_key_buffer = NULL;
  }

  if (elgamal_key_buffer != NULL) {
    free(elgamal_key_buffer);
    elgamal_key_buffer = NULL;
  }
}
