/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdlib.h>

#include <enclave_u.h> /* For sgx_enclave_id_t */

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>

#include "app.h"

bool enclave_tally_election() {
  sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;

  printf("[GatewayApp][TALLY]: Calling TALLY ecall to tally election\n");

  sgx_lasterr =
      ecall_tally(enclave_id, &ecall_retval, sealed_election_buffer, sealed_election_buffer_size);
  if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != SGX_SUCCESS)) {
    fprintf(stderr, "[GatewayApp][TALLY]: ERROR: ecall_tally returned %d\n",
            ecall_retval);
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
  }

  return (sgx_lasterr == SGX_SUCCESS);
}
