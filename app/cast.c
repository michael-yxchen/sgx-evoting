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

bool enclave_cast_election(const char* voterid) {
  sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;

  printf("[GatewayApp]: Calling CAST ecall to cast ballot %s\n", voterid);

  
  
  sgx_lasterr =
      ecall_cast(enclave_id, &ecall_retval, enc_ballot_buffer, enc_ballot_buffer_size,
                 user_sign_buffer, user_sign_buffer_size, election_hash_buffer, election_hash_buffer_size, sealed_election_buffer,
                 sealed_election_buffer_size, sealed_election_buffer,
                 sealed_election_buffer_size, voterid);
  if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != SGX_SUCCESS)) {
    fprintf(stderr, "[GatewayApp]: ERROR: ecall_cast returned %d\n",
            ecall_retval);
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
  }

  return (sgx_lasterr == SGX_SUCCESS);
}
