/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdarg.h>
#include <stdio.h>

#include "election_state.h"
#include "enclave.h"
#include <enclave_t.h>

#include "sgx_tgmp.h"
#include <gmp.h>
#include <sgx_quote.h>
#include <sgx_tcrypto.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>

sgx_status_t ecall_open(char *cmd, size_t cmd_size, char *signature,
                        size_t signature_size,
                        char *sealed_election_state_buffer,
                        size_t sealed_election_state_buffer_size) {

  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  election_state_t *election_state = NULL;
  uint32_t election_state_size = sizeof(*election_state);

  // Unseal election state
  if (sealed_election_state_buffer == NULL ||
      sealed_election_state_buffer_size == 0) {
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }
  {
    uint32_t unsealed_election_state_size = sgx_get_encrypt_txt_len(
        (const sgx_sealed_data_t *)sealed_election_state_buffer);
    if (unsealed_election_state_size != sizeof(*election_state)) {
      print("\nTrustedApp: sealed election state size mismatch !\n");
      ret = SGX_ERROR_INVALID_PARAMETER;
      goto cleanup;
    }
  }
  election_state = malloc(sizeof(*election_state));
  if (election_state == NULL) {
    print("\nTrustedApp: malloc(election_state) failed !\n");
    ret = SGX_ERROR_OUT_OF_MEMORY;
    goto cleanup;
  }
  memset_s(election_state, sizeof(*election_state), 0, sizeof(*election_state));

  if ((ret = sgx_unseal_data((sgx_sealed_data_t *)sealed_election_state_buffer,
                             NULL, NULL, (uint8_t *)election_state,
                             &election_state_size)) != SGX_SUCCESS) {
    print("\nTrustedApp: sgx_unseal_data() failed !\n");
    goto cleanup;
  }

  // Verify signature on ballot
  print("\nTrustedApp: verify_signature started !\n");
  {
    uint8_t result = 255;
    if ((ret = verify_signature((uint8_t *)cmd, (uint32_t)cmd_size,
                                election_state->admin_pk,
                                sizeof(election_state->admin_pk), signature,
                                signature_size, &result)) != SGX_SUCCESS) {
      print("\nTrustedApp: verify_signature failed !\n");
      goto cleanup;
    }
    printf("Signature verification result: %s", result == SGX_EC_VALID ? "True" : "False");
  }

  // Check command

  // Increment election state counter

  // Reseal election state

  print("\nTrustedApp: OPEN completed\n");
  ret = SGX_SUCCESS;

cleanup:
  // Step 4: Close Context.
  if (election_state) {
    free(election_state);
  }

  return ret;
}
