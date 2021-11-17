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

sgx_status_t ecall_close(char *cmd, size_t cmd_size, char *signature,
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
      print("[TrustedApp][CLOSE]: sealed election state size mismatch !\n");
      ret = SGX_ERROR_INVALID_PARAMETER;
      goto cleanup;
    }
  }
  election_state = malloc(sizeof(*election_state));
  if (election_state == NULL) {
    print("[TrustedApp][CLOSE]: malloc(election_state) failed !\n");
    ret = SGX_ERROR_OUT_OF_MEMORY;
    goto cleanup;
  }
  memset_s(election_state, sizeof(*election_state), 0, sizeof(*election_state));

  if ((ret = sgx_unseal_data((sgx_sealed_data_t *)sealed_election_state_buffer,
                             NULL, NULL, (uint8_t *)election_state,
                             &election_state_size)) != SGX_SUCCESS) {
    print("[TrustedApp][CLOSE]: sgx_unseal_data() failed !\n");
    goto cleanup;
  }

  // Verify signature on ballot
  print("[TrustedApp][CLOSE]: verify_signature started !\n");
  {
    uint8_t result = 255;
    if ((ret = verify_signature((uint8_t *)cmd, (uint32_t)cmd_size,
                                election_state->admin_pk,
                                sizeof(election_state->admin_pk), signature,
                                signature_size, &result)) != SGX_SUCCESS) {
      print("[TrustedApp][CLOSE]: verify_signature failed !\n");
      goto cleanup;
    }
    printf("[TrustedApp][CLOSE]: Signature verification result: %s\n", result == SGX_EC_VALID ? "True" : "False");
  }

  // Check command

  // Increment election state counter

  // Reseal election state

  print("[TrustedApp][CLOSE]: Completed.\n");
  ret = SGX_SUCCESS;

cleanup:
  // Step 4: Close Context.
  if (election_state) {
    free(election_state);
  }

  return ret;
}
