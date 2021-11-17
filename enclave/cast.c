/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

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

sgx_status_t ecall_cast(char *bal, size_t bal_size, char *signature,
                        size_t signature_size,
                        char *hash, size_t hash_size,
                        char *sealed_election_state_buffer,
                        size_t sealed_election_state_buffer_size, char *sealed_election_buffer,
                        size_t sealed_election_buffer_size, char* voterid) {

  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  election_state_t *election_state = NULL;
  uint32_t election_state_size = sizeof(*election_state);
  int voter = atoi(voterid);

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
      print("[TrustedApp][CAST]: sealed election state size mismatch !\n");
      ret = SGX_ERROR_INVALID_PARAMETER;
      goto cleanup;
    }
  }
  election_state = malloc(sizeof(*election_state));
  if (election_state == NULL) {
    print("[TrustedApp][CAST]: malloc(election_state) failed !\n");
    ret = SGX_ERROR_OUT_OF_MEMORY;
    goto cleanup;
  }
  memset_s(election_state, sizeof(*election_state), 0, sizeof(*election_state));

  if ((ret = sgx_unseal_data((sgx_sealed_data_t *)sealed_election_state_buffer,
                             NULL, NULL, (uint8_t *)election_state,
                             &election_state_size)) != SGX_SUCCESS) {
    print("[TrustedApp][CAST]: sgx_unseal_data() failed !\n");
    goto cleanup;
  }

  // Verify signature on ballot
  print("[TrustedApp][CAST]: Started verify_signature.\n");
  {
    uint8_t result = 255;
    if ((ret = verify_signature((uint8_t *)bal, (uint32_t)bal_size,
                                voter == 1 ? election_state->v1_pk : (voter == 2 ? election_state->v2_pk : election_state->v3_pk),
                                sizeof(voter == 1 ? election_state->v1_pk : (voter == 2 ? election_state->v2_pk : election_state->v3_pk)), signature,
                                signature_size, &result)) != SGX_SUCCESS) {
      print("[TrustedApp][CAST]: verify_signature failed !\n");
      goto cleanup;
    }
    printf("[TrustedApp][CAST]: Signature verification result: %s\n", result == SGX_EC_VALID ? "True" : "False");
  }

  printf("[TrustedApp][CAST]: EncBallot %c%c%c%c....%c%c%c%c\n", bal[0], bal[1], bal[2], bal[3], bal[124], bal[125], bal[126], bal[127]);

  size_t len = 128;
  size_t final_len = len / 2;
  unsigned char *chrs;

  //printf("[%d]\n", voter);
  if(voter == 1) 
    chrs = &election_state->v1_ballot[0];
  if(voter == 2)
    chrs = &election_state->v2_ballot[0];
  if(voter == 3)
    chrs = &election_state->v3_ballot[0];
  for (size_t i=0, j=0; j<final_len; i+=2, j++)
      chrs[j] = (bal[i] % 32 + 9) % 25 * 16 + (bal[i+1] % 32 + 9) % 25;
  



  //printf("First hexstring %c%c, first byte %d\n", bal[0], bal[1], chrs[0]);
  print("[TrustedApp][CAST]: Storing ballot.\n");
  // Check command

  // Increment election state counter

  // Reseal election state
  // Step 3: Calculate sealed data size.
  if (sealed_election_buffer_size >=
      sgx_calc_sealed_data_size(0U, sizeof(*election_state))) {
    if ((ret = sgx_seal_data(
             0U, NULL, sizeof(*election_state), (uint8_t *)election_state,
             (uint32_t)sealed_election_buffer_size,
             (sgx_sealed_data_t *)sealed_election_buffer)) != SGX_SUCCESS) {
      print("[TrustedApp][CAST]: sgx_seal_data() failed !\n");
      goto cleanup;
    }
  } else {
    print("[TrustedApp][CAST]: Size allocated for sealedelgamalkey by "
          "untrusted app "
          "is less than the required size !\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  print("[TrustedApp][CAST]: Completed.\n");
  ret = SGX_SUCCESS;

cleanup:
  // Step 4: Close Context.
  if (election_state) {
    free(election_state);
  }

  return ret;
}
