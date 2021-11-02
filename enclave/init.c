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

#include "sgx_tcrypto.h"
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

sgx_status_t ecall_init(char *sealed, size_t sealed_size,

                        char *ballot_buffer, size_t ballot_buffer_size,
                        char *admin_key_buffer, size_t admin_key_buffer_size,
                        char *voter1_key_buffer, size_t voter1_key_buffer_size,
                        char *voter2_key_buffer, size_t voter2_key_buffer_size,
                        char *voter3_key_buffer, size_t voter3_key_buffer_size,
                        char *bulletin_buffer, size_t bulletin_buffer_size,
                        char *sealed_election_buffer,
                        size_t sealed_election_buffer_size) {

  // Step 1: Open Context.
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;

  // Step 1: Calculate sealed/encrypted data length.
  uint32_t unsealed_data_size =
      sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed);
  int ballot_off = 0;
  size_t opt_off = 0;
  election_state_t election_state = {0};
  /*
  int x = unsealed_data_size;
  int length = snprintf( NULL, 0, "%d", x );
  char* str = malloc( length + 1 );
  snprintf( str, length + 1, "%d", x );
  print(str);
  free(str);
  */

  // unsealed_data_size = 128;
  uint8_t *const unsealed_data =
      (uint8_t *)malloc(unsealed_data_size); // Check malloc return;
  if (unsealed_data == NULL) {
    print("\nTrustedApp: malloc(unsealed_data_size) failed !\n");
    goto cleanup;
  }

  // Step 2: Unseal public key, and copy into report data
  if ((ret = sgx_unseal_data((sgx_sealed_data_t *)sealed, NULL, NULL,
                             unsealed_data, &unsealed_data_size)) !=
      SGX_SUCCESS) {
    print("\nTrustedApp: sgx_unseal_data() failed !\n");
    goto cleanup;
  }

  mpz_t p;
  mpz_t g;
  mpz_t sk;
  mpz_t pk;
  mpz_init(p);
  mpz_init(g);
  mpz_init(sk);
  mpz_init(pk);
  mpz_import(p, 1, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS, MPZ_NAILS,
             &unsealed_data[0]);
  mpz_import(g, 1, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS, MPZ_NAILS,
             &unsealed_data[32]);
  mpz_import(pk, 1, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS, MPZ_NAILS,
             &unsealed_data[64]);
  mpz_import(sk, 1, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS, MPZ_NAILS,
             &unsealed_data[96]);

  print("\n[TrustedApp]: INIT completed\n");

  assert(sizeof(election_state.admin_pk) == admin_key_buffer_size);
  for (size_t i = 0; i < sizeof(election_state.admin_pk); ++i) {
    election_state.admin_pk[i] = ((uint8_t *)admin_key_buffer)[i];
  }

  assert(sizeof(election_state.v1_pk) == voter1_key_buffer_size);
  for (size_t i = 0; i < sizeof(election_state.v1_pk); ++i) {
    election_state.v1_pk[i] = ((uint8_t *)voter1_key_buffer)[i];
  }

  assert(sizeof(election_state.v2_pk) == voter2_key_buffer_size);
  for (size_t i = 0; i < sizeof(election_state.v2_pk); ++i) {
    election_state.v2_pk[i] = ((uint8_t *)voter2_key_buffer)[i];
  }

  assert(sizeof(election_state.v3_pk) == voter3_key_buffer_size);
  for (size_t i = 0; i < sizeof(election_state.v3_pk); ++i) {
    election_state.v3_pk[i] = ((uint8_t *)voter3_key_buffer)[i];
  }

  election_state.ballot_len = ((uint8_t *)ballot_buffer)[0];
  ballot_off += 2;

  opt_off = 0;
  while (ballot_buffer[ballot_off] != '\n') {
    if (opt_off < sizeof(election_state.opt1)) {
      election_state.opt1[opt_off] = ballot_buffer[ballot_off];
      ++opt_off;
    }
    ++ballot_off;
  }
  ++ballot_off;

  opt_off = 0;
  while (ballot_buffer[ballot_off] != '\n') {
    if (opt_off < sizeof(election_state.opt2)) {
      election_state.opt2[opt_off] = ballot_buffer[ballot_off];
      ++opt_off;
    }
    ++ballot_off;
  }
  ++ballot_off;

  opt_off = 0;
  while (ballot_buffer[ballot_off] != '\n') {
    if (opt_off < sizeof(election_state.opt3)) {
      election_state.opt3[opt_off] = ballot_buffer[ballot_off];
      ++opt_off;
    }
    ++ballot_off;
  }
  ++ballot_off;

  for (size_t i = 0; i < sizeof(election_state.p); ++i) {
    election_state.p[i] = unsealed_data[i];
    election_state.g[i] = unsealed_data[32 + i];
    election_state.pk[i] = unsealed_data[64 + i];
    election_state.sk[i] = unsealed_data[96 + i];
  }

  if ((ret = sgx_sha256_msg(
           (const uint8_t*)&election_state,
           (char *)&(election_state.sk) - (char *)&election_state,
           (sgx_sha256_hash_t *)&election_state.election_hash)) !=
      SGX_SUCCESS) {
    print("\nTrustedApp: sgx_sha256_init failed !\n");
    goto cleanup;
  }

  election_state.state_counter = vt_registered;

  // int temp = sgx_calc_sealed_data_size(0U, sizeof(election_state));
  // int x = temp;
  // int length = snprintf(NULL, 0, "%d", x);
  // char *str = malloc(length + 1);
  // snprintf(str, length + 1, "%d", x);
  // print(str);
  // free(str);

  // Step 3: Calculate sealed data size.
  if (sealed_election_buffer_size >=
      sgx_calc_sealed_data_size(0U, sizeof(election_state))) {
    if ((ret = sgx_seal_data(
             0U, NULL, sizeof(election_state), (uint8_t *)&election_state,
             (uint32_t)sealed_election_buffer_size,
             (sgx_sealed_data_t *)sealed_election_buffer)) != SGX_SUCCESS) {
      print("\nTrustedApp: sgx_seal_data() failed !\n");
      goto cleanup;
    }
  } else {
    print("\n[TrustedApp]: Size allocated for sealedelgamalkey by "
          "untrusted app "
          "is less than the required size !\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  {
    bulletin_board_t *bb = (bulletin_board_t *)bulletin_buffer;
    assert(sizeof(bulletin_board_t) <= bulletin_buffer_size);
    for (size_t i = 0; i < sizeof(election_state.election_hash); ++i) {
      bb->election_hash[i] = election_state.election_hash[i];
    }

    assert(ballot_buffer_size <= sizeof(bb->ballot));
    for (size_t i = 0; i < ballot_buffer_size; i++) {
      bb->ballot[i] = ballot_buffer[i];
    }

    for (size_t i = 0; i < sizeof(election_state.p); ++i) {
      bb->p[i] = election_state.p[i];
      bb->g[i] = election_state.g[i];
      bb->pk[i] = election_state.pk[i];
    }
  }

  ret = SGX_SUCCESS;

cleanup:
  // Step 4: Close Context.
  if (unsealed_data) {
    free(unsealed_data);
  }


  return ret;
}
