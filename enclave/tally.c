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
#define MAX_SELECTIONS 10

// Decryption function for Elgamal
void Elgamal_decryptt(mpz_t message, mpz_t cipher0, mpz_t cipher1, mpz_t sk,
                     mpz_t modulus) {
  mpz_t gxy;
  mpz_t inv_gxy;

  mpz_init(gxy);
  mpz_init(inv_gxy);

  mpz_powm(gxy, cipher1, sk, modulus);
  mpz_invert(inv_gxy, gxy, modulus);
  mpz_mul(message, cipher0, inv_gxy);
  mpz_mod(message, message, modulus);

  mpz_clear(gxy);
  mpz_clear(inv_gxy);
}

sgx_status_t ecall_tally(char *sealed_election_state_buffer,
                        size_t sealed_election_state_buffer_size) {

  // Step 1: Context Definitions.
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  election_state_t *election_state = NULL;
  uint32_t election_state_size = sizeof(*election_state);

  // Step 2: Unseal Election State.
  if (sealed_election_state_buffer == NULL ||
      sealed_election_state_buffer_size == 0) {
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }
  {
    uint32_t unsealed_election_state_size = sgx_get_encrypt_txt_len(
        (const sgx_sealed_data_t *)sealed_election_state_buffer);
    if (unsealed_election_state_size != sizeof(*election_state)) {
      print("\n[TrustedApp][TALLY]: Sealed election state size mismatch !\n");
      ret = SGX_ERROR_INVALID_PARAMETER;
      goto cleanup;
    }
  }
  election_state = malloc(sizeof(*election_state));
  if (election_state == NULL) {
    print("\n[TrustedApp][TALLY]: malloc(election_state) failed !\n");
    ret = SGX_ERROR_OUT_OF_MEMORY;
    goto cleanup;
  }
  memset_s(election_state, sizeof(*election_state), 0, sizeof(*election_state));

  if ((ret = sgx_unseal_data((sgx_sealed_data_t *)sealed_election_state_buffer,
                             NULL, NULL, (uint8_t *)election_state,
                             &election_state_size)) != SGX_SUCCESS) {
    print("\n[TrustedApp][TALLY]: sgx_unseal_data() failed !\n");
    goto cleanup;
  }

  // Step 3: Initialize Tally Structures.
  int obama_tally = 0;
  int trump_tally = 0;
  int john_tally = 0;
  int joe_tally = 0;

  // Step 4: Extract and Initialize ElGamal Context.
  mpz_t p;
  mpz_t g;
  mpz_t sk;
  mpz_t pk;
  mpz_t ciphertext_0;
  mpz_t ciphertext_1;
  mpz_t decrypted_ciphertext;
  mpz_init(p);
  mpz_init(g);
  mpz_init(sk);
  mpz_init(pk);
  mpz_import(p, 1, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS, MPZ_NAILS, election_state->p);
  mpz_import(g, 1, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS, MPZ_NAILS, election_state->g);
  mpz_import(pk, 1, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS, MPZ_NAILS, election_state->pk);
  mpz_import(sk, 1, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS, MPZ_NAILS, election_state->sk);
  mpz_init(ciphertext_0);
  mpz_init(ciphertext_1);
  mpz_init(decrypted_ciphertext);


  // Step 5.1: Tally Voter1's Ballot.
  unsigned char *encrypted_ballot_buffer;
  encrypted_ballot_buffer = election_state->v1_ballot;
  mpz_import(ciphertext_0, 1, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS, MPZ_NAILS, &encrypted_ballot_buffer[0]);
  mpz_import(ciphertext_1, 1, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS, MPZ_NAILS, &encrypted_ballot_buffer[32]);

  Elgamal_decryptt(decrypted_ciphertext, ciphertext_0, ciphertext_1, sk, p);

  char decrypted_ballot_buffer[MAX_SELECTIONS+1];
  size_t decrypted_buffer_sz = MAX_SELECTIONS;
  size_t num_selections = 2;

  mpz_export(&decrypted_ballot_buffer[0], &decrypted_buffer_sz, MPZ_WORDS_ORDER, num_selections, MPZ_WORDS_ENDIANNESS, MPZ_NAILS, decrypted_ciphertext);

  printf("[TrustedApp][TALLY]: Voter1 Ballot %d %d\n", decrypted_ballot_buffer[0], decrypted_ballot_buffer[1]);
  if(decrypted_ballot_buffer[0] == 1)
    obama_tally++;
  else 
    trump_tally++;

  if(decrypted_ballot_buffer[1] == 1)
    john_tally++;
  else
    joe_tally++;


  // Step 5.2: Tally Voter2's Ballot.
  encrypted_ballot_buffer = election_state->v2_ballot;
  mpz_import(ciphertext_0, 1, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS, MPZ_NAILS, &encrypted_ballot_buffer[0]);
  mpz_import(ciphertext_1, 1, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS, MPZ_NAILS, &encrypted_ballot_buffer[32]);

  Elgamal_decryptt(decrypted_ciphertext, ciphertext_0, ciphertext_1, sk, p);

  mpz_export(&decrypted_ballot_buffer[0], &decrypted_buffer_sz, MPZ_WORDS_ORDER, num_selections, MPZ_WORDS_ENDIANNESS, MPZ_NAILS, decrypted_ciphertext);

  printf("[TrustedApp][TALLY]: Voter2 Ballot %d %d\n", decrypted_ballot_buffer[0], decrypted_ballot_buffer[1]);
  if(decrypted_ballot_buffer[0] == 1)
    obama_tally++;
  else 
    trump_tally++;

  if(decrypted_ballot_buffer[1] == 1)
    john_tally++;
  else
    joe_tally++;

  // Step 5.3: Tally Voter3's Ballot.
  encrypted_ballot_buffer = election_state->v3_ballot;
  mpz_import(ciphertext_0, 1, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS, MPZ_NAILS, &encrypted_ballot_buffer[0]);
  mpz_import(ciphertext_1, 1, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS, MPZ_NAILS, &encrypted_ballot_buffer[32]);

  Elgamal_decryptt(decrypted_ciphertext, ciphertext_0, ciphertext_1, sk, p);

  mpz_export(&decrypted_ballot_buffer[0], &decrypted_buffer_sz, MPZ_WORDS_ORDER, num_selections, MPZ_WORDS_ENDIANNESS, MPZ_NAILS, decrypted_ciphertext);

  printf("[TrustedApp][TALLY]: Voter3 Ballot %d %d\n", decrypted_ballot_buffer[0], decrypted_ballot_buffer[1]);
  if(decrypted_ballot_buffer[0] == 1)
    obama_tally++;
  else 
    trump_tally++;

  if(decrypted_ballot_buffer[1] == 1)
    john_tally++;
  else
    joe_tally++;


  /* [Debugging]: Hardcoded Encrypted Ballot */
  /*char *bal = "B603DE8E7EE60B5D9FD0A41D4ECD659B5A45F9CA9E2C94DE86D4B857D601BF0B356F1522EC624D353EC6D5493FAF75041ED2834D3ADCB46597E3DE887F36A204";
  size_t len = 128;
  size_t final_len = len / 2;
  unsigned char chrsw[65];
  for (size_t i=0, j=0; j<final_len; i+=2, j++)
      chrsw[j] = (bal[i] % 32 + 9) % 25 * 16 + (bal[i+1] % 32 + 9) % 25;
  */

  /* [Debugging] to inspect key material */
  /*char buffr[128];
  size_t buf_sz2 = 32;
  mpz_export(&buffr[0], &buf_sz2, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS,
             MPZ_NAILS, p);
  mpz_export(&buffr[32], &buf_sz2, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS,
             MPZ_NAILS, g);
  mpz_export(&buffr[64], &buf_sz2, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS,
             MPZ_NAILS, pk);
  mpz_export(&buffr[96], &buf_sz2, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS,
             MPZ_NAILS, sk);

  for(int i = 0; i < 32; i++) {
    printf("%hhx", buffr[i]);
  }
  printf("\n");
  for(int i = 0; i < 32; i++) {
    printf("%hhx", buffr[i+32]);
  }
  printf("\n");
  for(int i = 0; i < 32; i++) {
    printf("%hhx", buffr[i+64]);
  }
  printf("\n");
  for(int i = 0; i < 32; i++) {
    printf("%hhx", buffr[i+96]);
  }
  printf("\n");*/

  printf("[TrustedApp][TALLY]: FINAL TALLY: \n     [Who should be the next president?] [Obama][%d], [Trump][%d]\n     [Who should be the next mayor?]     [John] [%d], [Joe]  [%d]\n", obama_tally, trump_tally, john_tally, joe_tally);


  // [TODO] Step 6: Update Election State and Bulletin Board. 

  print("[TrustedApp][TALLY]: Completed.\n");
  ret = SGX_SUCCESS;

cleanup:
  // Step 7: Release Memory.
  if (election_state) {
    free(election_state);
  }
  mpz_clear(p);
  mpz_clear(g);
  mpz_clear(sk);
  mpz_clear(pk);
  mpz_clear(ciphertext_0);
  mpz_clear(ciphertext_1);
  mpz_clear(decrypted_ciphertext);

  return ret;
}
