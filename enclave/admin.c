/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdarg.h>
#include <stdio.h>

#include <enclave_t.h>
#include "enclave.h"

#include <sgx_quote.h>
#include <sgx_tcrypto.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>
#include "sgx_tgmp.h"
#include <gmp.h>

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


// Key generator for our scheme
void generator_Gen(mpz_t g, mpz_t *primes, int sz){
	int seedg = 1; //rand();
	int cg, equal_1;
	mpz_t condition;
	int gen_true = 1, yeah = 0;
	mpz_t p_1;
	mpz_t pq_i;

	mpz_init(condition);
	mpz_init(p_1);
	mpz_init(pq_i);
	gmp_randstate_t rg_state;
	
   gmp_randinit_default(rg_state);
	gmp_randseed_ui(rg_state, seedg);
 	
 	mpz_sub_ui(p_1, primes[0], 1);

 	while( gen_true == 1){
 		mpz_urandomm(g, rg_state, primes[0]);
 		for (cg = 1; cg < sz; ++cg){
 			mpz_cdiv_q(pq_i, p_1, primes[cg]);
 			mpz_powm(condition, g, pq_i, primes[0]);
 			equal_1 = mpz_cmp_ui(condition, 1);
 			if( equal_1 == 0){
 				yeah = 1;
 				cg = sz;
 			}
 		}
 		if(yeah == 0)
 			gen_true = 0;
 		else
 			yeah = 0;
 	}

 	mpz_cdiv_q(pq_i, p_1, primes[1]);
 	mpz_powm(g, g, pq_i, primes[0]);
 	mpz_clear(condition);
 	mpz_clear(p_1);
 	mpz_clear(pq_i);

}

// Key generator for Elgamal
void Elgamal_Gen(mpz_t sk, mpz_t pk, mpz_t g, mpz_t modulus){	
	int seedx = 1; //rand();
	gmp_randstate_t ry_state;
	
  gmp_randinit_default(ry_state);
	gmp_randseed_ui(ry_state, seedx);
 	
 	mpz_urandomm(sk, ry_state, modulus);
 	mpz_powm(pk, g, sk, modulus);
	gmp_randclear(ry_state);
}

// Encryption function for Elgamal
void Elgamal_encrypt(mpz_t cipher0, mpz_t cipher1, mpz_t message, mpz_t pk, mpz_t g, mpz_t modulus){
	int seedy = 1; //rand();
	
	mpz_t y;
	mpz_t pky;
	gmp_randstate_t ry_state;
	
	mpz_init(y);
	mpz_init(pky);
    gmp_randinit_default(ry_state);
	gmp_randseed_ui(ry_state, seedy);
 	
 	mpz_urandomm(y,ry_state, modulus);
 	
 	mpz_powm(pky, pk, y, modulus);
 	mpz_mul(cipher0, message, pky);
 	mpz_mod(cipher0, cipher0, modulus);
 	mpz_powm(cipher1, g, y, modulus);

	mpz_clear(y);
	mpz_clear(pky);
	gmp_randclear(ry_state);
}

// Decryption function for Elgamal
void Elgamal_decrypt(mpz_t message,mpz_t cipher0, mpz_t cipher1, mpz_t sk, mpz_t modulus){
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

#define MPZ_WORDS_MAX 32
#define MPZ_WORDS_ORDER 1 /* Most significant order first */
#define MPZ_WORDS_ENDIANNESS 0 /* Use host endianness */
#define MPZ_NAILS 0 /* Use full words */

sgx_status_t ecall_key_gen_and_seal_all_elgamal(char *sealedkey, size_t sealed_key_size) {

		// Step 1: Open Context.
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	
		// Step 2: Generate El-Gamal KeyPair.
		char hardcoded_p[32] = {	0x7B, 0x9F, 0x4C, 0xA3, 0xF8, 0x8A, 0x0E, 0x1F,
															0x4A, 0x8C, 0xEE, 0x10, 0xBE, 0x72, 0x1E, 0x2B,
															0x78, 0xAC, 0x50, 0xE0, 0x1B, 0x92, 0x1C, 0x96,
															0x9D, 0xF5, 0xF1, 0x30, 0xDD, 0x9C, 0x81, 0x11 };

		char hardcoded_q[16] = {	0xED, 0xD8, 0x3C, 0x02, 0xE1, 0xC9, 0x5B, 0x6B,
															0xF0, 0x33, 0xB5, 0x1E, 0xEA, 0x87, 0xC0, 0x05 };
	
		char hardcoded_3[8] = {		0xDD, 0x51, 0x63, 0x42, 0x42, 0xB3, 0x4B, 0x07 };
		char hardcoded_4[6] = {		0x71, 0xCB, 0x28, 0xA8, 0x18, 0x21 };
		char hardcoded_5[3] = {		0x0F, 0x4C, 0x0F };
		char hardcoded_6[1] = {		0x03 };
		char hardcoded_7[1] = {		0x02 };
	
		mpz_t *array;
		array = (mpz_t*) malloc(7 * sizeof(mpz_t));
		for (int i = 0; i < 7; i++) {
			mpz_init(array[i]);
		}

		mpz_t q;
		mpz_t p;
		mpz_t v3, v4, v5, v6, v7;
	
		mpz_init(q);
		mpz_init(p);
		mpz_init(v3);
		mpz_init(v4);
		mpz_init(v5);
		mpz_init(v6);
		mpz_init(v7);
	
		/*
		mpz_set_str(array[0], "7918324333004779287780879909121159911537551977796076554305607309994905870203", 10);
		mpz_set_str(array[1], "7645817649953398726194923102564833517", 10);
		mpz_set_str(array[2], "525710878681813469", 10);
		mpz_set_str(array[3], "36389784177521", 10);
		mpz_set_str(array[4], "1002511", 10);
		mpz_set_str(array[5], "3", 10);
		mpz_set_str(array[6], "2", 10);
		*/
	
		mpz_import(p, 1, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS, MPZ_NAILS, hardcoded_p);
		mpz_import(q, 1, MPZ_WORDS_ORDER, 16, MPZ_WORDS_ENDIANNESS, MPZ_NAILS, hardcoded_q);
		mpz_import(v3, 1, MPZ_WORDS_ORDER, 8, MPZ_WORDS_ENDIANNESS, MPZ_NAILS, hardcoded_3);
		mpz_import(v4, 1, MPZ_WORDS_ORDER, 6, MPZ_WORDS_ENDIANNESS, MPZ_NAILS, hardcoded_4);
		mpz_import(v5, 1, MPZ_WORDS_ORDER, 3, MPZ_WORDS_ENDIANNESS, MPZ_NAILS, hardcoded_5);
		mpz_import(v6, 1, MPZ_WORDS_ORDER, 1, MPZ_WORDS_ENDIANNESS, MPZ_NAILS, hardcoded_6);
		mpz_import(v7, 1, MPZ_WORDS_ORDER, 1, MPZ_WORDS_ENDIANNESS, MPZ_NAILS, hardcoded_7);
	
		mpz_set(array[0], p);
		mpz_set(array[1], q);
		mpz_set(array[2], v3);
		mpz_set(array[3], v4);
		mpz_set(array[4], v5);
		mpz_set(array[5], v6);
		mpz_set(array[6], v7);
	
		/*for (int i = 0; i < 7; i++) {
			gmp_printf("[%d]: %Zd\n", i, array[i]);
		}*/

	  mpz_t g;
    mpz_t sk;
    mpz_t pk;
		mpz_init(g);
		mpz_init(sk);
		mpz_init(pk);
		
		generator_Gen(g, array, 7);
    Elgamal_Gen(sk, pk, g, p);

		/*gmp_printf("\nvalue of g: \n%Zd ", g);
		gmp_printf("\nvalue of mod: \n%Zd ", p);
		gmp_printf("\nvalue of pk: \n%Zd ", pk);
		gmp_printf("\nvalue of sk: \n%Zd\n", sk);*/
	
		char buffer[128];
		size_t buf_sz = 32;
	
    /* Exports p/g/pk/sk into buffer */
    mpz_export(&buffer[0], &buf_sz, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS, MPZ_NAILS, p);
		mpz_export(&buffer[32], &buf_sz, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS, MPZ_NAILS, g);
		mpz_export(&buffer[64], &buf_sz, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS, MPZ_NAILS, pk);
		mpz_export(&buffer[96], &buf_sz, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS, MPZ_NAILS, sk);
   
		int x = sealed_key_size;
		int length = snprintf( NULL, 0, "%d", x );
		char* str = malloc( length + 1 );
		snprintf( str, length + 1, "%d", x );
		//print(str);
		free(str);
	
    // Step 3: Calculate sealed data size.
    if (sealed_key_size >= sgx_calc_sealed_data_size(0U, sizeof(buffer))) {
        if ((ret = sgx_seal_data(
                 0U, NULL, sizeof(buffer), (uint8_t *)&buffer,
                 (uint32_t)sealed_key_size, 
                 (sgx_sealed_data_t *)sealedkey)) != SGX_SUCCESS) {
            print("\nTrustedApp: sgx_seal_data() failed !\n");
            goto cleanup;
        }
    } else {
        print(
            "\nTrustedApp: Size allocated for sealedelgamalkey by untrusted app "
            "is less than the required size !\n");
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto cleanup;
    }

    print(
        "\nTrustedApp: ELGAMAL Key pair generated and sealed\n");
    ret = SGX_SUCCESS;

cleanup:
    // Step 4: Close Context.
		mpz_clear(q);
		mpz_clear(p);
		mpz_clear(v3);
		mpz_clear(v4);
		mpz_clear(v5);
		mpz_clear(v6);
		mpz_clear(v7);
		mpz_clear(g);
		mpz_clear(sk);
		mpz_clear(pk);
		mpz_clear(array);

    return ret;
}


sgx_status_t ecall_key_gen_and_seal_aldl_elgamal(char *sealedpubkey,
                                        size_t sealedpubkey_size,
                                        char *sealedprivkey,
                                        size_t sealedprivkey_size) {
    // Step 1: Open Context.
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    sgx_ecc_state_handle_t p_ecc_handle = NULL;

    if ((ret = sgx_ecc256_open_context(&p_ecc_handle)) != SGX_SUCCESS) {
        print("\n[[TrustedApp]]: sgx_ecc256_open_context() failed !\n");
        goto cleanup;
    }

    // Step 2: Create Key Pair.
    sgx_ec256_private_t p_private;
    sgx_ec256_public_t p_public;
    if ((ret = sgx_ecc256_create_key_pair(&p_private, &p_public,
                                          p_ecc_handle)) != SGX_SUCCESS) {
        print("\n[[TrustedApp]]: sgx_ecc256_create_key_pair() failed !\n");
        goto cleanup;
    }

    // Step 3.1: Calculate sealed private key data size.
    if (sealedprivkey_size >=
        sgx_calc_sealed_data_size(0U, sizeof(p_private))) {
        if ((ret = sgx_seal_data(
                 0U, NULL, sizeof(p_private), (uint8_t *)&p_private,
                 (uint32_t)sealedprivkey_size,
                 (sgx_sealed_data_t *)sealedprivkey)) != SGX_SUCCESS) {
            print("\nTrustedApp: sgx_seal_data() failed !\n");
            goto cleanup;
        }
    } else {
        print(
            "\n[[TrustedApp]]: Size allocated for sealedprivkey by untrusted "
            "app "
            "is less than the required size !\n");
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto cleanup;
    }

    // Step 3.2: Calculate sealed public key data size.
    if (sealedpubkey_size >= sgx_calc_sealed_data_size(0U, sizeof(p_public))) {
        if ((ret = sgx_seal_data(
                 0U, NULL, sizeof(p_public), (uint8_t *)&p_public,
                 (uint32_t)sealedpubkey_size,
                 (sgx_sealed_data_t *)sealedpubkey)) != SGX_SUCCESS) {
            print("\n[[TrustedApp]]: sgx_seal_data() failed !\n");
            goto cleanup;
        }
    } else {
        print(
            "\n[[TrustedApp]]: Size allocated for sealedpubkey by untrusted "
            "app "
            "is less than the required size !\n");
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto cleanup;
    }

    print(
        "\n[[TrustedApp]]: ELGAMAL Key pair generated and private & public keys were "
        "sealed.\n");
    ret = SGX_SUCCESS;

cleanup:
    // Step 4: Close Context.
    if (p_ecc_handle != NULL) {
        sgx_ecc256_close_context(p_ecc_handle);
    }

    return ret;
}


