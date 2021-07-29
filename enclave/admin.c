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

sgx_status_t ecall_key_gen_and_seal_elgamal(char *pubkey, size_t pubkey_size,
                                    char *sealedprivkey,
                                    size_t sealedprivkey_size) {
    // Step 1: Open Context.
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    sgx_ecc_state_handle_t p_ecc_handle = NULL;
    
    mpz_t g;
    mpz_t p;
    mpz_t sk;
    mpz_t pk;

    mpz_init(g); 
    mpz_init(p);
    mpz_init(pk);
    mpz_init(sk);
    
    Elgamal_Gen(sk, pk, g, p);

    //gmp_printf("\nvalue of g: \n%Zd ", g);
    //gmp_printf("\nvalue of mod: \n%Zd ", p);
    //gmp_printf("\nvalue of pk: \n%Zd ", pk);
    //gmp_printf("\nvalue of sk: \n%Zd\n", sk);
    
    if ((ret = sgx_ecc256_open_context(&p_ecc_handle)) != SGX_SUCCESS) {
        print("\nTrustedApp: sgx_ecc256_open_context() failed !\n");
        goto cleanup;
    }

    // Step 2: Create Key Pair.
    sgx_ec256_private_t p_private;
    if ((ret = sgx_ecc256_create_key_pair(
             &p_private, (sgx_ec256_public_t *)pubkey, p_ecc_handle)) !=
        SGX_SUCCESS) {
        print("\nTrustedApp: sgx_ecc256_create_key_pair() failed !\n");
        goto cleanup;
    }

    // Step 3: Calculate sealed data size.
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
            "\nTrustedApp: Size allocated for sealedprivkey by untrusted app "
            "is less than the required size !\n");
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto cleanup;
    }

    print(
        "\nTrustedApp: ELGAMAL Key pair generated and private key was sealed. Sent the "
        "public key and sealed private key back.\n");
    ret = SGX_SUCCESS;

cleanup:
    // Step 4: Close Context.
    if (p_ecc_handle != NULL) {
        sgx_ecc256_close_context(p_ecc_handle);
    }

    return ret;
}


sgx_status_t ecall_key_gen_and_seal_all_elgamal(char *sealedpubkey,
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


