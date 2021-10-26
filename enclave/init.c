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
#include "sgx_tcrypto.h"

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
#define MPZ_WORDS_ORDER 1 /* Most significant order first */
#define MPZ_WORDS_ENDIANNESS 0 /* Use host endianness */
#define MPZ_NAILS 0 /* Use full words */

sgx_status_t ecall_init(char *sealed, size_t sealed_size,
											 
						char *ballot_buffer, size_t ballot_buffer_size,
						char *admin_key_buffer, size_t admin_key_buffer_size,
						char *voter1_key_buffer, size_t voter1_key_buffer_size,
						char *voter2_key_buffer, size_t voter2_key_buffer_size,
						char *voter3_key_buffer, size_t voter3_key_buffer_size,
						char *bulletin_buffer, size_t bulletin_buffer_size,
						char *sealed_election_buffer, size_t sealed_election_buffer_size
											 ) {

		// Step 1: Open Context.
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	
    // Step 1: Calculate sealed/encrypted data length.
    uint32_t unsealed_data_size =
        sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed);
	
/*
int x = unsealed_data_size;
int length = snprintf( NULL, 0, "%d", x );
char* str = malloc( length + 1 );
snprintf( str, length + 1, "%d", x );
print(str);
free(str);
*/	

		//unsealed_data_size = 128;
    uint8_t *const unsealed_data =
        (uint8_t *)malloc(unsealed_data_size);  // Check malloc return;
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
		mpz_import(p, 1, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS, MPZ_NAILS, &unsealed_data[0]);
		mpz_import(g, 1, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS, MPZ_NAILS, &unsealed_data[32]);
		mpz_import(pk, 1, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS, MPZ_NAILS, &unsealed_data[64]);
		mpz_import(sk, 1, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS, MPZ_NAILS, &unsealed_data[96]);
	
    print("\n[TrustedApp]: INIT completed\n");

		

		
		char election_state[728];
		size_t buf_sz = 728;
	
		for(int j = 0; j < 64; j++) {
			election_state[j] = ((char*)admin_key_buffer)[27+j];
		}
		for(int j = 0; j < 60; j++) {
			election_state[64+j] = ((char*)admin_key_buffer)[92+j];
		}

		for(int j = 0; j < 64; j++) {
			election_state[128+j] = ((char*)voter1_key_buffer)[27+j];
		}
		for(int j = 0; j < 60; j++) {
			election_state[128+64+j] = ((char*)voter1_key_buffer)[92+j];
		}
	
		for(int j = 0; j < 64; j++) {
			election_state[256+j] = ((char*)voter2_key_buffer)[27+j];
		}
		for(int j = 0; j < 60; j++) {
			election_state[256+64+j] = ((char*)voter2_key_buffer)[92+j];
		}
	
		for(int j = 0; j < 64; j++) {
			election_state[384+j] = ((char*)voter3_key_buffer)[27+j];
		}
		for(int j = 0; j < 60; j++) {
			election_state[384+64+j] = ((char*)voter3_key_buffer)[92+j];
		}
	
		election_state[512] = ((char*)ballot_buffer)[0];
	
		for(int j = 0; j < 16; j++) {
			if(((char*)ballot_buffer)[2+j] != '\n') {
				election_state[516+j] = ((char*)ballot_buffer)[2+j];
			}
			else {
				break;
			}
		}
	
		for(int j = 0; j < 16; j++) {
			if(((char*)ballot_buffer)[10+j] != '\n') {
				election_state[532+j] = ((char*)ballot_buffer)[10+j];
			}
			else {
				break;
			}
		}

		for(int j = 0; j < 16; j++) {
			if(((char*)ballot_buffer)[16+j] != '\n') {
				election_state[548+j] = ((char*)ballot_buffer)[16+j];
			}
			else {
				break;
			}
		}
	
		for(int j = 0; j < 128; j++) {
			election_state[564+j] = unsealed_data[j];
		}
		
		uint8_t* digest_buffer = (uint8_t*)malloc((uint32_t)sizeof(sgx_sha256_hash_t));
		sgx_status_t rethash = sgx_sha256_msg((const uint8_t *) election_state, 692, (sgx_sha256_hash_t *)digest_buffer);

	
		for(int j = 0; j < 32; j++) {
			election_state[692+j] = digest_buffer[j];
		}
		
		election_state[724] = 1;
	
		int temp = sgx_calc_sealed_data_size(0U, sizeof(election_state));
int x = temp;
int length = snprintf( NULL, 0, "%d", x );
char* str = malloc( length + 1 );
snprintf( str, length + 1, "%d", x );
print(str);
free(str);	
		
		// Step 3: Calculate sealed data size.
    if (sealed_election_buffer_size >= sgx_calc_sealed_data_size(0U, sizeof(election_state))) {
        if ((ret = sgx_seal_data(
                 0U, NULL, sizeof(election_state), (uint8_t *)&election_state,
                 (uint32_t)sealed_election_buffer_size, 
                 (sgx_sealed_data_t *)sealed_election_buffer)) != SGX_SUCCESS) {
            print("\nTrustedApp: sgx_seal_data() failed !\n");
            goto cleanup;
        }
    } else {
        print(
            "\n[TrustedApp]: Size allocated for sealedelgamalkey by untrusted app "
            "is less than the required size !\n");
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto cleanup;
    }

		
		for (int j = 0; j < 32; j++) {
			bulletin_buffer[j] = digest_buffer[j];
		}
	
		for (int j = 0; j < 21; j++) {
			bulletin_buffer[j+32] = ballot_buffer[j];
		}
	
		for (int j = 0; j < 96; j++) {
			bulletin_buffer[j+64] = unsealed_data[j];
		}
		
	
	
    ret = SGX_SUCCESS;

cleanup:
    // Step 4: Close Context.

    return ret;
}



