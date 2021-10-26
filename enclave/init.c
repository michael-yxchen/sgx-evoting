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



#define MPZ_WORDS_MAX 32
#define MPZ_WORDS_ORDER 1 /* Most significant order first */
#define MPZ_WORDS_ENDIANNESS 0 /* Use host endianness */
#define MPZ_NAILS 0 /* Use full words */

sgx_status_t ecall_init(char *sealed, size_t sealed_size) {

		// Step 1: Open Context.
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	
    // Step 1: Calculate sealed/encrypted data length.
    uint32_t unsealed_data_size =
        sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed);
int x = unsealed_data_size;
int length = snprintf( NULL, 0, "%d", x );
char* str = malloc( length + 1 );
snprintf( str, length + 1, "%d", x );
print(str);
free(str);
	

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
	
    print("\nTrustedApp: INIT unsealed\n");

		
	
    ret = SGX_SUCCESS;

cleanup:
    // Step 4: Close Context.

    return ret;
}



