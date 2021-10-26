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

bool enclave_init_election() {
    sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;

    printf("[GatewayApp]: Calling INIT ecall to initialize election %d %c %c %c\n",  voter1_key_buffer_size, &voter1_key_buffer[0], &voter1_key_buffer[1], &voter1_key_buffer[2]);
	
	/*for(int i = 0; i < voter1_key_buffer_size; i++) {
		printf("%d, %c\n", i, ((char*)voter1_key_buffer)[i]);
	}*/

	
    sgx_lasterr = ecall_init(
        enclave_id, &ecall_retval, (char *)sealed_elgamal_key_buffer,
        sealed_elgamal_key_buffer_size, 
				(char *)ballot_buffer, ballot_buffer_size,
				(char *)admin_key_buffer, admin_key_buffer_size,
				(char *)voter1_key_buffer, voter1_key_buffer_size,
				(char *)voter2_key_buffer, voter2_key_buffer_size,
				(char *)voter3_key_buffer, voter3_key_buffer_size,
				(char *)bulletin_buffer, bulletin_buffer_size,
				(char *)sealed_election_buffer, sealed_election_buffer_size);
	
    if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != SGX_SUCCESS)) {
        fprintf(stderr,
                "[GatewayApp]: ERROR: ecall_init returned %d\n",
                ecall_retval);
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
    }

    return (sgx_lasterr == SGX_SUCCESS);
}


