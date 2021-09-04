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

bool enclave_generate_key_elgamal() {
    sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;

    printf("[GatewayApp]: Calling ELGAMAL enclave to generate key material\n");

    /*
     * Invoke ECALL, 'ecall_key_gen_and_seal()', to generate a keypair and seal
     * it to the enclave.
     */
    // sgx_lasterr = ecall_key_gen_and_seal_elgamal(
    sgx_lasterr = ecall_key_gen_and_seal_all_elgamal(
        enclave_id, &ecall_retval, (char *)sealed_pubkey_buffer,
        sealed_pubkey_buffer_size, (char *)sealed_privkey_buffer,
        sealed_privkey_buffer_size);
    if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != SGX_SUCCESS)) {
        fprintf(stderr,
                "[GatewayApp]: ERROR: ecall_key_gen_and_seal returned %d\n",
                ecall_retval);
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
    }

    return (sgx_lasterr == SGX_SUCCESS);
}


