/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>

#include <enclave_u.h> /* For sgx_enclave_id_t */

#include "app.h"

bool enclave_get_elgamal_buffer_sizes() {
    sgx_status_t ecall_retval = SGX_SUCCESS;

    printf("[GatewayApp]: Querying enclave for elgamal buffer sizes\n");

    /*
     * Invoke ECALL, 'ecall_calc_elgamal_buffer_sizes()', to calculate the sizes of
     * buffers needed for the untrusted app to store data (el_gamal key pair)
     * from the enclave.
     */
    sgx_lasterr = ecall_calc_elgamal_buffer_sizes(
        enclave_id, &ecall_retval, &elgamal_key_buffer_size,
        &sealed_elgamal_key_buffer_size);
    if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != 0)) {
        fprintf(stderr,
                "[GatewayApp]: ERROR: ecall_calc_elgamal_buffer_sizes returned %d\n",
                ecall_retval);
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
    }

    return (sgx_lasterr == SGX_SUCCESS);
}
