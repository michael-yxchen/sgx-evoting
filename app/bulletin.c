#include <stdlib.h>

#include <enclave_u.h> /* For sgx_enclave_id_t */

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>

#include "app.h"

bool enclave_init_bb() {
    sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;

    sgx_lasterr = ecall_calc_bb_buffer_size(enclave_id, &ecall_retval, bb_size,
                                            &sealed_bb_buffer_size);
    if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != SGX_SUCCESS)) {
        fprintf(stderr,
                "[GatewayApp]: ERROR: ecall_calc_bb_buffer_size returned %d\n",
                ecall_retval);
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
    }
    sealed_bb_buffer = calloc(sealed_bb_buffer, 1);

    printf("[GatewayApp]: Calling enclave to initialize bulletin board\n");

    sgx_lasterr = ecall_init_bb(enclave_id, &ecall_retval, bb_size,
                                sealed_bb_buffer, sealed_bb_buffer_size);

    if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != SGX_SUCCESS)) {
        fprintf(stderr,
                "[GatewayApp]: ERROR: ecall_init_bb returned %d\n",
                ecall_retval);
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
    }

    return (sgx_lasterr == SGX_SUCCESS);
}

bool save_bb(const char *const bb_file) {
    bool ret_status = true;

    printf("[GatewayApp]: Saving bulletin board\n");
    FILE *file = open_file(bb_file, "wt");

    if (file == NULL) {
        fprintf(stderr, "[GatewayApp]: save_bb() fopen failed\n");
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
        return false;
    }

    if (fwrite(sealed_bb_buffer, sealed_bb_buffer_size, 1, file) != 1) {
        fprintf(stderr,
                "[GatewayApp]: Bulletin board only partially written.\n");
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
        ret_status = false;
    }
    fclose(file);

    return ret_status;
}