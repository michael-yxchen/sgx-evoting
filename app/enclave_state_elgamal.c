/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>

#include "app.h"

bool save_enclave_state_elgamal(const char *const sealedkey_file) {
    // bool ret_status = true;
    // ret_status = save_state(sealedprivkey_file, sealed_privkey_buffer,
    //                        sealed_privkey_buffer_size);
    // ret_status = save_state(sealedpubkey_file, sealed_pubkey_buffer,
    //                        sealed_pubkey_buffer_size);
    // return ret_status;
    bool ret_status = true;

    printf("[GatewayApp]: Saving enclave state - sealed elgamal key\n");

    FILE *sk_file = open_file(sealedkey_file, "wb");

    if (sk_file == NULL) {
        fprintf(stderr, "[GatewayApp]: save_enclave_state() fopen failed\n");
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
        return false;
    }

    if (fwrite(sealed_elgamal_key_buffer, sealed_elgamal_key_buffer_size, 1, sk_file) !=
        1) {
        fprintf(stderr,
                "[GatewayApp]: Enclave state only partially written.\n");
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
        ret_status = false;
    }

    fclose(sk_file);

    return ret_status;
}

bool save_election_state_elgamal(const char *const sealedkey_file) {
    // bool ret_status = true;
    // ret_status = save_state(sealedprivkey_file, sealed_privkey_buffer,
    //                        sealed_privkey_buffer_size);
    // ret_status = save_state(sealedpubkey_file, sealed_pubkey_buffer,
    //                        sealed_pubkey_buffer_size);
    // return ret_status;
    bool ret_status = true;

    printf("[GatewayApp]: Saving enclave state - sealed elgamal key\n");

    FILE *sk_file = open_file(sealedkey_file, "wb");

    if (sk_file == NULL) {
        fprintf(stderr, "[GatewayApp]: save_enclave_state() fopen failed\n");
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
        return false;
    }

    if (fwrite(sealed_election_buffer, sealed_election_buffer_size, 1, sk_file) !=
        1) {
        fprintf(stderr,
                "[GatewayApp]: Enclave state only partially written.\n");
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
        ret_status = false;
    }

    fclose(sk_file);

    return ret_status;
}

bool save_bulletin(const char *const sealedkey_file) {
    // bool ret_status = true;
    // ret_status = save_state(sealedprivkey_file, sealed_privkey_buffer,
    //                        sealed_privkey_buffer_size);
    // ret_status = save_state(sealedpubkey_file, sealed_pubkey_buffer,
    //                        sealed_pubkey_buffer_size);
    // return ret_status;
    bool ret_status = true;

    printf("[GatewayApp]: Saving bulletin board\n");

    FILE *sk_file = open_file(sealedkey_file, "wb");

    if (sk_file == NULL) {
        fprintf(stderr, "[GatewayApp]: save_enclave_state() fopen failed\n");
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
        return false;
    }

    if (fwrite(bulletin_buffer, bulletin_buffer_size, 1, sk_file) !=
        1) {
        fprintf(stderr,
                "[GatewayApp]: Enclave state only partially written.\n");
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
        ret_status = false;
    }

    fclose(sk_file);

    return ret_status;
}

bool load_sealedkey(const char *const sealedkey_file) {
    printf("[GatewayApp]: Loading sealed elgamal key\n");
    // bool ret_status = load_sealed_data(sealedpubkey_file,
    // sealed_pubkey_buffer,
    //                                   sealed_pubkey_buffer_size);
    // return ret_status;
    void *new_buffer;
    size_t new_buffer_size;

    bool ret_status =
        read_file_into_memory(sealedkey_file, &new_buffer, &new_buffer_size);
    /* If we previously allocated a buffer, free it before putting new one in
     * its place */
    if (sealed_elgamal_key_buffer != NULL) {
        free(sealed_elgamal_key_buffer);
        sealed_elgamal_key_buffer = NULL;
    }

    /* Put new buffer into context */
    sealed_elgamal_key_buffer = new_buffer;
    sealed_elgamal_key_buffer_size = new_buffer_size;
		printf("[GatewayApp]: Loading sealed elgamal key %d\n", sealed_elgamal_key_buffer_size);
    return ret_status;
}
