/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "app.h"

/* Globals */

sgx_enclave_id_t enclave_id;
sgx_launch_token_t launch_token;
int launch_token_updated;
sgx_status_t sgx_lasterr;

void *public_key_buffer;
size_t public_key_buffer_size;
void *sealed_pubkey_buffer;
size_t sealed_pubkey_buffer_size;
void *sealed_privkey_buffer;
size_t sealed_privkey_buffer_size;
void *signature_buffer;
size_t signature_buffer_size;
void *input_buffer;
size_t input_buffer_size;
void *quote_buffer;
size_t quote_buffer_size;

// [HELIOS]
void *elgamal_key_buffer;
size_t elgamal_key_buffer_size;
void *sealed_elgamal_key_buffer;
size_t sealed_elgamal_key_buffer_size;

void *ballot_buffer;
size_t ballot_buffer_size;

void *admin_key_buffer;
size_t admin_key_buffer_size;

void *voter1_key_buffer;
size_t voter1_key_buffer_size;
void *voter2_key_buffer;
size_t voter2_key_buffer_size;
void *voter3_key_buffer;
size_t voter3_key_buffer_size;

void *admin_sign_buffer;
size_t admin_sign_buffer_size;
void *user_sign_buffer;
size_t user_sign_buffer_size;
void *election_hash_buffer;
size_t election_hash_buffer_size;