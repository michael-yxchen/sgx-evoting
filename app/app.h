/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _APP_H
#define _APP_H

#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>

#include <openssl/bn.h>

#include <sgx_quote.h>
#include <sgx_uae_epid.h>
#include <sgx_urts.h>

/* Globals */

extern sgx_enclave_id_t enclave_id;
extern sgx_launch_token_t launch_token;
extern int launch_token_updated;
extern sgx_status_t sgx_lasterr;

extern void *public_key_buffer;          /* unused for signing */
extern size_t public_key_buffer_size;    /* unused for signing */
extern void *sealed_pubkey_buffer;       /* unused for signing */
extern size_t sealed_pubkey_buffer_size; /* unused for signing */
extern void *sealed_privkey_buffer;
extern size_t sealed_privkey_buffer_size;
extern void *quote_buffer;
extern size_t quote_buffer_size;
extern void *signature_buffer;
extern size_t signature_buffer_size;
extern void *input_buffer;
extern size_t input_buffer_size;

// HELIOS
extern void *elgamal_key_buffer;
extern size_t elgamal_key_buffer_size;
extern void *sealed_elgamal_key_buffer;
extern size_t sealed_elgamal_key_buffer_size;

extern void *ballot_buffer;
extern size_t ballot_buffer_size;
extern void *admin_key_buffer;
extern size_t admin_key_buffer_size;
extern void *voter1_key_buffer;
extern size_t voter1_key_buffer_size;
extern void *voter2_key_buffer;
extern size_t voter2_key_buffer_size;
extern void *voter3_key_buffer;
extern size_t voter3_key_buffer_size;

extern void *admin_sign_buffer;
extern size_t admin_sign_buffer_size;
extern void *user_sign_buffer;
extern size_t user_sign_buffer_size;
extern void *election_hash_buffer;
extern size_t election_hash_buffer_size;
extern void *enc_ballot_buffer;
extern size_t enc_ballot_buffer_size;

extern void *bulletin_buffer;
extern size_t bulletin_buffer_size;
extern void *sealed_election_buffer;
extern size_t sealed_election_buffer_size;

extern void *command_buffer;
extern size_t command_buffer_size;

/* Function prototypes */

const char *decode_sgx_status(sgx_status_t status);

FILE *open_file(const char *const filename, const char *const mode);

bool create_enclave(const char *const enclave_binary);

bool enclave_get_buffer_sizes(void);

bool allocate_buffers(void);

bool read_file_into_memory(const char *const filename, void **buffer,
                           size_t *buffer_size);

bool load_enclave_state(const char *const statefile);

bool load_sealed_data(const char *const sealed_data_file, void *buffer,
                      size_t buffer_size);

bool load_sealedprivkey(const char *const sealedprivkey_file);

bool load_sealedpubkey(const char *const sealedpubkey_file);

bool load_input_file(const char *const input_file);

bool enclave_sign_data(void);

bool enclave_generate_key(void);

// [HELIOS]
bool read_pem_pubkey(const char *const filename, void **buffer,
                     size_t *buffer_size);
bool enclave_generate_key_elgamal(void);
bool enclave_get_elgamal_buffer_sizes(void);
bool allocate_elgamal_buffers(void);
bool save_enclave_state_elgamal(const char *const sealedkey_file);
bool load_sealedkey(const char *const sealedkey_file);
bool enclave_init_election(void);
bool allocate_election_buffers(void);
bool read_der_signature(const char *const filename, void **buffer,
                        size_t *buffer_size);
bool enclave_generate_quote(sgx_report_data_t report_data);
bool enclave_gen_quote();

// bool save_enclave_state(const char *const statefile);
bool save_enclave_state(const char *const sealedprivkey_file,
                        const char *const sealedpubkey_file);
bool save_state(const char *const statefile, void *buffer, size_t buffer_size);
bool save_bulletin(const char *const bulletin_file,
                   const char *const admin_file, const char *const voter1_file,
                   const char *const voter2_file,
                   const char *const voter3_file);

BIGNUM *bignum_from_little_endian_bytes_32(const unsigned char *const bytes);

bool save_signature(const char *const signature_file);

bool save_public_key(const char *const public_key_file);

bool save_quote(const char *const quote_file);

void destroy_enclave(void);

void cleanup_buffers(void);

// base64
char *base64_encode(const char *msg, size_t sz);
char *base64_decode(const char *msg, size_t *sz);

// hexutils
int from_hexstring(unsigned char *dest, const void *src, size_t len);
void print_hexstring(FILE *fp, const void *src, size_t len);
void print_hexstring_nl(FILE *fp, const void *src, size_t len);
const char *hexstring(const void *src, size_t len);

#endif /* !_APP_H */
