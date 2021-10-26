/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <getopt.h>
#include <stdio.h>

#include <openssl/evp.h>

#include "app.h"

static struct option long_options[] = {
    {"keygen", no_argument, 0, 0},
    {"quote", no_argument, 0, 0},
    {"sign", no_argument, 0, 0},
    {"admin", no_argument, 0, 0},
		{"init", no_argument, 0, 0},
		{"open", no_argument, 0, 0},
		{"cast", no_argument, 0, 0},
		{"close", no_argument, 0, 0},
		{"tally", no_argument, 0, 0},
    {"enclave-path", required_argument, 0, 0},
    {"sealedprivkey", required_argument, 0, 0},
    {"sealedpubkey", required_argument, 0, 0},
    {"signature", required_argument, 0, 0},
    {"public-key", required_argument, 0, 0},
    {"quotefile", required_argument, 0, 0},
		{"sealedkey", required_argument, 0, 0},
		{"adminkey", required_argument, 0, 0},
		{"ballot", required_argument, 0, 0},
		{"bulletin", required_argument, 0, 0},
		{"voter1", required_argument, 0, 0},
		{"voter2", required_argument, 0, 0},
		{"voter3", required_argument, 0, 0},
		{"adminsign", required_argument, 0, 0},
		{"usersign", required_argument, 0, 0},
		{"electionhash", required_argument, 0, 0},
		{"sealedelec", required_argument, 0, 0},
    {0, 0, 0, 0}};
			
/**
 * main()
 */

bool load_init_files(const char *const ballot_file, const char *const admin_file, const char *const voter1_file, const char *const voter2_file, const char *const voter3_file) {
		bool ret = false;
    printf("[GatewayApp]: Loading INIT ballot file = ");
    ret = read_file_into_memory(ballot_file, &ballot_buffer, &ballot_buffer_size);
		printf("%s\n", ret ? "true" : "false");
	  printf("[GatewayApp]: Loading INIT admin file = ");
    ret = read_file_into_memory(admin_file, &admin_key_buffer, &admin_key_buffer_size);
		printf("%s\n", ret ? "true" : "false");
	  printf("[GatewayApp]: Loading INIT voter1 file = ");
    ret = read_file_into_memory(voter1_file, &voter1_key_buffer, &voter1_key_buffer_size);
		printf("%s\n", ret ? "true" : "false");
	  printf("[GatewayApp]: Loading INIT voter2 file = ");
    ret = read_file_into_memory(voter2_file, &voter2_key_buffer, &voter2_key_buffer_size);
		printf("%s\n", ret ? "true" : "false");
	  printf("[GatewayApp]: Loading INIT voter3 file = ");
    ret = read_file_into_memory(voter3_file, &voter3_key_buffer, &voter3_key_buffer_size);
		printf("%s\n", ret ? "true" : "false");
		return ret;
}

bool load_adminsign(const char *const admin_file) {
		bool ret = false;
    printf("[GatewayApp]: Loading Signed Admin Command file = ");
    ret = read_file_into_memory(admin_file, &admin_sign_buffer, &admin_sign_buffer_size);
		printf("%s\n", ret ? "true" : "false");
		return ret;
}

bool load_usersign(const char *const user_file) {
		bool ret = false;
    printf("[GatewayApp]: Loading Signed User Command file = ");
    ret = read_file_into_memory(user_file, &user_sign_buffer, &user_sign_buffer_size);
		printf("%s\n", ret ? "true" : "false");
		return ret;
}

bool load_electionhash(const char *const hash_file) {
		bool ret = false;
    printf("[GatewayApp]: Loading Election Hash file = ");
    ret = read_file_into_memory(hash_file, &election_hash_buffer, &election_hash_buffer_size);
		printf("%s\n", ret ? "true" : "false");
		return ret;
}


int main(int argc, char **argv) {
    bool opt_keygen = false;
    bool opt_quote = false;
    bool opt_sign = false;
    bool opt_admin = false;
		bool opt_init = false;
		bool opt_open = false;
		bool opt_cast = false;
		bool opt_close = false;
		bool opt_tally = false;
	
    const char *opt_enclave_path = NULL;
    const char *opt_sealedprivkey_file = NULL;
    const char *opt_sealedpubkey_file = NULL;
    const char *opt_signature_file = NULL;
    const char *opt_input_file = NULL;
    const char *opt_public_key_file = NULL;
    const char *opt_quote_file = NULL;
	
		const char *opt_sealedkey_file = NULL;
	
		const char *opt_adminkey_file = NULL;
		const char *opt_ballot_file = NULL;
		const char *opt_bulletin_file = NULL;
		const char *opt_voter1_file = NULL;
		const char *opt_voter2_file = NULL;
		const char *opt_voter3_file = NULL;
	
		const char *opt_adminsign_file = NULL;
		const char *opt_usersign_file = NULL;
		const char *opt_election_hash = NULL;
	
		const char *opt_sealedelection_file = NULL;
	
    int option_index = 0;

    while (getopt_long_only(argc, argv, "", long_options, &option_index) !=
           -1) {
        switch (option_index) {
            case 0:
                opt_keygen = true;
                break;
            case 1:
                opt_quote = true;
                break;
            case 2:
                opt_sign = true;
                break;
            case 3:
                opt_admin = true;
                break;
            case 4:
                opt_init = true;
                break;
            case 5:
                opt_open = true;
                break;
            case 6:
                opt_cast = true;
                break;
            case 7:
                opt_close = true;
                break;
            case 8:
                opt_tally = true;
                break;
					
					
            case 9:
                opt_enclave_path = optarg;
                break;
            case 10:
                opt_sealedprivkey_file = optarg;
                break;
            case 11:
                opt_sealedpubkey_file = optarg;
                break;
            case 12:
                opt_signature_file = optarg;
                break;
            case 13:
                opt_public_key_file = optarg;
                break;
            case 14:
                opt_quote_file = optarg;
                break;
						case 15:
								opt_sealedkey_file = optarg;
								break;
					
						case 16:
								opt_adminkey_file = optarg;
								break;
						case 17:
								opt_ballot_file = optarg;
								break;
						case 18:
								opt_bulletin_file = optarg;
								break;
						case 19:
								opt_voter1_file = optarg;
								break;
						case 20:
								opt_voter2_file = optarg;
								break;
						case 21:
								opt_voter3_file = optarg;
								break;
					
						case 22:
								opt_adminsign_file = optarg;
								break;
						case 23:
								opt_usersign_file = optarg;
								break;
						case 24:
								opt_election_hash = optarg;
								break;
					
						case 25:
								opt_sealedelection_file = optarg;
								break;
					
						case 26:
								opt_bulletin_file = optarg;
								break;
					

        }
    }

    if (optind < argc) {
        opt_input_file = argv[optind++];
    }

    if (!opt_keygen && !opt_sign && !opt_quote && !opt_admin && !opt_init && !opt_open && !opt_cast && !opt_close && !opt_tally) {
        fprintf(
            stderr,
            "Error: Must specifiy either --keygen or --sign or --quotegen or --admin\n");
        return EXIT_FAILURE;
    }

    if (opt_keygen && (!opt_enclave_path || !opt_sealedprivkey_file ||
                       !opt_sealedprivkey_file || !opt_public_key_file)) {
        fprintf(stderr, "UsageKeygen:\n");
        fprintf(stderr,
                "  %s --keygen --enclave-path /path/to/enclave.signed.so "
                "--sealedprivkey sealedprivkey.bin "
                "--sealedpubkey sealedpubkey.bin "
                "--public-key mykey.pem\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    if (opt_quote &&
        (!opt_enclave_path || !opt_sealedpubkey_file || !opt_quote_file)) {
        fprintf(stderr, "UsageQuote:\n");
        fprintf(stderr,
                "  %s --quotegen --enclave-path /path/to/enclave.signed.so "
                "--sealedpubkey sealedpubkey.bin --quotefile quote.json\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    if (opt_sign && (!opt_enclave_path || !opt_sealedprivkey_file ||
                     !opt_signature_file || !opt_input_file)) {
        fprintf(stderr, "UsageSign:\n");
        fprintf(stderr,
                "  %s --sign --enclave-path /path/to/enclave.signed.so "
                "--sealedprivkey "
                "sealeddata.bin --signature inputfile.signature inputfile\n",
                argv[0]);
        return EXIT_FAILURE;
    }
    
    if (opt_admin && (!opt_enclave_path || !opt_sealedkey_file)) {
        fprintf(stderr, "UsageAdmin:\n");
        fprintf(stderr,
                "  %s --admin --enclave-path /path/to/enclave.signed.so "
                "--sealedkey sealedkey.bin\n",
                argv[0]);
        return EXIT_FAILURE;
    }
    
	  if (opt_init && (!opt_enclave_path || !opt_sealedkey_file || !opt_adminkey_file || !opt_ballot_file || !opt_bulletin_file || !opt_voter1_file || !opt_voter2_file || !opt_voter3_file || !opt_sealedelection_file)) {
        fprintf(stderr, "UsageInit:\n");
        fprintf(stderr,
                "  %s --init --enclave-path --adminkey secp256r1.pem --ballot ballot.txt --bulletin bulletin.txt --voter1 alice.pem --voter2 john.pem --voter3 justin.pem\n",
                argv[0]);
        return EXIT_FAILURE;
    }
	
	  if (opt_open && (!opt_enclave_path || !opt_adminsign_file)) {
        fprintf(stderr, "UsageOpen:\n");
        fprintf(stderr,
                "  %s --open --enclave-path --adminsign command.txt\n",
                argv[0]);
        return EXIT_FAILURE;
    }
	
	  if (opt_cast && (!opt_enclave_path || !opt_usersign_file || !opt_election_hash)) {
        fprintf(stderr, "UsageOpen:\n");
        fprintf(stderr,
                "  %s --cast --enclave-path --usersign command.txt --electionhash hash.txt\n",
                argv[0]);
        return EXIT_FAILURE;
    }
	
	  if (opt_close && (!opt_enclave_path || !opt_adminsign_file)) {
        fprintf(stderr, "UsageOpen:\n");
        fprintf(stderr,
                "  %s --close --enclave-path --adminsign command.txt\n",
                argv[0]);
        return EXIT_FAILURE;
    }
	
	  if (opt_tally && (!opt_enclave_path || !opt_adminsign_file)) {
        fprintf(stderr, "UsageOpen:\n");
        fprintf(stderr,
                "  %s --tally --enclave-path --adminsign command.txt\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    OpenSSL_add_all_algorithms(); /* Init OpenSSL lib */

    bool success_status =
        create_enclave(opt_enclave_path) && 
				(opt_admin ? enclave_get_elgamal_buffer_sizes() : enclave_get_buffer_sizes()) &&
        (opt_admin ? allocate_elgamal_buffers() : allocate_buffers()) && 
        // keygen
        (opt_keygen ? enclave_generate_key() : true) &&
        (opt_keygen
             ? save_enclave_state(opt_sealedprivkey_file, opt_sealedpubkey_file)
             : true) &&
        // admin
        (opt_admin ? enclave_generate_key_elgamal() : true) &&
        (opt_admin ? save_enclave_state_elgamal(opt_sealedkey_file) : true) &&     
				// init
				(opt_init ? load_sealedkey(opt_sealedkey_file) : true) &&
				(opt_init ? load_init_files(opt_ballot_file, opt_adminkey_file, opt_voter1_file, opt_voter2_file, opt_voter3_file) : true) &&
				(opt_init ? allocate_election_buffers() : true) && 
				(opt_init ? enclave_init_election() : true) &&
				(opt_init ? save_election_state_elgamal(opt_sealedelection_file) : true) && 
				(opt_init ? save_bulletin(opt_bulletin_file) : true) && 
				// open
				(opt_open ? load_adminsign(opt_adminsign_file) : true) &&
				(opt_open ? enclave_open_election() : true) &&
				// cast
				(opt_cast ? load_usersign(opt_usersign_file) : true) &&
				(opt_cast ? load_electionhash(opt_election_hash) : true) &&
				(opt_cast ? enclave_cast_election() : true) &&
				// close
				(opt_close ? load_adminsign(opt_adminsign_file) : true) &&
				(opt_close ? enclave_close_election() : true) &&
				// tally
				(opt_tally ? load_adminsign(opt_adminsign_file) : true) &&
				(opt_tally ? enclave_tally_election() : true) &&
        // quote
        (opt_quote ? load_sealedpubkey(opt_sealedpubkey_file) : true) &&
        (opt_quote ? enclave_gen_quote() : true) &&
        (opt_quote ? save_quote(opt_quote_file) : true) &&
        //(opt_quote ? save_public_key(opt_public_key_file) : true) &&
        // sign
        (opt_sign ? load_enclave_state(opt_sealedprivkey_file) : true) &&
        (opt_sign ? load_input_file(opt_input_file) : true) &&
        (opt_sign ? enclave_sign_data() : true) &&
        // save_enclave_state(opt_sealedprivkey_file) &&
        (opt_sign ? save_signature(opt_signature_file) : true);
    // TODO call function to generate report with public key in it
    //(opt_keygen ? enclave_generate_quote() : true);

    if (sgx_lasterr != SGX_SUCCESS) {
        fprintf(stderr, "[GatewayApp]: ERROR: %s\n",
                decode_sgx_status(sgx_lasterr));
    }

    destroy_enclave();
    cleanup_buffers();

    return success_status ? EXIT_SUCCESS : EXIT_FAILURE;
}

