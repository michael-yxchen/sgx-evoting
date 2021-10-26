#!/bin/sh -e
#                                               -*- Makefile -*-
#
# Copyright (C) 2011-2019 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#


test -d demo_sgx || mkdir demo_sgx
cd demo_sgx

# Clean up from previous runs
rm -f sealedkey.bin secp256r1-key.pem secp256r1.pem alice-key.pem alice.pem john-key.pem john.pem justin-key.pem justin.pem

echo "Provisioning election keypair in ENCLAVE:"
# Generate the keypair (both private & public keys are sealed to enclave)
../app/app --admin \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --sealedkey sealedkey.bin
echo "Key provisoning completed.\n"

echo "Admin creating keypair:"
# First generate the private key
openssl ecparam -name prime256v1 -genkey -out secp256r1-key.pem 2> /dev/null
# Then extract the public key (needed for signature verification later)
openssl ec -in secp256r1-key.pem -pubout -out secp256r1.pem 2> /dev/null
echo "Admin key created.\n"

echo "Creating voter keypairs:"
openssl ecparam -name prime256v1 -genkey -out alice-key.pem 2> /dev/null
openssl ec -in alice-key.pem -pubout -out alice.pem 2> /dev/null
openssl ecparam -name prime256v1 -genkey -out john-key.pem 2> /dev/null
openssl ec -in john-key.pem -pubout -out john.pem 2> /dev/null
openssl ecparam -name prime256v1 -genkey -out justin-key.pem 2> /dev/null
openssl ec -in justin-key.pem -pubout -out justin.pem 2> /dev/null
echo "Voter keys for Alice, John, and Justin created.\n"

echo "Creating ballot:"
echo '3
Barrack
Biden
Trump' > ballot.txt
echo "Ballot created for 3 candidates: Barrack, Joe, Donald.\n"

../app/app --init \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
		--sealedkey sealedkey.bin \
		--adminkey secp256r1.pem \
		--ballot ballot.txt \
		--bulletin bulletin.txt \
		--voter1 alice.pem \
		--voter2 john.pem \
		--voter3 justin.pem
#open sealed key, initialize state counter to 1, save admin public key, save pks of eligible voters, save ballot, seal meta data, compute hash metadata(-counter)+PK, save election identifier

echo 'placeholder' > open_command.txt

../app/app --open \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
		--adminsign open_command.txt
#state counter+1

echo 'placeholder' > signed_encrypted_ballot.txt
echo 'placeholder' > election.txt

../app/app --cast \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
		--usersign signed_encrypted_ballot.txt \
		--electionhash election.txt
#open sealed metadata if counter == 2, check signed ballot with eligible pks, add pk, ciphertext, and hash to sealed ballots, return hash

echo 'placeholder' > close_command.txt

../app/app --close \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
		--adminsign close_command.txt
#open sealed metadata counter+1

echo 'placeholder' > tally_command.txt

../app/app --tally \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
		--adminsign tally_command.txt
#decrypt ballots.compute tally, post tally, discard sealed key

