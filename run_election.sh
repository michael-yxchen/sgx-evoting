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
# Admin invoking the Ecall to initialize the election

../app/app --init \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
		--sealedkey sealedkey.bin \
		--adminkey secp256r1.pem \
		--ballot ballot.txt \
		--bulletin bulletin.txt \
		--voter1 alice.pem \
		--voter2 john.pem \
		--voter3 justin.pem \
		--sealedelec sealedhelios_state.bin
#open sealed key, initialize state counter to 1, save admin public key, save pks of eligible voters, save ballot, seal meta data, compute hash metadata(-counter)+PK, save election identifier


# Admin invoking the Ecall to open the election
echo '{ command: open }' > open_command.json
echo -n "Signing command with admin key.."
openssl dgst -sign secp256r1-key.pem -out Open.signature open_command.json
echo ".done"

../app/app --open \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
		--command open_command.json \
		--adminsign Open.signature \
		--sealedelec sealedhelios_state.bin
# exit

# Observing election hash from bulletin board and saving to seperate file
head -c 32 bulletin.txt > election.hash

# Actions Alice would take to cast her vote 1-2
#../ballot_prep/bps 
#../ballot_prep/bulletin-board.json
#d04b98f48e8f8bcc15c6ae5ac050801cd6dcfd428fb5f9e65c4e16e7807340fa
echo -n "Signing ballot with alice's key.."
openssl dgst -sign alice-key.pem -out EncBallotAlice.signature ../ballot_prep/encballot_alice.hex
echo ".done"

../app/app --cast \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
		--usersign EncBallotAlice.signature \
		--encballot ../ballot_prep/encballot_alice.hex \
		--electionhash election.hash \
		--sealedelec sealedhelios_state.bin \
		--voterid "1"





# Actions Justin would take to cast her vote 2-2
#../ballot_prep/bps 
#../ballot_prep/bulletin-board.json
#d04b98f48e8f8bcc15c6ae5ac050801cd6dcfd428fb5f9e65c4e16e7807340fa
echo -n "Signing ballot with justin's key.."
openssl dgst -sign justin-key.pem -out EncBallotJustin.signature ../ballot_prep/encballot_justin.hex
echo ".done"

../app/app --cast \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
		--usersign EncBallotJustin.signature \
		--encballot ../ballot_prep/encballot_justin.hex \
		--electionhash election.hash \
		--sealedelec sealedhelios_state.bin \
		--voterid "2"

		
		
		
# Actions John would take to cast her vote 1-2	
#../ballot_prep/bps 
#../ballot_prep/bulletin-board.json
#d04b98f48e8f8bcc15c6ae5ac050801cd6dcfd428fb5f9e65c4e16e7807340fa
echo -n "Signing ballot with john's key.."
openssl dgst -sign john-key.pem -out EncBallotJohn.signature ../ballot_prep/encballot_john.hex
echo ".done"

../app/app --cast \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
		--usersign EncBallotJohn.signature \
		--encballot ../ballot_prep/encballot_john.hex \
		--electionhash election.hash \
		--sealedelec sealedhelios_state.bin \
		--voterid "3"





# Admin invoking the Ecall to close the election
echo '{ command: close }' > close_command.json
echo -n "Signing command with admin key.."
openssl dgst -sign secp256r1-key.pem -out Close.signature close_command.json
echo ".done"

../app/app --close \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
		--command close_command.json \
		--adminsign Close.signature \
		--sealedelec sealedhelios_state.bin
		
		

# Admin invoking the Ecall to tally the election
echo '{ command: tally }' > tally_command.json
echo -n "Signing command with admin key.."
openssl dgst -sign secp256r1-key.pem -out Tally.signature tally_command.json
echo ".done"

../app/app --tally \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
		--command tally_command.json \
		--adminsign Tally.signature \
		--sealedelec sealedhelios_state.bin

#decrypt ballots.compute tally, post tally, discard sealed key

