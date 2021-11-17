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



echo "[Shell]: Admin creating public/private keypair using openssl:"
# First generate the private key
openssl ecparam -name prime256v1 -genkey -out secp256r1-key.pem 2> /dev/null
# Then extract the public key (needed for signature verification later)
openssl ec -in secp256r1-key.pem -pubout -out secp256r1.pem 2> /dev/null
echo "[Shell]: Admin key created. (secp256r1.pem)\n\n"

echo "[Shell]: Creating voter public/private keypair using openssl for ALICE, JOHN, JUSTIN:"
openssl ecparam -name prime256v1 -genkey -out alice-key.pem 2> /dev/null
openssl ec -in alice-key.pem -pubout -out alice.pem 2> /dev/null
openssl ecparam -name prime256v1 -genkey -out john-key.pem 2> /dev/null
openssl ec -in john-key.pem -pubout -out john.pem 2> /dev/null
openssl ecparam -name prime256v1 -genkey -out justin-key.pem 2> /dev/null
openssl ec -in justin-key.pem -pubout -out justin.pem 2> /dev/null
echo "[Shell]: Voter keys created. (alice.pem, john.pem, justin.pem)\n\n\n"

echo "[Shell]: Provisioning election keypair using ADMIN-ECALL:\n"
# Generate the keypair (both private & public keys are sealed to enclave)
../app/app --admin \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --sealedkey sealedkey.bin
echo "\n[Shell]: ADMIN-ECALL completed.\n\n\n"

echo '[
        {
            "question": "Who should be the next president?",
            "choice": [
                "Obama",
                "Trump"
            ]
        },
        {
            "question": "Who should be the next mayor?",
            "choice": [
                "John",
                "Joe"
            ]
        }
    ]' > ballot.txt
echo "[Shell]: Created 2 question ballot for president and mayor with candidates [Obama,Trump], [John,Joe]\n\n\n" 

# Admin invoking the Ecall to initialize the election

echo "[Shell]: Admin invoking election state init using INIT-ECALL:\n"
../app/app --init \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
		--sealedkey sealedkey.bin \
		--adminkey secp256r1.pem \
		--ballot ballot.txt \
		--bulletin bulletin.json \
		--voter1 alice.pem \
		--voter2 john.pem \
		--voter3 justin.pem \
		--sealedelec sealedhelios_state.bin
#open sealed key, initialize state counter to 1, save admin public key, save pks of eligible voters, save ballot, seal meta data, compute hash metadata(-counter)+PK, save election identifier
echo "\n[Shell]: INIT-ECALL completed. (ealedhelios_state.bin and bulletin-board.json)\n\n\n"


# Admin invoking the Ecall to open the election
echo '{ command: open }' > open_command.json
echo -n "[Shell]: Signing OPEN command with admin key.."
openssl dgst -sign secp256r1-key.pem -out Open.signature open_command.json
echo ".done"

echo "[Shell]: Admin advancing election state using OPEN-ECALL:\n"
../app/app --open \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
		--command open_command.json \
		--adminsign Open.signature \
		--sealedelec sealedhelios_state.bin
echo "\n[Shell]: OPEN-ECALL completed.\n\n\n"


# Observing election hash from bulletin board and saving to seperate file
echo "d04b98f48e8f8bcc15c6ae5ac050801cd6dcfd428fb5f9e65c4e16e7807340fa" > election.hash

# Actions Alice would take to cast her vote 1-2
#../ballot_prep/bps 
#../ballot_prep/bulletin-board.json
#d04b98f48e8f8bcc15c6ae5ac050801cd6dcfd428fb5f9e65c4e16e7807340fa
echo -n "[Shell] Using Alice's prepared encrypted ballot (../ballot_prep/encballot_alice.hex).\n"
echo -n "[Shell] Signing encrypted ballot with Alice's key.."
openssl dgst -sign alice-key.pem -out EncBallotAlice.signature ../ballot_prep/encballot_alice.hex
echo ".done"

echo "[Shell]: Alice casting vote using the CAST-ECALL:\n"
../app/app --cast \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
		--usersign EncBallotAlice.signature \
		--encballot ../ballot_prep/encballot_alice.hex \
		--electionhash election.hash \
		--sealedelec sealedhelios_state.bin \
		--voterid "1"
echo "\n[Shell]: Alice CAST-ECALL completed.\n\n\n"


# Actions John would take to cast her vote 1-2	
#../ballot_prep/bps 
#../ballot_prep/bulletin-board.json
#d04b98f48e8f8bcc15c6ae5ac050801cd6dcfd428fb5f9e65c4e16e7807340fa
echo -n "[Shell] Using John's prepared encrypted ballot (../ballot_prep/encballot_john.hex).\n"
echo -n "[Shell] Signing encrypted ballot with John's key.."
openssl dgst -sign john-key.pem  -out EncBallotJohn.signature ../ballot_prep/encballot_john.hex
echo ".done"

echo "[Shell]: John casting vote using the CAST-ECALL:\n"
../app/app --cast \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
		--usersign EncBallotJohn.signature \
		--encballot ../ballot_prep/encballot_john.hex \
		--electionhash election.hash \
		--sealedelec sealedhelios_state.bin \
		--voterid "2"
echo "\n[Shell]: John CAST-ECALL completed.\n\n\n"



# Actions Justin would take to cast her vote 2-2
#../ballot_prep/bps 
#../ballot_prep/bulletin-board.json
#d04b98f48e8f8bcc15c6ae5ac050801cd6dcfd428fb5f9e65c4e16e7807340fa
echo -n "[Shell] Using Justin's prepared encrypted ballot (../ballot_prep/encballot_justin.hex).\n"
echo -n "[Shell] Signing encrypted ballot with Justin's key.."
openssl dgst -sign justin-key.pem -out EncBallotJustin.signature ../ballot_prep/encballot_justin.hex
echo ".done"

echo "[Shell]: Justin casting vote using the CAST-ECALL:\n"
../app/app --cast \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
		--usersign EncBallotJustin.signature \
		--encballot ../ballot_prep/encballot_justin.hex \
		--electionhash election.hash \
		--sealedelec sealedhelios_state.bin \
		--voterid "3"
echo "\n[Shell]: Justin CAST-ECALL completed.\n\n\n"
		
		
		





# Admin invoking the Ecall to close the election
echo '{ command: close }' > close_command.json
echo -n "[Shell]: Signing CLOSE command with admin key.."
openssl dgst -sign secp256r1-key.pem -out Close.signature close_command.json
echo ".done"

echo "[Shell]: Admin advancing election state using CLOSE-ECALL:\n"
../app/app --close \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
		--command close_command.json \
		--adminsign Close.signature \
		--sealedelec sealedhelios_state.bin
echo "\n[Shell]: CLOSE-ECALL completed.\n\n\n"		
		

# Admin invoking the Ecall to tally the election
echo '{ command: tally }' > tally_command.json
echo -n "[Shell]: Signing TALLY command with admin key.."
openssl dgst -sign secp256r1-key.pem -out Tally.signature tally_command.json
echo ".done"

echo "[Shell]: Admin triggering final tally using TALLY-ECALL:\n"
../app/app --tally \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
		--command tally_command.json \
		--adminsign Tally.signature \
		--sealedelec sealedhelios_state.bin
echo "\n[Shell]: TALLY-ECALL completed.\n\n"	
exit

