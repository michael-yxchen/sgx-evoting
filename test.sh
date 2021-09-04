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
rm -f sealedbb.bin

echo "Initializing bulletin board"
# Generate the keypair (both private & public keys are sealed to enclave)
#../app/app --keygen --enclave-path `pwd`/../enclave/enclave.signed.so --statefile sealeddata.bin --public-key secp256r1.pem
../app/app --init-bulletin \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --bulletinfile sealedbb.bin
echo "Bulletin board created.\n"


