/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "enclave.h"
#include <enclave_t.h>
#include <stdio.h>
#include <stdarg.h>

void print(const char *const str) { ocall_print_string(str); }
void print_int(const int *num) { ocall_print_int(num); }
void printf(const char *fmt, ...) {
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}
// void printint(const int num) { ocall_print_int(num); }
