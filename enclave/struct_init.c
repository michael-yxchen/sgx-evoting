#include "enclave.h"

#include "enclave.h"
#include <enclave_t.h>
#include <sgx_quote.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>
#include <stdlib.h>
#include <string.h>

sgx_status_t ecall_init_bb(size_t bb_size, char *sealed_bb,
                           size_t sealedbb_size) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    char *bb = calloc(bb_size, 1);
    if (bb == NULL) {
        ret = SGX_ERROR_OUT_OF_MEMORY;
        return ret;
    }
    if (sealedbb_size >= sgx_calc_sealed_data_size(0U, bb_size)) {
        if ((ret =
                 sgx_seal_data(0U, NULL, bb_size, (uint8_t *)bb, sealedbb_size,
                               (sgx_sealed_data_t *)sealed_bb)) != SGX_SUCCESS) {
            print("\nTrustedApp: sgx_seal_data() failed!\n");
            goto cleanup;
        }
    }

cleanup:
    if (bb) {
        free(bb);
    }
    return ret;
}

sgx_status_t ecall_calc_bb_buffer_size(size_t bb_size,
                                       size_t *esealed_bb_size) {
    *esealed_bb_size = sgx_calc_sealed_data_size(0U, bb_size);
    return SGX_SUCCESS;
}
