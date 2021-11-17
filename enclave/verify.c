#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "enclave.h"
#include <enclave_t.h>

#include <sgx_tcrypto.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>

/**
 * @brief This function unseals the public key and signture from app and then
 * performs ECDSA verification on the data
 *
 * @param msg Input parameter for message whose signature is to be verified
 * @param msg_size Input parameter for size of msg
 * @param pubkey Input parameter for public key
 * @param pubkey_size Input parameter for size of pubkey
 * @param signature Input parameter for signature
 * @param signature_size Input parameter for size of signature
 * @param result The verification result: 0 means success
 * @return sgx_status_t SGX_SUCCESS (Error code = 0x0000) on success, some other
 * appropriate sgx_status_t value upon failure.
 */
sgx_status_t verify_signature(uint8_t *msg, uint32_t msg_size, uint8_t *pubkey,
                              size_t pubkey_size, char *signature,
                              size_t signature_size, uint8_t *result) {
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  sgx_ecc_state_handle_t p_ecc_handle = NULL;

  //print("\nTrustedApp: Received sensor data, sealed public key, and signature.\n");

  // Open Context.
  if ((ret = sgx_ecc256_open_context(&p_ecc_handle)) != SGX_SUCCESS) {
    print("[TrustedApp][VERIFY]: sgx_ecc256_open_context() failed !\n");
    goto cleanup;
  }

  // Perform ECDSA verification.
  if ((ret = sgx_ecdsa_verify(msg, msg_size, (sgx_ec256_public_t *)pubkey,
                              (sgx_ec256_signature_t *)signature, result,
                              p_ecc_handle)) != SGX_SUCCESS) {
    print("[TrustedApp][VERIFY]: sgx_ecdsa_verify() failed !\n");
    goto cleanup;
  }

  //print("[TrustedApp][VERIFY]: Unsealed the sealed public key, verified sensor data "
  //      "signature with this public key and then, sent the result back.\n");
  ret = SGX_SUCCESS;

cleanup:
  // Step 5: Close Context, release memory
  if (p_ecc_handle != NULL) {
    sgx_ecc256_close_context(p_ecc_handle);
  }

  return ret;
}
