#include "app.h"
#include "endianswap.h"
#include <assert.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <string.h>

// read from pem file and output public key in a 64 byte array
bool read_pem_pubkey(const char *const filename, void **buffer,
                     size_t *buffer_size) {
  bool ret_status = true;
  FILE *fp = NULL;
  long file_len = 0L;
  unsigned char *pkbuf = NULL;
  size_t pkbuf_size = 0L;
  EC_KEY *ec_key = NULL;

  if (buffer == NULL || buffer_size == NULL) {
    fprintf(stderr, "[GatewayApp]: read_pem_pubkey() invalid parameter\n");
    ret_status = false;
    goto cleanup;
  }
  *buffer = NULL;

  fp = fopen(filename, "rb");
  if (fp == NULL) {
    fprintf(stderr, "[GatewayApp]: read_file_into_memory() fopen failed\n");
    ret_status = false;
    goto cleanup;
  }

  fseek(fp, 0, SEEK_END);
  file_len = ftell(fp);
  if (file_len < 0 || file_len > INT_MAX) {
    fprintf(stderr, "[GatewayApp]: Invalid input file size\n");
    ret_status = false;
    goto cleanup;
  }

  fseek(fp, 0, SEEK_SET);
  ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);

  ec_key = PEM_read_EC_PUBKEY(fp, &ec_key, NULL, NULL);

  pkbuf_size =
      EC_KEY_key2buf(ec_key, POINT_CONVERSION_UNCOMPRESSED, &pkbuf, NULL);

  // z | x | y where z is 0x04
  assert(pkbuf_size == 65);
  pkbuf = pkbuf + 1; // skip z
  *buffer_size = 64;
  *buffer = malloc(*buffer_size);
  if (!*buffer) {
    fprintf(stderr, "[GatewayApp]: malloc() failed\n");
    ret_status = false;
    goto cleanup;
  }

  memset(*buffer, 0, *buffer_size);

  // flip from openssl big endian to sgx little endian
  for (size_t i = 0; i < 64; ++i) {
    (*(unsigned char **)buffer)[i] = pkbuf[i];
  }
  SWAP_ENDIAN_8X32B((*(unsigned char **)buffer));
  SWAP_ENDIAN_8X32B((*(unsigned char **)buffer) + 32);

cleanup:
  if (fp != NULL) {
    fclose(fp);
  }
  if (ec_key) {
    EC_KEY_free(ec_key);
  }
  return ret_status;
}

bool read_der_signature(const char *const filename, void **buffer,
                        size_t *buffer_size) {
  bool ret_status = true;

  ECDSA_SIG *ecdsa_sig = NULL;
  const BIGNUM *r = NULL, *s = NULL;

  FILE *file = NULL;
  char *file_buffer = NULL;
  size_t file_size = 0;
  // read the signature file to memory
  if (!read_file_into_memory(filename, &file_buffer, &file_size)) {
    fprintf(stderr, "[GatewayApp]: read file to memory\n");
    ret_status = false;
    goto cleanup;
  }

  // convert DER to BN to r/s
  ecdsa_sig = ECDSA_SIG_new();
  if (ecdsa_sig == NULL) {
    fprintf(stderr, "[GatewayApp]: memory alloction failure ecdsa_sig\n");
    ret_status = false;
    goto cleanup;
  }

  ecdsa_sig = d2i_ECDSA_SIG(&ecdsa_sig, (const unsigned char **)&file_buffer,
                            file_size);

  r = ECDSA_SIG_get0_r(ecdsa_sig);
  s = ECDSA_SIG_get0_s(ecdsa_sig);

  // convert r/s to little endian buffer
  *buffer_size = 64;
  *buffer = malloc(*buffer_size);
  if (!*buffer) {
    fprintf(stderr, "[GatewayApp]: malloc failed\n");
    ret_status = false;
    goto cleanup;
  }

  BN_bn2bin(r, *buffer);
  BN_bn2bin(s, ((unsigned char *)*buffer) + 32);

  SWAP_ENDIAN_8X32B((unsigned char *)*buffer);
  SWAP_ENDIAN_8X32B(((unsigned char *)*buffer) + 32);

cleanup:
  if (file) {
    fclose(file);
  }
  if (ecdsa_sig) {
    ECDSA_SIG_free(ecdsa_sig);
  }
  if (!ret_status && *buffer) {
    free(*buffer);
  }
  return ret_status;
}