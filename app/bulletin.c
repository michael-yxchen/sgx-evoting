#include "../enclave/election_state.h"
#include "app.h"
#include <json.h>

#define STRBUFSZ (PK_LEN * 2) + 1

static int hexify(const void *in, size_t insize, char *out, size_t outsize) {
  static const char *hex = "0123456789abcdef";
  if (outsize < insize * 2 + 1) {
    return -1;
  }
  const uint8_t *char_in = (const uint8_t *)in;
  int out_off = 0;
  for (size_t i = 0; i < insize; ++i) {
    out[out_off++] = hex[(char_in[i] >> 4) & 0xf];
    out[out_off++] = hex[char_in[i] & 0xf];
  }
  out[out_off++] = '\0';
  return out_off;
}

bool save_bulletin(const char *const bulletin_file,
                   const char *const admin_file, const char *const voter1_file,
                   const char *const voter2_file,
                   const char *const voter3_file) {
  bool ret_status = true;

  printf("[GatewayApp]: Saving bulletin board\n");

  FILE *bb_file = open_file(bulletin_file, "w");

  if (bb_file == NULL) {
    fprintf(stderr, "[GatewayApp]: save_enclave_state() fopen failed\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    return false;
  }

  bulletin_board_t *bb = (bulletin_board_t *)bulletin_buffer;

  char strbuf[STRBUFSZ];
  json_object *j = json_object_new_object();
  hexify(bb->election_hash, sizeof(bb->election_hash), strbuf, sizeof(strbuf));
  json_object_object_add(j, "0", json_object_new_string(strbuf));
  json_object *ballot = json_tokener_parse(bb->ballot);
  json_object_object_add(j, "1", ballot);

  json_object *pgpk;
  pgpk = json_object_new_array();

  hexify(bb->p, sizeof(bb->p), strbuf, sizeof(strbuf));
  json_object_array_add(pgpk, json_object_new_string(strbuf));
  hexify(bb->g, sizeof(bb->g), strbuf, sizeof(strbuf));
  json_object_array_add(pgpk, json_object_new_string(strbuf));
  hexify(bb->pk, sizeof(bb->pk), strbuf, sizeof(strbuf));
  json_object_array_add(pgpk, json_object_new_string(strbuf));
  json_object_object_add(j, "2", pgpk);

  json_object_object_add(j, "3", json_object_new_string("placeholder text"));

  char pembuf[256];
  FILE* fp;
  fp = fopen(admin_file, "r");
  fseek(fp, 0, SEEK_END);
  size_t flen = (size_t)ftell(fp);
  fseek(fp, 0, SEEK_SET);
  fread(pembuf, flen, 1, fp);
  pembuf[flen] = '\0';
  json_object_object_add(j, "4", json_object_new_string(pembuf));
  fclose(fp);
  fp = NULL;

  json_object* voter_key = json_object_new_array();
  fp = fopen(voter1_file, "r");
  fseek(fp, 0, SEEK_END);
  flen = (size_t)ftell(fp);
  fseek(fp, 0, SEEK_SET);
  fread(pembuf, flen, 1, fp);
  pembuf[flen] = '\0';
  json_object_array_add(voter_key, json_object_new_string(pembuf));
  fclose(fp);

  fp = fopen(voter2_file, "r");
  fseek(fp, 0, SEEK_END);
  flen = (size_t)ftell(fp);
  fseek(fp, 0, SEEK_SET);
  fread(pembuf, flen, 1, fp);
  pembuf[flen] = '\0';
  json_object_array_add(voter_key, json_object_new_string(pembuf));
  fclose(fp);

  fp = fopen(voter3_file, "r");
  fseek(fp, 0, SEEK_END);
  flen = (size_t)ftell(fp);
  fseek(fp, 0, SEEK_SET);
  fread(pembuf, flen, 1, fp);
  pembuf[flen] = '\0';
  json_object_array_add(voter_key, json_object_new_string(pembuf));
  fclose(fp);

  json_object_object_add(j, "5", voter_key);

  fprintf(bb_file, "%s", json_object_to_json_string(j));
  json_object_put(j);

  // if (fwrite(bulletin_buffer, bulletin_buffer_size, 1, bb_file) != 1) {
  //   fprintf(stderr, "[GatewayApp]: Enclave state only partially written.\n");
  //   sgx_lasterr = SGX_ERROR_UNEXPECTED;
  //   ret_status = false;
  // }

  fclose(bb_file);

  return ret_status;
}