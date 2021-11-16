#ifndef _ELECTION_STATE_H
#define _ELECTION_STATE_H
#include <stdint.h>

#define PK_LEN 64
#define ENC_BALLOT_LEN 64
#define BALLOT_LEN 1024

typedef enum state_ctr {
  vt_created = 0,
  vt_registered,
  vt_open,
  vt_closed,
  vt_tallied
} state_ctr_t;

typedef struct __attribute__((packed)) election_state {
  uint8_t admin_pk[PK_LEN];
  uint8_t v1_pk[PK_LEN];
  uint8_t v2_pk[PK_LEN];
  uint8_t v3_pk[PK_LEN];
  uint8_t ballot[BALLOT_LEN];
  int8_t opt1[16];
  int8_t opt2[16];
  int8_t opt3[16];
  uint8_t p[32];
  uint8_t g[32];
  uint8_t pk[32];
  uint8_t sk[32];
  uint8_t election_hash[32];
  uint8_t state_counter;
  uint8_t v1_ballot[ENC_BALLOT_LEN];
  uint8_t v2_ballot[ENC_BALLOT_LEN];
  uint8_t v3_ballot[ENC_BALLOT_LEN];
} election_state_t;

typedef struct __attribute__((packed)) bulletin_board {
  uint8_t election_hash[32];
  uint8_t ballot[BALLOT_LEN];
  uint8_t p[32];
  uint8_t g[32];
  uint8_t pk[32];
} bulletin_board_t;

#endif