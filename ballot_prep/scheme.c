/* --------------------------- *
 * This code was done by:      *
 * Cuate-Gónzales Oliver and,  *
 * Chi-Domínguez Jesús-Javier. *
 * --------------------------- */

#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void Elgamal_Gen();
void Elgamal_encrypt();
void Elgamal_decrypt();
void Enc_Scheme();
void Dec_Scheme();
void Hash();
void get_message();
void generator_Gen();

#define MPZ_WORDS_MAX 32
#define MPZ_WORDS_ORDER 1      /* Most significant order first */
#define MPZ_WORDS_ENDIANNESS 0 /* Use host endianness */
#define MPZ_NAILS 0            /* Use full words */

// Generates key pair and encrypts/decrypts message
int full_elgamal_example(void) {

  char hardcoded_p[32] = {0x7B, 0x9F, 0x4C, 0xA3, 0xF8, 0x8A, 0x0E, 0x1F,
                          0x4A, 0x8C, 0xEE, 0x10, 0xBE, 0x72, 0x1E, 0x2B,
                          0x78, 0xAC, 0x50, 0xE0, 0x1B, 0x92, 0x1C, 0x96,
                          0x9D, 0xF5, 0xF1, 0x30, 0xDD, 0x9C, 0x81, 0x11};

  char hardcoded_q[16] = {0xED, 0xD8, 0x3C, 0x02, 0xE1, 0xC9, 0x5B, 0x6B,
                          0xF0, 0x33, 0xB5, 0x1E, 0xEA, 0x87, 0xC0, 0x05};

  char hardcoded_3[8] = {0xDD, 0x51, 0x63, 0x42, 0x42, 0xB3, 0x4B, 0x07};
  char hardcoded_4[6] = {0x71, 0xCB, 0x28, 0xA8, 0x18, 0x21};
  char hardcoded_5[3] = {0x0F, 0x4C, 0x0F};
  char hardcoded_6[1] = {0x03};
  char hardcoded_7[1] = {0x02};

  mpz_t *array;
  array = (mpz_t *)malloc(7 * sizeof(mpz_t));
  for (int i = 0; i < 7; i++) {
    mpz_init(array[i]);
  }

  mpz_t q;
  mpz_t p;
  mpz_t v3, v4, v5, v6, v7;

  mpz_init(q);
  mpz_init(p);
  mpz_init(v3);
  mpz_init(v4);
  mpz_init(v5);
  mpz_init(v6);
  mpz_init(v7);

  /*
  mpz_set_str(array[0],
  "7918324333004779287780879909121159911537551977796076554305607309994905870203",
  10); mpz_set_str(array[1], "7645817649953398726194923102564833517", 10);
  mpz_set_str(array[2], "525710878681813469", 10);
  mpz_set_str(array[3], "36389784177521", 10);
  mpz_set_str(array[4], "1002511", 10);
  mpz_set_str(array[5], "3", 10);
  mpz_set_str(array[6], "2", 10);
  */

  mpz_import(p, 1, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS, MPZ_NAILS,
             hardcoded_p);
  mpz_import(q, 1, MPZ_WORDS_ORDER, 16, MPZ_WORDS_ENDIANNESS, MPZ_NAILS,
             hardcoded_q);
  mpz_import(v3, 1, MPZ_WORDS_ORDER, 8, MPZ_WORDS_ENDIANNESS, MPZ_NAILS,
             hardcoded_3);
  mpz_import(v4, 1, MPZ_WORDS_ORDER, 6, MPZ_WORDS_ENDIANNESS, MPZ_NAILS,
             hardcoded_4);
  mpz_import(v5, 1, MPZ_WORDS_ORDER, 3, MPZ_WORDS_ENDIANNESS, MPZ_NAILS,
             hardcoded_5);
  mpz_import(v6, 1, MPZ_WORDS_ORDER, 1, MPZ_WORDS_ENDIANNESS, MPZ_NAILS,
             hardcoded_6);
  mpz_import(v7, 1, MPZ_WORDS_ORDER, 1, MPZ_WORDS_ENDIANNESS, MPZ_NAILS,
             hardcoded_7);

  mpz_set(array[0], p);
  mpz_set(array[1], q);
  mpz_set(array[2], v3);
  mpz_set(array[3], v4);
  mpz_set(array[4], v5);
  mpz_set(array[5], v6);
  mpz_set(array[6], v7);

  /*for (int i = 0; i < 7; i++) {
          gmp_printf("[%d]: %Zd\n", i, array[i]);
  }*/

  mpz_t g;
  mpz_t sk;
  mpz_t pk;
  mpz_init(g);
  mpz_init(sk);
  mpz_init(pk);

  generator_Gen(g, array, 7);
  Elgamal_Gen(sk, pk, g, p);

  gmp_printf("\nvalue of g: \n%Zd ", g);
  gmp_printf("\nvalue of mod: \n%Zd ", p);
  gmp_printf("\nvalue of pk: \n%Zd ", pk);
  gmp_printf("\nvalue of sk: \n%Zd\n", sk);

  mpz_t plaintext;
  mpz_t ciphertext_0;
  mpz_t ciphertext_1;
  mpz_t decrypted_ciphertext;

  mpz_init(plaintext);
  mpz_init(ciphertext_0);
  mpz_init(ciphertext_1);
  mpz_init(decrypted_ciphertext);

  char plaintext_ballot[1] = {0x04};
  mpz_import(plaintext, 1, MPZ_WORDS_ORDER, 1, MPZ_WORDS_ENDIANNESS, MPZ_NAILS,
             plaintext_ballot);

  gmp_printf("\nplaintext: \n%Zd", plaintext);
  Elgamal_encrypt(ciphertext_0, ciphertext_1, plaintext, pk, g, p);
  Elgamal_decrypt(decrypted_ciphertext, ciphertext_0, ciphertext_1, sk, p);
  gmp_printf("\nciphertext: \n%Zd\n%Zd ", ciphertext_0, ciphertext_1);
  gmp_printf("\ndecrypted_ciphertext: \n%Zd\n", decrypted_ciphertext);

  printf("cipher sizes: p %d c0 %d c1 %d\n",
         mpz_sizeinbase(plaintext, (1 << 8)),
         mpz_sizeinbase(ciphertext_0, (1 << 8)),
         mpz_sizeinbase(ciphertext_1, (1 << 8)));

  char buffer[128];
  size_t buf_sz = 32;

  /* Exports p/g/pk/sk into buffer */
  mpz_export(&buffer[0], &buf_sz, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS,
             MPZ_NAILS, p);
  mpz_export(&buffer[32], &buf_sz, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS,
             MPZ_NAILS, g);
  mpz_export(&buffer[64], &buf_sz, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS,
             MPZ_NAILS, pk);
  mpz_export(&buffer[96], &buf_sz, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS,
             MPZ_NAILS, sk);

  printf("%02X:%02X:%02X:%02X\n", buffer[0], buffer[1], buffer[32], buffer[64]);

  mpz_t p1;
  mpz_t g1;
  mpz_t sk1;
  mpz_t pk1;
  mpz_init(p1);
  mpz_init(g1);
  mpz_init(sk1);
  mpz_init(pk1);

  mpz_import(p1, 1, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS, MPZ_NAILS,
             &buffer[0]);
  mpz_import(g1, 1, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS, MPZ_NAILS,
             &buffer[32]);
  mpz_import(pk1, 1, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS, MPZ_NAILS,
             &buffer[64]);
  mpz_import(sk1, 1, MPZ_WORDS_ORDER, 32, MPZ_WORDS_ENDIANNESS, MPZ_NAILS,
             &buffer[96]);

  gmp_printf("\nvalue of p1: \n%Zd ", p1);
  gmp_printf("\nvalue of g1: \n%Zd ", g1);
  gmp_printf("\nvalue of pk1: \n%Zd ", pk1);
  gmp_printf("\nvalue of sk1: \n%Zd\n", sk1);

  return 0;
}

int main(void) {

  full_elgamal_example();
  return 0;

  mpz_t *array1;
  array1 = (mpz_t *)malloc(7 * sizeof(mpz_t));

  mpz_t q1;
  mpz_t p1;
  mpz_init(q1);
  mpz_init(p1);

  for (int i = 0; i < 7; i++) {
    mpz_init(array1[i]);
  }
  mpz_init(array1[1]);

  mpz_set_str(array1[0],
              "79183243330047792877808799091211599115375519777960765543056073"
              "09994905870203",
              10);
  mpz_set_str(array1[1], "7645817649953398726194923102564833517", 10);
  mpz_set_str(array1[2], "525710878681813469", 10);
  mpz_set_str(array1[3], "36389784177521", 10);
  mpz_set_str(array1[4], "1002511", 10);
  mpz_set_str(array1[5], "3", 10);
  mpz_set_str(array1[6], "2", 10);

  mpz_set(p1, array1[0]);
  mpz_set(q1, array1[1]);

  mpz_t g1;
  mpz_t sk1;
  mpz_t pk1;

  gmp_printf(" \n p1: %Zd ", p1);

  size_t data_inp_sz = 0, data_out_sz = 0;

  char data_out[100000];
  char data_inp[100000];
  /* Handles output bufer */

  data_out_sz = 100000;
  if (data_out_sz < mpz_sizeinbase(p1, (1 << 8))) /* size in bytes */
  {
    /* Output buffer too short */
    printf("Smol Buffer!\n");
    return 0;
  }

  /* Exports mpz_t in data_out */
  mpz_export(data_out, &data_out_sz, MPZ_WORDS_ORDER,
             mpz_sizeinbase(p1, (1 << 8)), MPZ_WORDS_ENDIANNESS, MPZ_NAILS, q1);

  printf("\nTrustedApp: Pre GEN!\n");

  /*printf("%d\n", mpz_sizeinbase(p1, (1 << 8)));
  printf("%02X:%02X:%02X:%02X\n", data_out[0], data_out[1], data_out[2],
  data_out[3]); printf("%02X:%02X:%02X:%02X\n", data_out[4], data_out[5],
  data_out[6], data_out[7]); printf("%02X:%02X:%02X:%02X\n", data_out[8],
  data_out[9], data_out[10], data_out[11]); printf("%02X:%02X:%02X:%02X\n",
  data_out[12], data_out[13], data_out[14], data_out[15]);
  printf("%02X:%02X:%02X:%02X\n", data_out[16], data_out[17], data_out[18],
  data_out[19]); printf("%02X:%02X:%02X:%02X\n", data_out[20], data_out[21],
  data_out[22], data_out[23]); printf("%02X:%02X:%02X:%02X\n", data_out[24],
  data_out[25], data_out[26], data_out[27]); printf("%02X:%02X:%02X:%02X\n",
  data_out[28], data_out[29], data_out[30], data_out[31]);
  printf("%02X:%02X:%02X:%02X\n", data_out[32], data_out[1], data_out[2],
  data_out[3]);*/
  char hardcoded_p[32] = {0x7B, 0x9F, 0x4C, 0xA3, 0xF8, 0x8A, 0x0E, 0x1F,
                          0x4A, 0x8C, 0xEE, 0x10, 0xBE, 0x72, 0x1E, 0x2B,
                          0x78, 0xAC, 0x50, 0xE0, 0x1B, 0x92, 0x1C, 0x96,
                          0x9D, 0xF5, 0xF1, 0x30, 0xDD, 0x9C, 0x81, 0x11};

  char hardcoded_q[32] = {0xED, 0xD8, 0x3C, 0x02, 0xE1, 0xC9, 0x5B, 0x6B,
                          0xF0, 0x33, 0xB5, 0x1E, 0xEA, 0x87, 0xC0, 0x05};

  mpz_t input;
  mpz_init(input);
  mpz_import(input, 1, MPZ_WORDS_ORDER, 16, MPZ_WORDS_ENDIANNESS, MPZ_NAILS,
             hardcoded_q);

  for (int i = 0; i < 7; i++) {
    gmp_printf("[%d]: %Zd\n", i, array1[i]);
  }
  generator_Gen(g1, array1, 7);
  Elgamal_Gen(sk1, pk1, g1, p1);

  printf("\nTrustedApp: Post GEN!\n");

  gmp_printf("\nvalue of g: \n%Zd ", g1);
  gmp_printf("\nvalue of mod: \n%Zd ", p1);
  gmp_printf("\nvalue of pk: \n%Zd ", pk1);
  gmp_printf("\nvalue of sk: \n%Zd\n", sk1);

  test();
  return 0;
  while (1) {
  }
  srand(time(NULL));
  int solve;
  mpz_t q;
  mpz_t p;

  mpz_init(q);
  mpz_init(p);

  /* In this part we read the possible prime that it's in file_name.txt */
  char ch, file_name[20000], message_file[10000];
  FILE *fp;
  char m0[100000], m1[100000];

  fp = fopen("primes.txt", "r"); // read mode

  if (fp == NULL) {
    perror("Error while opening the file.\n");
    exit(EXIT_FAILURE);
  }

  printf("The %s file contains the public prime q:\n", file_name);

  int nk = 0;
  while (fscanf(fp, "%s", file_name) != EOF) // reading file..
    nk += 1;

  mpz_t *array;

  array = (mpz_t *)malloc(nk * sizeof(mpz_t));
  int qwert;

  for (qwert = 0; qwert < nk; qwert++)
    mpz_init(array[qwert]);

  rewind(fp);
  for (qwert = 0; qwert < nk; qwert++) {
    fscanf(fp, "%s", file_name);
    mpz_set_str(array[qwert], file_name, 10);
  }

  /* set N to the number file_name (as a number and not as string)*/

  mpz_set(p, array[0]);
  mpz_set(q, array[1]);

  gmp_printf(" \n%Zd ", q);

  mpz_set_str(array[1], "525710878681813469", 10);

  printf("BEFORE ME!\n");
  mpz_set(q, array[1]);
  gmp_printf(" \n%Zd ", q);
  printf("AFTER ME!\n");

  while (1) {
  }

  /* Miller-Rabin */
  solve = miller_rabin(q);

  gmp_printf("And 2*k*q + 1 is equal to: \n%Zd ", p);

  /* Miller-Rabin */
  solve = miller_rabin(p);

  get_message(m0, m1);

  /*EXAMPLE OF ELGAMAL*/
  mpz_t g;
  mpz_t sk;
  mpz_t pk;
  mpz_t m_0;
  mpz_t m_1;
  mpz_t c_0;
  mpz_t c_1;
  mpz_t m;

  mpz_init(g);
  mpz_init(pk);
  mpz_init(sk);
  mpz_init(m_0);
  mpz_init(m_1);
  mpz_init(c_0);
  mpz_init(c_1);
  mpz_init(m);

  generator_Gen(g, array, nk);
  mpz_set_str(m_0, m0, 10);
  mpz_set_str(m_1, m1, 10);

  printf("*********EXAMPLE OF ELGAMAL*********");

  Elgamal_Gen(sk, pk, g, p);

  gmp_printf("\nvalue of g: \n%Zd ", g);
  gmp_printf("\nvalue of mod: \n%Zd ", p);
  gmp_printf("\nvalue of pk: \n%Zd ", pk);
  gmp_printf("\nvalue of sk: \n%Zd\n", sk);

  gmp_printf("\nvalue of msg0: \n%Zd", m_0);
  Elgamal_encrypt(c_0, c_1, m_0, pk, g, p);
  Elgamal_decrypt(m, c_0, c_1, sk, p);
  gmp_printf("\nvalue of c0: \n%Zd ", c_0);
  gmp_printf("\nvalue of c1: \n%Zd ", c_1);
  gmp_printf("\nvalue of m0: \n%Zd\n", m);

  gmp_printf("\nvalue of msg1: \n%Zd", m_1);
  Elgamal_encrypt(c_0, c_1, m_1, pk, g, p);
  Elgamal_decrypt(m, c_0, c_1, sk, p);
  gmp_printf("\nvalue of c0: \n%Zd ", c_0);
  gmp_printf("\nvalue of c1: \n%Zd ", c_1);
  gmp_printf("\nvalue of m1: \n%Zd\n", m);

  printf("\n*********EXAMPLE OF OUR CRYPTOSYSTEM*********");

  gmp_printf("\nvalue of msg0: \n%Zd", m_0);
  Enc_Scheme(c_0, c_1, m_0, pk, g, p);
  Dec_Scheme(m, c_0, c_1, sk, p);
  gmp_printf("\nvalue of c0: \n%Zd ", c_0);
  gmp_printf("\nvalue of c1: \n%Zd ", c_1);
  gmp_printf("\nvalue of m0: \n%Zd\n", m);

  gmp_printf("\nvalue of msg1: \n%Zd", m_1);
  Enc_Scheme(c_0, c_1, m_1, pk, g, p);
  Dec_Scheme(m, c_0, c_1, sk, p);
  gmp_printf("\nvalue of c0: \n%Zd ", c_0);
  gmp_printf("\nvalue of c1: \n%Zd ", c_1);
  gmp_printf("\nvalue of m0: \n%Zd\n", m);

  /* free used memory */
  mpz_clear(q);
  mpz_clear(p);
  mpz_clear(g);
  mpz_clear(sk);
  mpz_clear(pk);
  mpz_clear(m_0);
  mpz_clear(m_1);
  mpz_clear(c_0);
  mpz_clear(c_1);

  for (qwert = 0; qwert < nk; qwert++)
    mpz_clear(array[qwert]);

  free(array);
  fclose(fp);

  return EXIT_SUCCESS;
}

// The following function computes: m*2^k
int m_times_2_to_the_k(mpz_t m, mpz_t N) {
  int equal, k;
  mpz_t auxN;
  mpz_t residual;

  mpz_init(auxN);
  mpz_init(residual);

  mpz_set(auxN, N);
  mpz_mod_ui(residual, auxN, 2);
  equal = mpz_cmp_ui(residual, 0);
  k = 0;

  while (equal == 0) {
    k += 1;
    mpz_divexact_ui(auxN, auxN, 2);
    mpz_mod_ui(residual, auxN, 2);
    equal = mpz_cmp_ui(residual, 0);
  }

  mpz_set(m, auxN);

  mpz_clear(auxN);
  mpz_clear(residual);
  return k;
}

// Miller rabin algorithm
int miller_rabin(mpz_t N) {
  int seed = rand();

  int k;
  mpz_t N_one;
  mpz_t m;
  mpz_t a;
  mpz_t b;
  int equal;
  gmp_randstate_t r_state;

  mpz_init(N_one);
  mpz_init(m);
  mpz_init(b);

  gmp_randinit_default(r_state);
  gmp_randseed_ui(r_state, seed);
  mpz_init(a);

  mpz_sub_ui(N_one, N, 1);
  mpz_set_str(m, "0", 10);
  k = m_times_2_to_the_k(m, N_one);

  mpz_urandomm(a, r_state, N);

  mpz_powm(b, a, m, N);

  equal = mpz_cmp_ui(b, 1);
  if (equal == 0) {
    return 1;
  } else {
    int i;
    for (i = 0; i < k; ++i) {
      equal = mpz_cmp(b, N_one);
      if (equal == 0) {
        return 1;
        break;
      } else {
        mpz_powm_ui(b, b, 2, N);
      }
    }
    return 0;
  }

  /* free used memory */
  mpz_clear(N_one);
  mpz_clear(m);
  mpz_clear(b);
  gmp_randclear(r_state);
  mpz_clear(a);
}

// Key generator for our scheme
void generator_Gen(mpz_t g, mpz_t *primes, int sz) {
  int seedg = 1; // rand();
  int cg, equal_1;
  mpz_t condition;
  int gen_true = 1, yeah = 0;
  mpz_t p_1;
  mpz_t pq_i;

  mpz_init(condition);
  mpz_init(p_1);
  mpz_init(pq_i);
  gmp_randstate_t rg_state;

  gmp_randinit_default(rg_state);
  gmp_randseed_ui(rg_state, seedg);

  mpz_sub_ui(p_1, primes[0], 1);

  while (gen_true == 1) {
    mpz_urandomm(g, rg_state, primes[0]);
    for (cg = 1; cg < sz; ++cg) {
      mpz_cdiv_q(pq_i, p_1, primes[cg]);
      mpz_powm(condition, g, pq_i, primes[0]);
      equal_1 = mpz_cmp_ui(condition, 1);
      if (equal_1 == 0) {
        yeah = 1;
        cg = sz;
      }
    }
    if (yeah == 0)
      gen_true = 0;
    else
      yeah = 0;
  }

  mpz_cdiv_q(pq_i, p_1, primes[1]);
  mpz_powm(g, g, pq_i, primes[0]);
  mpz_clear(condition);
  mpz_clear(p_1);
  mpz_clear(pq_i);
}

// Key generator for Elgamal
void Elgamal_Gen(mpz_t sk, mpz_t pk, mpz_t g, mpz_t modulus) {
  int seedx = rand();
  gmp_randstate_t ry_state;

  gmp_randinit_default(ry_state);
  gmp_randseed_ui(ry_state, seedx);

  mpz_urandomm(sk, ry_state, modulus);
  mpz_powm(pk, g, sk, modulus);
  gmp_randclear(ry_state);
}

// Encryption function for Elgamal
void Elgamal_encrypt(mpz_t cipher0, mpz_t cipher1, mpz_t message, mpz_t pk,
                     mpz_t g, mpz_t modulus) {
  int seedy = rand();

  mpz_t y;
  mpz_t pky;
  gmp_randstate_t ry_state;

  mpz_init(y);
  mpz_init(pky);
  gmp_randinit_default(ry_state);
  gmp_randseed_ui(ry_state, seedy);

  mpz_urandomm(y, ry_state, modulus);

  mpz_powm(pky, pk, y, modulus);
  mpz_mul(cipher0, message, pky);
  mpz_mod(cipher0, cipher0, modulus);
  mpz_powm(cipher1, g, y, modulus);

  mpz_clear(y);
  mpz_clear(pky);
  gmp_randclear(ry_state);
}

// Decryption function for Elgamal
void Elgamal_decrypt(mpz_t message, mpz_t cipher0, mpz_t cipher1, mpz_t sk,
                     mpz_t modulus) {
  mpz_t gxy;
  mpz_t inv_gxy;

  mpz_init(gxy);
  mpz_init(inv_gxy);

  mpz_powm(gxy, cipher1, sk, modulus);
  mpz_invert(inv_gxy, gxy, modulus);
  mpz_mul(message, cipher0, inv_gxy);
  mpz_mod(message, message, modulus);

  mpz_clear(gxy);
  mpz_clear(inv_gxy);
}

/*
void Hash(mpz_t h,mpz_t x,mpz_t modulus){
        mpz_mod(h, x, modulus);
}
*/

// Hash function implementation
void Hash(mpz_t h, mpz_t K, mpz_t M) {
  double c = 0.6180339887;
  mpf_t prod;
  mpf_t cons;
  mpf_t aux;

  mpf_init(prod);
  mpf_init(cons);
  mpf_init(aux);
  mpf_set_z(prod, K);
  mpf_set_d(cons, c);

  mpf_mul(prod, prod, cons);
  mpf_floor(aux, prod);
  mpf_sub(prod, prod, aux);
  mpf_set_z(aux, M);
  mpf_mul(prod, prod, aux);
  mpf_floor(prod, prod);
  mpz_set_f(h, prod);
}

// Encryption function for our scheme
void Enc_Scheme(mpz_t cipher0, mpz_t cipher1, mpz_t message, mpz_t pk, mpz_t g,
                mpz_t modulus) {
  int seedy = rand();
  mpz_t b;
  mpz_t m;
  mpz_t pkb;
  mpz_t h;
  gmp_randstate_t ry_state;

  mpz_init(b);
  mpz_init(m);
  mpz_init(pkb);
  mpz_init(h);
  gmp_randinit_default(ry_state);
  gmp_randseed_ui(ry_state, seedy);
  mpz_urandomm(b, ry_state, modulus);

  mpz_powm(pkb, pk, b, modulus);
  Hash(h, pkb, modulus);
  mpz_xor(m, message, h);
  mpz_mul(cipher0, m, pkb);
  mpz_mod(cipher0, cipher0, modulus);
  mpz_powm(cipher1, g, b, modulus);

  mpz_clear(b);
  mpz_clear(pkb);
  gmp_randclear(ry_state);
}

// Decryption function for our scheme
void Dec_Scheme(mpz_t message, mpz_t cipher0, mpz_t cipher1, mpz_t sk,
                mpz_t modulus) {
  mpz_t gxy;
  mpz_t h;
  mpz_t inv_gxy;

  mpz_init(gxy);
  mpz_init(h);
  mpz_init(inv_gxy);

  mpz_powm(gxy, cipher1, sk, modulus);
  mpz_invert(inv_gxy, gxy, modulus);
  Hash(h, gxy, modulus);
  mpz_mul(message, cipher0, inv_gxy);
  mpz_mod(message, message, modulus);
  mpz_xor(message, message, h);

  mpz_clear(gxy);
  mpz_clear(inv_gxy);
}

// Read the message from file
void get_message(char *m_0, char *m_1) {
  FILE *fm;
  char message_file[100];
  printf("\nEnter the name of file where the message is:\n");
  scanf("%s", message_file);

  printf("\n");
  fm = fopen(message_file, "r"); // read mode

  if (fm == NULL) {
    perror("Error while opening the file.\n");
    exit(EXIT_FAILURE);
  }

  fseek(fm, 0, SEEK_END);
  int dig = ftell(fm) - 1;
  rewind(fm);
  fgets(m_0, dig / 2 + 1, fm);
  fgets(m_1, dig, fm);
  fclose(fm);
}
