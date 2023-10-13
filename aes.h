/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef FAEST_AES_H
#define FAEST_AES_H

#include "macros.h"
#include "instances.h"

#include <openssl/evp.h>
#include <stdint.h>
#include <stdlib.h>

#include <immintrin.h>
#include <wmmintrin.h>


FAEST_BEGIN_C_DECL

#define AES_MAX_ROUNDS 14

typedef uint8_t aes_word_t[4];
// round key with 4 (AES) up to 8 (Rijndael-256) units
// TODO: aes_round_key_t[8] should this be 8 ?
typedef aes_word_t aes_round_key_t[8];

// # of rows
#define AES_NR 4

// block with 4 (AES) up to 8 (Rijndael-256) units
typedef aes_word_t aes_block_t[8];

typedef struct {
  aes_round_key_t round_keys[AES_MAX_ROUNDS + 1];
} aes_round_keys_t;

int aes128_init_round_keys(aes_round_keys_t* round_key, const uint8_t* key);
int aes192_init_round_keys(aes_round_keys_t* round_key, const uint8_t* key);
int aes256_init_round_keys(aes_round_keys_t* round_key, const uint8_t* key);
int rijndael192_init_round_keys(aes_round_keys_t* round_key, const uint8_t* key);
int rijndael256_init_round_keys(aes_round_keys_t* round_key, const uint8_t* key);

int aes128_encrypt_block(const aes_round_keys_t* key, const uint8_t* plaintext,
                         uint8_t* ciphertext);
int aes192_encrypt_block(const aes_round_keys_t* key, const uint8_t* plaintext,
                         uint8_t* ciphertext);
int aes256_encrypt_block(const aes_round_keys_t* key, const uint8_t* plaintext,
                         uint8_t* ciphertext);
int rijndael192_encrypt_block(const aes_round_keys_t* key, const uint8_t* plaintext,
                              uint8_t* ciphertext);
int rijndael256_encrypt_block(const aes_round_keys_t* key, const uint8_t* plaintext,
                              uint8_t* ciphertext);

void aes_increment_iv(uint8_t* iv);

uint8_t* aes_extend_witness(const uint8_t* key, const uint8_t* in, const faest_paramset_t* params);

int expand_key(aes_round_keys_t* round_keys, const uint8_t* key, unsigned int key_words,
               unsigned int block_words, unsigned int num_rounds);

void prg(const uint8_t* key, const uint8_t* iv, uint8_t* out, unsigned int seclvl, size_t outlen);

typedef __m128i block128;
typedef __m256i block256;

#define ROUNDS_128 10
#define ROUNDS_192 12
#define ROUNDS_256 14

typedef struct
{
	uint64_t data[3];
} block192;

typedef struct
{
	block192 keys[ROUNDS_192 + 1];
} rijndael192_round_keys;

typedef struct
{
	block256 keys[ROUNDS_256 + 1];
} rijndael256_round_keys;

union CCR_CTX {
  EVP_CIPHER_CTX* evp_ctx;
  rijndael192_round_keys r192_round_keys;
  rijndael256_round_keys r256_round_keys;
};

union CCR_CTX CCR_CTX_setup(unsigned int seclvl, const uint8_t* iv);

void CCR_CTX_free(union CCR_CTX* ctx, unsigned int seclvl);

// TODO outlen should be fixed
void ccr(const uint8_t* key, const uint8_t* iv, uint8_t* out, unsigned int seclvl, size_t outlen);

void ccr2(const uint8_t* src, const uint8_t* iv, uint8_t* seed, size_t seed_len,
          uint8_t* commitment, size_t commitment_len, unsigned int seclvl);

void ccr2_x4(const uint8_t* src0, const uint8_t* src1, const uint8_t* src2, const uint8_t* src3,
             const uint8_t* iv,
             uint8_t* seed0, uint8_t* seed1, uint8_t* seed2, uint8_t* seed3, size_t seed_len,
             uint8_t* commitment0, uint8_t* commitment1, uint8_t* commitment2, uint8_t* commitment3, size_t commitment_len,
             unsigned int seclvl);

void ccr_with_ctx(union CCR_CTX* ctx, const uint8_t* in, uint8_t* out, size_t outlen);

void ccr2_with_ctx(union CCR_CTX* ctx, const uint8_t* src, uint8_t* seed, size_t seed_len,
          uint8_t* commitment, size_t commitment_len);

void ccr2_x4_with_ctx(union CCR_CTX* ctx, const uint8_t* src0, const uint8_t* src1, const uint8_t* src2, const uint8_t* src3,
             uint8_t* seed0, uint8_t* seed1, uint8_t* seed2, uint8_t* seed3, size_t seed_len,
             uint8_t* commitment0, uint8_t* commitment1, uint8_t* commitment2, uint8_t* commitment3, size_t commitment_len);
FAEST_END_C_DECL

#endif
