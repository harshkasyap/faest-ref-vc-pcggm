/*
 *  SPDX-License-Identifier: MIT
 */

#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif

#include "aes.h"

#include "fields.h"
#include "compat.h"
#include "utils.h"

#if defined(HAVE_OPENSSL)
#include <openssl/evp.h>
#endif
#include <string.h>

#define KEY_WORDS_128 4
#define KEY_WORDS_192 6
#define KEY_WORDS_256 8

#define AES_BLOCK_WORDS 4
#define RIJNDAEL_BLOCK_WORDS_192 6
#define RIJNDAEL_BLOCK_WORDS_256 8

static const bf8_t round_constants[30] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91,
};

static int contains_zero(const bf8_t* block) {
  return !block[0] | !block[1] | !block[2] | !block[3];
}

static bf8_t compute_sbox(bf8_t in) {
  bf8_t t  = bf8_inv(in);
  bf8_t t0 = set_bit(
      get_bit(t, 0) ^ get_bit(t, 4) ^ get_bit(t, 5) ^ get_bit(t, 6) ^ get_bit(t, 7) ^ 0x01, 0);
  bf8_t t1 = set_bit(
      get_bit(t, 0) ^ get_bit(t, 1) ^ get_bit(t, 5) ^ get_bit(t, 6) ^ get_bit(t, 7) ^ 0x01, 1);
  bf8_t t2 =
      set_bit(get_bit(t, 0) ^ get_bit(t, 1) ^ get_bit(t, 2) ^ get_bit(t, 6) ^ get_bit(t, 7), 2);
  bf8_t t3 =
      set_bit(get_bit(t, 0) ^ get_bit(t, 1) ^ get_bit(t, 2) ^ get_bit(t, 3) ^ get_bit(t, 7), 3);
  bf8_t t4 =
      set_bit(get_bit(t, 0) ^ get_bit(t, 1) ^ get_bit(t, 2) ^ get_bit(t, 3) ^ get_bit(t, 4), 4);
  bf8_t t5 = set_bit(
      get_bit(t, 1) ^ get_bit(t, 2) ^ get_bit(t, 3) ^ get_bit(t, 4) ^ get_bit(t, 5) ^ 0x01, 5);
  bf8_t t6 = set_bit(
      get_bit(t, 2) ^ get_bit(t, 3) ^ get_bit(t, 4) ^ get_bit(t, 5) ^ get_bit(t, 6) ^ 0x01, 6);
  bf8_t t7 =
      set_bit(get_bit(t, 3) ^ get_bit(t, 4) ^ get_bit(t, 5) ^ get_bit(t, 6) ^ get_bit(t, 7), 7);
  return t0 ^ t1 ^ t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7;
}

void aes_increment_iv(uint8_t* iv) {
  for (unsigned int i = 16; i > 0; i--) {
    if (iv[i - 1] == 0xff) {
      iv[i - 1] = 0x00;
      continue;
    }
    iv[i - 1] += 0x01;
    break;
  }
}

// ## AES ##
// Round Functions
static void add_round_key(unsigned int round, aes_block_t state, const aes_round_keys_t* round_key,
                          unsigned int block_words) {
  for (unsigned int c = 0; c < block_words; c++) {
    xor_u8_array(&state[c][0], &round_key->round_keys[round][c][0], &state[c][0], AES_NR);
  }
}

static int sub_bytes(aes_block_t state, unsigned int block_words) {
  int ret = 0;

  for (unsigned int c = 0; c < block_words; c++) {
    ret |= contains_zero(&state[c][0]);
    for (unsigned int r = 0; r < AES_NR; r++) {
      state[c][r] = compute_sbox(state[c][r]);
    }
  }

  return ret;
}

static void shift_row(aes_block_t state, unsigned int block_words) {
  aes_block_t new_state;
  switch (block_words) {
  case 4:
  case 6:
    for (unsigned int i = 0; i < block_words; ++i) {
      new_state[i][0] = state[i][0];
      new_state[i][1] = state[(i + 1) % block_words][1];
      new_state[i][2] = state[(i + 2) % block_words][2];
      new_state[i][3] = state[(i + 3) % block_words][3];
    }
    break;
  case 8:
    for (unsigned int i = 0; i < block_words; i++) {
      new_state[i][0] = state[i][0];
      new_state[i][1] = state[(i + 1) % 8][1];
      new_state[i][2] = state[(i + 3) % 8][2];
      new_state[i][3] = state[(i + 4) % 8][3];
    }
    break;
  }

  for (unsigned int i = 0; i < block_words; ++i) {
    memcpy(&state[i][0], &new_state[i][0], AES_NR);
  }
}

static void mix_column(aes_block_t state, unsigned int block_words) {
  for (unsigned int c = 0; c < block_words; c++) {
    bf8_t tmp = bf8_mul(state[c][0], 0x02) ^ bf8_mul(state[c][1], 0x03) ^ state[c][2] ^ state[c][3];
    bf8_t tmp_1 =
        state[c][0] ^ bf8_mul(state[c][1], 0x02) ^ bf8_mul(state[c][2], 0x03) ^ state[c][3];
    bf8_t tmp_2 =
        state[c][0] ^ state[c][1] ^ bf8_mul(state[c][2], 0x02) ^ bf8_mul(state[c][3], 0x03);
    bf8_t tmp_3 =
        bf8_mul(state[c][0], 0x03) ^ state[c][1] ^ state[c][2] ^ bf8_mul(state[c][3], 0x02);

    state[c][0] = tmp;
    state[c][1] = tmp_1;
    state[c][2] = tmp_2;
    state[c][3] = tmp_3;
  }
}

// Key Expansion functions
static void sub_words(bf8_t* words) {
  words[0] = compute_sbox(words[0]);
  words[1] = compute_sbox(words[1]);
  words[2] = compute_sbox(words[2]);
  words[3] = compute_sbox(words[3]);
}

static void rot_word(bf8_t* words) {
  bf8_t tmp = words[0];
  words[0]  = words[1];
  words[1]  = words[2];
  words[2]  = words[3];
  words[3]  = tmp;
}

int expand_key(aes_round_keys_t* round_keys, const uint8_t* key, unsigned int key_words,
               unsigned int block_words, unsigned int num_rounds) {
  int ret = 0;

  for (unsigned int k = 0; k < key_words; k++) {
    round_keys->round_keys[k / block_words][k % block_words][0] = bf8_load(&key[4 * k]);
    round_keys->round_keys[k / block_words][k % block_words][1] = bf8_load(&key[(4 * k) + 1]);
    round_keys->round_keys[k / block_words][k % block_words][2] = bf8_load(&key[(4 * k) + 2]);
    round_keys->round_keys[k / block_words][k % block_words][3] = bf8_load(&key[(4 * k) + 3]);
  }

  for (unsigned int k = key_words; k < block_words * (num_rounds + 1); ++k) {
    bf8_t tmp[AES_NR];
    memcpy(tmp, round_keys->round_keys[(k - 1) / block_words][(k - 1) % block_words], sizeof(tmp));

    if (k % key_words == 0) {
      rot_word(tmp);
      ret |= contains_zero(tmp);
      sub_words(tmp);
      tmp[0] ^= round_constants[(k / key_words) - 1];
    }

    if (key_words > 6 && (k % key_words) == 4) {
      ret |= contains_zero(tmp);
      sub_words(tmp);
    }

    unsigned int m = k - key_words;
    round_keys->round_keys[k / block_words][k % block_words][0] =
        round_keys->round_keys[m / block_words][m % block_words][0] ^ tmp[0];
    round_keys->round_keys[k / block_words][k % block_words][1] =
        round_keys->round_keys[m / block_words][m % block_words][1] ^ tmp[1];
    round_keys->round_keys[k / block_words][k % block_words][2] =
        round_keys->round_keys[m / block_words][m % block_words][2] ^ tmp[2];
    round_keys->round_keys[k / block_words][k % block_words][3] =
        round_keys->round_keys[m / block_words][m % block_words][3] ^ tmp[3];
  }

  return ret;
}

// Calling Functions

int aes128_init_round_keys(aes_round_keys_t* round_key, const uint8_t* key) {
  return expand_key(round_key, key, KEY_WORDS_128, AES_BLOCK_WORDS, ROUNDS_128);
}

int aes192_init_round_keys(aes_round_keys_t* round_key, const uint8_t* key) {
  return expand_key(round_key, key, KEY_WORDS_192, AES_BLOCK_WORDS, ROUNDS_192);
}

int aes256_init_round_keys(aes_round_keys_t* round_key, const uint8_t* key) {
  return expand_key(round_key, key, KEY_WORDS_256, AES_BLOCK_WORDS, ROUNDS_256);
}

int rijndael192_init_round_keys(aes_round_keys_t* round_key, const uint8_t* key) {
  return expand_key(round_key, key, KEY_WORDS_192, RIJNDAEL_BLOCK_WORDS_192, ROUNDS_192);
}

int rijndael256_init_round_keys(aes_round_keys_t* round_key, const uint8_t* key) {
  return expand_key(round_key, key, KEY_WORDS_256, RIJNDAEL_BLOCK_WORDS_256, ROUNDS_256);
}

static void load_state(aes_block_t state, const uint8_t* src, unsigned int block_words) {
  for (unsigned int i = 0; i != block_words * 4; ++i) {
    state[i / 4][i % 4] = bf8_load(&src[i]);
  }
}

static void store_state(uint8_t* dst, aes_block_t state, unsigned int block_words) {
  for (unsigned int i = 0; i != block_words * 4; ++i) {
    bf8_store(&dst[i], state[i / 4][i % 4]);
  }
}

static int aes_encrypt(const aes_round_keys_t* keys, aes_block_t state, unsigned int block_words,
                       unsigned int num_rounds) {
  int ret = 0;

  // first round
  add_round_key(0, state, keys, block_words);

  for (unsigned int round = 1; round < num_rounds; ++round) {
    ret |= sub_bytes(state, block_words);
    shift_row(state, block_words);
    mix_column(state, block_words);
    add_round_key(round, state, keys, block_words);
  }

  // last round
  ret |= sub_bytes(state, block_words);
  shift_row(state, block_words);
  add_round_key(num_rounds, state, keys, block_words);

  return ret;
}

int aes128_encrypt_block(const aes_round_keys_t* key, const uint8_t* plaintext,
                         uint8_t* ciphertext) {
  aes_block_t state;
  load_state(state, plaintext, AES_BLOCK_WORDS);
  const int ret = aes_encrypt(key, state, AES_BLOCK_WORDS, ROUNDS_128);
  store_state(ciphertext, state, AES_BLOCK_WORDS);
  return ret;
}

int aes192_encrypt_block(const aes_round_keys_t* key, const uint8_t* plaintext,
                         uint8_t* ciphertext) {
  aes_block_t state;
  load_state(state, plaintext, AES_BLOCK_WORDS);
  const int ret = aes_encrypt(key, state, AES_BLOCK_WORDS, ROUNDS_192);
  store_state(ciphertext, state, AES_BLOCK_WORDS);
  return ret;
}

int aes256_encrypt_block(const aes_round_keys_t* key, const uint8_t* plaintext,
                         uint8_t* ciphertext) {
  aes_block_t state;
  load_state(state, plaintext, AES_BLOCK_WORDS);
  const int ret = aes_encrypt(key, state, AES_BLOCK_WORDS, ROUNDS_256);
  store_state(ciphertext, state, AES_BLOCK_WORDS);
  return ret;
}

int rijndael192_encrypt_block(const aes_round_keys_t* key, const uint8_t* plaintext,
                              uint8_t* ciphertext) {
  aes_block_t state;
  load_state(state, plaintext, RIJNDAEL_BLOCK_WORDS_192);
  const int ret = aes_encrypt(key, state, RIJNDAEL_BLOCK_WORDS_192, ROUNDS_192);
  store_state(ciphertext, state, RIJNDAEL_BLOCK_WORDS_192);
  return ret;
}

int rijndael256_encrypt_block(const aes_round_keys_t* key, const uint8_t* plaintext,
                              uint8_t* ciphertext) {
  aes_block_t state;
  load_state(state, plaintext, RIJNDAEL_BLOCK_WORDS_256);
  const int ret = aes_encrypt(key, state, RIJNDAEL_BLOCK_WORDS_256, ROUNDS_256);
  store_state(ciphertext, state, RIJNDAEL_BLOCK_WORDS_256);
  return ret;
}

// avx stuff
inline block128 block128_xor(block128 x, block128 y) { return _mm_xor_si128(x, y); }
inline block256 block256_xor(block256 x, block256 y) { return _mm256_xor_si256(x, y); }
inline block128 block128_set_zero() { return _mm_setzero_si128(); }
inline block256 block256_set_zero() { return _mm256_setzero_si256(); }
inline block256 block256_set_low128(block128 x)
{
	return _mm256_inserti128_si256(_mm256_setzero_si256(), x, 0);
}

static inline block128 load_high_64(const block192* block)
{
	return _mm_cvtsi64_si128(block->data[2]);
}

static inline block128 load_high_128(const block256* block)
{
	block128 out;
	memcpy(&out, ((unsigned char*) block) + sizeof(block128), sizeof(out));
	return out;
}

inline block192 block192_set_low64(uint64_t x)
{
	block192 out = {{x, 0, 0}};
	return out;
}

inline block192 block192_set_low32(uint32_t x)
{
	return block192_set_low64(x);
}

inline block192 block192_set_zero()
{
	return block192_set_low64(0);
}

inline block192 block192_set_low128(const uint8_t* x)
{
	block192 out = {{*((uint64_t*)(x)), *((uint64_t*)(x+8)), 0}};
	return out;
}

static void rijndael192_keygen_helper(
	const block192* round_key_in, block128 kga, block192* round_key_out)
{
	block128 t1, t2, t4;
	uint64_t t3;

	memcpy(&t1, &round_key_in->data[0], sizeof(t1));
	t2 = kga;
	t3 = round_key_in->data[2];

	t2 = _mm_shuffle_epi32(t2, 0x55);
	t4 = _mm_slli_si128(t1, 0x4);
	t1 = _mm_xor_si128(t1, t4);
	t4 = _mm_slli_si128(t4, 0x4);
	t1 = _mm_xor_si128(t1, t4);
	t4 = _mm_slli_si128(t4, 0x4);
	t1 = _mm_xor_si128(t1, t4);
	t1 = _mm_xor_si128(t1, t2);
	t3 ^= (uint32_t) _mm_extract_epi32(t1, 3);
	t3 ^= t3 << 32;

	memcpy(&round_key_out->data[0], &t1, sizeof(t1));
	round_key_out->data[2] = t3;
}

static void rijndael256_keygen_helper(
	const block256* round_key_in, block128 kga, block256* round_key_out)
{
	block128 t1, t2, t3, t4;

	memcpy(&t1, round_key_in, sizeof(t1));
	t3 = load_high_128(round_key_in);
	t2 = kga;

	t2 = _mm_shuffle_epi32(t2, 0xff);
	t4 = _mm_slli_si128(t1, 0x4);
	t1 = _mm_xor_si128(t1, t4);
	t4 = _mm_slli_si128(t4, 0x4);
	t1 = _mm_xor_si128(t1, t4);
	t4 = _mm_slli_si128(t4, 0x4);
	t1 = _mm_xor_si128(t1, t4);
	t1 = _mm_xor_si128(t1, t2);

	memcpy(round_key_out, &t1, sizeof(t1));

	t4 = _mm_aeskeygenassist_si128(t1, 0x00);
	t2 = _mm_shuffle_epi32(t4, 0xaa);
	t4 = _mm_slli_si128(t3, 0x4);
	t3 = _mm_xor_si128(t3, t4);
	t4 = _mm_slli_si128(t4, 0x4);
	t3 = _mm_xor_si128(t3, t4);
	t4 = _mm_slli_si128(t4, 0x4);
	t3 = _mm_xor_si128(t3, t4);
	t3 = _mm_xor_si128(t3, t2);

	memcpy(((unsigned char*) round_key_out) + sizeof(t1), &t3, sizeof(t3));
}

void rijndael192_keygen(rijndael192_round_keys* round_keys, block192 key)
{
	round_keys->keys[0] = key;

	block128 kga;
	kga = _mm_aeskeygenassist_si128(load_high_64(&round_keys->keys[0]), 0x01);
	rijndael192_keygen_helper(&round_keys->keys[0], kga, &round_keys->keys[1]);
	kga = _mm_aeskeygenassist_si128(load_high_64(&round_keys->keys[1]), 0x02);
	rijndael192_keygen_helper(&round_keys->keys[1], kga, &round_keys->keys[2]);
	kga = _mm_aeskeygenassist_si128(load_high_64(&round_keys->keys[2]), 0x04);
	rijndael192_keygen_helper(&round_keys->keys[2], kga, &round_keys->keys[3]);
	kga = _mm_aeskeygenassist_si128(load_high_64(&round_keys->keys[3]), 0x08);
	rijndael192_keygen_helper(&round_keys->keys[3], kga, &round_keys->keys[4]);
	kga = _mm_aeskeygenassist_si128(load_high_64(&round_keys->keys[4]), 0x10);
	rijndael192_keygen_helper(&round_keys->keys[4], kga, &round_keys->keys[5]);
	kga = _mm_aeskeygenassist_si128(load_high_64(&round_keys->keys[5]), 0x20);
	rijndael192_keygen_helper(&round_keys->keys[5], kga, &round_keys->keys[6]);
	kga = _mm_aeskeygenassist_si128(load_high_64(&round_keys->keys[6]), 0x40);
	rijndael192_keygen_helper(&round_keys->keys[6], kga, &round_keys->keys[7]);
	kga = _mm_aeskeygenassist_si128(load_high_64(&round_keys->keys[7]), 0x80);
	rijndael192_keygen_helper(&round_keys->keys[7], kga, &round_keys->keys[8]);
	kga = _mm_aeskeygenassist_si128(load_high_64(&round_keys->keys[8]), 0x1B);
	rijndael192_keygen_helper(&round_keys->keys[8], kga, &round_keys->keys[9]);
	kga = _mm_aeskeygenassist_si128(load_high_64(&round_keys->keys[9]), 0x36);
	rijndael192_keygen_helper(&round_keys->keys[9], kga, &round_keys->keys[10]);
	kga = _mm_aeskeygenassist_si128(load_high_64(&round_keys->keys[10]), 0x6C);
	rijndael192_keygen_helper(&round_keys->keys[10], kga, &round_keys->keys[11]);
	kga = _mm_aeskeygenassist_si128(load_high_64(&round_keys->keys[11]), 0xD8);
	rijndael192_keygen_helper(&round_keys->keys[11], kga, &round_keys->keys[12]);
}

void rijndael256_keygen(rijndael256_round_keys* round_keys, block256 key)
{
	round_keys->keys[0] = key;

	block128 kga;
	kga = _mm_aeskeygenassist_si128(load_high_128(&round_keys->keys[0]), 0x01);
	rijndael256_keygen_helper(&round_keys->keys[0], kga, &round_keys->keys[1]);
	kga = _mm_aeskeygenassist_si128(load_high_128(&round_keys->keys[1]), 0x02);
	rijndael256_keygen_helper(&round_keys->keys[1], kga, &round_keys->keys[2]);
	kga = _mm_aeskeygenassist_si128(load_high_128(&round_keys->keys[2]), 0x04);
	rijndael256_keygen_helper(&round_keys->keys[2], kga, &round_keys->keys[3]);
	kga = _mm_aeskeygenassist_si128(load_high_128(&round_keys->keys[3]), 0x08);
	rijndael256_keygen_helper(&round_keys->keys[3], kga, &round_keys->keys[4]);
	kga = _mm_aeskeygenassist_si128(load_high_128(&round_keys->keys[4]), 0x10);
	rijndael256_keygen_helper(&round_keys->keys[4], kga, &round_keys->keys[5]);
	kga = _mm_aeskeygenassist_si128(load_high_128(&round_keys->keys[5]), 0x20);
	rijndael256_keygen_helper(&round_keys->keys[5], kga, &round_keys->keys[6]);
	kga = _mm_aeskeygenassist_si128(load_high_128(&round_keys->keys[6]), 0x40);
	rijndael256_keygen_helper(&round_keys->keys[6], kga, &round_keys->keys[7]);
	kga = _mm_aeskeygenassist_si128(load_high_128(&round_keys->keys[7]), 0x80);
	rijndael256_keygen_helper(&round_keys->keys[7], kga, &round_keys->keys[8]);
	kga = _mm_aeskeygenassist_si128(load_high_128(&round_keys->keys[8]), 0x1B);
	rijndael256_keygen_helper(&round_keys->keys[8], kga, &round_keys->keys[9]);
	kga = _mm_aeskeygenassist_si128(load_high_128(&round_keys->keys[9]), 0x36);
	rijndael256_keygen_helper(&round_keys->keys[9], kga, &round_keys->keys[10]);
	kga = _mm_aeskeygenassist_si128(load_high_128(&round_keys->keys[10]), 0x6C);
	rijndael256_keygen_helper(&round_keys->keys[10], kga, &round_keys->keys[11]);
	kga = _mm_aeskeygenassist_si128(load_high_128(&round_keys->keys[11]), 0xD8);
	rijndael256_keygen_helper(&round_keys->keys[11], kga, &round_keys->keys[12]);
	kga = _mm_aeskeygenassist_si128(load_high_128(&round_keys->keys[12]), 0xAB);
	rijndael256_keygen_helper(&round_keys->keys[12], kga, &round_keys->keys[13]);
	kga = _mm_aeskeygenassist_si128(load_high_128(&round_keys->keys[13]), 0x4D);
	rijndael256_keygen_helper(&round_keys->keys[13], kga, &round_keys->keys[14]);
}

inline block192 block192_xor(block192 x, block192 y)
{
	// Plain c version for now at least. Hopefully it will be autovectorized.
	block192 out;
	out.data[0] = x.data[0] ^ y.data[0];
	out.data[1] = x.data[1] ^ y.data[1];
	out.data[2] = x.data[2] ^ y.data[2];
	return out;
}

static inline void cvt192_to_2x128(block128* out, const block192* in)
{
	memcpy(&out[0], &in->data[0], sizeof(out[0]));
	out[1] = _mm_set1_epi64x(in->data[2]);
}

// This implements the rijndael192 RotateRows step, then cancels out the RotateRows of AES so
// that AES-NI can be used for the sbox. The rijndael192 state is represented with the first 4
// columns in the first block128, and then the last two columns are stored twice in the second
// block128.
inline void rijndael192_rotate_rows_undo_128(block128* s)
{
	block128 mask = _mm_setr_epi8(
		0, -1, -1,  0,
		0,  0, -1, -1,
		0,  0,  0, -1,
		0,  0,  0,  0);
	block128 b0_blended = _mm_blendv_epi8(s[0], s[1], mask);
	block128 b1_blended = _mm_blendv_epi8(s[1], s[0], mask);

	block128 shuffle_b0 = _mm_setr_epi8(
		 0,  1,  2, 11,
		 4,  5,  6,  7,
		 8,  9, 10,  3,
		12, 13, 14, 15);
	block128 shuffle_b1 = _mm_setr_epi8(
		 0,  1,  2, 11,
		 4,  5,  6,  7,
		 0,  1,  2, 11,
		 4,  5,  6,  7);
	s[0] = _mm_shuffle_epi8(b0_blended, shuffle_b0);
	s[1] = _mm_shuffle_epi8(b1_blended, shuffle_b1);
}

// Just do 1 block at a time because this function shouldn't be used much.
void rijndael192_encrypt_block_avx(
	const rijndael192_round_keys* restrict fixed_key, block192* restrict block)
{
	block192 xored_block = block192_xor(*block, fixed_key->keys[0]);
	block128 state[2], round_key[2];
	cvt192_to_2x128(&state[0], &xored_block);

	for (int round = 1; round < ROUNDS_192; ++round)
	{
		cvt192_to_2x128(&round_key[0], &fixed_key->keys[round]);
		rijndael192_rotate_rows_undo_128(&state[0]);
		state[0] = _mm_aesenc_si128(state[0], round_key[0]);
		state[1] = _mm_aesenc_si128(state[1], round_key[1]);
	}

	rijndael192_rotate_rows_undo_128(&state[0]);
	cvt192_to_2x128(&round_key[0], &fixed_key->keys[ROUNDS_192]);
	state[0] = _mm_aesenclast_si128(state[0], round_key[0]);
	state[1] = _mm_aesenclast_si128(state[1], round_key[1]);

	memcpy(block, &state[0], sizeof(*block));
}

// This implements the rijndael256 RotateRows step, then cancels out the RotateRows of AES so
// that AES-NI can be used for the sbox.
inline void rijndael256_rotate_rows_undo_128(block128* s)
{
	// Swapping bytes between 128-bit halves is equivalent to rotating left overall, then
	// rotating right within each half.
	block128 mask = _mm_setr_epi8(
		0, -1, -1, -1,
		0,  0, -1, -1,
		0,  0, -1, -1,
		0,  0,  0, -1);
	block128 b0_blended = _mm_blendv_epi8(s[0], s[1], mask);
	block128 b1_blended = _mm_blendv_epi8(s[1], s[0], mask);

	// The rotations for 128-bit AES are different, so rotate within the halves to
	// match.
	block128 perm = _mm_setr_epi8(
		 0,  1,  6,  7,
		 4,  5, 10, 11,
		 8,  9, 14, 15,
		12, 13,  2,  3);
	s[0] = _mm_shuffle_epi8(b0_blended, perm);
	s[1] = _mm_shuffle_epi8(b1_blended, perm);
}


inline void rijndael256_round(
	const rijndael256_round_keys* round_keys, block256* state,
	size_t num_keys, size_t evals_per_key, int round)
{
	for (size_t i = 0; i < num_keys * evals_per_key; ++i)
	{
		block128 s[2], round_key[2];
		memcpy(&s[0], &state[i], sizeof(block256));
		memcpy(&round_key[0], &round_keys[i / evals_per_key].keys[round], sizeof(block256));

		// Use AES-NI to implement the round function.
		if (round == 0)
		{
			s[0] = block128_xor(s[0], round_key[0]);
			s[1] = block128_xor(s[1], round_key[1]);
		}
		else if (round < ROUNDS_256)
		{
			rijndael256_rotate_rows_undo_128(&s[0]);
			s[0] = _mm_aesenc_si128(s[0], round_key[0]);
			s[1] = _mm_aesenc_si128(s[1], round_key[1]);
		}
		else
		{
			rijndael256_rotate_rows_undo_128(&s[0]);
			s[0] = _mm_aesenclast_si128(s[0], round_key[0]);
			s[1] = _mm_aesenclast_si128(s[1], round_key[1]);
		}

		memcpy(&state[i], &s[0], sizeof(block256));
	}
}

void rijndael256_encrypt_block_avx(
	const rijndael256_round_keys* restrict fixed_key, block256* restrict block)
{
	// the round function takes care of the first and the last round
	rijndael256_round(fixed_key, block, 1, 1, 0);
	for (int round = 1; round < ROUNDS_256; ++round)
		rijndael256_round(fixed_key, block, 1, 1, round);
	rijndael256_round(fixed_key, block, 1, 1, ROUNDS_256);
}

// sigma(x_l || x_r) = (x_l ^ x_r) || x_l
static inline void ortho(const uint8_t* in, uint8_t* out, size_t len) {
  size_t i = 0;
  for (; i < len/2; i+=4) {
    out[i] = in[i] ^ in[i + len/2];
    out[i + 1] = in[i + 1] ^ in[i + len/2 + 1];
    out[i + 2] = in[i + 2] ^ in[i + len/2 + 2];
    out[i + 3] = in[i + 3] ^ in[i + len/2 + 3];
  }
  for (; i < len; i+=4) {
    out[i] = in[i];
    out[i + 1] = in[i + 1];
    out[i + 2] = in[i + 2];
    out[i + 3] = in[i + 3];
  }
}

static inline void ortho_tweaked(const uint8_t* in, uint8_t* out, size_t len) {
  ortho(in, out, len);
  out[0] ^= 1;
}

static inline void permute_with_ctx(union CCR_CTX* ctx, const uint8_t* in, uint8_t* out, size_t outlen) {
  // we need to create these temporary variables because they need to be aligned
  block256 tmp256 = block256_set_zero();
  int len = 0;
  switch (outlen*8) { // outlen is the seclvl
  case 256:
    tmp256 = _mm256_loadu_si256((block256 const*)in);
    rijndael256_encrypt_block_avx(&ctx->r256_round_keys, &tmp256);
    memcpy(out, (uint8_t*)(&tmp256), outlen);
    break;
  case 192:
    memcpy(out, in, outlen);
    rijndael192_encrypt_block_avx(&ctx->r192_round_keys, (block192*) out);
    break;
  default:
    EVP_EncryptUpdate(ctx->evp_ctx, out, &len, in, outlen);
    break;
  }
  /*
  uint8_t iv[16] = {0};
  for (size_t idx = 0; idx < outlen / 16; idx += 1, out += 16) {
    EVP_EncryptUpdate(ctx, out, &len, iv, sizeof(iv));
    iv[0] += 1; // iv acts as counter
    for (size_t i = 0; i < 16; i+=4) {
      out[i] ^= in[idx * 16 + i];
      out[i + 1] ^= in[idx * 16 + i + 1];
      out[i + 2] ^= in[idx * 16 + i + 2];
      out[i + 3] ^= in[idx * 16 + i + 3];
    }
  }
  */
}

union CCR_CTX CCR_CTX_setup(unsigned int seclvl, const uint8_t* iv) {
  const EVP_CIPHER* cipher;
  union CCR_CTX out;
  block256 iv256 = block256_set_low128(_mm_loadu_si128((block128 const*)iv));
  block192 iv192 = block192_set_low128(iv);
  switch (seclvl) {
  case 256:
    rijndael256_keygen(&out.r256_round_keys, iv256);
    return out;
  case 192:
    rijndael192_keygen(&out.r192_round_keys, iv192);
    return out;
  default:
    cipher = EVP_aes_128_ecb();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    static const uint8_t dummy[16] = {0};
    EVP_EncryptInit_ex(ctx, cipher, NULL, iv, dummy);
    out.evp_ctx = ctx;
    return out;
  }
}

void CCR_CTX_free(union CCR_CTX *ctx, unsigned int seclvl) {
  switch (seclvl) {
  case 256:
    // no need to do anything because the fixed key is on stack
    break;
  case 192:
    // no need to do anything because the fixed key is on stack
    break;
  default:
    EVP_CIPHER_CTX_free(ctx->evp_ctx);
    break;
  }
}

// AES(ortho(x)) ^ ortho(x)
void ccr(const uint8_t* key, const uint8_t* iv, uint8_t* out, unsigned int seclvl, size_t outlen) {
  static uint8_t tmp[32];
  ortho(key, tmp, outlen);
  prg(tmp, iv, out, seclvl, outlen);
  for (size_t i = 0; i < outlen; i++) {
    out[i] ^= tmp[i];
  }
}

// AES(ortho(x)) ^ ortho(x)
void ccr_with_ctx(union CCR_CTX* ctx, const uint8_t* in, uint8_t* out, size_t outlen) {
  static uint8_t tmp[32];
  ortho(in, tmp, outlen);
  permute_with_ctx(ctx, tmp, out, outlen);
  for (size_t i = 0; i < outlen; i++) {
    out[i] ^= tmp[i];
  }
}

static inline void ccr_tweaked(const uint8_t* key, const uint8_t* iv, uint8_t* out, unsigned int seclvl, size_t outlen) {
  static uint8_t tmp[32];
  ortho_tweaked(key, tmp, outlen);
  prg(tmp, iv, out, seclvl, outlen);
  for (size_t i = 0; i < outlen; i++) {
    out[i] ^= tmp[i];
  }
}

static inline void ccr_tweaked_with_ctx(union CCR_CTX* ctx, const uint8_t* in, uint8_t* out, size_t outlen) {
  static uint8_t tmp[32];
  ortho_tweaked(in, tmp, outlen);
  permute_with_ctx(ctx, tmp, out, outlen);
  for (size_t i = 0; i < outlen; i++) {
    out[i] ^= tmp[i];
  }
}

void ccr2(const uint8_t* src, const uint8_t* iv, uint8_t* seed, size_t seed_len,
          uint8_t* commitment, size_t commitment_len, unsigned int seclvl) {
  ccr(src, iv, seed, seclvl, seed_len);
  ccr_tweaked(src, iv, commitment, seclvl, commitment_len/2);
  // zero the other half of commitment
  memset(commitment + commitment_len/2, 0, commitment_len/2);
}

void ccr2_with_ctx(union CCR_CTX* ctx, const uint8_t* src, uint8_t* seed, size_t seed_len,
          uint8_t* commitment, size_t commitment_len) {
  ccr_with_ctx(ctx, src, seed, seed_len);
  ccr_tweaked_with_ctx(ctx, src, commitment, commitment_len/2);
  // zero the other half of commitment
  memset(commitment + commitment_len/2, 0, commitment_len/2);
}

void ccr2_x4(const uint8_t* src0, const uint8_t* src1, const uint8_t* src2, const uint8_t* src3,
             const uint8_t* iv,
             uint8_t* seed0, uint8_t* seed1, uint8_t* seed2, uint8_t* seed3, size_t seed_len,
             uint8_t* commitment0, uint8_t* commitment1, uint8_t* commitment2, uint8_t* commitment3, size_t commitment_len,
             unsigned int seclvl) {
  ccr2(src0, iv, seed0, seed_len, commitment0, commitment_len, seclvl);
  ccr2(src1, iv, seed1, seed_len, commitment1, commitment_len, seclvl);
  ccr2(src2, iv, seed2, seed_len, commitment2, commitment_len, seclvl);
  ccr2(src3, iv, seed3, seed_len, commitment3, commitment_len, seclvl);
}

void ccr2_x4_with_ctx(union CCR_CTX* ctx, const uint8_t* src0, const uint8_t* src1, const uint8_t* src2, const uint8_t* src3,
             uint8_t* seed0, uint8_t* seed1, uint8_t* seed2, uint8_t* seed3, size_t seed_len,
             uint8_t* commitment0, uint8_t* commitment1, uint8_t* commitment2, uint8_t* commitment3, size_t commitment_len) {
  ccr2_with_ctx(ctx, src0, seed0, seed_len, commitment0, commitment_len);
  ccr2_with_ctx(ctx, src1, seed1, seed_len, commitment1, commitment_len);
  ccr2_with_ctx(ctx, src2, seed2, seed_len, commitment2, commitment_len);
  ccr2_with_ctx(ctx, src3, seed3, seed_len, commitment3, commitment_len);
}

void prg(const uint8_t* key, const uint8_t* iv, uint8_t* out, unsigned int seclvl, size_t outlen) {
#if !defined(HAVE_OPENSSL)
  uint8_t internal_iv[16];
  memcpy(internal_iv, iv, sizeof(internal_iv));

  aes_round_keys_t round_key;

  switch (seclvl) {
  case 256:
    aes256_init_round_keys(&round_key, key);
    for (; outlen >= 16; outlen -= 16, out += 16) {
      aes_block_t state;
      load_state(state, internal_iv, AES_BLOCK_WORDS);
      aes_encrypt(&round_key, state, AES_BLOCK_WORDS, ROUNDS_256);
      store_state(out, state, AES_BLOCK_WORDS);
      aes_increment_iv(internal_iv);
    }
    if (outlen) {
      aes_block_t state;
      load_state(state, internal_iv, AES_BLOCK_WORDS);
      aes_encrypt(&round_key, state, AES_BLOCK_WORDS, ROUNDS_256);
      uint8_t tmp[16];
      store_state(tmp, state, AES_BLOCK_WORDS);
      memcpy(out, tmp, outlen);
    }
    return;
  case 192:
    aes192_init_round_keys(&round_key, key);
    for (; outlen >= 16; outlen -= 16, out += 16) {
      aes_block_t state;
      load_state(state, internal_iv, AES_BLOCK_WORDS);
      aes_encrypt(&round_key, state, AES_BLOCK_WORDS, ROUNDS_192);
      store_state(out, state, AES_BLOCK_WORDS);
      aes_increment_iv(internal_iv);
    }
    if (outlen) {
      aes_block_t state;
      load_state(state, internal_iv, AES_BLOCK_WORDS);
      aes_encrypt(&round_key, state, AES_BLOCK_WORDS, ROUNDS_192);
      uint8_t tmp[16];
      store_state(tmp, state, AES_BLOCK_WORDS);
      memcpy(out, tmp, outlen);
    }
    return;
  default:
    aes128_init_round_keys(&round_key, key);
    for (; outlen >= 16; outlen -= 16, out += 16) {
      aes_block_t state;
      load_state(state, internal_iv, AES_BLOCK_WORDS);
      aes_encrypt(&round_key, state, AES_BLOCK_WORDS, ROUNDS_128);
      store_state(out, state, AES_BLOCK_WORDS);
      aes_increment_iv(internal_iv);
    }
    if (outlen) {
      aes_block_t state;
      load_state(state, internal_iv, AES_BLOCK_WORDS);
      aes_encrypt(&round_key, state, AES_BLOCK_WORDS, ROUNDS_128);
      uint8_t tmp[16];
      store_state(tmp, state, AES_BLOCK_WORDS);
      memcpy(out, tmp, outlen);
    }
    return;
  }
#else
  const EVP_CIPHER* cipher;
  switch (seclvl) {
  case 256:
    cipher = EVP_aes_256_ctr();
    break;
  case 192:
    cipher = EVP_aes_192_ctr();
    break;
  default:
    cipher = EVP_aes_128_ctr();
    break;
  }

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  assert(ctx);

  EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);

  static const uint8_t plaintext[16] = {0};

  int len = 0;
  for (size_t idx = 0; idx < outlen / 16; idx += 1, out += 16) {
    EVP_EncryptUpdate(ctx, out, &len, plaintext, sizeof(plaintext));
  }
  if (outlen % 16) {
    EVP_EncryptUpdate(ctx, out, &len, plaintext, outlen % 16);
  }
  EVP_EncryptFinal_ex(ctx, out, &len);
  EVP_CIPHER_CTX_free(ctx);
#endif
}

uint8_t* aes_extend_witness(const uint8_t* key, const uint8_t* in, const faest_paramset_t* params) {
  const unsigned int lambda     = params->faest_param.lambda;
  const unsigned int l          = params->faest_param.l;
  const unsigned int L_ke       = params->faest_param.Lke;
  const unsigned int S_ke       = params->faest_param.Ske;
  const unsigned int num_rounds = params->faest_param.R;

  uint8_t* w           = malloc((l + 7) / 8);
  uint8_t* const w_out = w;

  unsigned int block_words = AES_BLOCK_WORDS;
  unsigned int beta        = 1;
  switch (params->faest_paramid) {
  case FAEST_192F:
  case FAEST_192S:
  case FAEST_256F:
  case FAEST_256S:
    beta = 2;
    break;
  case FAEST_EM_192F:
  case FAEST_EM_192S:
    block_words = RIJNDAEL_BLOCK_WORDS_192;
    break;
  case FAEST_EM_256F:
  case FAEST_EM_256S:
    block_words = RIJNDAEL_BLOCK_WORDS_256;
    break;
  default:
    break;
  }

  if (!L_ke) {
    // switch input and key for EM
    const uint8_t* tmp = key;
    key                = in;
    in                 = tmp;
  }

  // Step 3
  aes_round_keys_t round_keys;
  switch (lambda) {
  case 256:
    if (block_words == RIJNDAEL_BLOCK_WORDS_256) {
      rijndael256_init_round_keys(&round_keys, key);
    } else {
      aes256_init_round_keys(&round_keys, key);
    }
    break;
  case 192:
    if (block_words == RIJNDAEL_BLOCK_WORDS_192) {
      rijndael192_init_round_keys(&round_keys, key);
    } else {
      aes192_init_round_keys(&round_keys, key);
    }
    break;
  default:
    aes128_init_round_keys(&round_keys, key);
    break;
  }

  // Step 4
  if (L_ke > 0) {
    // Key schedule constraints only needed for normal AES, not EM variant.
    for (unsigned int i = 0; i != params->faest_param.Nwd; ++i) {
      memcpy(w, round_keys.round_keys[i / 4][i % 4], sizeof(aes_word_t));
      w += sizeof(aes_word_t);
    }

    for (unsigned int j = 0, ik = params->faest_param.Nwd; j < S_ke / 4; ++j) {
      memcpy(w, round_keys.round_keys[ik / 4][ik % 4], sizeof(aes_word_t));
      w += sizeof(aes_word_t);
      ik += lambda == 192 ? 6 : 4;
    }
  } else {
    // saving the OWF key to the extended witness
    memcpy(w, in, lambda / 8);
    w += lambda / 8;
  }

  // Step 10
  for (unsigned b = 0; b < beta; ++b, in += sizeof(aes_word_t) * block_words) {
    // Step 12
    aes_block_t state;
    load_state(state, in, block_words);

    // Step 13
    add_round_key(0, state, &round_keys, block_words);

    for (unsigned int round = 1; round < num_rounds; ++round) {
      // Step 15
      sub_bytes(state, block_words);
      // Step 16
      shift_row(state, block_words);
      // Step 17
      store_state(w, state, block_words);
      w += sizeof(aes_word_t) * block_words;
      // Step 18
      mix_column(state, block_words);
      // Step 19
      add_round_key(round, state, &round_keys, block_words);
    }
    // last round is not commited to, so not computed
  }

  return w_out;
}

