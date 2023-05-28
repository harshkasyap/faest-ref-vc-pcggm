#ifndef FAEST_FAEST_AES_H
#define FAEST_FAEST_AES_H

#include <stdbool.h>

#include "vc.h"
#include "vole.h"
#include "fields.h"
#include "universal_hashing.h"
#include "aes.h"

uint8_t* aes_key_schedule_forward(uint32_t lambda, uint32_t R, uint32_t Nwd, uint32_t Lke,
                                  uint32_t m, const uint8_t* x, uint8_t Mtag, uint8_t Mkey,
                                  const uint8_t* delta);

uint8_t* aes_key_schedule_backward(uint32_t lambda, uint32_t R, uint32_t Nwd, uint32_t Ske,
                                   uint8_t Lke, uint32_t m, const uint8_t* x, const uint8_t* xk,
                                   uint8_t Mtag, uint8_t Mkey, const uint8_t* delta);

void aes_key_schedule_constraints(uint32_t lambda, uint32_t R, uint32_t Nwd, uint32_t Ske,
                                  uint32_t Lke, const uint8_t* w, const uint8_t* v,
                                  const uint8_t Mkey, const uint8_t* q, const uint8_t* delta,
                                  uint8_t* A0, uint8_t* A1, uint8_t* k, uint8_t* vk, uint8_t* B,
                                  uint8_t* qk);

int aes_enc_forward(uint32_t lambda, uint32_t R, uint32_t m, uint32_t Lenc, const uint8_t* x,
                    uint8_t* xk, uint8_t* in, uint8_t Mtag, uint8_t Mkey, const uint8_t* delta,
                    uint8_t* y_out);

int aes_enc_backward(uint32_t lambda, uint32_t R, uint32_t m, uint32_t Lenc, const uint8_t* x,
                     uint8_t* xk, uint8_t Mtag, uint8_t Mkey, const uint8_t* delta, uint8_t* out,
                     uint8_t* y_out);

int aes_enc_constraints(uint32_t lambda, uint32_t R, uint32_t Lenc, uint32_t Senc,
                        const uint8_t* in, const uint8_t* out, const uint8_t* w, const uint8_t* v,
                        const uint8_t* k, const uint8_t* vk, uint8_t Mkey, const uint8_t* q,
                        const uint8_t* qk, const uint8_t* delta, uint8_t* A0, uint8_t* A1,
                        uint8_t* B);

void aes_prove(uint8_t* w, uint8_t* u, uint8_t** V, const uint8_t* in, const uint8_t* out,
               const uint8_t* chal, uint32_t lambda, uint32_t R, uint32_t tau, uint32_t l,
               uint32_t beta, uint32_t Lke, uint32_t Lenc, uint32_t C, uint32_t Nwd, uint32_t Ske,
               uint32_t Senc, uint8_t* a_tilde, uint8_t* b_tilde);

bool aes_verify(uint8_t* d, uint8_t** Q, const uint8_t* chal_2, const uint8_t* chal_3,
                const uint8_t* a_tilde, const uint8_t* b_tilde, const uint8_t* in,
                const uint8_t* out, uint32_t lambda, uint32_t tau, uint32_t l, uint32_t beta,
                uint32_t R, uint32_t Nwd, uint32_t Ske, uint32_t Lke, uint32_t Lenc, uint32_t Senc,
                uint32_t C, uint32_t k0, uint32_t k1, uint32_t t0, uint32_t t1);

#endif