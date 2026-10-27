#ifndef SYMMETRIC_H
#define SYMMETRIC_H

#include <stdint.h>
#include "fips202.h"
#include "../include/dilithium/params.h"

/**
 * symmetric.h — Symmetric Primitive Stream Abstraction
 *
 * CONCEPTUAL MAPPING FROM KYBER:
 * - Kyber uses kyber_shake128_absorb for matrix generation (with (i,j) index).
 * - Dilithium uses stream128_init / stream256_init with a 16-bit nonce instead.
 *
 * WHY TWO STREAMS?
 * - SHAKE128 is used for matrix A expansion (fast, wide output per block).
 * - SHAKE256 is used for secret polynomial sampling and signing PRF (higher security).
 *
 * This header provides macro aliases so that poly.c / polyvec.c don't need to
 * care which underlying primitive is used — just call stream128_init / stream256_init.
 */

typedef keccak_state stream128_state;
typedef keccak_state stream256_state;

void dilithium_shake128_stream_init(keccak_state *state,
                                    const uint8_t seed[SEEDBYTES],
                                    uint16_t nonce);

void dilithium_shake256_stream_init(keccak_state *state,
                                    const uint8_t seed[CRHBYTES],
                                    uint16_t nonce);

#define STREAM128_BLOCKBYTES SHAKE128_RATE
#define STREAM256_BLOCKBYTES SHAKE256_RATE

#define stream128_init(STATE, SEED, NONCE) \
        dilithium_shake128_stream_init(STATE, SEED, NONCE)
#define stream128_squeezeblocks(OUT, OUTBLOCKS, STATE) \
        shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define stream256_init(STATE, SEED, NONCE) \
        dilithium_shake256_stream_init(STATE, SEED, NONCE)
#define stream256_squeezeblocks(OUT, OUTBLOCKS, STATE) \
        shake256_squeezeblocks(OUT, OUTBLOCKS, STATE)

#endif
