#include <stdint.h>
#include "symmetric.h"
#include "fips202.h"
#include "../include/dilithium/params.h"

/**
 * symmetric.c — SHAKE128/256 Stream Initialization for Dilithium
 *
 * PURPOSE:
 * Provides the two key stream initialization functions that Dilithium uses
 * to derive pseudorandom bytes from seeds:
 *
 *   1. shake128_stream_init — expands the public seed (rho) into matrix A.
 *      Uses SHAKE128 because matrix expansion needs many bytes quickly.
 *      The nonce encodes the (row, col) position: nonce = (i << 8) + j
 *
 *   2. shake256_stream_init — expands rhoprime into secret polynomials y.
 *      Uses SHAKE256 for higher-security PRF output.
 *
 * CONCEPTUAL MAPPING FROM KYBER:
 *   Kyber's kyber_shake128_absorb(state, seed, x, y) absorbs seed + two index bytes.
 *   Dilithium's stream_init functions do the same: seed + 2-byte nonce.
 *   The nonce encodes the polynomial's position in the vector/matrix.
 */

/*
 * dilithium_shake128_stream_init
 * Initialize a SHAKE128 stream from a SEEDBYTES seed and 16-bit nonce.
 * Used by poly_uniform() to expand matrix row/column entries from rho.
 */
void dilithium_shake128_stream_init(keccak_state *state,
                                    const uint8_t seed[SEEDBYTES],
                                    uint16_t nonce)
{
  uint8_t t[2];
  /* Encode nonce as 2 little-endian bytes for domain separation */
  t[0] = (uint8_t)nonce;
  t[1] = (uint8_t)(nonce >> 8);

  shake128_init(state);
  shake128_absorb(state, seed, SEEDBYTES);
  shake128_absorb(state, t, 2);
  shake128_finalize(state);
}

/*
 * dilithium_shake256_stream_init
 * Initialize a SHAKE256 stream from a CRHBYTES seed and 16-bit nonce.
 * Used by poly_uniform_eta() to expand secret key seeds into s1, s2,
 * and by poly_uniform_gamma1() to expand rhoprime into masking vector y.
 */
void dilithium_shake256_stream_init(keccak_state *state,
                                    const uint8_t seed[CRHBYTES],
                                    uint16_t nonce)
{
  uint8_t t[2];
  t[0] = (uint8_t)nonce;
  t[1] = (uint8_t)(nonce >> 8);

  shake256_init(state);
  shake256_absorb(state, seed, CRHBYTES);
  shake256_absorb(state, t, 2);
  shake256_finalize(state);
}
