#include <stdint.h>
#include "reduce.h"
#include "../include/dilithium/params.h"

/**
 * reduce.c — Modular Arithmetic Reduction for Dilithium
 *
 * PURPOSE:
 * Implements fast modular reduction without expensive integer division.
 * This is one of the most performance-critical modules — called millions
 * of times per signature operation.
 *
 * CONCEPTUAL MAPPING FROM KYBER:
 * - Kyber uses 16-bit Montgomery (R = 2^16, q = 3329, QINV is 16-bit).
 * - Dilithium uses 32-bit Montgomery (R = 2^32, q = 8380417, QINV is 32-bit).
 * - The algorithm structure is identical — only bit widths differ.
 *
 * WHY MONTGOMERY REDUCTION?
 * - NTT multiplication produces 64-bit products: a * b where a,b < q*8.
 * - Standard reduction: r = a mod q requires a division (slow, ~20-80 cycles).
 * - Montgomery: given a*2^32, compute a mod q using only multiply+shift (fast, ~4 cycles).
 * - Trick: instead of tracking real coefficients, we track a*R^{-1} mod q throughout.
 *   Before outputting a result, we apply one inverse Montgomery to recover a.
 *
 * WHY reduce32 (Barrett-style)?
 * - For coefficients that are just modestly oversized (after add/sub, not multiply),
 *   a simpler Barrett approximation is used: t = a / q ≈ a * (1/q) via shift.
 *   The magic constant (1<<22) is floor(2^23 / q) = 1 (since q ≈ 2^23).
 */

/*
 * montgomery_reduce
 * Input: a in [-2^31 * Q, Q * 2^31]
 * Output: r = a * 2^{-32} mod Q, with |r| < Q
 *
 * Algorithm (Montgomery reduction):
 * 1. t = a * QINV mod 2^32   (low 32 bits of a * QINV)
 * 2. r = (a - t * Q) >> 32   (subtract multiple of Q, shift out R=2^32)
 */
int32_t montgomery_reduce(int64_t a) {
  int32_t t;
  /* Step 1: compute t = a * QINV mod 2^32 */
  t = (int64_t)(int32_t)a * QINV;
  /* Step 2: subtract t*Q, then divide by 2^32 */
  t = (a - (int64_t)t * Q) >> 32;
  return t;
}

/*
 * reduce32
 * Input: a < 2^31 - 2^22
 * Output: r ≡ a (mod Q) with |r| <= 6283008
 *
 * Uses a single multiply-shift approximation of a/Q.
 * Cheaper than Montgomery; used after add/sub accumulation.
 */
int32_t reduce32(int32_t a) {
  int32_t t;
  /* Approximate t = round(a / Q) using fixed-point arithmetic */
  t = (a + (1 << 22)) >> 23;
  /* Exact reduction: a - t*Q is now in the centered range */
  t = a - t * Q;
  return t;
}

/*
 * caddq
 * Conditionally add Q to make a coefficient non-negative.
 * Used after subtraction to bring results into [0, Q-1].
 */
int32_t caddq(int32_t a) {
  /* Arithmetic right shift gives 0 if a >= 0, or 0xFFFFFFFF if a < 0 */
  a += (a >> 31) & Q;
  return a;
}

/*
 * freeze
 * Full reduction to the canonical representative in [0, Q-1].
 * = reduce32 followed by caddq.
 */
int32_t freeze(int32_t a) {
  a = reduce32(a);
  a = caddq(a);
  return a;
}
