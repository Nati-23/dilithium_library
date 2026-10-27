#ifndef REDUCE_H
#define REDUCE_H

#include <stdint.h>
#include "../include/dilithium/params.h"

/**
 * reduce.h — Modular Reduction Constants and Prototypes
 *
 * CONCEPTUAL MAPPING FROM KYBER:
 * - Kyber uses Montgomery with R = 2^16 and q = 3329.
 * - Dilithium uses Montgomery with R = 2^32 and q = 8380417.
 *   Because q is a 23-bit prime, products fit in 64-bit integers.
 *
 * MONTGOMERY CONSTANT:
 * - MONT = 2^32 mod q = 4193792
 * - QINV = q^-1 mod 2^32 = 58728449
 *   (satisfies: q * QINV ≡ 1 mod 2^32)
 */

#define MONT  4193792U   /* 2^32 mod Q (Montgomery factor) */
#define QINV  58728449U  /* q^{-1} mod 2^32 */

int32_t montgomery_reduce(int64_t a);
int32_t reduce32(int32_t a);
int32_t caddq(int32_t a);
int32_t freeze(int32_t a);

#endif
