#include <stdint.h>
#include "rounding.h"
#include "../include/dilithium/params.h"

/**
 * rounding.c — Power2Round, Decompose, MakeHint, UseHint
 *
 * These four functions implement the signature compression mechanism:
 * - power2round: splits public key t into t1 (public, 10-bit) + t0 (secret, 13-bit)
 * - decompose:   splits commitment w into w1 (high, sent) + w0 (low, checked)
 * - make_hint:   signals when low bits overflow into high bits during signing
 * - use_hint:    verifier uses hint to reconstruct correct high bits
 */

int32_t power2round(int32_t *a0, int32_t a) {
  int32_t a1;
  a1  = (a + (1 << (D-1)) - 1) >> D;
  *a0 = a - (a1 << D);
  return a1;
}

int32_t decompose(int32_t *a0, int32_t a) {
  int32_t a1;
  a1  = (a + 127) >> 7;
#if GAMMA2 == (Q-1)/32
  a1  = (a1 * 1025 + (1 << 21)) >> 22;
  a1 &= 15;
#elif GAMMA2 == (Q-1)/88
  a1  = (a1 * 11275 + (1 << 23)) >> 24;
  a1 ^= ((43 - a1) >> 31) & a1;
#endif
  *a0  = a - a1 * 2 * GAMMA2;
  *a0 -= (((Q-1)/2 - *a0) >> 31) & Q;
  return a1;
}

unsigned int make_hint(int32_t a0, int32_t a1) {
  if (a0 > GAMMA2 || a0 < -GAMMA2 || (a0 == -GAMMA2 && a1 != 0))
    return 1;
  return 0;
}

int32_t use_hint(int32_t a, unsigned int hint) {
  int32_t a0, a1;
  a1 = decompose(&a0, a);
  if (hint == 0)
    return a1;
#if GAMMA2 == (Q-1)/32
  if (a0 > 0) return (a1 + 1) & 15;
  else         return (a1 - 1) & 15;
#elif GAMMA2 == (Q-1)/88
  if (a0 > 0) return (a1 == 43) ? 0 : a1 + 1;
  else         return (a1 ==  0) ? 43 : a1 - 1;
#endif
}
