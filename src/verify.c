#include <stddef.h>
#include <stdint.h>
#include "verify.h"

/**
 * verify.c — Constant-Time Byte Comparison and Memory Utilities
 *
 * PURPOSE:
 * Provides side-channel resistant comparison and conditional move operations.
 *
 * CONCEPTUAL MAPPING FROM KYBER:
 * - Identical role to Kyber's verify.c. Fully reusable between PQC schemes.
 *
 * WHY CONSTANT-TIME?
 * - A naive comparison (for loop with early-exit break) leaks which byte
 *   first differs through CPU timing measurements. An attacker measuring
 *   ~nanosecond differences can learn secret information.
 * - Our comparison accumulates all differences with OR (no branching) and
 *   returns the combined result only after checking ALL bytes. This takes
 *   the same time regardless of where the mismatch occurs.
 *
 * SECURITY IMPORTANCE:
 * - Used during signature verification to compare the recomputed challenge
 *   hash c2 with the received challenge c. Any timing leak here could allow
 *   an attacker to forge signatures or determine secret key information.
 */

/*
 * verify
 * Compare a and b in constant time.
 * Returns 0 if a == b, nonzero if a != b.
 */
int verify(const uint8_t *a, const uint8_t *b, size_t len) {
  uint8_t r = 0;
  /* XOR all bytes together — any mismatch sets a bit in r */
  for (size_t i = 0; i < len; i++)
    r |= a[i] ^ b[i];
  /* Return nonzero if any byte differed */
  return (int)r;
}

/*
 * cmov
 * Conditionally copy b into r in constant time.
 * b is copied into r if and only if cond != 0.
 * Used during decapsulation to avoid branching on secret data.
 */
void cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b) {
  uint8_t mask;
  /* Create an all-1s mask if b != 0, or all-0s if b == 0 */
  b = -b; /* 0 -> 0x00, nonzero -> 0xFF */
  mask = (uint8_t)b;
  for (size_t i = 0; i < len; i++)
    r[i] ^= mask & (r[i] ^ x[i]);
}
