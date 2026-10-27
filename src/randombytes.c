#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "randombytes.h"

/**
 * randombytes.c — Cryptographically Secure OS Randomness Provider
 *
 * PURPOSE:
 * Provides a single function randombytes(buf, len) that fills a buffer with
 * cryptographically strong random bytes sourced from the operating system.
 *
 * CONCEPTUAL MAPPING FROM KYBER:
 * - Identical role to Kyber's randombytes.c. This layer is completely reusable
 *   between Kyber, Dilithium, and Falcon.
 *
 * WHY DOES THIS MATTER?
 * - The security of Dilithium's key generation depends entirely on the quality
 *   of the 32-byte master seed. If this seed is predictable, all security is lost.
 * - We use OS-level entropy sources which collect entropy from hardware interrupts,
 *   timing jitter, network events, and other non-deterministic physical events.
 *
 * PLATFORM SUPPORT:
 * - Windows: BCryptGenRandom (Windows CNG — NIST-approved CSPRNG)
 * - Linux/macOS: getrandom() syscall, or /dev/urandom fallback
 */

#if defined(_WIN32) || defined(_WIN64)
/* ── Windows: BCryptGenRandom ──────────────────────────────────── */
#include <windows.h>
#include <bcrypt.h>
#ifdef _MSC_VER
#pragma comment(lib, "bcrypt.lib")
#endif


void randombytes(uint8_t *out, size_t outlen) {
  /* BCryptGenRandom: part of Windows CNG, uses FIPS 800-90A compliant DRBG */
  if (BCryptGenRandom(NULL, (PUCHAR)out, (ULONG)outlen,
                      BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
    fprintf(stderr, "FATAL: BCryptGenRandom failed\n");
    abort();
  }
}

#elif defined(__linux__)
/* ── Linux: getrandom() syscall ─────────────────────────────────── */
#include <sys/random.h>

void randombytes(uint8_t *out, size_t outlen) {
  ssize_t ret;
  while (outlen > 0) {
    /* getrandom() blocks until kernel entropy pool is initialized */
    ret = getrandom(out, outlen, 0);
    if (ret < 0) {
      perror("FATAL: getrandom");
      abort();
    }
    out    += ret;
    outlen -= ret;
  }
}

#else
/* ── Fallback: /dev/urandom ─────────────────────────────────────── */
void randombytes(uint8_t *out, size_t outlen) {
  FILE *f = fopen("/dev/urandom", "rb");
  if (!f) {
    fprintf(stderr, "FATAL: cannot open /dev/urandom\n");
    abort();
  }
  if (fread(out, 1, outlen, f) != outlen) {
    fprintf(stderr, "FATAL: /dev/urandom read failed\n");
    fclose(f);
    abort();
  }
  fclose(f);
}
#endif
