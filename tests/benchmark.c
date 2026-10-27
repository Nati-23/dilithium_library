#include <stdio.h>
#include <stdint.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif
#include "dilithium/dilithium.h"

static double now_ms(void)
{
#ifdef _WIN32
  static LARGE_INTEGER freq;
  LARGE_INTEGER t;
  if(freq.QuadPart == 0)
    QueryPerformanceFrequency(&freq);
  QueryPerformanceCounter(&t);
  return 1000.0 * (double)t.QuadPart / (double)freq.QuadPart;
#else
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
#endif
}

int main(void)
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t sig[CRYPTO_BYTES];
  size_t siglen;
  const char *msg = "benchmark message for Dilithium3";
  size_t mlen = strlen(msg);
  int i;
  double t0, t1;

  t0 = now_ms();
  for(i = 0; i < 10; ++i)
    crypto_sign_keypair(pk, sk);
  t1 = now_ms();
  printf("keygen:  %.2f ms/op (10 runs)\n", (t1 - t0) / 10.0);

  t0 = now_ms();
  for(i = 0; i < 10; ++i)
    crypto_sign_signature(sig, &siglen, (const uint8_t *)msg, mlen, sk);
  t1 = now_ms();
  printf("sign:    %.2f ms/op (10 runs)\n", (t1 - t0) / 10.0);

  if(crypto_sign_verify(sig, siglen, (const uint8_t *)msg, mlen, pk) != 0) {
    fprintf(stderr, "verify sanity check failed\n");
    return 1;
  }

  t0 = now_ms();
  for(i = 0; i < 100; ++i) {
    if(crypto_sign_verify(sig, siglen, (const uint8_t *)msg, mlen, pk) != 0) {
      fprintf(stderr, "verify failed during benchmark\n");
      return 1;
    }
  }
  t1 = now_ms();
  printf("verify:  %.2f ms/op (100 runs)\n", (t1 - t0) / 100.0);

  return 0;
}
