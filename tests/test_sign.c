#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "dilithium/dilithium.h"

int main(void)
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t sig[CRYPTO_BYTES];
  size_t siglen;
  const char *msg = "Dilithium test message";

  if(crypto_sign_keypair(pk, sk) != 0) {
    fprintf(stderr, "keypair failed\n");
    return 1;
  }

  if(crypto_sign_signature(sig, &siglen, (const uint8_t *)msg, strlen(msg), sk) != 0) {
    fprintf(stderr, "sign failed\n");
    return 1;
  }

  if(siglen != CRYPTO_BYTES) {
    fprintf(stderr, "unexpected siglen %zu\n", siglen);
    return 1;
  }

  // 1. Verify deterministic signatures are indeed identical
  uint8_t sig_det2[CRYPTO_BYTES];
  size_t sig_det2_len;
  if(crypto_sign_signature(sig_det2, &sig_det2_len, (const uint8_t *)msg, strlen(msg), sk) != 0) {
    fprintf(stderr, "second deterministic sign failed\n");
    return 1;
  }
  if(memcmp(sig, sig_det2, CRYPTO_BYTES) != 0) {
    fprintf(stderr, "deterministic signatures differ\n");
    return 1;
  }

  // 2. Verify randomized signatures are valid and differ each run
  uint8_t sig_rand1[CRYPTO_BYTES];
  size_t sig_rand1_len;
  if(crypto_sign_signature_randomized(sig_rand1, &sig_rand1_len, (const uint8_t *)msg, strlen(msg), sk) != 0) {
    fprintf(stderr, "randomized sign 1 failed\n");
    return 1;
  }
  if(crypto_sign_verify(sig_rand1, sig_rand1_len, (const uint8_t *)msg, strlen(msg), pk) != 0) {
    fprintf(stderr, "randomized signature verification failed\n");
    return 1;
  }

  uint8_t sig_rand2[CRYPTO_BYTES];
  size_t sig_rand2_len;
  if(crypto_sign_signature_randomized(sig_rand2, &sig_rand2_len, (const uint8_t *)msg, strlen(msg), sk) != 0) {
    fprintf(stderr, "randomized sign 2 failed\n");
    return 1;
  }
  if(memcmp(sig_rand1, sig_rand2, CRYPTO_BYTES) == 0) {
    fprintf(stderr, "randomized signatures are identical (entropy leak)\n");
    return 1;
  }

  printf("sign OK (sig=%u bytes, randomized signatures verified successfully)\n", (unsigned)CRYPTO_BYTES);
  return 0;
}
