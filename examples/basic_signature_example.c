#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "dilithium/dilithium.h"

int main(void)
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t sm[CRYPTO_BYTES + 256];
  uint8_t opened[256];
  size_t smlen, mlen;
  const char *message = "Hello from Dilithium3!";

  crypto_sign_keypair(pk, sk);

  if(crypto_sign(sm, &smlen, (const uint8_t *)message, strlen(message), sk) != 0) {
    fprintf(stderr, "signing failed\n");
    return 1;
  }

  if(crypto_sign_open(opened, &mlen, sm, smlen, pk) != 0) {
    fprintf(stderr, "open failed\n");
    return 1;
  }

  printf("Signed and verified message: %.*s\n", (int)mlen, opened);
  return 0;
}
