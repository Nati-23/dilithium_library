#include <stdio.h>
#include <stdint.h>
#include "dilithium/dilithium.h"

int main(void)
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];

  if(crypto_sign_keypair(pk, sk) != 0) {
    fprintf(stderr, "keypair failed\n");
    return 1;
  }

  printf("keygen OK (pk=%u bytes, sk=%u bytes)\n",
         (unsigned)CRYPTO_PUBLICKEYBYTES,
         (unsigned)CRYPTO_SECRETKEYBYTES);
  return 0;
}
