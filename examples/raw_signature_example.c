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
  const char *message = "Dilithium Raw Signature Demonstration";
  size_t mlen = strlen(message);

  printf("--- Dilithium Raw Signature Example ---\n");

  // 1. Generate keypair
  if (crypto_sign_keypair(pk, sk) != 0) {
    fprintf(stderr, "Key generation failed\n");
    return 1;
  }
  printf("Keypair generated successfully.\n");
  printf("Public key size: %u bytes\n", (unsigned)CRYPTO_PUBLICKEYBYTES);
  printf("Secret key size: %u bytes\n", (unsigned)CRYPTO_SECRETKEYBYTES);

  // 2. Sign message to get standalone signature
  if (crypto_sign_signature(sig, &siglen, (const uint8_t *)message, mlen, sk) != 0) {
    fprintf(stderr, "Signing failed\n");
    return 1;
  }
  printf("Message signed successfully.\n");
  printf("Message: \"%s\"\n", message);
  printf("Signature size: %zu bytes\n", siglen);

  // 3. Verify the standalone signature
  if (crypto_sign_verify(sig, siglen, (const uint8_t *)message, mlen, pk) != 0) {
    fprintf(stderr, "Signature verification failed\n");
    return 1;
  }
  printf("Signature verified successfully!\n");

  return 0;
}
