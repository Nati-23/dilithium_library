#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "dilithium/dilithium.h"

int main(void)
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t sig1[CRYPTO_BYTES];
  uint8_t sig2[CRYPTO_BYTES];
  size_t siglen1, siglen2;
  const char *message = "Dilithium Randomized Signing Demonstration";
  size_t mlen = strlen(message);

  printf("--- Dilithium Randomized Signature Example ---\n");

  // 1. Generate keypair
  if (crypto_sign_keypair(pk, sk) != 0) {
    fprintf(stderr, "Key generation failed\n");
    return 1;
  }
  printf("Keypair generated successfully.\n");

  // 2. Sign message the first time (randomized)
  if (crypto_sign_signature_randomized(sig1, &siglen1, (const uint8_t *)message, mlen, sk) != 0) {
    fprintf(stderr, "First signing failed\n");
    return 1;
  }
  printf("Signature 1 generated successfully (%zu bytes).\n", siglen1);

  // 3. Sign the same message the second time (randomized)
  if (crypto_sign_signature_randomized(sig2, &siglen2, (const uint8_t *)message, mlen, sk) != 0) {
    fprintf(stderr, "Second signing failed\n");
    return 1;
  }
  printf("Signature 2 generated successfully (%zu bytes).\n", siglen2);

  // 4. Verify both signatures
  if (crypto_sign_verify(sig1, siglen1, (const uint8_t *)message, mlen, pk) != 0) {
    fprintf(stderr, "Signature 1 verification failed\n");
    return 1;
  }
  if (crypto_sign_verify(sig2, siglen2, (const uint8_t *)message, mlen, pk) != 0) {
    fprintf(stderr, "Signature 2 verification failed\n");
    return 1;
  }
  printf("Both signatures verified successfully against the public key.\n");

  // 5. Compare the signature bytes to prove non-determinism
  if (memcmp(sig1, sig2, CRYPTO_BYTES) == 0) {
    printf("ERROR: Signatures are identical! Randomized signing is not working.\n");
    return 1;
  } else {
    printf("SUCCESS: Signatures are different! Entropy was successfully injected.\n");
  }

  return 0;
}
