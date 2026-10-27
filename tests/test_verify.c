#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "dilithium/dilithium.h"

int main(void)
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t pk_other[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk_other[CRYPTO_SECRETKEYBYTES];
  uint8_t sig[CRYPTO_BYTES];
  size_t siglen;
  const char *msg = "Dilithium verify test";
  const char *msg_tampered = "Dilithium verify test.";

  // Generate main keypair
  if(crypto_sign_keypair(pk, sk) != 0) {
    fprintf(stderr, "First keypair generation failed\n");
    return 1;
  }

  // Generate secondary keypair for cross-key verification tests
  if(crypto_sign_keypair(pk_other, sk_other) != 0) {
    fprintf(stderr, "Second keypair generation failed\n");
    return 1;
  }

  // Generate signature
  if(crypto_sign_signature(sig, &siglen, (const uint8_t *)msg, strlen(msg), sk) != 0) {
    fprintf(stderr, "Signature generation failed\n");
    return 1;
  }

  // Test 1: Verify correct signature
  if(crypto_sign_verify(sig, siglen, (const uint8_t *)msg, strlen(msg), pk) != 0) {
    fprintf(stderr, "verify failed on valid signature\n");
    return 1;
  }

  // Test 2: Verify with a tampered message
  if(crypto_sign_verify(sig, siglen, (const uint8_t *)msg_tampered, strlen(msg_tampered), pk) == 0) {
    fprintf(stderr, "verify accepted tampered message\n");
    return 1;
  }

  // Test 3: Verify with a different public key
  if(crypto_sign_verify(sig, siglen, (const uint8_t *)msg, strlen(msg), pk_other) == 0) {
    fprintf(stderr, "verify accepted signature from a different keypair\n");
    return 1;
  }

  // Test 4: Verify with truncated signature length
  if(crypto_sign_verify(sig, siglen - 1, (const uint8_t *)msg, strlen(msg), pk) == 0) {
    fprintf(stderr, "verify accepted signature with truncated length\n");
    return 1;
  }

  // Test 5: Verify with extended signature length
  if(crypto_sign_verify(sig, siglen + 1, (const uint8_t *)msg, strlen(msg), pk) == 0) {
    fprintf(stderr, "verify accepted signature with extended length\n");
    return 1;
  }

  // Test 6: Verify with single-bit tampering at the beginning of signature (c part)
  uint8_t sig_tampered[CRYPTO_BYTES];
  memcpy(sig_tampered, sig, CRYPTO_BYTES);
  sig_tampered[0] ^= 1;
  if(crypto_sign_verify(sig_tampered, siglen, (const uint8_t *)msg, strlen(msg), pk) == 0) {
    fprintf(stderr, "verify accepted tampered signature (start of sig)\n");
    return 1;
  }

  // Test 7: Verify with single-bit tampering in the middle of signature (z part)
  memcpy(sig_tampered, sig, CRYPTO_BYTES);
  sig_tampered[siglen / 2] ^= 1;
  if(crypto_sign_verify(sig_tampered, siglen, (const uint8_t *)msg, strlen(msg), pk) == 0) {
    fprintf(stderr, "verify accepted tampered signature (middle of sig)\n");
    return 1;
  }

  // Test 8: Verify with single-bit tampering at the end of signature (h part)
  memcpy(sig_tampered, sig, CRYPTO_BYTES);
  sig_tampered[siglen - 1] ^= 1;
  if(crypto_sign_verify(sig_tampered, siglen, (const uint8_t *)msg, strlen(msg), pk) == 0) {
    fprintf(stderr, "verify accepted tampered signature (end of sig)\n");
    return 1;
  }

  printf("verify OK\n");
  return 0;
}

