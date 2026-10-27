#ifndef DILITHIUM_H
#define DILITHIUM_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"

/**
 * dilithium.h — CRYSTALS-Dilithium Public API Definitions
 *
 * CONCEPTUAL MAPPING FROM KYBER:
 * - Kyber KEM exposes: keypair, enc (encapsulate), dec (decapsulate)
 * - Dilithium Signature exposes: keypair, sign (generate signature), verify (validate signature)
 *
 * This API conforms to both the standard NIST digital signature wrapping (signature-envelope style)
 * and the raw signature extraction style (signature-only style).
 */

/* Public API Symbols */
#define crypto_sign_keypair dilithium_crypto_sign_keypair
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

#define crypto_sign dilithium_crypto_sign
int crypto_sign(uint8_t *sm, size_t *smlen,
                const uint8_t *m, size_t mlen,
                const uint8_t *sk);

#define crypto_sign_open dilithium_crypto_sign_open
int crypto_sign_open(uint8_t *m, size_t *mlen,
                     const uint8_t *sm, size_t smlen,
                     const uint8_t *pk);

#define crypto_sign_signature dilithium_crypto_sign_signature
int crypto_sign_signature(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *sk);

#define crypto_sign_signature_randomized dilithium_crypto_sign_signature_randomized
int crypto_sign_signature_randomized(uint8_t *sig, size_t *siglen,
                                     const uint8_t *m, size_t mlen,
                                     const uint8_t *sk);

#define crypto_sign_randomized dilithium_crypto_sign_randomized
int crypto_sign_randomized(uint8_t *sm, size_t *smlen,
                           const uint8_t *m, size_t mlen,
                           const uint8_t *sk);

#define crypto_sign_verify dilithium_crypto_sign_verify
int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen,
                       const uint8_t *pk);

#endif
