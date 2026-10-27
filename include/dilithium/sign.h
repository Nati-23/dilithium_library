#ifndef SIGN_H
#define SIGN_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"

/**
 * sign.h — Internal Protocol Signatures and Packing Declarations
 *
 * CONCEPTUAL MAPPING FROM KYBER:
 * - Kyber uses indcpa_pack_publickey/indcpa_unpack_publickey in indcpa.h to serialize elements.
 * - Dilithium uses pack_pk/unpack_pk, pack_sk/unpack_sk, and pack_sig/unpack_sig
 *   to marshal the polynomial vectors t1, t0, s1, s2, and z into byte streams.
 */

#define pack_pk DILITHIUM_NAMESPACE(pack_pk)
void pack_pk(uint8_t *r, const uint8_t *rho, const void *t1);

#define unpack_pk DILITHIUM_NAMESPACE(unpack_pk)
void unpack_pk(uint8_t *rho, void *t1, const uint8_t *pk);

#define pack_sk DILITHIUM_NAMESPACE(pack_sk)
void pack_sk(uint8_t *r,
             const uint8_t *rho,
             const uint8_t *tr,
             const uint8_t *key,
             const void *s1,
             const void *s2,
             const void *t0);

#define unpack_sk DILITHIUM_NAMESPACE(unpack_sk)
void unpack_sk(uint8_t *rho,
               uint8_t *tr,
               uint8_t *key,
               void *s1,
               void *s2,
               void *t0,
               const uint8_t *sk);

#define pack_sig DILITHIUM_NAMESPACE(pack_sig)
void pack_sig(uint8_t *r, const uint8_t *c, const void *z, const void *h);

#define unpack_sig DILITHIUM_NAMESPACE(unpack_sig)
int unpack_sig(uint8_t *c, void *z, void *h, const uint8_t *sig);

#endif
