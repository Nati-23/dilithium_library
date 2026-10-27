#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../include/dilithium/params.h"
#include "packing.h"
#include "poly.h"
#include "polyvec.h"
#include "randombytes.h"
#include "symmetric.h"
#include "fips202.h"
#include "verify.h"
#include "utils.h"

/* Empty ML-DSA context: pre = (0, 0) */
static const uint8_t EMPTY_PRE[2] = {0, 0};

static int crypto_sign_signature_internal(uint8_t *sig,
                                          size_t *siglen,
                                          const uint8_t *m,
                                          size_t mlen,
                                          const uint8_t *pre,
                                          size_t prelen,
                                          const uint8_t rnd[RNDBYTES],
                                          const uint8_t *sk)
{
  unsigned int n;
  uint8_t seedbuf[2*SEEDBYTES + TRBYTES + 2*CRHBYTES];
  uint8_t *rho, *tr, *key, *mu, *rhoprime;
  uint16_t nonce = 0;
  polyvecl mat[K], s1, y, z;
  polyveck t0, s2, w1, w0, h;
  poly cp;
  keccak_state state;

  rho = seedbuf;
  tr = rho + SEEDBYTES;
  key = tr + TRBYTES;
  mu = key + SEEDBYTES;
  rhoprime = mu + CRHBYTES;
  unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

  shake256_init(&state);
  shake256_absorb(&state, tr, TRBYTES);
  shake256_absorb(&state, pre, prelen);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);

  shake256_init(&state);
  shake256_absorb(&state, key, SEEDBYTES);
  shake256_absorb(&state, rnd, RNDBYTES);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_finalize(&state);
  shake256_squeeze(rhoprime, CRHBYTES, &state);

  polyvec_matrix_expand(mat, rho);
  polyvecl_ntt(&s1);
  polyveck_ntt(&s2);
  polyveck_ntt(&t0);

rej:
  polyvecl_uniform_gamma1(&y, rhoprime, nonce++);

  z = y;
  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1);

  polyveck_caddq(&w1);
  polyveck_decompose(&w1, &w0, &w1);
  polyveck_pack_w1(sig, &w1);

  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, sig, K*POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(sig, CTILDEBYTES, &state);
  poly_challenge(&cp, sig);
  poly_ntt(&cp);

  polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
  polyvecl_invntt_tomont(&z);
  polyvecl_add(&z, &z, &y);
  polyvecl_reduce(&z);
  if(polyvecl_chknorm(&z, GAMMA1 - BETA))
    goto rej;

  polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
  polyveck_invntt_tomont(&h);
  polyveck_sub(&w0, &w0, &h);
  polyveck_reduce(&w0);
  if(polyveck_chknorm(&w0, GAMMA2 - BETA))
    goto rej;

  polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
  polyveck_invntt_tomont(&h);
  polyveck_reduce(&h);
  if(polyveck_chknorm(&h, GAMMA2))
    goto rej;

  polyveck_add(&w0, &w0, &h);
  n = polyveck_make_hint(&h, &w0, &w1);
  if(n > OMEGA)
    goto rej;

  pack_sig(sig, sig, &z, &h);
  *siglen = CRYPTO_BYTES;

  /* Secure zeroization of sensitive variables */
  secure_zeroize(seedbuf, sizeof(seedbuf));
  secure_zeroize(&s1, sizeof(s1));
  secure_zeroize(&s2, sizeof(s2));
  secure_zeroize(&t0, sizeof(t0));
  secure_zeroize(&y, sizeof(y));
  secure_zeroize(&w0, sizeof(w0));
  secure_zeroize(&w1, sizeof(w1));
  secure_zeroize(&cp, sizeof(cp));
  secure_zeroize(&state, sizeof(state));

  return 0;
}

static int crypto_sign_verify_internal(const uint8_t *sig,
                                       size_t siglen,
                                       const uint8_t *m,
                                       size_t mlen,
                                       const uint8_t *pre,
                                       size_t prelen,
                                       const uint8_t *pk)
{
  unsigned int i;
  uint8_t buf[K*POLYW1_PACKEDBYTES];
  uint8_t rho[SEEDBYTES];
  uint8_t mu[CRHBYTES];
  uint8_t c[CTILDEBYTES];
  uint8_t c2[CTILDEBYTES];
  poly cp;
  polyvecl mat[K], z;
  polyveck t1, w1, h;
  keccak_state state;

  if(siglen != CRYPTO_BYTES)
    return -1;

  unpack_pk(rho, &t1, pk);

  if(unpack_sig(c, &z, &h, sig))
    return -1;
  if(polyvecl_chknorm(&z, GAMMA1 - BETA))
    return -1;

  shake256(mu, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES);
  shake256_init(&state);
  shake256_absorb(&state, mu, TRBYTES);
  shake256_absorb(&state, pre, prelen);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);

  poly_challenge(&cp, c);
  polyvec_matrix_expand(mat, rho);

  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

  poly_ntt(&cp);
  polyveck_shiftl(&t1);
  polyveck_ntt(&t1);
  polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

  polyveck_sub(&w1, &w1, &t1);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1);

  polyveck_caddq(&w1);
  polyveck_use_hint(&w1, &w1, &h);
  polyveck_pack_w1(buf, &w1);

  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, buf, K*POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(c2, CTILDEBYTES, &state);

  for(i = 0; i < CTILDEBYTES; ++i)
    if(c[i] != c2[i])
      return -1;

  return 0;
}

int dilithium_crypto_sign_keypair(uint8_t *pk, uint8_t *sk)
{
  uint8_t seedbuf[2*SEEDBYTES + CRHBYTES];
  uint8_t tr[TRBYTES];
  const uint8_t *rho, *rhoprime, *key;
  polyvecl mat[K];
  polyvecl s1, s1hat;
  polyveck s2, t1, t0, t;

  randombytes(seedbuf, SEEDBYTES);
  seedbuf[SEEDBYTES+0] = K;
  seedbuf[SEEDBYTES+1] = L;
  shake256(seedbuf, 2*SEEDBYTES + CRHBYTES, seedbuf, SEEDBYTES+2);
  rho = seedbuf;
  rhoprime = rho + SEEDBYTES;
  key = rhoprime + CRHBYTES;

  polyvec_matrix_expand(mat, rho);

  polyvecl_uniform_eta(&s1, rhoprime, 0);
  polyveck_uniform_eta(&s2, rhoprime, L);

  s1hat = s1;
  polyvecl_ntt(&s1hat);
  polyvec_matrix_pointwise_montgomery(&t, mat, &s1hat);
  polyveck_reduce(&t);
  polyveck_invntt_tomont(&t);
  polyveck_add(&t, &t, &s2);

  polyveck_caddq(&t);
  polyveck_power2round(&t1, &t0, &t);
  pack_pk(pk, rho, &t1);

  shake256(tr, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES);
  pack_sk(sk, rho, tr, key, &t0, &s1, &s2);

  /* Secure zeroization of sensitive variables */
  secure_zeroize(seedbuf, sizeof(seedbuf));
  secure_zeroize(&s1, sizeof(s1));
  secure_zeroize(&s1hat, sizeof(s1hat));
  secure_zeroize(&s2, sizeof(s2));
  secure_zeroize(&t0, sizeof(t0));
  secure_zeroize(&t, sizeof(t));

  return 0;
}

int dilithium_crypto_sign_signature(uint8_t *sig, size_t *siglen,
                                  const uint8_t *m, size_t mlen,
                                  const uint8_t *sk)
{
  uint8_t rnd[RNDBYTES];
  memset(rnd, 0, RNDBYTES);
  return crypto_sign_signature_internal(sig, siglen, m, mlen,
                                        EMPTY_PRE, sizeof(EMPTY_PRE),
                                        rnd, sk);
}

int dilithium_crypto_sign_signature_randomized(uint8_t *sig, size_t *siglen,
                                             const uint8_t *m, size_t mlen,
                                             const uint8_t *sk)
{
  uint8_t rnd[RNDBYTES];
  randombytes(rnd, RNDBYTES);
  int ret = crypto_sign_signature_internal(sig, siglen, m, mlen,
                                           EMPTY_PRE, sizeof(EMPTY_PRE),
                                           rnd, sk);
  secure_zeroize(rnd, RNDBYTES);
  return ret;
}

int dilithium_crypto_sign_verify(const uint8_t *sig, size_t siglen,
                                 const uint8_t *m, size_t mlen,
                                 const uint8_t *pk)
{
  return crypto_sign_verify_internal(sig, siglen, m, mlen,
                                     EMPTY_PRE, sizeof(EMPTY_PRE), pk);
}

int dilithium_crypto_sign(uint8_t *sm, size_t *smlen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *sk)
{
  size_t i;

  for(i = 0; i < mlen; ++i)
    sm[CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];
  if(dilithium_crypto_sign_signature(sm, smlen, sm + CRYPTO_BYTES, mlen, sk))
    return -1;
  *smlen += mlen;
  return 0;
}

int dilithium_crypto_sign_randomized(uint8_t *sm, size_t *smlen,
                                    const uint8_t *m, size_t mlen,
                                    const uint8_t *sk)
{
  size_t i;

  for(i = 0; i < mlen; ++i)
    sm[CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];
  if(dilithium_crypto_sign_signature_randomized(sm, smlen, sm + CRYPTO_BYTES, mlen, sk))
    return -1;
  *smlen += mlen;
  return 0;
}

int dilithium_crypto_sign_open(uint8_t *m, size_t *mlen,
                               const uint8_t *sm, size_t smlen,
                               const uint8_t *pk)
{
  size_t i;

  if(smlen < CRYPTO_BYTES)
    goto badsig;

  *mlen = smlen - CRYPTO_BYTES;
  if(dilithium_crypto_sign_verify(sm, CRYPTO_BYTES, sm + CRYPTO_BYTES, *mlen, pk))
    goto badsig;

  for(i = 0; i < *mlen; ++i)
    m[i] = sm[CRYPTO_BYTES + i];
  return 0;

badsig:
  *mlen = 0;
  for(i = 0; i < smlen; ++i)
    m[i] = 0;
  return -1;
}
