#include <stdint.h>
#include "poly.h"
#include "ntt.h"
#include "reduce.h"
#include "rounding.h"
#include "symmetric.h"
#include "fips202.h"
#include "../include/dilithium/params.h"

/* ── Basic arithmetic ─────────────────────────────────────────── */

void poly_reduce(poly *a) {
  unsigned int i;
  for (i = 0; i < N; ++i)
    a->coeffs[i] = reduce32(a->coeffs[i]);
}

void poly_caddq(poly *a) {
  unsigned int i;
  for (i = 0; i < N; ++i)
    a->coeffs[i] = caddq(a->coeffs[i]);
}

void poly_add(poly *c, const poly *a, const poly *b) {
  unsigned int i;
  for (i = 0; i < N; ++i)
    c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

void poly_sub(poly *c, const poly *a, const poly *b) {
  unsigned int i;
  for (i = 0; i < N; ++i)
    c->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}

/* Multiply by 2^D (shift left). Used in verification to reconstruct t. */
void poly_shiftl(poly *a) {
  unsigned int i;
  for (i = 0; i < N; ++i)
    a->coeffs[i] <<= D;
}

void poly_ntt(poly *a)          { ntt(a->coeffs); }
void poly_invntt_tomont(poly *a){ invntt_tomont(a->coeffs); }

void poly_pointwise_montgomery(poly *c, const poly *a, const poly *b) {
  unsigned int i;
  for (i = 0; i < N; ++i)
    c->coeffs[i] = montgomery_reduce((int64_t)a->coeffs[i] * b->coeffs[i]);
}

/* ── Rounding operations ──────────────────────────────────────── */

void poly_power2round(poly *a1, poly *a0, const poly *a) {
  unsigned int i;
  for (i = 0; i < N; ++i)
    a1->coeffs[i] = power2round(&a0->coeffs[i], a->coeffs[i]);
}

void poly_decompose(poly *a1, poly *a0, const poly *a) {
  unsigned int i;
  for (i = 0; i < N; ++i)
    a1->coeffs[i] = decompose(&a0->coeffs[i], a->coeffs[i]);
}

unsigned int poly_make_hint(poly *h, const poly *a0, const poly *a1) {
  unsigned int i, s = 0;
  for (i = 0; i < N; ++i) {
    h->coeffs[i] = make_hint(a0->coeffs[i], a1->coeffs[i]);
    s += h->coeffs[i];
  }
  return s;
}

void poly_use_hint(poly *b, const poly *a, const poly *h) {
  unsigned int i;
  for (i = 0; i < N; ++i)
    b->coeffs[i] = use_hint(a->coeffs[i], h->coeffs[i]);
}

/* ── Norm check ───────────────────────────────────────────────── */

int poly_chknorm(const poly *a, int32_t B) {
  unsigned int i;
  int32_t t;
  if (B > (Q-1)/8) return 1;
  for (i = 0; i < N; ++i) {
    /* Constant-time absolute value via arithmetic shift */
    t = a->coeffs[i] >> 31;
    t = a->coeffs[i] - (t & 2*a->coeffs[i]);
    if (t >= B) return 1;
  }
  return 0;
}

/* ── Rejection sampling helpers ───────────────────────────────── */

/* Uniform sampling: accept bytes whose 23-bit value is < Q */
static unsigned int rej_uniform(int32_t *a, unsigned int len,
                                const uint8_t *buf, unsigned int buflen) {
  unsigned int ctr = 0, pos = 0;
  uint32_t t;
  while (ctr < len && pos + 3 <= buflen) {
    t  = buf[pos++];
    t |= (uint32_t)buf[pos++] << 8;
    t |= (uint32_t)buf[pos++] << 16;
    t &= 0x7FFFFF;
    if (t < (uint32_t)Q)
      a[ctr++] = t;
  }
  return ctr;
}

/* Eta-bounded sampling: accept nibbles in [0, 2*ETA] */
static unsigned int rej_eta(int32_t *a, unsigned int len,
                            const uint8_t *buf, unsigned int buflen) {
  unsigned int ctr = 0, pos = 0;
  uint32_t t0, t1;
  while (ctr < len && pos < buflen) {
    t0 = buf[pos] & 0x0F;
    t1 = buf[pos++] >> 4;
#if ETA == 2
    if (t0 < 15) { t0 = t0 - (205*t0 >> 10)*5; a[ctr++] = 2 - t0; }
    if (t1 < 15 && ctr < len) { t1 = t1 - (205*t1 >> 10)*5; a[ctr++] = 2 - t1; }
#elif ETA == 4
    if (t0 < 9) a[ctr++] = 4 - t0;
    if (t1 < 9 && ctr < len) a[ctr++] = 4 - t1;
#endif
  }
  return ctr;
}

/* ── Polynomial sampling functions ────────────────────────────── */

#define POLY_UNIFORM_NBLOCKS ((768 + STREAM128_BLOCKBYTES - 1)/STREAM128_BLOCKBYTES)
void poly_uniform(poly *a, const uint8_t seed[SEEDBYTES], uint16_t nonce) {
  unsigned int i, ctr, off;
  unsigned int buflen = POLY_UNIFORM_NBLOCKS * STREAM128_BLOCKBYTES;
  uint8_t buf[POLY_UNIFORM_NBLOCKS * STREAM128_BLOCKBYTES + 2];
  stream128_state state;
  stream128_init(&state, seed, nonce);
  stream128_squeezeblocks(buf, POLY_UNIFORM_NBLOCKS, &state);
  ctr = rej_uniform(a->coeffs, N, buf, buflen);
  while (ctr < N) {
    off = buflen % 3;
    for (i = 0; i < off; ++i)
      buf[i] = buf[buflen - off + i];
    stream128_squeezeblocks(buf + off, 1, &state);
    buflen = STREAM128_BLOCKBYTES + off;
    ctr += rej_uniform(a->coeffs + ctr, N - ctr, buf, buflen);
  }
}

#if ETA == 2
#define POLY_UNIFORM_ETA_NBLOCKS ((136 + STREAM256_BLOCKBYTES - 1)/STREAM256_BLOCKBYTES)
#elif ETA == 4
#define POLY_UNIFORM_ETA_NBLOCKS ((227 + STREAM256_BLOCKBYTES - 1)/STREAM256_BLOCKBYTES)
#endif
void poly_uniform_eta(poly *a, const uint8_t seed[CRHBYTES], uint16_t nonce) {
  unsigned int ctr;
  unsigned int buflen = POLY_UNIFORM_ETA_NBLOCKS * STREAM256_BLOCKBYTES;
  uint8_t buf[POLY_UNIFORM_ETA_NBLOCKS * STREAM256_BLOCKBYTES];
  stream256_state state;
  stream256_init(&state, seed, nonce);
  stream256_squeezeblocks(buf, POLY_UNIFORM_ETA_NBLOCKS, &state);
  ctr = rej_eta(a->coeffs, N, buf, buflen);
  while (ctr < N) {
    stream256_squeezeblocks(buf, 1, &state);
    ctr += rej_eta(a->coeffs + ctr, N - ctr, buf, STREAM256_BLOCKBYTES);
  }
}

#define POLY_UNIFORM_GAMMA1_NBLOCKS ((POLYZ_PACKEDBYTES + STREAM256_BLOCKBYTES - 1)/STREAM256_BLOCKBYTES)
void poly_uniform_gamma1(poly *a, const uint8_t seed[CRHBYTES], uint16_t nonce) {
  uint8_t buf[POLY_UNIFORM_GAMMA1_NBLOCKS * STREAM256_BLOCKBYTES];
  stream256_state state;
  stream256_init(&state, seed, nonce);
  stream256_squeezeblocks(buf, POLY_UNIFORM_GAMMA1_NBLOCKS, &state);
  polyz_unpack(a, buf);
}

/* ── Challenge polynomial generation ─────────────────────────── */

void poly_challenge(poly *c, const uint8_t seed[CTILDEBYTES]) {
  unsigned int i, b, pos;
  uint64_t signs;
  uint8_t buf[SHAKE256_RATE];
  keccak_state state;
  shake256_init(&state);
  shake256_absorb(&state, seed, CTILDEBYTES);
  shake256_finalize(&state);
  shake256_squeezeblocks(buf, 1, &state);
  signs = 0;
  for (i = 0; i < 8; ++i)
    signs |= (uint64_t)buf[i] << 8*i;
  pos = 8;
  for (i = 0; i < N; ++i) c->coeffs[i] = 0;
  for (i = N-TAU; i < N; ++i) {
    do {
      if (pos >= SHAKE256_RATE) { shake256_squeezeblocks(buf, 1, &state); pos = 0; }
      b = buf[pos++];
    } while (b > i);
    c->coeffs[i] = c->coeffs[b];
    c->coeffs[b] = 1 - 2*(signs & 1);
    signs >>= 1;
  }
}

/* ── Serialization ────────────────────────────────────────────── */

void polyeta_pack(uint8_t *r, const poly *a) {
  unsigned int i;
  uint8_t t[8];
#if ETA == 4
  for (i = 0; i < N/2; ++i) {
    t[0] = ETA - a->coeffs[2*i+0];
    t[1] = ETA - a->coeffs[2*i+1];
    r[i] = t[0] | (t[1] << 4);
  }
#elif ETA == 2
  for (i = 0; i < N/8; ++i) {
    t[0]=ETA-a->coeffs[8*i+0]; t[1]=ETA-a->coeffs[8*i+1];
    t[2]=ETA-a->coeffs[8*i+2]; t[3]=ETA-a->coeffs[8*i+3];
    t[4]=ETA-a->coeffs[8*i+4]; t[5]=ETA-a->coeffs[8*i+5];
    t[6]=ETA-a->coeffs[8*i+6]; t[7]=ETA-a->coeffs[8*i+7];
    r[3*i+0] = (t[0]>>0)|(t[1]<<3)|(t[2]<<6);
    r[3*i+1] = (t[2]>>2)|(t[3]<<1)|(t[4]<<4)|(t[5]<<7);
    r[3*i+2] = (t[5]>>1)|(t[6]<<2)|(t[7]<<5);
  }
#endif
}

void polyeta_unpack(poly *r, const uint8_t *a) {
  unsigned int i;
#if ETA == 4
  for (i = 0; i < N/2; ++i) {
    r->coeffs[2*i+0] = ETA - (a[i] & 0x0F);
    r->coeffs[2*i+1] = ETA - (a[i] >> 4);
  }
#elif ETA == 2
  for (i = 0; i < N/8; ++i) {
    r->coeffs[8*i+0] = ETA - ((a[3*i+0]>>0)&7);
    r->coeffs[8*i+1] = ETA - ((a[3*i+0]>>3)&7);
    r->coeffs[8*i+2] = ETA - (((a[3*i+0]>>6)|(a[3*i+1]<<2))&7);
    r->coeffs[8*i+3] = ETA - ((a[3*i+1]>>1)&7);
    r->coeffs[8*i+4] = ETA - ((a[3*i+1]>>4)&7);
    r->coeffs[8*i+5] = ETA - (((a[3*i+1]>>7)|(a[3*i+2]<<1))&7);
    r->coeffs[8*i+6] = ETA - ((a[3*i+2]>>2)&7);
    r->coeffs[8*i+7] = ETA - ((a[3*i+2]>>5)&7);
  }
#endif
}

void polyt1_pack(uint8_t *r, const poly *a) {
  unsigned int i;
  for (i = 0; i < N/4; ++i) {
    r[5*i+0] = (a->coeffs[4*i+0]>>0);
    r[5*i+1] = (a->coeffs[4*i+0]>>8)|(a->coeffs[4*i+1]<<2);
    r[5*i+2] = (a->coeffs[4*i+1]>>6)|(a->coeffs[4*i+2]<<4);
    r[5*i+3] = (a->coeffs[4*i+2]>>4)|(a->coeffs[4*i+3]<<6);
    r[5*i+4] = (a->coeffs[4*i+3]>>2);
  }
}

void polyt1_unpack(poly *r, const uint8_t *a) {
  unsigned int i;
  for (i = 0; i < N/4; ++i) {
    r->coeffs[4*i+0] = ((a[5*i+0]>>0)|((uint32_t)a[5*i+1]<<8))&0x3FF;
    r->coeffs[4*i+1] = ((a[5*i+1]>>2)|((uint32_t)a[5*i+2]<<6))&0x3FF;
    r->coeffs[4*i+2] = ((a[5*i+2]>>4)|((uint32_t)a[5*i+3]<<4))&0x3FF;
    r->coeffs[4*i+3] = ((a[5*i+3]>>6)|((uint32_t)a[5*i+4]<<2))&0x3FF;
  }
}

void polyt0_pack(uint8_t *r, const poly *a) {
  unsigned int i;
  uint32_t t[8];
  for (i = 0; i < N/8; ++i) {
    t[0]=(1<<(D-1))-a->coeffs[8*i+0]; t[1]=(1<<(D-1))-a->coeffs[8*i+1];
    t[2]=(1<<(D-1))-a->coeffs[8*i+2]; t[3]=(1<<(D-1))-a->coeffs[8*i+3];
    t[4]=(1<<(D-1))-a->coeffs[8*i+4]; t[5]=(1<<(D-1))-a->coeffs[8*i+5];
    t[6]=(1<<(D-1))-a->coeffs[8*i+6]; t[7]=(1<<(D-1))-a->coeffs[8*i+7];
    r[13*i+ 0]= t[0];       r[13*i+ 1]= t[0]>> 8; r[13*i+ 1]|=t[1]<< 5;
    r[13*i+ 2]= t[1]>> 3;   r[13*i+ 3]= t[1]>>11; r[13*i+ 3]|=t[2]<< 2;
    r[13*i+ 4]= t[2]>> 6;   r[13*i+ 4]|=t[3]<< 7; r[13*i+ 5]= t[3]>> 1;
    r[13*i+ 6]= t[3]>> 9;   r[13*i+ 6]|=t[4]<< 4; r[13*i+ 7]= t[4]>> 4;
    r[13*i+ 8]= t[4]>>12;   r[13*i+ 8]|=t[5]<< 1; r[13*i+ 9]= t[5]>> 7;
    r[13*i+ 9]|=t[6]<< 6;   r[13*i+10]= t[6]>> 2; r[13*i+11]= t[6]>>10;
    r[13*i+11]|=t[7]<< 3;   r[13*i+12]= t[7]>> 5;
  }
}

void polyt0_unpack(poly *r, const uint8_t *a) {
  unsigned int i;
  for (i = 0; i < N/8; ++i) {
    r->coeffs[8*i+0] = a[13*i+0]|((uint32_t)a[13*i+1]<<8); r->coeffs[8*i+0]&=0x1FFF;
    r->coeffs[8*i+1] =(a[13*i+1]>>5)|((uint32_t)a[13*i+2]<<3)|((uint32_t)a[13*i+3]<<11); r->coeffs[8*i+1]&=0x1FFF;
    r->coeffs[8*i+2] =(a[13*i+3]>>2)|((uint32_t)a[13*i+4]<<6); r->coeffs[8*i+2]&=0x1FFF;
    r->coeffs[8*i+3] =(a[13*i+4]>>7)|((uint32_t)a[13*i+5]<<1)|((uint32_t)a[13*i+6]<<9); r->coeffs[8*i+3]&=0x1FFF;
    r->coeffs[8*i+4] =(a[13*i+6]>>4)|((uint32_t)a[13*i+7]<<4)|((uint32_t)a[13*i+8]<<12); r->coeffs[8*i+4]&=0x1FFF;
    r->coeffs[8*i+5] =(a[13*i+8]>>1)|((uint32_t)a[13*i+9]<<7); r->coeffs[8*i+5]&=0x1FFF;
    r->coeffs[8*i+6] =(a[13*i+9]>>6)|((uint32_t)a[13*i+10]<<2)|((uint32_t)a[13*i+11]<<10); r->coeffs[8*i+6]&=0x1FFF;
    r->coeffs[8*i+7] =(a[13*i+11]>>3)|((uint32_t)a[13*i+12]<<5); r->coeffs[8*i+7]&=0x1FFF;
    r->coeffs[8*i+0]=(1<<(D-1))-r->coeffs[8*i+0]; r->coeffs[8*i+1]=(1<<(D-1))-r->coeffs[8*i+1];
    r->coeffs[8*i+2]=(1<<(D-1))-r->coeffs[8*i+2]; r->coeffs[8*i+3]=(1<<(D-1))-r->coeffs[8*i+3];
    r->coeffs[8*i+4]=(1<<(D-1))-r->coeffs[8*i+4]; r->coeffs[8*i+5]=(1<<(D-1))-r->coeffs[8*i+5];
    r->coeffs[8*i+6]=(1<<(D-1))-r->coeffs[8*i+6]; r->coeffs[8*i+7]=(1<<(D-1))-r->coeffs[8*i+7];
  }
}

void polyz_pack(uint8_t *r, const poly *a) {
  unsigned int i;
  uint32_t t[2];
#if GAMMA1 == (1 << 19)
  for (i = 0; i < N/2; ++i) {
    t[0] = GAMMA1 - a->coeffs[2*i+0];
    t[1] = GAMMA1 - a->coeffs[2*i+1];
    r[5*i+0]  = t[0];
    r[5*i+1]  = t[0] >> 8;
    r[5*i+2]  = t[0] >> 16;
    r[5*i+2] |= t[1] << 4;
    r[5*i+3]  = t[1] >> 4;
    r[5*i+4]  = t[1] >> 12;
  }
#elif GAMMA1 == (1 << 17)
  uint32_t t4[4];
  for (i = 0; i < N/4; ++i) {
    t4[0]=GAMMA1-a->coeffs[4*i+0]; t4[1]=GAMMA1-a->coeffs[4*i+1];
    t4[2]=GAMMA1-a->coeffs[4*i+2]; t4[3]=GAMMA1-a->coeffs[4*i+3];
    r[9*i+0]=t4[0]; r[9*i+1]=t4[0]>>8; r[9*i+2]=t4[0]>>16; r[9*i+2]|=t4[1]<<2;
    r[9*i+3]=t4[1]>>6; r[9*i+4]=t4[1]>>14; r[9*i+4]|=t4[2]<<4;
    r[9*i+5]=t4[2]>>4; r[9*i+6]=t4[2]>>12; r[9*i+6]|=t4[3]<<6;
    r[9*i+7]=t4[3]>>2; r[9*i+8]=t4[3]>>10;
  }
#endif
}

void polyz_unpack(poly *r, const uint8_t *a) {
  unsigned int i;
#if GAMMA1 == (1 << 19)
  for (i = 0; i < N/2; ++i) {
    r->coeffs[2*i+0]  = a[5*i+0];
    r->coeffs[2*i+0] |= (uint32_t)a[5*i+1] << 8;
    r->coeffs[2*i+0] |= (uint32_t)a[5*i+2] << 16;
    r->coeffs[2*i+0] &= 0xFFFFF;
    r->coeffs[2*i+1]  = a[5*i+2] >> 4;
    r->coeffs[2*i+1] |= (uint32_t)a[5*i+3] << 4;
    r->coeffs[2*i+1] |= (uint32_t)a[5*i+4] << 12;
    r->coeffs[2*i+0]  = GAMMA1 - r->coeffs[2*i+0];
    r->coeffs[2*i+1]  = GAMMA1 - r->coeffs[2*i+1];
  }
#elif GAMMA1 == (1 << 17)
  for (i = 0; i < N/4; ++i) {
    r->coeffs[4*i+0]  = a[9*i+0]|((uint32_t)a[9*i+1]<<8)|((uint32_t)a[9*i+2]<<16); r->coeffs[4*i+0]&=0x3FFFF;
    r->coeffs[4*i+1]  = (a[9*i+2]>>2)|((uint32_t)a[9*i+3]<<6)|((uint32_t)a[9*i+4]<<14); r->coeffs[4*i+1]&=0x3FFFF;
    r->coeffs[4*i+2]  = (a[9*i+4]>>4)|((uint32_t)a[9*i+5]<<4)|((uint32_t)a[9*i+6]<<12); r->coeffs[4*i+2]&=0x3FFFF;
    r->coeffs[4*i+3]  = (a[9*i+6]>>6)|((uint32_t)a[9*i+7]<<2)|((uint32_t)a[9*i+8]<<10); r->coeffs[4*i+3]&=0x3FFFF;
    r->coeffs[4*i+0]=GAMMA1-r->coeffs[4*i+0]; r->coeffs[4*i+1]=GAMMA1-r->coeffs[4*i+1];
    r->coeffs[4*i+2]=GAMMA1-r->coeffs[4*i+2]; r->coeffs[4*i+3]=GAMMA1-r->coeffs[4*i+3];
  }
#endif
}

void polyw1_pack(uint8_t *r, const poly *a) {
  unsigned int i;
#if GAMMA2 == (Q-1)/32
  /* 4 bits per coefficient — pack two per byte */
  for (i = 0; i < N/2; ++i)
    r[i] = a->coeffs[2*i+0] | (a->coeffs[2*i+1] << 4);
#elif GAMMA2 == (Q-1)/88
  /* 6 bits per coefficient */
  for (i = 0; i < N/4; ++i) {
    r[3*i+0]  = a->coeffs[4*i+0];
    r[3*i+0] |= a->coeffs[4*i+1] << 6;
    r[3*i+1]  = a->coeffs[4*i+1] >> 2;
    r[3*i+1] |= a->coeffs[4*i+2] << 4;
    r[3*i+2]  = a->coeffs[4*i+2] >> 4;
    r[3*i+2] |= a->coeffs[4*i+3] << 2;
  }
#endif
}
