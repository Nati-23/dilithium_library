#ifndef PARAMS_H
#define PARAMS_H

/**
 * params.h — Dilithium3 (ML-DSA-65) Cryptographic Parameter Configuration
 *
 * CONCEPTUAL MAPPING FROM KYBER:
 * - In Kyber768 (KEM), the prime modulus is q = 3329 and polynomial dimension is N = 256.
 * - In Dilithium3 (Signature), the prime modulus is q = 8380417, which is a 23-bit prime.
 *   The polynomial dimension remains N = 256.
 * - The dimension parameters (K = 6, L = 5) represent rows and columns in the public key matrix A.
 * - Unlike Kyber, which uses Centered Binomial Noise (eta = 2), Dilithium uses a uniform noise limit (eta = 4)
 *   and bounded uniform error masks (Gamma1, Gamma2) for rejection sampling.
 */

#define DILITHIUM_MODE 3

#define SEEDBYTES 32      /* Master seed length in bytes */
#define CRHBYTES 64       /* Collision-resistant hash length in bytes */
#define TRBYTES 64        /* Public key hash length in bytes */
#define RNDBYTES 32       /* Randomness byte length */
#define N 256             /* Polynomial degree */
#define Q 8380417         /* Modular prime modulus */
#define D 13              /* Number of dropped bits from public key t */
#define ROOT_OF_UNITY 1753

/* Dilithium3 Specific Parameters */
#define K 6               /* Row dimension of matrix A */
#define L 5               /* Column dimension of matrix A */
#define ETA 4             /* Uniform secret/error bound */
#define TAU 49            /* Number of non-zero coefficients in challenge c */
#define BETA 196          /* Beta bound */
#define GAMMA1 (1 << 19)  /* Scoping mask bound for y (2^19) */
#define GAMMA2 ((Q-1)/32) /* Rounding interval bound (261888) */
#define OMEGA 55          /* Maximum hint weight */
#define CTILDEBYTES 48    /* Hash length in signature */

/* Packed Polynomial Byte Sizes */
#define POLYT1_PACKEDBYTES  320  /* (256 * 10) / 8 = 320 bytes */
#define POLYT0_PACKEDBYTES  416  /* (256 * 13) / 8 = 416 bytes */
#define POLYVECH_PACKEDBYTES (OMEGA + K) /* Serialization size of hints */
#define POLYZ_PACKEDBYTES   640  /* (256 * 20) / 8 = 640 bytes (for Gamma1 = 2^19) */
#define POLYW1_PACKEDBYTES  128  /* (256 * 4) / 8 = 128 bytes (for Gamma2 = (Q-1)/32) */
#define POLYETA_PACKEDBYTES 128  /* (256 * 4) / 8 = 128 bytes (for eta = 4) */

/* Cryptographic Packet Byte Sizes */
#define CRYPTO_PUBLICKEYBYTES (SEEDBYTES + K*POLYT1_PACKEDBYTES) /* 1952 bytes */
#define CRYPTO_SECRETKEYBYTES (2*SEEDBYTES \
                               + TRBYTES \
                               + L*POLYETA_PACKEDBYTES \
                               + K*POLYETA_PACKEDBYTES \
                               + K*POLYT0_PACKEDBYTES)            /* 4032 bytes */
#define CRYPTO_BYTES (CTILDEBYTES + L*POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES) /* 3309 bytes */

#endif
