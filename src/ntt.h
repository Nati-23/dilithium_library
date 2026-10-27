#ifndef NTT_H
#define NTT_H

#include <stdint.h>
#include "../include/dilithium/params.h"

/**
 * ntt.h — Number Theoretic Transform Prototypes
 */

void ntt(int32_t a[N]);
void invntt_tomont(int32_t a[N]);

#endif
