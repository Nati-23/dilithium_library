#ifndef API_H
#define API_H

#include "params.h"

/**
 * api.h — Namespacing and Algorithm Metadata Definitions
 *
 * CONCEPTUAL MAPPING FROM KYBER:
 * - Maps local library function names to an algorithm-specific namespace.
 * - This prevents name collision when linking multiple cryptosystems into the same project.
 */

#define DILITHIUM_NAMESPACE(s) dilithium_##s

#define CRYPTO_ALGNAME "Dilithium3"

#endif
