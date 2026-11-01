/* SHA-256 (FIPS 180-4). Public-domain style, no external dependency: the
 * patcher has to run inside an app bundle we cannot link CommonCrypto into on
 * every SDK we build against, and 120 lines is cheaper than a dependency. */
#ifndef DS_SHA256_H
#define DS_SHA256_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t h[8];
    uint64_t total;
    uint8_t  buf[64];
    size_t   used;
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const void *data, size_t len);
void sha256_final(sha256_ctx *c, uint8_t out[32]);
void sha256(const void *data, size_t len, uint8_t out[32]);

#endif
