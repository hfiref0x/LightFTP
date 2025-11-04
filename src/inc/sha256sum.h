/*
 * sha256sum.h
 *
 *  Created on: Jul 25, 2025
 *
 *  Modified on: Jul 25, 2025
 *
 *      Author: lightftp
 */

#ifndef SHA256SUM_H_
#define SHA256SUM_H_ 1

#include <stdint.h>
#include <string.h>
#include <sys/types.h>

typedef struct _SHA256_CTX {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX, *PSHA256_CTX;

void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t hash[]);

#endif /* SHA256SUM_H_ */
