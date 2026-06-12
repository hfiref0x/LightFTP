/*
 *  fcrypt.h
 *
 *  Created on: Jun 12, 2026
 *
 *  Modified on: Jun 12, 2026
 *
 *      Author: lightftp
 */

#ifndef FCRYPT_H_
#define FCRYPT_H_ 1

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

size_t base64encode(const uint8_t *s, size_t s_size, char *b64, size_t b64_size);
size_t base64decode(const char *b64, uint8_t *data, size_t data_size, size_t *cbfeed);

#endif /* FCRYPT_H_ */
