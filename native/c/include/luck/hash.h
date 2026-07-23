#ifndef LUCK_HASH_H
#define LUCK_HASH_H
#include <stddef.h>
#include <stdint.h>
#include "luck/cookie.h"
#ifdef __cplusplus
extern "C" {
#endif
#define LUCK_SHA256_DIGEST_SIZE 32U
#define LUCK_SHA256_HEX_SIZE 65U
typedef struct luck_sha256 { uint32_t state[8]; uint64_t bit_length; unsigned char block[64]; size_t block_length; } luck_sha256;
void luck_sha256_init(luck_sha256 *context);
void luck_sha256_update(luck_sha256 *context, const void *data, size_t length);
void luck_sha256_final(luck_sha256 *context, unsigned char digest[LUCK_SHA256_DIGEST_SIZE]);
void luck_sha256_hex(const unsigned char digest[LUCK_SHA256_DIGEST_SIZE], char output[LUCK_SHA256_HEX_SIZE]);
luck_status luck_cookie_fingerprint(const luck_cookie_collection *collection, char output[LUCK_SHA256_HEX_SIZE]);
#ifdef __cplusplus
}
#endif
#endif
