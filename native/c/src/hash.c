#include "luck/hash.h"
#include <string.h>

#define ROTR32(value, bits) (((value) >> (bits)) | ((value) << (32U - (bits))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR32((x), 2U) ^ ROTR32((x), 13U) ^ ROTR32((x), 22U))
#define EP1(x) (ROTR32((x), 6U) ^ ROTR32((x), 11U) ^ ROTR32((x), 25U))
#define SIG0(x) (ROTR32((x), 7U) ^ ROTR32((x), 18U) ^ ((x) >> 3U))
#define SIG1(x) (ROTR32((x), 17U) ^ ROTR32((x), 19U) ^ ((x) >> 10U))

static const uint32_t constants[64] = {
    UINT32_C(0x428a2f98),UINT32_C(0x71374491),UINT32_C(0xb5c0fbcf),UINT32_C(0xe9b5dba5),
    UINT32_C(0x3956c25b),UINT32_C(0x59f111f1),UINT32_C(0x923f82a4),UINT32_C(0xab1c5ed5),
    UINT32_C(0xd807aa98),UINT32_C(0x12835b01),UINT32_C(0x243185be),UINT32_C(0x550c7dc3),
    UINT32_C(0x72be5d74),UINT32_C(0x80deb1fe),UINT32_C(0x9bdc06a7),UINT32_C(0xc19bf174),
    UINT32_C(0xe49b69c1),UINT32_C(0xefbe4786),UINT32_C(0x0fc19dc6),UINT32_C(0x240ca1cc),
    UINT32_C(0x2de92c6f),UINT32_C(0x4a7484aa),UINT32_C(0x5cb0a9dc),UINT32_C(0x76f988da),
    UINT32_C(0x983e5152),UINT32_C(0xa831c66d),UINT32_C(0xb00327c8),UINT32_C(0xbf597fc7),
    UINT32_C(0xc6e00bf3),UINT32_C(0xd5a79147),UINT32_C(0x06ca6351),UINT32_C(0x14292967),
    UINT32_C(0x27b70a85),UINT32_C(0x2e1b2138),UINT32_C(0x4d2c6dfc),UINT32_C(0x53380d13),
    UINT32_C(0x650a7354),UINT32_C(0x766a0abb),UINT32_C(0x81c2c92e),UINT32_C(0x92722c85),
    UINT32_C(0xa2bfe8a1),UINT32_C(0xa81a664b),UINT32_C(0xc24b8b70),UINT32_C(0xc76c51a3),
    UINT32_C(0xd192e819),UINT32_C(0xd6990624),UINT32_C(0xf40e3585),UINT32_C(0x106aa070),
    UINT32_C(0x19a4c116),UINT32_C(0x1e376c08),UINT32_C(0x2748774c),UINT32_C(0x34b0bcb5),
    UINT32_C(0x391c0cb3),UINT32_C(0x4ed8aa4a),UINT32_C(0x5b9cca4f),UINT32_C(0x682e6ff3),
    UINT32_C(0x748f82ee),UINT32_C(0x78a5636f),UINT32_C(0x84c87814),UINT32_C(0x8cc70208),
    UINT32_C(0x90befffa),UINT32_C(0xa4506ceb),UINT32_C(0xbef9a3f7),UINT32_C(0xc67178f2)
};

static void transform(luck_sha256 *context, const unsigned char block[64]) {
    uint32_t words[64];
    uint32_t a,b,c,d,e,f,g,h;
    size_t index;
    for (index = 0U; index < 16U; index += 1U) {
        size_t offset = index * 4U;
        words[index] = ((uint32_t)block[offset] << 24U) | ((uint32_t)block[offset+1U] << 16U) |
                       ((uint32_t)block[offset+2U] << 8U) | (uint32_t)block[offset+3U];
    }
    for (index = 16U; index < 64U; index += 1U)
        words[index] = SIG1(words[index-2U]) + words[index-7U] + SIG0(words[index-15U]) + words[index-16U];
    a=context->state[0]; b=context->state[1]; c=context->state[2]; d=context->state[3];
    e=context->state[4]; f=context->state[5]; g=context->state[6]; h=context->state[7];
    for (index = 0U; index < 64U; index += 1U) {
        uint32_t first = h + EP1(e) + CH(e,f,g) + constants[index] + words[index];
        uint32_t second = EP0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+first; d=c; c=b; b=a; a=first+second;
    }
    context->state[0]+=a; context->state[1]+=b; context->state[2]+=c; context->state[3]+=d;
    context->state[4]+=e; context->state[5]+=f; context->state[6]+=g; context->state[7]+=h;
    luck_secure_zero(words, sizeof words);
}

void luck_sha256_init(luck_sha256 *context) {
    if (context == NULL) return;
    context->state[0]=UINT32_C(0x6a09e667); context->state[1]=UINT32_C(0xbb67ae85);
    context->state[2]=UINT32_C(0x3c6ef372); context->state[3]=UINT32_C(0xa54ff53a);
    context->state[4]=UINT32_C(0x510e527f); context->state[5]=UINT32_C(0x9b05688c);
    context->state[6]=UINT32_C(0x1f83d9ab); context->state[7]=UINT32_C(0x5be0cd19);
    context->bit_length=0U; context->block_length=0U; memset(context->block,0,sizeof context->block);
}

void luck_sha256_update(luck_sha256 *context, const void *data, size_t length) {
    const unsigned char *bytes = (const unsigned char *)data;
    size_t index;
    if (context == NULL || (data == NULL && length != 0U)) return;
    for (index=0U; index<length; index+=1U) {
        context->block[context->block_length++] = bytes[index];
        if (context->block_length == 64U) { transform(context, context->block); context->bit_length += UINT64_C(512); context->block_length=0U; }
    }
}

void luck_sha256_final(luck_sha256 *context, unsigned char digest[LUCK_SHA256_DIGEST_SIZE]) {
    size_t index = context->block_length;
    uint64_t bit_length;
    if (context == NULL || digest == NULL) return;
    context->block[index++] = 0x80U;
    if (index > 56U) { while (index < 64U) context->block[index++] = 0U; transform(context, context->block); index=0U; }
    while (index < 56U) context->block[index++] = 0U;
    bit_length = context->bit_length + (uint64_t)context->block_length * UINT64_C(8);
    for (index=0U; index<8U; index+=1U) context->block[63U-index] = (unsigned char)(bit_length >> (index*8U));
    transform(context, context->block);
    for (index=0U; index<8U; index+=1U) {
        digest[index*4U]=(unsigned char)(context->state[index]>>24U);
        digest[index*4U+1U]=(unsigned char)(context->state[index]>>16U);
        digest[index*4U+2U]=(unsigned char)(context->state[index]>>8U);
        digest[index*4U+3U]=(unsigned char)context->state[index];
    }
    luck_secure_zero(context, sizeof *context);
}

void luck_sha256_hex(const unsigned char digest[LUCK_SHA256_DIGEST_SIZE], char output[LUCK_SHA256_HEX_SIZE]) {
    static const char alphabet[]="0123456789abcdef";
    size_t index;
    if (digest == NULL || output == NULL) return;
    for (index=0U; index<LUCK_SHA256_DIGEST_SIZE; index+=1U) {
        output[index*2U]=alphabet[digest[index]>>4U]; output[index*2U+1U]=alphabet[digest[index]&0x0fU];
    }
    output[LUCK_SHA256_HEX_SIZE-1U]='\0';
}

luck_status luck_cookie_fingerprint(const luck_cookie_collection *collection, char output[LUCK_SHA256_HEX_SIZE]) {
    luck_sha256 context;
    unsigned char digest[LUCK_SHA256_DIGEST_SIZE];
    size_t index;
    const char separator='\0';
    if (collection == NULL || output == NULL) return LUCK_ERROR_INVALID_ARGUMENT;
    luck_sha256_init(&context);
    for (index=0U; index<collection->length; index+=1U) {
        const luck_cookie *cookie=&collection->items[index];
        luck_sha256_update(&context,cookie->store_id,strlen(cookie->store_id)); luck_sha256_update(&context,&separator,1U);
        luck_sha256_update(&context,cookie->partition_site,strlen(cookie->partition_site)); luck_sha256_update(&context,&separator,1U);
        luck_sha256_update(&context,cookie->domain,strlen(cookie->domain)); luck_sha256_update(&context,&separator,1U);
        luck_sha256_update(&context,cookie->path,strlen(cookie->path)); luck_sha256_update(&context,&separator,1U);
        luck_sha256_update(&context,cookie->name,strlen(cookie->name)); luck_sha256_update(&context,&separator,1U);
        luck_sha256_update(&context,cookie->value,strlen(cookie->value)); luck_sha256_update(&context,&separator,1U);
    }
    luck_sha256_final(&context,digest); luck_sha256_hex(digest,output); luck_secure_zero(digest,sizeof digest);
    return LUCK_OK;
}
