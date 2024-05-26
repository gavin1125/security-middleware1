#ifndef __SHA2_H_INC__
#define __SHA2_H_INC__

#ifdef __cplusplus
extern "C" {
#endif

#define long64	long long

// sha224/sha256上下文结构
typedef struct
{
    unsigned char data[64];
    unsigned int datalen;
    unsigned int bitlen[2];
    unsigned int state[8];
} sha224_context, sha256_context;

// sha224
void sha224_init(sha224_context *ctx);
void sha224_update(sha224_context *ctx, const unsigned char* data, int len);
void sha224_final(unsigned char* digest, sha224_context *ctx);

// sha256
void sha256_init(sha256_context *ctx);
void sha256_update(sha256_context *ctx, const unsigned char* data, int len);
void sha256_final(unsigned char* digest, sha256_context *ctx);


// sha384/sha512 context
typedef struct
{
    unsigned long64 total[2]; /*!< number of bytes processed */
    unsigned long64 state[8]; /*!< intermediate digest state */
    unsigned char buffer[128]; /*!< data block being processed */
} sha384_context, sha512_context;

// sha384
void sha384_init(sha384_context *ctx);
void sha384_update(sha384_context *ctx, const unsigned char *data, int len);
void sha384_final(unsigned char* digest, sha384_context *ctx);

// sha512
void sha512_init(sha512_context *ctx);
void sha512_update(sha512_context *ctx, const unsigned char *data, int len);
void sha512_final(unsigned char* digest, sha512_context *ctx);

// sha512/224
void sha512_224_init(sha512_context *ctx);
void sha512_224_update(sha512_context *ctx, const unsigned char *data, int len);
void sha512_224_final(unsigned char* digest, sha512_context *ctx);

// sha512/256
void sha512_256_init(sha512_context *ctx);
void sha512_256_update(sha512_context *ctx, const unsigned char *data, int len);
void sha512_256_final(unsigned char* digest, sha512_context *ctx);


#ifdef __cplusplus
}
#endif

#endif

