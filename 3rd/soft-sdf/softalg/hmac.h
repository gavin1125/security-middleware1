// hmac.h

#ifndef __HMAC_H_INC__
#define __HMAC_H_INC__

#include "sha1.h"
#include "sha2.h"
//#include "sha3.h"

#define MAX_DIGEST_SIZE		128
#define MAX_KEY_SIZE		1024

#define MAX_CONTEXT_SIZE	1024

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*sha_init)(void *hd);
typedef void (*sha_update)(void *hd, const unsigned char *inbuf, int inlen);
typedef void (*sha_final)(unsigned char *digest, void *hd);

// hash param
typedef struct
{
    int mdlen;	// 输出大小
    int bklen;	// 块大小

    // hash
    sha_init init;
    sha_update update;
    sha_final final;
} hash_param;

// hmac context
typedef struct
{
    unsigned char	digest[MAX_DIGEST_SIZE];
    unsigned char	key[MAX_KEY_SIZE];

    const hash_param* param;
    unsigned char	ctx[MAX_CONTEXT_SIZE];	// hash context
} hmac_context;

void hmac_init(hmac_context *hmac, const hash_param* param, const unsigned char *key, int length);
void hmac_update(hmac_context *hmac, const void *data, int len);
void hmac_final(void *mac, hmac_context *hmac);

#ifdef __cplusplus
}
#endif

#endif
