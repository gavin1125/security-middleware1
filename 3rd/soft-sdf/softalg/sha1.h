// sha1.h

#ifndef __SHA1_H_INC__
#define __SHA1_H_INC__

#ifdef __cplusplus
extern "C" {
#endif


typedef struct
{
    unsigned int  h0, h1, h2, h3, h4;
    unsigned int  nblocks;
    unsigned char buf[64];
    int  count;
} sha1_context;

void sha1_init(sha1_context *hd);
void sha1_update(sha1_context *hd, const unsigned char *inbuf, int inlen);
void sha1_final(unsigned char *digest, sha1_context *hd);

#ifdef __cplusplus
}
#endif

#endif
