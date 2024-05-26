// md5.h

#ifndef __MD5_H__
#define __MD5_H__


/* MD5 context. */
typedef struct
{
    unsigned int state[4];        /* state (ABCD) */
    unsigned int count[2];        /* number of bits, modulo 2^64 (lsb first) */
    unsigned char buffer[64];     /* input buffer */
} md5_context;


#ifdef __cplusplus
extern "C" {
#endif

void md5_init (md5_context *context);
void md5_update (md5_context *context, const unsigned char *input, int inputLen);
void md5_final (unsigned char digest[16], md5_context *context);

#ifdef __cplusplus
}
#endif

#endif	// __MD5_H__