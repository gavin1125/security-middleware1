// sha256.c

#include <stdio.h>
#include <string.h>
#include "sha2.h"

#define UL64(x) x##ULL

// DBL_INT_ADD treats two unsigned ints a and b as one 64-bit integer and adds c to it
#define DBL_INT_ADD(a,b,c) if (a > 0xffffffff - (c)) ++b; a += c;
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))



unsigned int k[64] =
{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


void sha256_transform(sha256_context *ctx, unsigned char data[])
{
    unsigned int a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4)
    {
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    }
    for ( ; i < 64; ++i)
    {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i)
    {
        t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void sha224_init(sha224_context *ctx)
{
    ctx->datalen = 0;
    ctx->bitlen[0] = 0;
    ctx->bitlen[1] = 0;
    ctx->state[0] = 0xc1059ed8;
    ctx->state[1] = 0x367cd507;
    ctx->state[2] = 0x3070dd17;
    ctx->state[3] = 0xf70e5939;
    ctx->state[4] = 0xffc00b31;
    ctx->state[5] = 0x68581511;
    ctx->state[6] = 0x64f98fa7;
    ctx->state[7] = 0xbefa4fa4;
}

void sha224_update(sha224_context *ctx, const unsigned char* data, int len)
{
    sha256_update(ctx, data, len);
}

void sha224_final(unsigned char* digest, sha224_context *ctx)
{
    unsigned char buf[32];

    sha256_final(buf, ctx);
    memcpy(digest, buf, 28);
}

void sha256_init(sha256_context *ctx)
{
    ctx->datalen = 0;
    ctx->bitlen[0] = 0;
    ctx->bitlen[1] = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

void sha256_update(sha256_context *ctx, const unsigned char* data, int len)
{
    int i;

    for (i = 0; i < len; ++i)
    {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64)
        {
            sha256_transform(ctx, ctx->data);
            DBL_INT_ADD(ctx->bitlen[0], ctx->bitlen[1], 512);
            ctx->datalen = 0;
        }
    }
}

void sha256_final(unsigned char* digest, sha256_context *ctx)
{
    unsigned int i;

    i = ctx->datalen;

    // Pad whatever data is left in the buffer.
    if (ctx->datalen < 56)
    {
        ctx->data[i++] = 0x80;
        while (i < 56)
        {
            ctx->data[i++] = 0x00;
        }
    }
    else
    {
        ctx->data[i++] = 0x80;
        while (i < 64)
        {
            ctx->data[i++] = 0x00;
        }
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    // Append to the padding the total message's length in bits and transform.
    DBL_INT_ADD(ctx->bitlen[0], ctx->bitlen[1], ctx->datalen * 8);
    ctx->data[63] = ctx->bitlen[0];
    ctx->data[62] = ctx->bitlen[0] >> 8;
    ctx->data[61] = ctx->bitlen[0] >> 16;
    ctx->data[60] = ctx->bitlen[0] >> 24;
    ctx->data[59] = ctx->bitlen[1];
    ctx->data[58] = ctx->bitlen[1] >> 8;
    ctx->data[57] = ctx->bitlen[1] >> 16;
    ctx->data[56] = ctx->bitlen[1] >> 24;
    sha256_transform(ctx, ctx->data);

    // Since this implementation uses little endian byte ordering and SHA uses big endian,
    // reverse all the bytes when copying the final state to the output hash.
    for (i = 0; i < 4; ++i)
    {
        digest[i]    = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
        digest[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
        digest[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
        digest[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
        digest[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
        digest[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
        digest[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
        digest[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////
// sha384, sha512

/*
* 64-bit integer manipulation macros (big endian)
*/
#ifndef GET_UINT64_BE
#define GET_UINT64_BE(n,b,i) \
    { \
        (n) = ( (unsigned long64) (b)[(i) ] << 56 ) \
              | ( (unsigned long64) (b)[(i) + 1] << 48 ) \
              | ( (unsigned long64) (b)[(i) + 2] << 40 ) \
              | ( (unsigned long64) (b)[(i) + 3] << 32 ) \
              | ( (unsigned long64) (b)[(i) + 4] << 24 ) \
              | ( (unsigned long64) (b)[(i) + 5] << 16 ) \
              | ( (unsigned long64) (b)[(i) + 6] << 8 ) \
              | ( (unsigned long64) (b)[(i) + 7] ); \
    }
#endif

#ifndef PUT_UINT64_BE
#define PUT_UINT64_BE(n,b,i) \
    { \
        (b)[(i) ] = (unsigned char) ( (n) >> 56 ); \
        (b)[(i) + 1] = (unsigned char) ( (n) >> 48 ); \
        (b)[(i) + 2] = (unsigned char) ( (n) >> 40 ); \
        (b)[(i) + 3] = (unsigned char) ( (n) >> 32 ); \
        (b)[(i) + 4] = (unsigned char) ( (n) >> 24 ); \
        (b)[(i) + 5] = (unsigned char) ( (n) >> 16 ); \
        (b)[(i) + 6] = (unsigned char) ( (n) >> 8 ); \
        (b)[(i) + 7] = (unsigned char) ( (n) ); \
    }
#endif

static const unsigned char sha4_padding[128] =
{
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
* Round constants
*/
static const unsigned long64 K[80] =
{
    UL64(0x428A2F98D728AE22), UL64(0x7137449123EF65CD),
    UL64(0xB5C0FBCFEC4D3B2F), UL64(0xE9B5DBA58189DBBC),
    UL64(0x3956C25BF348B538), UL64(0x59F111F1B605D019),
    UL64(0x923F82A4AF194F9B), UL64(0xAB1C5ED5DA6D8118),
    UL64(0xD807AA98A3030242), UL64(0x12835B0145706FBE),
    UL64(0x243185BE4EE4B28C), UL64(0x550C7DC3D5FFB4E2),
    UL64(0x72BE5D74F27B896F), UL64(0x80DEB1FE3B1696B1),
    UL64(0x9BDC06A725C71235), UL64(0xC19BF174CF692694),
    UL64(0xE49B69C19EF14AD2), UL64(0xEFBE4786384F25E3),
    UL64(0x0FC19DC68B8CD5B5), UL64(0x240CA1CC77AC9C65),
    UL64(0x2DE92C6F592B0275), UL64(0x4A7484AA6EA6E483),
    UL64(0x5CB0A9DCBD41FBD4), UL64(0x76F988DA831153B5),
    UL64(0x983E5152EE66DFAB), UL64(0xA831C66D2DB43210),
    UL64(0xB00327C898FB213F), UL64(0xBF597FC7BEEF0EE4),
    UL64(0xC6E00BF33DA88FC2), UL64(0xD5A79147930AA725),
    UL64(0x06CA6351E003826F), UL64(0x142929670A0E6E70),
    UL64(0x27B70A8546D22FFC), UL64(0x2E1B21385C26C926),
    UL64(0x4D2C6DFC5AC42AED), UL64(0x53380D139D95B3DF),
    UL64(0x650A73548BAF63DE), UL64(0x766A0ABB3C77B2A8),
    UL64(0x81C2C92E47EDAEE6), UL64(0x92722C851482353B),
    UL64(0xA2BFE8A14CF10364), UL64(0xA81A664BBC423001),
    UL64(0xC24B8B70D0F89791), UL64(0xC76C51A30654BE30),
    UL64(0xD192E819D6EF5218), UL64(0xD69906245565A910),
    UL64(0xF40E35855771202A), UL64(0x106AA07032BBD1B8),
    UL64(0x19A4C116B8D2D0C8), UL64(0x1E376C085141AB53),
    UL64(0x2748774CDF8EEB99), UL64(0x34B0BCB5E19B48A8),
    UL64(0x391C0CB3C5C95A63), UL64(0x4ED8AA4AE3418ACB),
    UL64(0x5B9CCA4F7763E373), UL64(0x682E6FF3D6B2B8A3),
    UL64(0x748F82EE5DEFB2FC), UL64(0x78A5636F43172F60),
    UL64(0x84C87814A1F0AB72), UL64(0x8CC702081A6439EC),
    UL64(0x90BEFFFA23631E28), UL64(0xA4506CEBDE82BDE9),
    UL64(0xBEF9A3F7B2C67915), UL64(0xC67178F2E372532B),
    UL64(0xCA273ECEEA26619C), UL64(0xD186B8C721C0C207),
    UL64(0xEADA7DD6CDE0EB1E), UL64(0xF57D4F7FEE6ED178),
    UL64(0x06F067AA72176FBA), UL64(0x0A637DC5A2C898A6),
    UL64(0x113F9804BEF90DAE), UL64(0x1B710B35131C471B),
    UL64(0x28DB77F523047D84), UL64(0x32CAAB7B40C72493),
    UL64(0x3C9EBE0A15C9BEBC), UL64(0x431D67C49C100D4C),
    UL64(0x4CC5D4BECB3E42B6), UL64(0x597F299CFC657E2A),
    UL64(0x5FCB6FAB3AD6FAEC), UL64(0x6C44198C4A475817)
};

static void sha4_process(sha512_context *ctx, const unsigned char data[128])
{
    int i;
    unsigned long64 temp1, temp2, W[80];
    unsigned long64 A, B, C, D, E, F, G, H;

#define SHR(x,n) (x >> n)
#define ROTR(x,n) (SHR(x,n) | (x << (64 - n)))

#define S0(x) (ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7))
#define S1(x) (ROTR(x,19) ^ ROTR(x,61) ^ SHR(x, 6))

#define S2(x) (ROTR(x,28) ^ ROTR(x,34) ^ ROTR(x,39))
#define S3(x) (ROTR(x,14) ^ ROTR(x,18) ^ ROTR(x,41))

#define F0(x,y,z) ((x & y) | (z & (x | y)))
#define F1(x,y,z) (z ^ (x & (y ^ z)))

#define P(a,b,c,d,e,f,g,h,x,K) \
    { \
        temp1 = h + S3(e) + F1(e,f,g) + K + x; \
        temp2 = S2(a) + F0(a,b,c); \
        d += temp1; h = temp1 + temp2; \
    }

    for ( i = 0; i < 16; i++ )
    {
        GET_UINT64_BE( W[i], data, i << 3 );
    }

    for ( ; i < 80; i++ )
    {
        W[i] = S1(W[i - 2]) + W[i - 7] +
               S0(W[i - 15]) + W[i - 16];
    }

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    F = ctx->state[5];
    G = ctx->state[6];
    H = ctx->state[7];
    i = 0;

    do
    {
        P( A, B, C, D, E, F, G, H, W[i], K[i] );
        i++;
        P( H, A, B, C, D, E, F, G, W[i], K[i] );
        i++;
        P( G, H, A, B, C, D, E, F, W[i], K[i] );
        i++;
        P( F, G, H, A, B, C, D, E, W[i], K[i] );
        i++;
        P( E, F, G, H, A, B, C, D, W[i], K[i] );
        i++;
        P( D, E, F, G, H, A, B, C, W[i], K[i] );
        i++;
        P( C, D, E, F, G, H, A, B, W[i], K[i] );
        i++;
        P( B, C, D, E, F, G, H, A, W[i], K[i] );
        i++;
    } while ( i < 80 );

    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
    ctx->state[4] += E;
    ctx->state[5] += F;
    ctx->state[6] += G;
    ctx->state[7] += H;
}

void sha384_init(sha384_context *ctx)
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    ctx->state[0] = UL64(0xCBBB9D5DC1059ED8);
    ctx->state[1] = UL64(0x629A292A367CD507);
    ctx->state[2] = UL64(0x9159015A3070DD17);
    ctx->state[3] = UL64(0x152FECD8F70E5939);
    ctx->state[4] = UL64(0x67332667FFC00B31);
    ctx->state[5] = UL64(0x8EB44A8768581511);
    ctx->state[6] = UL64(0xDB0C2E0D64F98FA7);
    ctx->state[7] = UL64(0x47B5481DBEFA4FA4);
}

void sha384_update(sha384_context *ctx, const unsigned char* data, int len)
{
    sha512_update(ctx, data, len);
}

void sha384_final(unsigned char* digest, sha384_context *ctx)
{
    unsigned char buf[64];

    sha512_final(buf, ctx);
    memcpy(digest, buf, 48);
}

// sha512 context setup
void sha512_init(sha512_context *ctx)
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    ctx->state[0] = UL64(0x6A09E667F3BCC908);
    ctx->state[1] = UL64(0xBB67AE8584CAA73B);
    ctx->state[2] = UL64(0x3C6EF372FE94F82B);
    ctx->state[3] = UL64(0xA54FF53A5F1D36F1);
    ctx->state[4] = UL64(0x510E527FADE682D1);
    ctx->state[5] = UL64(0x9B05688C2B3E6C1F);
    ctx->state[6] = UL64(0x1F83D9ABFB41BD6B);
    ctx->state[7] = UL64(0x5BE0CD19137E2179);
}

// sha512 process buffer
void sha512_update(sha512_context *ctx, const unsigned char *data, int len)
{
    int fill;
    unsigned int left;

    if ( len <= 0 )
    {
        return;
    }

    left = (unsigned int) (ctx->total[0] & 0x7F);
    fill = 128 - left;

    ctx->total[0] += (unsigned long64) len;

    if ( ctx->total[0] < (unsigned long64) len )
    {
        ctx->total[1]++;
    }

    if ( left && len >= fill )
    {
        memcpy( (void *) (ctx->buffer + left),
                (void *) data, fill );
        sha4_process( ctx, ctx->buffer );
        data += fill;
        len -= fill;
        left = 0;
    }

    while ( len >= 128 )
    {
        sha4_process( ctx, data );
        data += 128;
        len -= 128;
    }

    if ( len > 0 )
    {
        memcpy( (void *) (ctx->buffer + left),
                (void *) data, len );
    }
}

// sha-512 final digest
void sha512_final(unsigned char* digest, sha512_context *ctx)
{
    int last, padn;
    unsigned long64 high, low;
    unsigned char msglen[16];

    high = ( ctx->total[0] >> 61 )
           | ( ctx->total[1] << 3 );
    low = ( ctx->total[0] << 3 );

    PUT_UINT64_BE( high, msglen, 0 );
    PUT_UINT64_BE( low, msglen, 8 );

    last = (int)(ctx->total[0] & 0x7F);
    padn = ( last < 112 ) ? ( 112 - last ) : ( 240 - last );

    sha512_update( ctx, (unsigned char *) sha4_padding, padn );
    sha512_update( ctx, msglen, 16 );

    PUT_UINT64_BE( ctx->state[0], digest, 0 );
    PUT_UINT64_BE( ctx->state[1], digest, 8 );
    PUT_UINT64_BE( ctx->state[2], digest, 16 );
    PUT_UINT64_BE( ctx->state[3], digest, 24 );
    PUT_UINT64_BE( ctx->state[4], digest, 32 );
    PUT_UINT64_BE( ctx->state[5], digest, 40 );
    PUT_UINT64_BE( ctx->state[6], digest, 48 );
    PUT_UINT64_BE( ctx->state[7], digest, 56 );
}


// sha512/t
static void sha512_t_init(sha512_context *ctx)
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    ctx->state[0] = UL64(0xCFAC43C256196CAD);
    ctx->state[1] = UL64(0x1EC20B20216F029E);
    ctx->state[2] = UL64(0x99CB56D75B315D8E);
    ctx->state[3] = UL64(0x00EA509FFAB89354);
    ctx->state[4] = UL64(0xF4ABF7DA08432774);
    ctx->state[5] = UL64(0x3EA0CD298E9BC9BA);
    ctx->state[6] = UL64(0xBA267C0E5EE418CE);
    ctx->state[7] = UL64(0xFE4568BCB6DB84DC);
}

// sha512/224
void sha512_224_init(sha512_context *ctx)
{
    const char* data = "SHA-512/224";
    int len = (int)strlen(data);
    unsigned char buf[64];

    sha512_t_init(ctx);
    sha512_update(ctx, data, len);
    sha512_final(buf, ctx);

    ctx->total[0] = 0;
    ctx->total[1] = 0;
}

void sha512_224_update(sha512_context *ctx, const unsigned char *data, int len)
{
    sha512_update(ctx, data, len);
}

void sha512_224_final(unsigned char* digest, sha512_context *ctx)
{
    unsigned char buf[64];

    sha512_final(buf, ctx);
    memcpy(digest, buf, 28);
}

// sha512/256
void sha512_256_init(sha512_context *ctx)
{
    const char* data = "SHA-512/256";
    int len = (int)strlen(data);
    unsigned char buf[64];

    sha512_t_init(ctx);
    sha512_update(ctx, data, len);
    sha512_final(buf, ctx);

    ctx->total[0] = 0;
    ctx->total[1] = 0;
}

void sha512_256_update(sha512_context *ctx, const unsigned char *data, int len)
{
    sha512_update(ctx, data, len);
}

void sha512_256_final(unsigned char* digest, sha512_context *ctx)
{
    unsigned char buf[64];

    sha512_final(buf, ctx);
    memcpy(digest, buf, 32);
}

