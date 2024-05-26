/**
 * @file sm3_alg.c
 * @brief SM3算法接口
 * @author cws
 * @version 1.1
 * @date
 */
#include "sm3_alg.h"

/*
压缩主程序
参数 hd  压缩上下文
     buf 64字节长原始消息
*/
#define T0  0x79cc4519
#define T1  0x7a879d8a


#define  rol(a,x) ((a)<<(x)|(a)>>(32-(x)))

#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n,b,i)                             \
    {                                                       \
        (n) = ( (unsigned long) (b)[(i)    ] << 24 )        \
              | ( (unsigned long) (b)[(i) + 1] << 16 )        \
              | ( (unsigned long) (b)[(i) + 2] <<  8 )        \
              | ( (unsigned long) (b)[(i) + 3]       );       \
    }
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                             \
    {                                                       \
        (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
        (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
        (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
        (b)[(i) + 3] = (unsigned char) ( (n)       );       \
    }
#endif

static void transform(SM3_CONTEXT *hd, const unsigned char* buf)
{
    /*
    该处的内存占用量 应为该摘要算法的最主要部分
    */
    register XU32 t = 0;
    int  i = 0;
    XU32 w[132];
    XU32 a, b, c, d, e, f, g, h;
    XU32 ss1, ss2, tt1, tt2;

    while ( i < 16)
    {
        GET_ULONG_BE(w[i++], buf, 0);
        buf += 4;

    }

    //扩展
    for ( i = 16; i < 68; i++ )
    {

        // Wj-16^Wj-9^(Wj-3 <<< 15)
        t = w[i - 16] ^ w[i - 9] ^ rol(w[i - 3], 15);

        //P1(x) = x^(x<<<15)^(x<<<23)
        t = t ^ rol(t, 15)^rol(t, 23);

        // Wj = P1( Wj-16^Wj-9^(Wj-3 << 15) ) ^(Wj-13 << 7) ^(Wj-6)
        w[i] = t ^ rol(w[i - 13], 7)^w[i - 6];
    }

    for ( i = 0; i < 64; i++ )
    {
        w[68 + i] = w[i] ^ w[i + 4];
    }

    //压缩
    a = hd->regw[0];
    b = hd->regw[1];
    c = hd->regw[2];
    d = hd->regw[3];
    e = hd->regw[4];
    f = hd->regw[5];
    g = hd->regw[6];
    h = hd->regw[7];

    for ( i = 0; i < 16; i++ )
    {
        ss1 = rol( ( rol(a, 12) + e + rol(T0, i) ), 7);
        ss2 = ss1 ^ rol(a, 12);
        //FF = x^y^z
        //GG = x^y^z
        tt1 = (a ^ b ^ c) + d + ss2 + w[68 + i];
        tt2 = (e ^ f ^ g) + h + ss1 + w[i];
        d = c;
        c = rol(b, 9);
        b = a;
        a = tt1;
        h = g;
        g = rol(f, 19);
        f = e;
        //P0(x) = x^(x<<<9)^(x<<<17)
        e = tt2 ^ rol(tt2, 9)^rol(tt2, 17);
    }


    for ( i = 16; i < 32 ; i++ )
    {
        ss1 = rol( ( rol(a, 12) + e + rol(T1, i) ), 7);
        ss2 = ss1 ^ rol(a, 12);
        //FF = (x&y)|(x&z)|(y&z)
        //GG = (x&y)|(~x&z)
        tt1 = ( (a & b) | (a & c) | (b & c)) + d + ss2 + w[68 + i];
        tt2 = ( (e & f)   | (~e & g)  ) + h + ss1 + w[i];
        d = c;
        c = rol(b, 9);
        b = a;
        a = tt1;
        h = g;
        g = rol(f, 19);
        f = e;
        //P0(x) = x^(x<<<9)^(x<<<17)
        e = tt2 ^ rol(tt2, 9)^rol(tt2, 17);
    }
    for ( i = 32; i < 64 ; i++ )
    {
        ss1 = rol( ( rol(a, 12) + e + rol(T1, (i - 32)) ), 7);
        ss2 = ss1 ^ rol(a, 12);
        //FF = (x&y)|(x&z)|(y&z)
        //GG = (x&y)|(~x&z)
        tt1 = ( (a & b) | (a & c) | (b & c)) + d + ss2 + w[68 + i];
        tt2 = ( (e & f)   | (~e & g)  ) + h + ss1 + w[i];
        d = c;
        c = rol(b, 9);
        b = a;
        a = tt1;
        h = g;
        g = rol(f, 19);
        f = e;
        //P0(x) = x^(x<<<9)^(x<<<17)
        e = tt2 ^ rol(tt2, 9)^rol(tt2, 17);
    }

    hd->regw[0] ^= a;
    hd->regw[1] ^= b;
    hd->regw[2] ^= c;
    hd->regw[3] ^= d;
    hd->regw[4] ^= e;
    hd->regw[5] ^= f;
    hd->regw[6] ^= g;
    hd->regw[7] ^= h;

}
/*
初始化SM3 执行环境
参数 hd 入、出
*/
void SM3_Init(SM3_CONTEXT *hd)
{
    //IV 0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e
    hd->regw[0] = 0x7380166f;
    hd->regw[1] = 0x4914b2b9;
    hd->regw[2] = 0x172442d7;
    hd->regw[3] = 0xda8a0600;
    hd->regw[4] = 0xa96f30bc;
    hd->regw[5] = 0x163138aa;
    hd->regw[6] = 0xe38dee4d;
    hd->regw[7] = 0xb0fb0e4e;

    hd->count   = 0;
    hd->nblocks = 0;
}

/*
对消息进行摘要运算
如消息有剩余 参加下次运算
*/
void SM3_Update(SM3_CONTEXT *hd, const unsigned char *inbuf, int inlen)
{
    if ( hd->count == 64 )
    {
        transform( hd, hd->buf );
        hd->count = 0;
        hd->nblocks++;
    }

    if ( !inbuf) //该句多余?
    {
        return ;
    }
    if ( hd->count )
    {
        for ( ; inlen && hd->count < 64; inlen-- )
        {
            hd->buf[hd->count++] = *inbuf++;
        }
        SM3_Update( hd, 0, 0 );
        if ( !inlen )
        {
            return;
        }
    }

    while ( inlen >= 64 )
    {
        transform( hd, inbuf );
        hd->count = 0;
        hd->nblocks++;
        inlen -= 64;
        inbuf += 64;
    }
    for ( ; inlen && hd->count < 64; inlen-- )
    {
        hd->buf[hd->count++] = *inbuf++;
    }
}


void SM3_Final(unsigned char *digest, SM3_CONTEXT *hd)
{
    XU64 t;
    XU32 msb, lsb;
    int i = 0;


    SM3_Update(hd, 0, 0); /* flush */;

    t = hd->nblocks;
    /* multiply by 64 to make a byte count */
    lsb = (XU32)(t << 6);
    msb = (XU32)(t >> 26);
    /* add the count */
    t = lsb;
    if ( (lsb += hd->count) < t )
    {
        msb++;
    }
    /* multiply by 8 to make a bit count */
    t = lsb;
    lsb <<= 3;
    msb <<= 3;
    msb |= t >> 29;

    if ( hd->count < 56 )  /* enough room */
    {
        hd->buf[hd->count++] = 0x80; /* pad */
        while ( hd->count < 56 )
        {
            hd->buf[hd->count++] = 0;    /* pad */
        }
    }
    else   /* need one extra block */
    {
        hd->buf[hd->count++] = 0x80; /* pad character */
        while ( hd->count < 64 )
        {
            hd->buf[hd->count++] = 0;
        }
        SM3_Update(hd, 0, 0);  /* flush */;

        while (hd->count < 56)
        {
            hd->buf[hd->count++] = 0;    /* fill next block with zeroes */
        }
        hd->count = 0;
    }
    /* append the 64 bit count */
    hd->buf[56] = msb >> 24;
    hd->buf[57] = msb >> 16;
    hd->buf[58] = msb >>  8;
    hd->buf[59] = msb	   ;
    hd->buf[60] = lsb >> 24;
    hd->buf[61] = lsb >> 16;
    hd->buf[62] = lsb >>  8;
    hd->buf[63] = lsb	   ;
    transform( hd, hd->buf );

    for (i = 0; i < 8; i++)
    {
        PUT_ULONG_BE(*(hd->regw + i), digest, 0);
        digest += 4;
    }
}

