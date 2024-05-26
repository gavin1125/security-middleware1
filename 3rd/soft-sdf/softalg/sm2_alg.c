/**
 * @file 
 * @brief SM2算法接口
 * @author cws
 * @version 1.1
 * @date
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "soft_ecc.h"
#include "sm2_alg.h"
#include "sm3_alg.h"
#include "sha2.h"
#include "hmac_sha2.h"

//SM2曲线参数 字符类型
SM2Curve default_sm2_curve =
{
    //.p = {
    {
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    },
    //.a = {
    {
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
    },
    //.b = {
    {
        0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34, 0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
        0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92, 0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93,
    },
    //.n = {
    {
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x72, 0x03, 0xDF, 0x6B, 0x21, 0xC6, 0x05, 0x2B, 0x53, 0xBB, 0xF4, 0x09, 0x39, 0xD5, 0x41, 0x23,
    },
    //.Gx = {
    {
        0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
        0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1, 0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7,
    },
    //.Gy = {
    {
        0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
        0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40, 0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0,
    },
};

///nist p256曲线参数
SM2Curve nistp256_param = 
{
	//.p = {
	{
		0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	},
	//.a = {
	{
		0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfc,
	},
	//.b = {
	{
		0x5a,0xc6,0x35,0xd8,0xaa,0x3a,0x93,0xe7,0xb3,0xeb,0xbd,0x55,0x76,0x98,0x86,0xbc,
		0x65,0x1d,0x06,0xb0,0xcc,0x53,0xb0,0xf6,0x3b,0xce,0x3c,0x3e,0x27,0xd2,0x60,0x4b,
	},
	//.n = {
	{
		0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
		0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51,
	},
	//.Gx = {
	{
		0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,
		0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96,
	},
	//.Gy = {
	{
		0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,
		0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5,
	},
};


//SM2曲线参数 大数M_BIG_INT类型
static M_BIG_INT default_curve_bigint[7] =
{
    {8, 0, {0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE}}, //p
    {8, 0, {0xFFFFFFFC, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE}}, //a
    {8, 0, {0x4D940E93, 0xDDBCBD41, 0x15AB8F92, 0xF39789F5, 0xCF6509A7, 0x4D5A9E4B, 0x9D9F5E34, 0x28E9FA9E}}, //b
    {8, 0, {0x334C74C7, 0x715A4589, 0xF2660BE1, 0x8FE30BBF, 0x6A39C994, 0x5F990446, 0x1F198119, 0x32C4AE2C}}, //Gx
    {8, 0, {0x2139F0A0, 0x02DF32E5, 0xC62A4740, 0xD0A9877C, 0x6B692153, 0x59BDCEE3, 0xF4F6779C, 0xBC3736A2}}, //Gy
    {8, 0, {0x39D54123, 0x53BBF409, 0x21C6052B, 0x7203DF6B, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE}}	 //n
};

//static unsigned char test_random[32]={"\x9c\x1f\xbd\xa7\x0b\x5a\xdb\x42\xa5\xb0\x74\x57\x60\x59\xad\xb4\x7c\xda\x60\x24\x42\x69\xc9\xa0\x8f\x6a\x8d\xa5\xc7\x87\xd9\x17"};
static int Generate_Random(unsigned short len, unsigned char* buf)
{
    int i;
    for (i = 0; i < len; i++)
    {
        buf[i] = rand() & 0xff;
    }
    return 0;
}
static void memxor(unsigned char *w1, unsigned char *w2, unsigned int len)
{
    unsigned int i;
    for ( i = 0; i < len; i++)
    {
        w1[i] ^= w2[i];
    }
    return;
}
//检查是否全零比特串
static int CheckZero(unsigned char * buf, unsigned int len)
{
    unsigned int i, count = 0;
    for (i = 0; i < len; i++)
    {
        if (buf[i] == 0x00)
        {
            count++;
        }
    }
    if (count == len)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

#ifdef SM2_KEY_AGREE
//ZA =sm3_hash(ENTLA∥IDA∥a∥b∥Gx∥Gy∥Px∥Py)  //curv 曲线参数 p(模)  a  b    Gx  Gy  n(基点的阶) h
static void Zaf(unsigned char * IDa, unsigned short IDaL, M_BIG_INT *curv, M_BIG_INT* pxy, unsigned char *Za)
{

    SM3_CONTEXT hd;
    unsigned char inbuf[ECC_BIGINT_MAXLEN * sizeof(unsigned int)];
    unsigned short IDaLb;

    IDaLb    = IDaL * 8;
    inbuf[0] = (unsigned char)( IDaLb >> 8 );
    inbuf[1] = (unsigned char)IDaLb;

    SM3_Init(&hd);
    SM3_Update(&hd, inbuf, 2);
    SM3_Update(&hd, IDa, IDaL);


    //曲线参数
    ECCBigInt2Char (inbuf, ECC_BIGINT_MAXLEN * 4, &curv[1]); // a
    SM3_Update(&hd, inbuf, ECC_BIGINT_MAXLEN * 4);

    ECCBigInt2Char (inbuf, ECC_BIGINT_MAXLEN * 4, &curv[2]); // b
    SM3_Update(&hd, inbuf, ECC_BIGINT_MAXLEN * 4);

    ECCBigInt2Char (inbuf, ECC_BIGINT_MAXLEN * 4, &curv[3]); // Gx
    SM3_Update(&hd, inbuf, ECC_BIGINT_MAXLEN * 4);

    ECCBigInt2Char (inbuf, ECC_BIGINT_MAXLEN * 4, &curv[4]); // Gy
    SM3_Update(&hd, inbuf, ECC_BIGINT_MAXLEN * 4);

    //用户公钥
    ECCBigInt2Char (inbuf, ECC_BIGINT_MAXLEN * 4, &pxy[0]); // Px
    SM3_Update(&hd, inbuf, ECC_BIGINT_MAXLEN * 4);

    ECCBigInt2Char (inbuf, ECC_BIGINT_MAXLEN * 4, &pxy[1]); // Py
    SM3_Update(&hd, inbuf, ECC_BIGINT_MAXLEN * 4);

    SM3_Final(Za, &hd);
}

//za 长度为32字节 输出为e
static void Eaf(unsigned char * Mes, unsigned short MesL, unsigned char *Za, M_BIG_INT *e)
{
    SM3_CONTEXT hd;
    unsigned char  tmp[32];

    SM3_Init(&hd);
    SM3_Update(&hd, Za, 32);
    SM3_Update(&hd, Mes, MesL);
    SM3_Final(tmp, &hd);

    ECCChar2BigInt (e, ECC_BIGINT_MAXLEN, tmp, ECC_BIGINT_MAXLEN * 4);
}
//计算:_x1=2^w+(x1&(2^w-1))
//该函数的假设 是  该循环群的元素个数(n)的最高位与次高位不能同时为零 当同时为零时，说明该曲线的n的选取不够理想
static void _big(M_BIG_INT *_x, M_BIG_INT *x)
{
    unsigned short i, l;
    l = x->uLen;
    _x->uLen = l;
    for (i = 0; i < l / 2; i++)
    {
        _x->auValue[i] = x->auValue[i];
    }
    for (i = l / 2; i < l; i++)
    {
        _x->auValue[i] = 0;
    }
    _x->auValue[(l / 2) - 1] = _x->auValue[(l / 2) - 1] | 0x80000000;
}
static void KDFagree(M_BIG_INT *xu, M_BIG_INT *yu, unsigned char *Za, unsigned char *Zb, unsigned char * buf, unsigned int Klenbit)
{
    SM3_CONTEXT hd;
    unsigned char inbuf[256];
    unsigned int Klenbyte;
    unsigned int KlenBlock;
    unsigned int count;
    unsigned int i;

    count = 1;
    Klenbyte = (Klenbit + 7) / 8;
    KlenBlock = (Klenbyte + 31) / 32;
    ECCBigInt2Char (inbuf, ECC_BIGINT_MAXLEN * 4, xu);
    ECCBigInt2Char (inbuf + ECC_BIGINT_MAXLEN * 4, ECC_BIGINT_MAXLEN * 4, yu);
    memcpy(inbuf + ECC_BIGINT_MAXLEN * 4 * 2, Za, ECC_BIGINT_MAXLEN * 4);
    memcpy(inbuf + ECC_BIGINT_MAXLEN * 4 * 3, Zb, ECC_BIGINT_MAXLEN * 4);
    for (i = 0; i < KlenBlock; i++)
    {
        SM3_Init(&hd);
        inbuf[ECC_BIGINT_MAXLEN * 16]   = (unsigned char)(count >> 24);
        inbuf[ECC_BIGINT_MAXLEN * 16 + 1] = (unsigned char)(count >> 16);
        inbuf[ECC_BIGINT_MAXLEN * 16 + 2] = (unsigned char)(count >> 8);
        inbuf[ECC_BIGINT_MAXLEN * 16 + 3] = (unsigned char)(count);
        SM3_Update(&hd, inbuf, ECC_BIGINT_MAXLEN * 4 * 4 + 4);
        SM3_Final(buf + i * 32, &hd);
        count++;
    }
}

static void SABFagree(unsigned char tag, M_BIG_INT *xu, M_BIG_INT *yu, M_BIG_INT *x1, M_BIG_INT *y1, M_BIG_INT *x2, M_BIG_INT *y2, unsigned char *Za, unsigned char *Zb, unsigned char * buf)
{
    SM3_CONTEXT hd;
    unsigned char inbuf[256];

    SM3_Init(&hd);
    ECCBigInt2Char (inbuf, ECC_BIGINT_MAXLEN * 4, xu);
    SM3_Update(&hd, inbuf, ECC_BIGINT_MAXLEN * 4);
    SM3_Update(&hd, Za, ECC_BIGINT_MAXLEN * 4);
    SM3_Update(&hd, Zb, ECC_BIGINT_MAXLEN * 4);
    ECCBigInt2Char (inbuf, ECC_BIGINT_MAXLEN * 4, x1);
    SM3_Update(&hd, inbuf, ECC_BIGINT_MAXLEN * 4);
    ECCBigInt2Char (inbuf, ECC_BIGINT_MAXLEN * 4, y1);
    SM3_Update(&hd, inbuf, ECC_BIGINT_MAXLEN * 4);
    ECCBigInt2Char (inbuf, ECC_BIGINT_MAXLEN * 4, x2);
    SM3_Update(&hd, inbuf, ECC_BIGINT_MAXLEN * 4);
    ECCBigInt2Char (inbuf, ECC_BIGINT_MAXLEN * 4, y2);
    SM3_Update(&hd, inbuf, ECC_BIGINT_MAXLEN * 4);
    SM3_Final(buf, &hd);
    SM3_Init(&hd);
    SM3_Update(&hd, &tag, 1);
    ECCBigInt2Char (inbuf, ECC_BIGINT_MAXLEN * 4, yu);
    SM3_Update(&hd, inbuf, ECC_BIGINT_MAXLEN * 4);
    SM3_Update(&hd, buf, ECC_BIGINT_MAXLEN * 4);
    SM3_Final(buf, &hd);
}
#endif

static void C3F(M_BIG_INT *x2, M_BIG_INT *y2, unsigned char *M, unsigned int Mlenbyte, unsigned char *C3)
{
    SM3_CONTEXT hd;
    unsigned char inbuf[256];

    SM3_Init(&hd);

    ECCBigInt2Char (inbuf, ECC_BIGINT_MAXLEN * 4, x2);
    SM3_Update(&hd, inbuf, ECC_BIGINT_MAXLEN * 4);

    SM3_Update(&hd, M, Mlenbyte);
    ECCBigInt2Char (inbuf, ECC_BIGINT_MAXLEN * 4, y2);

    SM3_Update(&hd, inbuf, ECC_BIGINT_MAXLEN * 4);
    SM3_Final(C3, &hd);
}

//KDF(x2||y2,klen)
static void KDF(M_BIG_INT *x2, M_BIG_INT *y2, unsigned char *keyor, unsigned int Klenbit)
{
    SM3_CONTEXT hd;
    unsigned char inbuf[256];
    unsigned int Klenbyte;
    unsigned int KlenBlock;
    unsigned int count;
    unsigned int i;

    count = 1;
    Klenbyte =  (Klenbit + 7) / 8;
    KlenBlock = (Klenbyte + 31) / 32;

    ECCBigInt2Char (inbuf,                        ECC_BIGINT_MAXLEN * 4,   x2 );
    ECCBigInt2Char (inbuf + ECC_BIGINT_MAXLEN * 4,  ECC_BIGINT_MAXLEN * 4,  y2 );

    for (i = 0; i < KlenBlock; i++)
    {
        SM3_Init(&hd);

        //memcpy(inbuf + ECC_BIGINT_MAXLEN * 8,(unsigned char*)&count,4);
        inbuf[ECC_BIGINT_MAXLEN * 8]   = (unsigned char)(count >> 24);
        inbuf[ECC_BIGINT_MAXLEN * 8 + 1] = (unsigned char)(count >> 16);
        inbuf[ECC_BIGINT_MAXLEN * 8 + 2] = (unsigned char)(count >> 8);
        inbuf[ECC_BIGINT_MAXLEN * 8 + 3] = (unsigned char)(count);

        SM3_Update(&hd, inbuf, ECC_BIGINT_MAXLEN * 8 + 4);
        SM3_Final(keyor + i * 32, &hd);
        count++;
    }
}

void SM2_lib_init(void * cb_malloc, void * cb_free, void * cb_random)
{
    srand((unsigned int)time(NULL));//初始化随机数熵源
}

void trans_curve(SM2Curve *curve, M_BIG_INT *to)
{
#ifdef USER_CURVE
    ECCChar2BigInt (&to[0], ECC_BIGINT_MAXLEN, (unsigned char*)curve->p, ECC_BIGINT_MAXLEN * 4);
    ECCChar2BigInt (&to[1], ECC_BIGINT_MAXLEN, (unsigned char*)curve->a, ECC_BIGINT_MAXLEN * 4);
    ECCChar2BigInt (&to[2], ECC_BIGINT_MAXLEN, (unsigned char*)curve->b, ECC_BIGINT_MAXLEN * 4);
    ECCChar2BigInt (&to[3], ECC_BIGINT_MAXLEN, (unsigned char*)curve->Gx, ECC_BIGINT_MAXLEN * 4);
    ECCChar2BigInt (&to[4], ECC_BIGINT_MAXLEN, (unsigned char*)curve->Gy, ECC_BIGINT_MAXLEN * 4);
    ECCChar2BigInt (&to[5], ECC_BIGINT_MAXLEN, (unsigned char*)curve->n, ECC_BIGINT_MAXLEN * 4);
#endif
}

//签名预处理
static int DoSm3CalZa( const unsigned char *id, int idlen, SM2Curve *curve, SM2PublicKey *pub, const unsigned char *m, int mlen, unsigned char *hash )
{
    SM3_CONTEXT hd;
    unsigned short idlenbit  = idlen * 8;
    unsigned char inbuf[2];

    SM3_Init(&hd);
    inbuf[0] = (unsigned char)( idlenbit >> 8 );
    inbuf[1] = (unsigned char)idlenbit;
    SM3_Update(&hd, inbuf, 2);
    SM3_Update(&hd, id, idlen);
    SM3_Update(&hd, curve->a, 32);
    SM3_Update(&hd, curve->b, 32);
    SM3_Update(&hd, curve->Gx, 32);
    SM3_Update(&hd, curve->Gy, 32);
    SM3_Update(&hd, pub->x, 32);
    SM3_Update(&hd, pub->y, 32);
    SM3_Final(hash, &hd); //z

    SM3_Init(&hd);
    SM3_Update(&hd, hash, 32);
    SM3_Update(&hd, m, mlen);
    SM3_Final(hash, &hd); //e
    return 0;
}


int SM2_genkeypair(SM2PublicKey *publickey, SM2PrivateKey *privatekey)
{
    int ret = 0;
    SM2Curve *curv = NULL;
    M_BIG_INT cr[7];
    M_BIG_INT * pcr;
    M_BIG_INT tmpd;
    M_BIG_INT x, y;
    M_BIG_INT w;

    if ((publickey == NULL) || (privatekey == NULL))
    {
        return SM2_RES_PARAM;
    }


    pcr = default_curve_bigint;


    bigset(&tmpd, 0);
    bigset(&x, 0);
    bigset(&y, 0);

    //1.产生随机数作为私钥
    Generate_Random(32, (unsigned char*)tmpd.auValue);

    //将tmpd转换为小于阶的数  即进行一个模n的运算
    bigset(&w, 0);
    BigModAddBig(tmpd.auValue, w.auValue, pcr[5].auValue, tmpd.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* tmpd=(tmpd+0) (mod n) */
    //将转换完得小于n的tmpd再转换为字节串 以返回给调用者
    ECCBigInt2Char(privatekey->d, ECC_BIGINT_MAXLEN * 4, &tmpd);

    //2.计算kG作为公钥
    generate_key_pair(&tmpd, &x, &y, pcr);
    ECCBigInt2Char(publickey->x, ECC_BIGINT_MAXLEN * 4, &x);
    ECCBigInt2Char(publickey->y, ECC_BIGINT_MAXLEN * 4, &y);
    publickey->bits = ECC_BIGINT_MAXLEN * 4 * 8;
    privatekey->bits = ECC_BIGINT_MAXLEN * 4 * 8;

    //4、返回
    return ret;
}



int SM2_signature(SM2Curve *curve, SM2PublicKey *pub, SM2PrivateKey *priv, unsigned char *id, int idlen, unsigned char *message, int mlen, SM2Signature *value)
{
    M_BIG_INT r, s;
    M_BIG_INT d;
    PM_BIG_INT curv = default_curve_bigint;
    M_BIG_INT k;
    M_BIG_INT x1, y1;
    M_BIG_INT w;
    M_BIG_INT e;
    unsigned char digest[32] = {0}, * pdigest = NULL;
    bigset(&k, 0);
    bigset(&x1, 0);
    bigset(&y1, 0);
    bigset(&w, 0);
    bigset(&e, 0);
    bigset(&r, 0);
    bigset(&s, 0);

    //A1,A2: e值
    if (pub != NULL && id != NULL)
    {
        DoSm3CalZa(id, idlen, &default_sm2_curve, pub, message, mlen, digest);
        pdigest = digest;
    }
    else
    {
        pdigest = message;
    }
    ECCChar2BigInt (&e, ECC_BIGINT_MAXLEN, pdigest, ECC_BIGINT_MAXLEN * 4);

    //A3: 产生随机数k [1,n-1]，并计算kG
regenerate_key_pair:
    Generate_Random(32, (unsigned char*)k.auValue);

    //将k转换为小于阶的数  即进行一个模n的运算
    bigset(&w, 0);
    BigModAddBig(k.auValue, w.auValue, curv[5].auValue, k.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* k=(k+0) (mod n) */

    //A4: 计算kG=(x1,y1)
    generate_key_pair(&k, &x1, &y1, curv);

    //A5: 计算r = e + x1
    BigModAddBig(e.auValue, x1.auValue, curv[5].auValue, r.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* r=(e+x1) (mod n)*/
    // 若r=0 或  r+k=n  则返回 A3
    if (bigDigits(&r) == 0)
    {
        goto regenerate_key_pair;
    }
    BigAddsBig(r.auValue, k.auValue, w.auValue, ECC_BIGINT_MAXLEN * 4 * 8);
    if (bigcmp(&w, &curv[5]) == 0)
    {
        goto regenerate_key_pair;
    }

    //A6: 计算s
    //        1
    //  s = ------ *(k-r*da) mod n
    //      (1+da)
    // k-r*da
    ECCChar2BigInt (&d, ECC_BIGINT_MAXLEN, (unsigned char*)priv->d, ECC_BIGINT_MAXLEN * 4);
    BigModMulBig(r.auValue, d.auValue, curv[5].auValue, s.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* s=r*da (mod n) */
    BigModSubBig(k.auValue, s.auValue, curv[5].auValue, s.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* s=k-s (mod n) */

    //1+da
    bigset(&w, 1);
    BigModAddBig(d.auValue, w.auValue, curv[5].auValue, w.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w=da+1 (mod n) */

    //  1
    //------- mod n
    //(1+da)
    BigModInversBig(w.auValue, curv[5].auValue, w.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w=w^-1 (mod n) */
    BigModMulBig(s.auValue, w.auValue, curv[5].auValue, s.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* s=s*w (mod n)  */

    //若s=0则返回A3
    if (bigDigits(&s) == 0)
    {
        goto regenerate_key_pair;
    }

    //A7: 签名的结果是r和s
    ECCBigInt2Char(value->r, 32, &r);
    ECCBigInt2Char(value->s, 32, &s);

    return SM2_RES_OK;
}


int SM2_verify(SM2Curve *curve, SM2PublicKey *pub, unsigned char *id, int idlen, unsigned char *message, int mlen, SM2Signature *value)
{
    M_BIG_INT r, s;
    PM_BIG_INT curv = default_curve_bigint;//标准曲线
    M_BIG_INT pxy[2] = {0};  //用户公钥
    unsigned char digest[32] = {0}, * pdigest = NULL;
    M_BIG_INT x1, y1, z1;
    M_BIG_INT x2, y2, z2;
    M_BIG_INT u, t, e;

    bigset(&x1, 0);
    bigset(&y1, 0);
    bigset(&z1, 0);
    bigset(&x2, 0);
    bigset(&y2, 0);
    bigset(&z2, 0);
    bigset(&u, 0);
    bigset(&t, 0);
    bigset(&e, 0);
    bigset(&r, 0);
    bigset(&s, 0);

    //E值计算
    if (pub != NULL && id != NULL)
    {
        DoSm3CalZa(id, idlen, &default_sm2_curve, pub, message, mlen, digest);
        pdigest = digest;
    }
    else
    {
        pdigest = message;
    }

    //B1:
    ECCChar2BigInt (&r, ECC_BIGINT_MAXLEN, value->r, ECC_BIGINT_MAXLEN * 4);
    if (bigcmp(&r, &curv[5]) > 0)
    {
        return SM2_VRF_B1;    /* verify fail */
    }
    //B2:
    ECCChar2BigInt (&s, ECC_BIGINT_MAXLEN, value->s, ECC_BIGINT_MAXLEN * 4);
    if (bigcmp(&s, &curv[5]) > 0)
    {
        return SM2_VRF_B2;    /* verify fail */
    }

    //B3,B4: 摘要值
    ECCChar2BigInt (&e, ECC_BIGINT_MAXLEN, pdigest, ECC_BIGINT_MAXLEN * 4);
    //B5: 计算t
    BigModAddBig(r.auValue, s.auValue, curv[5].auValue, t.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* t=(r+s) (mod n) */
    if (bigcmp(&t, &curv[5]) == 0)
    {
        return SM2_VRF_B5;    /* verify fail */
    }

    //B6: [s]G+[t]Pa
    // [s]G
    bigcpy(&x2, &curv[3]); /* p2=g */
    bigcpy(&y2, &curv[4]);
    ecc_mult(&s, &x2, &y2, curv);	/* p2=s*g */

    //[t]Pa
    ECCChar2BigInt (&pxy[0], ECC_BIGINT_MAXLEN, (unsigned char*)pub->x, ECC_BIGINT_MAXLEN * 4); /* xa=xas */
    ECCChar2BigInt (&pxy[1], ECC_BIGINT_MAXLEN, (unsigned char*)pub->y, ECC_BIGINT_MAXLEN * 4); /* ya=yas */
    bigcpy(&x1, &pxy[0]);		/* p1=g */
    bigcpy(&y1, &pxy[1]);
    ecc_mult(&t, &x1, &y1, curv);	/* p1=t*p1 */

    bigset(&z1, 1);
    bigset(&z2, 1);

    ecc_add(&x1, &y1, &z1, &x2, &y2, &z2, curv);	/* p2+=p1 */
    ecc_inverse(&x2, &y2, &z2, curv);

    //B7:
    BigModAddBig(e.auValue, x2.auValue, curv[5].auValue, u.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* u=(e+x2) (mod n) */
    if (bigcmp(&u, &r) != 0)
    {
        return SM2_VRF_B7;    /* verify fail */
    }

    return SM2_RES_OK;
}
static void CalKDF(M_BIG_INT *x2, unsigned char * SharedInfo1,int SharedInfo1len, unsigned char* outbuf, int outbit)
{
	sha256_context hd;
	unsigned char data[256];
	unsigned int Klenbyte;
	unsigned int KlenBlock;
	unsigned int count;
	unsigned int i, len;
	int x2len=32;
	unsigned char x2buf[32];

	count = 1;
	Klenbyte =  (outbit+7)/8;
	KlenBlock = (Klenbyte+31)/32;

	ECCBigInt2Char (x2buf ,                        ECC_BIGINT_MAXLEN*4,   x2 );
	// data = inbuf || count[ || ShareInfo1]
	len = x2len + 4;
	memcpy(data, x2buf, x2len);
	if(SharedInfo1len > 0)
	{
		memcpy(data + len, SharedInfo1, SharedInfo1len);
		len += SharedInfo1len; 
	}
	for(i = 0; i < KlenBlock; i++)
	{
		sha256_init(&hd);

		//memcpy(inbuf + ECC_BIGINT_MAXLEN * 8,(unsigned char*)&count,4);
		data[x2len]   = (unsigned char)(count>>24);
		data[x2len+ 1] = (unsigned char)(count>>16);
		data[x2len+ 2] = (unsigned char)(count>>8);
		data[x2len+ 3] = (unsigned char)(count);

		sha256_update(&hd, data, len);
		sha256_final(outbuf + i*32, &hd);
		count++;
	}
}
unsigned char g_SharedInfo1[SM2_MAX_BITS]={0};
int g_SharedInfo1Len=0;


int SM2_public_encrypt(SM2Curve *curve, SM2PublicKey *pub, unsigned char *datain, int dlen, unsigned char *dataout, int *outlen)
{
    PM_BIG_INT curv = default_curve_bigint;
    M_BIG_INT pxy[2]  = {0};  //用户公钥
    M_BIG_INT k;
    M_BIG_INT x1, y1, x2, y2, w;
    unsigned char  keyor[MAX_CIPHER_LEN] = {0};

    bigset(&k, 0);
    bigset(&x1, 0);
    bigset(&y1, 0);

    if (dlen > MAX_CIPHER_LEN - 97)
    {
        return SM2_RES_PARAM;
    }
    //if(*outlen < dlen + 97)
    //	return SM2_RES_BUFFER;


    //A1:应先产生随机数 ke
    Generate_Random(32, (unsigned char*)k.auValue);
    k.uLen = ECC_BIGINT_MAXLEN;
    bigset(&w, 0);
    BigModAddBig(k.auValue, w.auValue, curv[5].auValue, k.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* k=(k+0) (mod n) */

    //A2: 计算C1
    generate_key_pair(&k, &x1, &y1, curv);
    dataout[0] = 0x04;
    ECCBigInt2Char(dataout + 1, 32, &x1);
    ECCBigInt2Char(dataout + 33, 32, &y1);

    //A3: 因h=1,h和点pb相乘的结果点S即pb点，这里判断若S是无穷远点，则报错并退出
    ECCChar2BigInt (&pxy[0], ECC_BIGINT_MAXLEN, (unsigned char*)pub->x, ECC_BIGINT_MAXLEN * 4);
    ECCChar2BigInt (&pxy[1], ECC_BIGINT_MAXLEN, (unsigned char*)pub->y, ECC_BIGINT_MAXLEN * 4);
    if (bigDigits(&pxy[0]) == 0)
    {
        return SM2_ENC_A3;
    }

    //A4: k*Pb 接下来计算k和点pb相乘的结果点p2
    bigcpy(&x2, &pxy[0]); //p2=pb
    bigcpy(&y2, &pxy[1]);
    ecc_mult(&k, &x2, &y2, curv);	// p2=k*pb

    //A5: KDF(x2||y2,klen)
    KDF(&x2, &y2, keyor, dlen * 8);
    //判断keyor是否全0
    if (CheckZero(keyor, dlen))
    {
        return SM2_ENC_A5;
    }

    //A6: C2=M⊕keyor
    memxor(keyor, datain, dlen);
    memcpy(dataout + 65, keyor, dlen);

    //A7: C3=Hash(x2∥M∥y2)
    C3F(&x2, &y2, datain, dlen, dataout + 65 + dlen);

    //A8: 输出：密文C=04 || C1 || C2 || C3
    *outlen = dlen + 97;

    return SM2_RES_OK;
}

int SM2_private_decrypt(SM2Curve *curve, SM2PrivateKey *priv, unsigned char *datain, int dlen, unsigned char *dataout, int *outlen)
{
    PM_BIG_INT curv = default_curve_bigint;
    M_BIG_INT d;  //用户私钥
    M_BIG_INT w, u, x1, y1;
    unsigned char keyor[MAX_CIPHER_LEN] = {0};
    unsigned char hash[32];

    bigset(&w, 0);
    bigset(&u, 3); //
    bigset(&x1, 0);
    bigset(&y1, 0);
    if (dlen > MAX_CIPHER_LEN)
    {

        return SM2_RES_PARAM;
    }
    //if(*outlen < dlen - 97)
    //	return SM2_RES_BUFFER;
    if (datain[0] != 0x04)
    {
        return SM2_DEC_DATA;
    }

    *outlen = (dlen - 97);

    //B1:解密方首先验算C1是不是曲线上的点，若不是则报错并退出
    ECCChar2BigInt(&x1, ECC_BIGINT_MAXLEN, datain + 1, ECC_BIGINT_MAXLEN * 4);
    ECCChar2BigInt(&y1, ECC_BIGINT_MAXLEN, datain + 33, ECC_BIGINT_MAXLEN * 4);
    PowMod(u.auValue, x1.auValue, u.auValue, curv[0].auValue, ECC_BIGINT_MAXLEN * 32); /* u=x1^3 (mod p) */
    BigModMulBig(curv[1].auValue, x1.auValue, curv[0].auValue, w.auValue, ECC_BIGINT_MAXLEN * 32); /* w=a*x1 (mod p) */
    BigModAddBig(u.auValue, w.auValue, curv[0].auValue, u.auValue, ECC_BIGINT_MAXLEN * 32); /* u+=w (mod p) */
    BigModAddBig(u.auValue, curv[2].auValue, curv[0].auValue, u.auValue, ECC_BIGINT_MAXLEN * 32); /* u+=b (mod p) */
    BigModMulBig(y1.auValue, y1.auValue, curv[0].auValue, w.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w=y1^2 (mod p) */
    if (bigcmp(&w, &u) != 0)
    {
        return SM2_DEC_B1;
    }

    //B2: 因h=1,h和点p1相乘的结果点S即p1点，这里判断若S是无穷远点，则报错并退出
    if (bigDigits(&y1) == 0)
    {

        return SM2_DEC_B2;
    }
    //B3: P2 = [d]C1

    ECCChar2BigInt(&d, ECC_BIGINT_MAXLEN, (unsigned char*)priv->d, ECC_BIGINT_MAXLEN * 4); /* da=das */
   
 ecc_mult(&d, &x1, &y1, curv);

    //B4:
    KDF(&x1, &y1, keyor, *outlen*8);
    if (CheckZero(keyor, *outlen))
    {

        return SM2_DEC_B4;
    }
    //B5:
    memxor(keyor, datain + 65, *outlen);
    //B6:
    C3F(&x1, &y1, keyor, *outlen, hash);

    if (memcmp(hash, datain + 65 + *outlen, 32) )
    {
        return SM2_DEC_B6; //验证摘要错误
    }
    //B7:
    memcpy(dataout, keyor, *outlen);
    return SM2_RES_OK;
}

int SM2_pubkey_check(unsigned char *pubkey)
{
	PM_BIG_INT curv = default_curve_bigint;
	M_BIG_INT w, u, x1, y1;

	bigset(&w, 0);
	bigset(&u, 3); 
	bigset(&x1, 0);
	bigset(&y1, 0);
	
	//B1:首先验算C1是不是曲线上的点，若不是则报错并退出
	ECCChar2BigInt(&x1, ECC_BIGINT_MAXLEN, pubkey, ECC_BIGINT_MAXLEN * 4);
	ECCChar2BigInt(&y1, ECC_BIGINT_MAXLEN, pubkey + 32, ECC_BIGINT_MAXLEN * 4);
	PowMod(u.auValue, x1.auValue, u.auValue, curv[0].auValue, ECC_BIGINT_MAXLEN * 32); /* u=x1^3 (mod p) */
	BigModMulBig(curv[1].auValue, x1.auValue, curv[0].auValue, w.auValue, ECC_BIGINT_MAXLEN * 32); /* w=a*x1 (mod p) */
	BigModAddBig(u.auValue, w.auValue, curv[0].auValue, u.auValue, ECC_BIGINT_MAXLEN * 32); /* u+=w (mod p) */
	BigModAddBig(u.auValue, curv[2].auValue, curv[0].auValue, u.auValue, ECC_BIGINT_MAXLEN * 32); /* u+=b (mod p) */
	BigModMulBig(y1.auValue, y1.auValue, curv[0].auValue, w.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w=y1^2 (mod p) */
	if (bigcmp(&w, &u) != 0)
	{
		return SM2_DEC_B1;
	}

	return SM2_RES_OK;
}

int SM2_signature_check(unsigned char *signature)
{
	int i;
	int r0 = 0;
	int s0 = 0;
	M_BIG_INT r, s;
	PM_BIG_INT curv = default_curve_bigint;//标准曲线
	bigset(&r, 0);
	bigset(&s, 0);

	for(i=0;i<32;i++)
	{
		if(0 != signature[i])
		{
			r0 = 1;
			break;
		}
	}

	for(i=0;i<32;i++)
	{
		if(0 != signature[i+32])
		{
			s0 = 1;
			break;
		}
	}

	if (0 == r0)
	{
		return SM2_VRF_B1;
	}
	if (0 == s0)
	{
		return SM2_VRF_B2;
	}
	//B1:
	ECCChar2BigInt (&r, ECC_BIGINT_MAXLEN, signature, ECC_BIGINT_MAXLEN * 4);
	if (bigcmp(&r, &curv[5]) > 0)
	{
		return SM2_VRF_B1;    /* verify fail */
	}
	//B2:
	ECCChar2BigInt (&s, ECC_BIGINT_MAXLEN, signature+32, ECC_BIGINT_MAXLEN * 4);
	if (bigcmp(&s, &curv[5]) > 0)
	{
		return SM2_VRF_B2;    /* verify fail */
	}

	return SM2_RES_OK;
}


int ECC_public_encrypt( ECC256Curve *curve, ECC256PublicKey *pub, unsigned char *datain, int dlen, unsigned char *dataout, int *outlen )
{
    M_BIG_INT cr[7] = {0};   //曲线参数
    M_BIG_INT pxy[2]  = {0};  //用户公钥
    unsigned char  keyor[MAX_CIPHER_LEN] = {0};
    PM_BIG_INT pcr = NULL;
    M_BIG_INT k;
    M_BIG_INT x1, y1, x2, y2, w;
	unsigned char kdfbuf[1024+32];	// EK || MK
	unsigned char* kdf = NULL;
	hmac_context hmac;

	bigset(&k, 0);
	bigset(&x1, 0);
	bigset(&y1, 0);

	if (dlen > MAX_CIPHER_LEN - 97)
	{
		return SM2_RES_PARAM;
	}

	if (dlen <= 1024)
	{
		kdf = kdfbuf;
	}
	else
	{
		kdf =(unsigned char*) malloc( dlen+32 );
		if( !kdf)
			return -1;
		memset(kdf,0x0,dlen+32);
	}

	//曲线参数设置
	if (curve == NULL)
	{
		pcr = default_curve_bigint;
	}
	else
	{
		trans_curve(curve, cr);
		pcr = cr;
	}
	//A1:应先产生随机数 ke
	Generate_Random(32, (unsigned char*)k.auValue);
	k.uLen = ECC_BIGINT_MAXLEN;
	bigset(&w, 0);
	BigModAddBig(k.auValue, w.auValue, pcr[5].auValue, k.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* k=(k+0) (mod n) */

	//A2: 计算C1
	generate_key_pair(&k, &x1, &y1, pcr);
	dataout[0] = 0x04;
	ECCBigInt2Char(dataout + 1, 32, &x1);
	ECCBigInt2Char(dataout + 33, 32, &y1);

	//A3: 因h=1,h和点pb相乘的结果点S即pb点，这里判断若S是无穷远点，则报错并退出
	ECCChar2BigInt (&pxy[0], ECC_BIGINT_MAXLEN, (unsigned char*)pub->x, ECC_BIGINT_MAXLEN * 4);
	ECCChar2BigInt (&pxy[1], ECC_BIGINT_MAXLEN, (unsigned char*)pub->y, ECC_BIGINT_MAXLEN * 4);
	if (bigDigits(&pxy[0]) == 0)
	{
		return SM2_ENC_A3;
	}

	//A4: k*Pb 接下来计算k和点pb相乘的结果点p2
	bigcpy(&x2, &pxy[0]); //p2=pb
	bigcpy(&y2, &pxy[1]);
	ecc_mult(&k, &x2, &y2, pcr);	// p2=k*pb

    //A5: KDF(Z[ || SharedInfo1]) = EK || MK 
	CalKDF(&x2,g_SharedInfo1,g_SharedInfo1Len,kdf,(dlen+32)*8);
   //A6:  EM = ENC(EK, M)
	memxor(kdf,datain,dlen);
	memcpy(dataout+65, kdf, dlen);

    //A7: D = MAC(MK, EM[ || SharedInfo2])
	//memcpy(mac, kdf, inlen);
	//if(g_shareInfo2.len > 0)
	//{
	//	memcpy(mac + 16, g_shareInfo2.szShareInfo, g_shareInfo2.len);
	//}
    hmac_init(&hmac, sha256_param(), kdf + dlen, 32);
	//hmac_sha256_finalize(&hmac, mac, inlen + shareInfo2len);
	hmac_final(kdf, &hmac);

	//A8: 输出：密文C=04 || C1 || C2 || C3
	memcpy(dataout+65+dlen, hmac.digest, 32);	
	*outlen = dlen + 97;

	return SM2_RES_OK;
}


int ECC_private_decrypt( ECC256Curve *curve, ECC256PrivateKey *priv, unsigned char *datain, int dlen, unsigned char *dataout, int *outlen )
{
    M_BIG_INT cr[7] = {0};   //曲线参数
    M_BIG_INT d;  //用户私钥
	unsigned char keyor[MAX_CIPHER_LEN] = {0};
    PM_BIG_INT pcr = NULL;
    M_BIG_INT w, u, x1, y1;
	unsigned char kdfbuf[1024+32];	// EK || MK
	unsigned char* kdf=NULL;	
	hmac_context hmac;


	bigset(&w, 0);
	bigset(&u, 3); //
	bigset(&x1, 0);
	bigset(&y1, 0);

	if (dlen > MAX_CIPHER_LEN)
	{
		return SM2_RES_PARAM;
	}
	*outlen = (dlen - 97);
	//if(*outlen < dlen - 97)
	//	return SM2_RES_BUFFER;
	if (datain[0] != 0x04)
	{
		return SM2_DEC_DATA;
	}
	if (*outlen <= 1024)
	{
		kdf = kdfbuf;
	}
	else
	{
		kdf =(unsigned char*) malloc( *outlen+32 );
		if( !kdf)
			return -1;
		memset(kdf,0x0,*outlen+32);
	}

	//曲线参数设置
	if (curve == NULL)
	{
		pcr = default_curve_bigint;
	}
	else
	{
		trans_curve(curve, cr);
		pcr = cr;
	}

	//B1:解密方首先验算C1是不是曲线上的点，若不是则报错并退出
	ECCChar2BigInt(&x1, ECC_BIGINT_MAXLEN, datain + 1, ECC_BIGINT_MAXLEN * 4);
	ECCChar2BigInt(&y1, ECC_BIGINT_MAXLEN, datain + 33, ECC_BIGINT_MAXLEN * 4);
	PowMod(u.auValue, x1.auValue, u.auValue, pcr[0].auValue, ECC_BIGINT_MAXLEN * 32); /* u=x1^3 (mod p) */
	BigModMulBig(pcr[1].auValue, x1.auValue, pcr[0].auValue, w.auValue, ECC_BIGINT_MAXLEN * 32); /* w=a*x1 (mod p) */
	BigModAddBig(u.auValue, w.auValue, pcr[0].auValue, u.auValue, ECC_BIGINT_MAXLEN * 32); /* u+=w (mod p) */
	BigModAddBig(u.auValue, pcr[2].auValue, pcr[0].auValue, u.auValue, ECC_BIGINT_MAXLEN * 32); /* u+=b (mod p) */
	BigModMulBig(y1.auValue, y1.auValue, pcr[0].auValue, w.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w=y1^2 (mod p) */
	if (bigcmp(&w, &u) != 0)
	{
		return SM2_DEC_B1;
	}

	//B2: 因h=1,h和点p1相乘的结果点S即p1点，这里判断若S是无穷远点，则报错并退出
	if (bigDigits(&y1) == 0)
	{
		return SM2_DEC_B2;
	}

	//B3: P2 = [d]C1
	ECCChar2BigInt(&d, ECC_BIGINT_MAXLEN, (unsigned char*)priv->d, ECC_BIGINT_MAXLEN * 4); /* da=das */
	ecc_mult(&d, &x1, &y1, pcr);

	//B4:
	CalKDF(&x1,g_SharedInfo1,g_SharedInfo1Len, kdf, (*outlen+32) * 8);
	//B5:
	//memcpy(mac, ciphertext + 65, msglen);
	//if(g_shareInfo2.len > 0)
	//{
	//	memcpy(mac + 16, g_shareInfo2.szShareInfo, g_shareInfo2.len);
	//}
	hmac_init(&hmac, sha256_param(), kdf + *outlen, 32);
	//hmac_sha256_finalize(&hmac, mac, msglen + shareInfo2len);
	hmac_final(datain + 65, &hmac);
	//B6:
	if(memcmp(datain + 65 + *outlen, hmac.digest, 32) != 0)
	{
		return SM2_DEC_B6;
	}
	memxor(kdf,datain + 65,*outlen);
	//B7:
	memcpy(dataout, kdf, *outlen);

	return SM2_RES_OK;
}


int ECC_private_decrypt_final( unsigned char* xybuf, unsigned char *datain, int dlen, unsigned char *dataout, int *outlen )
{
	unsigned char*  kdf = NULL;
	//unsigned char hash[32];
	unsigned char kdfbuf[1024] = { 0 };//小于1K的明文，直接使用栈空间；大于1K小于32K的明文动态申请
	M_BIG_INT x1, y1;
	hmac_context hmac;
    //hash_param *param;

	*outlen = dlen - 97;
	if (*outlen <= 1024)
	{
		kdf = kdfbuf;
	}
	else
	{
		kdf = (unsigned char*)malloc(*outlen);
		if (!kdf)
		{
			return -1;
		}
		memset(kdf, 0x0, *outlen);
	}

	bigset(&x1, 0);
	bigset(&y1, 0);

	ECCChar2BigInt(&x1, ECC_BIGINT_MAXLEN, xybuf, ECC_BIGINT_MAXLEN * 4);
	ECCChar2BigInt(&y1, ECC_BIGINT_MAXLEN, xybuf + 32, ECC_BIGINT_MAXLEN * 4);

	//B4:
	CalKDF(&x1,g_SharedInfo1,g_SharedInfo1Len, kdf, (*outlen+32) * 8);
	//B5:
	//memcpy(mac, ciphertext + 65, msglen);
	//if(g_shareInfo2.len > 0)
	//{
	//	memcpy(mac + 16, g_shareInfo2.szShareInfo, g_shareInfo2.len);
	//}
	hmac_init(&hmac, sha256_param(), kdf + *outlen, 32);
	//hmac_sha256_finalize(&hmac, mac, msglen + shareInfo2len);
	hmac_final(datain + 65, &hmac);

	//B6:
	if(memcmp(datain + 65 + *outlen, hmac.digest, 32) != 0)
	{
		return SM2_DEC_B6;
	}
	memxor(kdf,datain + 65,*outlen);
	//B7:
	memcpy(dataout, kdf, *outlen);
	if (*outlen > 1024 && kdf != NULL)
	{
		free(kdf);
	}

	return SM2_RES_OK;
}

int SM2_private_decrypt_final(unsigned char* xybuf, unsigned char *datain, int dlen, unsigned char *dataout, int *outlen)
{
    unsigned char*  keyor = NULL;
    unsigned char hash[32];
    unsigned char kdfbuf[1024] = { 0 };//小于1K的明文，直接使用栈空间；大于1K小于32K的明文动态申请
    M_BIG_INT x1, y1;

    *outlen = dlen - 97;
    if (*outlen <= 1024)
    {
        keyor = kdfbuf;
    }
    else
    {
        keyor = (unsigned char*)malloc(*outlen);
        if (!keyor)
        {
            return -1;
        }
        memset(keyor, 0x0, *outlen);
    }

    bigset(&x1, 0);
    bigset(&y1, 0);

    ECCChar2BigInt(&x1, ECC_BIGINT_MAXLEN, xybuf, ECC_BIGINT_MAXLEN * 4);
    ECCChar2BigInt(&y1, ECC_BIGINT_MAXLEN, xybuf + 32, ECC_BIGINT_MAXLEN * 4);

    //B4:
    KDF(&x1, &y1, keyor, *outlen * 8);//e
    if (CheckZero(keyor, *outlen))
    {
        return SM2_DEC_B4;
    }
    //B5:
    memxor(keyor, datain + 65, *outlen);//m

    //B6:
    C3F(&x1, &y1, keyor, *outlen, hash);//hash
    if (memcmp(hash, datain + 65 + *outlen, 32))
    {
        return SM2_DEC_B6; //验证摘要错误
    }
    memcpy(dataout, keyor, *outlen);
    if (*outlen > 1024 && keyor != NULL)
    {
        free(keyor);
    }

    return SM2_RES_OK;
}

int ECC_mult(ECC256Curve *curve, ECC256PrivateKey *k, ECC256PublicKey * P, ECC256PublicKey * Q)
{
    M_BIG_INT cr[7] = {0};   //曲线参数
    PM_BIG_INT pcr = NULL;
    M_BIG_INT bk;
    M_BIG_INT x1, y1;

    //曲线参数设置
    if (curve == NULL)
    {
        pcr = default_curve_bigint;
    }
    else
    {
        trans_curve(curve, cr);
        pcr = cr;
    }

    //运算
    ECCChar2BigInt(&bk, 8, k->d, 32);
    ECCChar2BigInt(&x1, 8, P->x, 32); //p2=pb
    ECCChar2BigInt(&y1, 8, P->y, 32);

    ecc_mult(&bk, &x1, &y1, pcr);

    ECCBigInt2Char(Q->x, 32, &x1);
    ECCBigInt2Char(Q->y, 32, &y1);

    return 0;
}

int ECC_add(ECC256Curve *curve, ECC256PublicKey *P1, ECC256PublicKey * P2, ECC256PublicKey * Q)
{
    M_BIG_INT cr[7] = {0};   //曲线参数
    PM_BIG_INT pcr = NULL;
    M_BIG_INT x1, y1, z1, x2, y2, z2;

    //曲线参数设置
    if (curve == NULL)
    {
        pcr = default_curve_bigint;
    }
    else
    {
        trans_curve(curve, cr);
        pcr = cr;
    }

    //数据转换
    ECCChar2BigInt(&x1, 8, P1->x, 32); //p2=pb
    ECCChar2BigInt(&y1, 8, P1->y, 32);
    ECCChar2BigInt(&x2, 8, P2->x, 32); //p2=pb
    ECCChar2BigInt(&y2, 8, P2->y, 32);
    bigset(&z1, 1);
    bigset(&z2, 1);

    //运算，坐标系转换
    ecc_add(&x1, &y1, &z1, &x2, &y2, &z2, pcr);	/* p2+=p1 */
    ecc_inverse(&x2, &y2, &z2, pcr);

    ECCBigInt2Char(Q->x, 32, &x2);
    ECCBigInt2Char(Q->y, 32, &y2);

    return 0;
}

/*
点压缩 取y的最后一个比特 (最低有效位)
入参： y的字节串形式，32个字节 ，y[31]为最后一个字节
*/
unsigned char  compress_y(unsigned char* y)
{
    //最后一个为1则 返回1 ，最后一个为0 则返回0
    return  (y[31] & 0x01);
}
/*
参数
IN curv 曲线参数
IN  x    x坐标 32字节，字节串形式 x[31]为最低有效字节
OUT y    y坐标 32字节，返回值为字节串形式 y[31]为最低有效字节
IN  y_lsb 点压缩形式中y的最低有效位
*/
int  SM2_decomp_xy(SM2Curve *curve, unsigned char* x, unsigned char* y, unsigned char  y_lsb)
{
    M_BIG_INT cr[7];
    M_BIG_INT * pcr = NULL;
    M_BIG_INT p_x, p_y, u, w;
    int i = 0;
    unsigned int h[ECC_BIGINT_MAXLEN], b[ECC_BIGINT_MAXLEN], d[ECC_BIGINT_MAXLEN] /* ,c[ECC_BIGINT_MAXLEN] */;

    //曲线参数设置
    if (curve == NULL)
    {
        pcr = default_curve_bigint;
    }
    else
    {
        trans_curve(curve, cr);
        pcr = cr;
    }

    bigset(&p_x, 0);
    bigset(&p_y, 0);
    bigset(&w, 0);

    ECCChar2BigInt(&p_x, ECC_BIGINT_MAXLEN, x, ECC_BIGINT_MAXLEN * 4);

    ///U=(x^3+a*x+b) modp
    bigset(&u, 3);
    PowMod(u.auValue, p_x.auValue, u.auValue, pcr[0].auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* u=x2^3 (mod p) */
    BigModMulBig(pcr[1].auValue, p_x.auValue, pcr[0].auValue, w.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w=a*x2 (mod p) */
    BigModAddBig(u.auValue, w.auValue, pcr[0].auValue, u.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* u+=w (mod p) */
    BigModAddBig(u.auValue, pcr[2].auValue, pcr[0].auValue, u.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* u+=b (mod p) */

    //模p =  4h+3
    //y = u^(h+1)mod p
    //z = y^2 mod p
    // 若 z = u 则输出y为平方根 否则返回错误

    //求h    h = c div 4 and b = c mod 4.
    memset(&d, 0, sizeof(d));
    d[0] = 4;
    BIG_Div(h, b, pcr[0].auValue, 8, d, 8);
    if (b[0] != 0x03)
    {
        //暂时不支持 非4h+3的运算
        return 1;
    }
    for (i = 1; i < ECC_BIGINT_MAXLEN; i++)
    {
        //暂时不支持 非4h+3的运算
        if (d[i] != 0)
        {
            return 1;
        }
    }
    //
    d[0] = 1;
    //h = h+1
    BIG_Add(h, h, d, 8);
    //y = u^(h+1)mod p
    PowMod(p_y.auValue, u.auValue, h, pcr[0].auValue, ECC_BIGINT_MAXLEN * 4 * 8);

    d[0] = 2;
    //w = y^2 mod p
    PowMod(w.auValue, p_y.auValue, d, pcr[0].auValue, ECC_BIGINT_MAXLEN * 4 * 8);

    //若 w = u 则输出y为平方根 否则返回错误
    if ( bigcmp(&w, &u) )
    {
        //无平方根
        return 2;
    }

    //如果 p_y.auValue[0]&0x01 ==  y_lsb 则返回y
    //否则 返回 p -y
    if ( (p_y.auValue[0] & 0x01) == y_lsb) //优先级 & 小于 ==
    {
        ECCBigInt2Char(y, ECC_BIGINT_MAXLEN * 4, &p_y);
    }
    else
    {
        BIG_Sub(p_y.auValue, pcr[0].auValue, p_y.auValue, ECC_BIGINT_MAXLEN);
        ECCBigInt2Char(y, ECC_BIGINT_MAXLEN * 4, &p_y);
    }

    return 0;
}

#ifdef SM2_KEY_AGREE
int SM2_exchange_random(SM2Curve *curve, SM2PublicKey *tpub, SM2PrivateKey *tpriv)
{
    M_BIG_INT cr[7];
    M_BIG_INT * pcr;
    M_BIG_INT tmpd;
    M_BIG_INT x, y;
    M_BIG_INT w;

    if ((tpub == NULL) || (tpriv == NULL))
    {
        return SM2_RES_PARAM;
    }

    //曲线参数设置
    if (curve == NULL)
    {
        pcr = default_curve_bigint;
    }
    else
    {
        trans_curve(curve, cr);
        pcr = cr;
    }

    bigset(&tmpd, 0);
    bigset(&x, 0);
    bigset(&y, 0);

    //1.产生随机数作为私钥
    Generate_Random(32, (unsigned char*)tmpd.auValue);

    //将tmpd转换为小于阶的数  即进行一个模n的运算
    bigset(&w, 0);
    BigModAddBig(tmpd.auValue, w.auValue, pcr[5].auValue, tmpd.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* tmpd=(tmpd+0) (mod n) */
    //将转换完得小于n的tmpd再转换为字节串 以返回给调用者
    ECCBigInt2Char(tpriv->d, ECC_BIGINT_MAXLEN * 4, &tmpd);

    //2.计算kG作为公钥
    generate_key_pair(&tmpd, &x, &y, pcr);
    ECCBigInt2Char(tpub->x, ECC_BIGINT_MAXLEN * 4, &x);
    ECCBigInt2Char(tpub->y, ECC_BIGINT_MAXLEN * 4, &y);
    tpub->bits = ECC_BIGINT_MAXLEN * 4 * 8;
    tpriv->bits = ECC_BIGINT_MAXLEN * 4 * 8;

    return 0;
}

int SM2_exchange_cale(SM2Curve *curve, SM2PrivateKey *mytpriv, SM2PublicKey *mytpub, SM2PublicKey *peertpub, unsigned char *myid, int myidlen,
                      unsigned char *peerid, int peeridlen, SM2PublicKey *mypub, SM2PrivateKey *mypriv, SM2PublicKey *peerpub, int keylen, int role,
                      unsigned char *key, ex_hash *s1, ex_hash *s2)
{
    M_BIG_INT cr[7];   //曲线参数
    M_BIG_INT * curv = NULL;
    M_BIG_INT ExApxyd[3];
    M_BIG_INT ExBpxyd[3];
    unsigned char Arxy[64];
    unsigned char Brxy[64];
    unsigned char r[32];
    M_BIG_INT _x1, _x2;
    M_BIG_INT myRx, myRy, peerRx, peerRy, ra;
    M_BIG_INT d, u, w, ta, xu, yu;
    unsigned char Za[32];
    unsigned char Zb[32];

    bigset(&_x1, 0);
    bigset(&_x2, 0);
    bigset(&d, 0);
    bigset(&u, 0);
    bigset(&w, 0);
    bigset(&ta, 0);
    bigset(&myRx, 0);
    bigset(&peerRx, 0);
    bigset(&peerRy, 0);
    bigset(&ra, 0);
    bigset(&xu, 0);
    bigset(&yu, 0);
    bigset(&myRy, 0);


    //曲线参数设置
    if (curve == NULL)
    {
        curv = default_curve_bigint;
    }
    else
    {
        trans_curve(curve, cr);
        curv = cr;
    }

    memcpy(Arxy, mytpub->x, ECC_BIGINT_MAXLEN * 4);
    memcpy(Arxy + 32, mytpub->y, ECC_BIGINT_MAXLEN * 4);
    memcpy(Brxy, peertpub->x, ECC_BIGINT_MAXLEN * 4);
    memcpy(Brxy + 32, peertpub->y, ECC_BIGINT_MAXLEN * 4);

    memcpy(r, mytpriv->d, ECC_BIGINT_MAXLEN * 4);
    //转换公钥
    ECCChar2BigInt (&ExApxyd[0], ECC_BIGINT_MAXLEN, (unsigned char*)mypub->x, ECC_BIGINT_MAXLEN * 4); /* xa=xas */
    ECCChar2BigInt (&ExApxyd[1], ECC_BIGINT_MAXLEN, (unsigned char*)mypub->y, ECC_BIGINT_MAXLEN * 4); /* ya=yas */

    ECCChar2BigInt (&ExBpxyd[0], ECC_BIGINT_MAXLEN, (unsigned char*)peerpub->x, ECC_BIGINT_MAXLEN * 4); /* xa=xas */
    ECCChar2BigInt (&ExBpxyd[1], ECC_BIGINT_MAXLEN, (unsigned char*)peerpub->y, ECC_BIGINT_MAXLEN * 4); /* ya=yas */
    //私钥
    ECCChar2BigInt (&ExApxyd[2], ECC_BIGINT_MAXLEN, (unsigned char*)mypriv->d, ECC_BIGINT_MAXLEN * 4);


    ECCChar2BigInt(&myRx, ECC_BIGINT_MAXLEN, Arxy, ECC_BIGINT_MAXLEN * 4);
    ECCChar2BigInt(&myRy, ECC_BIGINT_MAXLEN, Arxy + 32, ECC_BIGINT_MAXLEN * 4);
    ECCChar2BigInt(&peerRx, ECC_BIGINT_MAXLEN, Brxy, ECC_BIGINT_MAXLEN * 4);
    ECCChar2BigInt(&peerRy, ECC_BIGINT_MAXLEN, Brxy + 32, ECC_BIGINT_MAXLEN * 4);
    ECCChar2BigInt(&ra, ECC_BIGINT_MAXLEN, r, ECC_BIGINT_MAXLEN * 4);

    // 计算:_x1=2^w+(x1&(2^w-1))
    // _x2=2^w+(x2&(2^w-1))
    _big(&_x1, &myRx);
    _big(&_x2, &peerRx);

    /* 计算自己的：tA=(dA+_x1*rA ) mod n */
    BigModMulBig(_x1.auValue, ra.auValue, curv[5].auValue, ta.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* ta=_x1*ra (mod n) */
    BigModAddBig(ta.auValue, ExApxyd[2].auValue, curv[5].auValue, ta.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* ta+=da (mod n) */

    /* 验证RB 是否满足椭圆曲线方程 */
    bigset(&u, 3);
    PowMod(u.auValue, peerRx.auValue, u.auValue, curv[0].auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* u=x2^3 (mod p) */
    BigModMulBig(curv[1].auValue, peerRx.auValue, curv[0].auValue, w.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w=a*x2 (mod p) */
    BigModAddBig(u.auValue, w.auValue, curv[0].auValue, u.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* u+=w (mod p) */
    BigModAddBig(u.auValue, curv[2].auValue, curv[0].auValue, u.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* u+=b (mod p) */

    BigModMulBig(peerRy.auValue, peerRy.auValue, curv[0].auValue, w.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w=y2^2 (mod p) */

    if (bigcmp(&w, &u) != 0)
    {
        return 2;    // key_agrement fail
    }

    //计算 公共 椭圆曲线点U=[h*tA](PB+[_x2]RB)=(xU;yU)
    bigcpy(&xu, &peerRx);
    bigcpy(&yu, &peerRy);
    ecc_mult(&_x2, &xu, &yu, curv); // U=_x2*RB

    bigset(&w, 1); //变量借用，相当于Z    hejun
    bigset(&u, 1);
    ecc_add(&ExBpxyd[0], &ExBpxyd[1], &w, &xu, &yu, &u, curv);	// U+=PB
    ecc_inverse(&xu, &yu, &u, curv);

    ecc_mult(&ta, &xu, &yu, curv);	// U=ta*U

    if (bigDigits(&yu) == 0 )
    {
        return 3;
    }

    //ZA =sm3_hash(ENTLA∥IDA∥a∥b∥xG∥yG∥xA∥yA)
    //Zb =sm3_hash(ENTLb∥IDb∥a∥b∥xG∥yG∥xB∥yB)
    if (role == 1) //主动协商
    {
        Zaf(myid, myidlen, curv, ExApxyd, Za);
        Zaf(peerid, peeridlen, curv, ExBpxyd, Zb);
    }
    else //被动协商
    {
        Zaf(peerid, peeridlen, curv, ExBpxyd, Za);
        Zaf(myid, myidlen, curv, ExApxyd, Zb);
    }
    //计算密钥 	 计算KB =KDF(xV∥yV∥ZA∥ZB;klen)，得到协商的密钥
    KDFagree(&xu, &yu, Za, Zb, key, keylen);

    //计算 s02
    if ( role == 1)
    {
        SABFagree(0x02, &xu, &yu, &myRx, &myRy, &peerRx, &peerRy, Za, Zb, s1->data);
    }
    else
    {
        SABFagree(0x02, &xu, &yu, &peerRx, &peerRy, &myRx, &myRy, Za, Zb, s1->data);
    }
    //计算S03=Hash(0x03∥yV∥Hash(xV∥ZA∥ZB∥x1∥y1∥x2∥y2))
    if ( role == 1)
    {
        SABFagree(0x03, &xu, &yu, &myRx, &myRy, &peerRx, &peerRy, Za, Zb, s2->data);
    }
    else
    {
        SABFagree(0x03, &xu, &yu, &peerRx, &peerRy, &myRx, &myRy, Za, Zb, s2->data);
    }
    s1->len = 32;
    s2->len = 32;

    return 0;
}

int ECC_BKCalcExtPubkey(int curveType, unsigned char *fBuf, unsigned int fBufLen, unsigned char *seedPubKey, unsigned char *extPubKey)
{
	M_BIG_INT curve[7];   //曲线参数
	unsigned char info[64] = {0};
	M_BIG_INT tmpP;
	M_BIG_INT x,y,z1,z2,Ax,Ay;
	unsigned int tmpValue[16] = {0};
	unsigned int t = 0;
	unsigned int i = 0;
	unsigned int u = 0;
	int j = 0;

	bigset(&tmpP,0);
	bigset(&x,0);
	bigset(&y,0);
	bigset(&z1,0);
	bigset(&z2,0);
	bigset(&Ax,0);
	bigset(&Ay,0);

	if (0 == curveType)//SM2
	{
		trans_curve(&default_sm2_curve, curve);
	}
	else //NISTP256
	{
		trans_curve(&nistp256_param, curve);
	}

	//get tmpValue
	for (i = 0, j = fBufLen - 1; i < (fBufLen/4) && j >= 0; i++)
	{
		t = 0;
		for (u = 0; j >= 0 && u < BIG_LEN; j--, u += 8)
			t |= ((unsigned int)fBuf[j]) << u;
		tmpValue[i] = t;
	}

	for (; i < (fBufLen/4); i++)
		tmpValue[i] = 0;

	BIG_Mod(tmpP.auValue, tmpValue, fBufLen/4, curve[5].auValue, 8);

	//calc Bl
	//f1(ck, l) * G
	bigcpy(&x,&curve[3]);  /* p=G */
	bigcpy(&y,&curve[4]);

	ecc_mult(&tmpP, &x, &y, curve);/* p=d*G */

	ECCChar2BigInt(&Ax, 8, seedPubKey, 32);
	ECCChar2BigInt(&Ay, 8, seedPubKey+32, 32);
	//Bl = A + f1(ck, l) * G
	bigset(&z1,1);
	bigset(&z2,1);
	ecc_add(&Ax, &Ay, &z1, &x, &y, &z2, curve);
	ecc_inverse(&x,&y,&z2, curve);

	ECCBigInt2Char(info, 32, &x);
	memcpy(extPubKey, info, 32);
	ECCBigInt2Char(info, 32, &y);
	memcpy(extPubKey+32, info, 32);
	return 0;
}

#endif

//验算(x,y)是不是曲线上的点
int check_point_in_curve(SM2Curve *curve, unsigned char *x, unsigned char *y)
{
	M_BIG_INT cr[7] = {0};  
	PM_BIG_INT curv;
	M_BIG_INT w, u, x1, y1;

    bigset(&w,0);
	bigset(&u,0);
	bigset(&x1,0);
	bigset(&y1,0);

	if (curve == NULL)
	{
		curv = default_curve_bigint;
	}
	else
	{
		trans_curve(curve, cr);
		curv = cr;
	}

	ECCChar2BigInt(&x1, ECC_BIGINT_MAXLEN, x, ECC_BIGINT_MAXLEN * 4);
	ECCChar2BigInt(&y1, ECC_BIGINT_MAXLEN, y, ECC_BIGINT_MAXLEN * 4);
    
    bigset(&u, 3);
	PowMod(u.auValue, x1.auValue, u.auValue, curv[0].auValue, ECC_BIGINT_MAXLEN * 32); /* u=x1^3 (mod p) */
	BigModMulBig(curv[1].auValue, x1.auValue, curv[0].auValue, w.auValue, ECC_BIGINT_MAXLEN * 32); /* w=a*x1 (mod p) */
	BigModAddBig(u.auValue, w.auValue, curv[0].auValue, u.auValue, ECC_BIGINT_MAXLEN * 32); /* u+=w (mod p) */
	BigModAddBig(u.auValue, curv[2].auValue, curv[0].auValue, u.auValue, ECC_BIGINT_MAXLEN * 32); /* u+=b (mod p) */
	BigModMulBig(y1.auValue, y1.auValue, curv[0].auValue, w.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w=y1^2 (mod p) */
	if (bigcmp(&w, &u) != 0)
	{
		return SM2_RES_ERR;
	}

	return SM2_RES_OK;
}

//检查(x,y)是不是无穷远点
int check_point_infinity(unsigned char *x, unsigned char *y)
{
	M_BIG_INT pxy[2]  = {0};  //Point

	//因h=1,h和点P相乘的结果点S，这里判断若S是无穷远点，则报错并退出
	ECCChar2BigInt (&pxy[0], ECC_BIGINT_MAXLEN, x, ECC_BIGINT_MAXLEN * 4);
	ECCChar2BigInt (&pxy[1], ECC_BIGINT_MAXLEN, y, ECC_BIGINT_MAXLEN * 4);
	if (bigDigits(&pxy[0]) == 0)
	{
		return SM2_RES_ERR;
	}

	return SM2_RES_OK;
}

