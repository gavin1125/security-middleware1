/**
 * @file soft_ecc.h
 * @brief 封装ECC基本运算接口
 * @version 1.0.0.1
 * @date 20200224
 */
#ifndef _SOFT_ECC_H
#define _SOFT_ECC_H

#include "soft_bigint.h"


#ifndef ECC_BIGINT_MAXLEN
    #define ECC_BIGINT_MAXLEN 	8
#endif

/*
x     被设置的大数指针
value 需设置的数值
在使用大数前，建议运行bigset(xx,0)
*/
void bigset(M_BIG_INT *x, unsigned int value);
//将y的值 复制给 x
void bigcpy(M_BIG_INT *x, M_BIG_INT *y);
//大数比较
int bigcmp(M_BIG_INT *a, M_BIG_INT *b);
//大数转换
unsigned int bigDigits (M_BIG_INT * a);

/*
将一个字节数组转换为大数
a      大数指针
digits 大数长度
b      字节数组  b[0]代表大数的最高字节 b[len-1]代表大数的最低字节
len    字节数组长度
*/
void ECCChar2BigInt (M_BIG_INT *a, unsigned int digits, unsigned char * b, unsigned int len);

/*
将一个大数转化为字节数组
a      字节数组
len    字节数组长度
b      大数指针       转化后b[0]存储大数的最高字节 b[len-1]存储大数的最低字节
*/
void ECCBigInt2Char (unsigned char *a, unsigned int len, M_BIG_INT *b);

//以下为ecc 函数
//点乘
void  ecc_mult(M_BIG_INT *e, M_BIG_INT *x, M_BIG_INT *y, M_BIG_INT *curv);
//点加
unsigned char ecc_add(M_BIG_INT *x1t, M_BIG_INT *y1t, M_BIG_INT *z1t, M_BIG_INT *x2t, M_BIG_INT *y2t, M_BIG_INT *z2t, M_BIG_INT *curv);
//倍点
void  ecc_double(M_BIG_INT *xt, M_BIG_INT *yt, M_BIG_INT *zt, M_BIG_INT *curv);
// 坐标转换
void  ecc_inverse(M_BIG_INT *xt, M_BIG_INT *yt, M_BIG_INT *zt, M_BIG_INT *curv);
//产生密钥对k和kG
void  generate_key_pair(M_BIG_INT *d, M_BIG_INT *x, M_BIG_INT *y, M_BIG_INT *curv);

void BigAddsBig(unsigned int *pstuA,unsigned int *pstuB,unsigned int *pstuC,unsigned short uBits);
void BigModAddBig(unsigned int *pstuA,unsigned int *pstuB,unsigned int *pstuM,unsigned int *pstuC,unsigned short uBits);
void BigModInversBig(unsigned int *pstuA,unsigned int *pstuM,unsigned int *pstuY,unsigned short uBits);
void PowMod(unsigned int *a, unsigned int *b ,unsigned int *c ,unsigned int *n,unsigned short uBits);
void BigModMulBig(unsigned int *pstuA,unsigned int *pstuB,unsigned int *pstuM,unsigned int *pstuC,unsigned short uBits);
void BigModSubBig(unsigned int *pstuA,unsigned int *pstuB,unsigned int *pstuM,unsigned int *pstuC,unsigned short uBits);
void ECC_big(unsigned char *in, unsigned char *out);

#endif

