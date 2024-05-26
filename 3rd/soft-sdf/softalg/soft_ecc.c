#include <string.h>
#include <stdio.h>
#include "soft_ecc.h"
#include "sm3_alg.h"  //sm3头文件


/* Returns the significant length of a in digits. */
unsigned int bigDigits (M_BIG_INT * a)
{
    unsigned int digits;
    digits = a->uLen;
    if (digits)
    {
        digits--;
        do
        {
            if (a->auValue[digits])
            {
                break;
            }
        } while (digits--);

        return (digits + 1);
    }
    return (digits);
}

/* Returns the significant length of a in bits, where a is a digit. */

static  unsigned int bigDigitBits (unsigned int a)
{
    unsigned int i;

    for (i = 0; i < BIG_LEN; i++, a >>= 1)
        if (a == 0)
        {
            break;
        }

    return (i);
}

static unsigned int bigBits (M_BIG_INT *a)
{
    unsigned int digits;
    if ((digits = bigDigits (a)) == 0)
    {
        return (0);
    }
    return ((digits - 1) * BIG_LEN + bigDigitBits (a->auValue[digits - 1]));
}

static unsigned int bigGetBits (M_BIG_INT *a, unsigned int i)
{
    return a->auValue[i / BIG_LEN] & (1 << (i % BIG_LEN));
}

void bigset(M_BIG_INT *x, unsigned int value)
{
    unsigned int i;
    x->uLen = ECC_BIGINT_MAXLEN;
    x->auValue[0] = value;
    for (i = 1; i < ECC_BIGINT_MAXLEN; i++)
    {
        x->auValue[i] = 0;
    }
}

void bigcpy(M_BIG_INT *x, M_BIG_INT *y)
{
    unsigned int i;
    x->uLen = y->uLen;
    for (i = 0; i < y->uLen; i++)
    {
        x->auValue[i] = y->auValue[i];
    }
}

/* Returns sign of a - b. */
int bigcmp(M_BIG_INT *a, M_BIG_INT *b)
{
    unsigned int digits;
    digits = a->uLen;
    if (digits)
    {
        do
        {
            digits--;
            if ( a->auValue[digits] > b->auValue[digits] )
            {
                return (1);
            }
            if ( a->auValue[digits] < b->auValue[digits] )
            {
                return (-1);
            }
        } while (digits);
    }
    return (0);
}

//Y = (A) / 2 要实现
BIG_INT BigSHRAddsBig(unsigned int *pstuA,unsigned int *pstuC,unsigned short uBits)
{
	BIG_INT m=0;

	m = BIG_RShift(pstuC,pstuA,1,uBits/32);

	return m;
}

//Y = A + B 要实现
void BigAddsBig(unsigned int *pstuA,unsigned int *pstuB,unsigned int *pstuC,unsigned short uBits)
{
	/* BIG_INT m = */ BIG_Add(pstuC,pstuA,pstuB,uBits/32);
}

//Y = A + B mod M 要实现
void BigModAddBig(unsigned int *pstuA,unsigned int *pstuB,unsigned int *pstuM,unsigned int *pstuC,unsigned short uBits)
{
	unsigned int max_256[9] ={0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000};

	BIG_INT m = BIG_Add(max_256,pstuA,pstuB,uBits/32);
	if(m) //有进位位
	{
		max_256[8]= m;
		BIG_Mod(pstuC,max_256,9,pstuM,8);
		return ;
	}
	BIG_Mod(pstuC,max_256,8,pstuM,8);
	return ;
} 

//Y = A - B mod M 要实现
void BigModSubBig(unsigned int *pstuA,unsigned int *pstuB,unsigned int *pstuM,unsigned int *pstuC,unsigned short uBits)
{
	unsigned int t[8]={0};
	unsigned int t2[8]={0};
	if (  BIG_Cmp(pstuA,pstuB,uBits/32) == 1 )  //a > b
	{
		BIG_Sub(t,pstuA,pstuB,uBits/32);
		BIG_Mod(pstuC,t,uBits/32,pstuM,uBits/32);
	}
	else
	{
		// a < b
		BIG_Sub(t,pstuB,pstuA,uBits/32);         // b-a
		BIG_Mod(t2,t,uBits/32,pstuM,uBits/32);   // t2 = (b-a)mod m
		BIG_Sub(pstuC,pstuM,t2,uBits/32);  //   pstuC=m-t2
	}
} 
//Y = A * B mod M 要实现
void BigModMulBig(unsigned int *pstuA,unsigned int *pstuB,unsigned int *pstuM,unsigned int *pstuC,unsigned short uBits)
{
	BIG_ModMult(pstuC,pstuA,pstuB,pstuM,uBits/32);
}
// a = b ^ c mod n 要实现
void PowMod(unsigned int *a, unsigned int *b ,unsigned int *c ,unsigned int *n,unsigned short uBits)
{
	BIG_ModExp(a,b,c,uBits/32,n,uBits/32);
}
//Y = 1 / A mod M 要实现
void BigModInversBig(unsigned int *pstuA,unsigned int *pstuM,unsigned int *pstuY,unsigned short uBits)
{
	BIG_ModInv(pstuY,pstuA,pstuM,uBits/32);
} 

/*
e  乘数
x ,y 被乘点
curv 曲线参数 p(模)  a  b    Gx  Gy  n(基点的阶) h(曲线元素个数/基于该基点的群元素)

*/
void ecc_mult(M_BIG_INT *e, M_BIG_INT *x, M_BIG_INT *y, M_BIG_INT *curv)
/* 计算大数和点的乘法(x2,y2)=e*(x1,y1) */
{
    /* 需要如下局部变量： */
    unsigned int i;
    M_BIG_INT z;
    M_BIG_INT x1, y1, z1;
    M_BIG_INT c, d;

    bigset(&z, 0);
    bigset(&x1, 0);
    bigset(&y1, 0);
    bigset(&z1, 0);
    bigset(&c, 0);
    bigset(&d, 0);

    if (bigDigits(e) == 0)   /* multiplied by 0 */
    {
        bigset(x, 0);   /* 设置结果为无穷远点 */
        bigset(y, 0);
        return;
    }
    bigcpy(&x1, x); /* p1=p2 */
    bigcpy(&y1, y);

    bigset(&z1, 1); /* 初始化z值 */
    bigset(&z, 1);

    if (bigBits(e) == 1)         /* if e=1,then p2=p1 */
    {
        return;
    }

    bigcpy(&c, e); /* c=e */


    i = bigBits(&c) - 1;
    for (; i > 0; i--)
    {
        ecc_double(x, y, &z, curv);        /* p=2*p */
        if (bigGetBits(&c, i - 1))
        {
            if (!(ecc_add(&x1, &y1, &z1, x, y, &z, curv)))
            {
                return;
            }
        }
    }
    ecc_inverse(x, y, &z, curv);


    return;
}
//curv 曲线参数 p(模)  a  b    Gx  Gy  n(基点的阶) h
unsigned char ecc_add(M_BIG_INT *x1t, M_BIG_INT *y1t, M_BIG_INT *z1t, M_BIG_INT *x2t, M_BIG_INT *y2t, M_BIG_INT *z2t, M_BIG_INT *curv)
{
    /* add two points on the current ecurve:  p2+=p1;   */

    /* 需要如下局部变量： */
    M_BIG_INT w1, w2, w3, w4, w5, w6, p;
    M_BIG_INT *x1, *y1, *z1, *x2, *y2, *z2;

    x1 = x1t;
    y1 = y1t;
    z1 = z1t;
    x2 = x2t;
    y2 = y2t;
    z2 = z2t;

    bigset(&w1, 0);
    bigset(&w2, 0);
    bigset(&w3, 0);
    bigset(&w4, 0);
    bigset(&w5, 0);
    bigset(&w6, 0);
    bigcpy(&p, &curv[0]);

    /* 这里开始是雅可比加重射影坐标的情况 */
    /* 计算和z2相关的w1和w2 */
    BigModMulBig(z2->auValue, z2->auValue, p.auValue, w6.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w6=z2^2 (mod p) */
    BigModMulBig(x1->auValue, w6.auValue, p.auValue, w1.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w1=x1*z2^2 (mod p) */
    BigModMulBig(w6.auValue, z2->auValue, p.auValue, w6.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w6=z2^3 (mod p) */
    BigModMulBig(w6.auValue, y1->auValue, p.auValue, w2.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w2=y1*z2^3 (mod p) */

    /* 这里计算和z1相关的w4和w5 */
    BigModMulBig(z1->auValue, z1->auValue, p.auValue, w6.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w6=z1^2 (mod p) */
    BigModMulBig(x2->auValue, w6.auValue, p.auValue, w4.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w4=x2*z1^2 (mod p) */
    BigModMulBig(w6.auValue, z1->auValue, p.auValue, w6.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w6=z1^3 (mod p) */
    BigModMulBig(w6.auValue, y2->auValue, p.auValue, w5.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w5=y2*z1^3 (mod p) */

    /* 然后做进一步的计算（w1=x1*z2^2-x2*z1^2,w2=y1*z2^3-y2*z1^3） */
    BigModSubBig(w1.auValue, w4.auValue, p.auValue, w1.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w1=w1-w4 (mod p) */
    BigModSubBig(w2.auValue, w5.auValue, p.auValue, w2.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w2=w2-w5 (mod p) */

    if (bigDigits(&w1) == 0)	/* 如果w1为零 */
    {
        if (bigDigits(&w2) == 0)	/* 且w2也为零，这里应该走双倍点的流程 */
        {
            /* should have doubled ! */
            return 0;
        }
        else		/* 如果w1为零而w2不为零，则相加结果是无穷远点 */
        {
            /* point at infinity */
            bigset(x2, 0); /* 设置结果为无穷远点 */
            bigset(y2, 0);
            return 1;
        }
    }
    /* 继续计算（w4=x1*z2^2+x2*z1^2,w5=y1*z2^3+y2*z1^3）*/
    BigModAddBig(w4.auValue, w4.auValue, p.auValue, w6.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w6=2*w4 (mod p) */
    BigModAddBig(w1.auValue, w6.auValue, p.auValue, w4.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w4=w1+2*w4=x1*z2^2+x2*z1^2 (mod p) */
    BigModAddBig(w5.auValue, w5.auValue, p.auValue, w6.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w6=2*w5 (mod p) */
    BigModAddBig(w2.auValue, w6.auValue, p.auValue, w5.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w5=w2+2*w5=w2=y1*z2^3+y2*z1^3 (mod p) */

    /* 计算z'=x1*z1*z2^3-x2*z1^3*z2 */
    BigModMulBig(z1->auValue, z2->auValue, p.auValue, w3.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w3=z1*z2 (mod p) */
    BigModMulBig(w3.auValue, w1.auValue, p.auValue, z2->auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* z2'=w1*z1*z2 (mod p) */

    BigModMulBig(w1.auValue, w1.auValue, p.auValue, w6.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w6=w1^2=(x1*z2^2-x2*z1^2)^2 (mod p) */
    BigModMulBig(w1.auValue, w6.auValue, p.auValue, w1.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w1*=w6=(x1*z2^2-x2*z1^2)^3 (mod p) */
    BigModMulBig(w6.auValue, w4.auValue, p.auValue, w6.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w6*=(x1*z2^2+x2*z1^2) (mod p) */
    BigModMulBig(w2.auValue, w2.auValue, p.auValue, w4.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w4=w2^2=(y1*z2^3-y2*z1^3)^2 (mod p) */

    BigModSubBig(w4.auValue, w6.auValue, p.auValue, x2->auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* x2'=w4-w6 (mod p) */
    BigModSubBig(w6.auValue, x2->auValue, p.auValue, w6.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w6=w6-x2' (mod p) */
    BigModSubBig(w6.auValue, x2->auValue, p.auValue, w6.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w6=w6-x2' (mod p) */
    BigModMulBig(w2.auValue, w6.auValue, p.auValue, w2.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w2=w2*w6 (mod p) */
    BigModMulBig(w1.auValue, w5.auValue, p.auValue, w1.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w1=w1*w5 (mod p) */
    BigModSubBig(w2.auValue, w1.auValue, p.auValue, w5.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w5=w2-w1 (mod p) */

    /* divide by 2 */
    if (BigSHRAddsBig(w5.auValue, y2->auValue, ECC_BIGINT_MAXLEN * 4 * 8) != 0) /* y2=w5/2 */
    {
        /* if w5 is odd,即不能被2整除 */
        BigSHRAddsBig(p.auValue, w1.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w1=p/2 */
        BigModAddBig(y2->auValue, w1.auValue, p.auValue, y2->auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* y2 = (w5/2 + p/2) (mod p) */
        bigset(&w1, 1);
        BigModAddBig(y2->auValue, w1.auValue, p.auValue, y2->auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* y2 = (w5/2 + p/2 + 1) (mod p) */
        /* y'=y'/2 (mod p) */
    }	/* 有限域上的除法，因除数是2，无需复杂的求逆过程 */

    return 1;
}

//curv 曲线参数 p(模)  a  b    Gx  Gy  n(基点的阶) h
void ecc_double(M_BIG_INT *xt, M_BIG_INT *yt, M_BIG_INT *zt, M_BIG_INT *curv)	/* 两倍点的运算函数 */
{
    /* double point on active ecurve y^2=x^3+Ax+B */

    /* 需要如下局部变量： */
    M_BIG_INT w1, w2, w3, w4, p, a, b;
    M_BIG_INT *x, *y, *z;
    x = xt;
    y = yt;
    z = zt;


    bigset(&w1, 0);
    bigset(&w2, 0);
    bigset(&w3, 0);
    bigset(&w4, 0);

    bigcpy(&p, &curv[0]);
    bigcpy(&a, &curv[1]);
    bigcpy(&b, &curv[2]);

    if (bigDigits(y) == 0) /* if p==0,return */
    {
        /* 2 times infinity == infinity ! */
        return;
    }

    BigModMulBig(z->auValue, z->auValue, p.auValue, w2.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w2=z*z (mod p) */

    /* 以下是雅可比加重射影坐标的双倍点计算，之前已经计算了w2=z^2 */
    BigModMulBig(w2.auValue, w2.auValue, p.auValue, w3.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w3=w2*w2=z^4 (mod p) */
    BigModMulBig(w3.auValue, a.auValue, p.auValue, w3.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w3=A*w3=a*z^4 (mod p) */
    BigModMulBig(x->auValue, x->auValue, p.auValue, w1.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w1=x*x (mod p) */

    BigModAddBig(w1.auValue, w1.auValue, p.auValue, w4.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w4=2X^2 (mod p) */
    BigModAddBig(w1.auValue, w4.auValue, p.auValue, w4.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w4=3X^2 (mod p) */
    BigModAddBig(w3.auValue, w4.auValue, p.auValue, w4.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w4=3X^2+Aw3=3x^2+a*z^4 (mod p) */

    BigModMulBig(y->auValue, z->auValue, p.auValue, z->auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* z=y*z (mod p) */
    BigModAddBig(z->auValue, z->auValue, p.auValue, z->auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* z'=z+z=2*y*z (mod p) */


    BigModMulBig(y->auValue, y->auValue, p.auValue, w2.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w2=y^2 (mod p) */
    BigModMulBig(x->auValue, w2.auValue, p.auValue, w3.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w3=x*y^2 (mod p) */

    BigModAddBig(w3.auValue, w3.auValue, p.auValue, w3.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w3=2*x*y^2 (mod p) */
    BigModAddBig(w3.auValue, w3.auValue, p.auValue, w3.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w3=4*x*y^2 (mod p) */
    BigModMulBig(w4.auValue, w4.auValue, p.auValue, w1.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w1=w4^2 (mod p) */
    BigModAddBig(w3.auValue, w3.auValue, p.auValue, x->auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* x=2w3 (mod p) */

    BigModSubBig(w1.auValue, x->auValue, p.auValue, x->auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* x'=w1-x=w4^2-2w3 (mod p) */


    BigModMulBig(w2.auValue, w2.auValue, p.auValue, w2.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w2=y^4 (mod p) */
    BigModAddBig(w2.auValue, w2.auValue, p.auValue, w2.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w2=2*y^4 (mod p) */
    BigModAddBig(w2.auValue, w2.auValue, p.auValue, w2.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w2=4*y^4 (mod p) */
    BigModAddBig(w2.auValue, w2.auValue, p.auValue, w2.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w2=8*y^4 =yn (mod p) */
    BigModSubBig(w3.auValue, x->auValue, p.auValue, w3.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w3=w3-x' (mod p) */
    BigModMulBig(w3.auValue, w4.auValue, p.auValue, w3.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w3=w3*w4 (mod p) */
    BigModSubBig(w3.auValue, w2.auValue, p.auValue, y->auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* y'=w3-w2 (mod p) */

    return;
}

//curv 曲线参数 p(模)  a  b    Gx  Gy  n(基点的阶) h
void ecc_inverse(M_BIG_INT *xt, M_BIG_INT *yt, M_BIG_INT *zt, M_BIG_INT *curv)	/* 求逆运算 */
{
    /* computation inverse */
    /* 需要如下局部变量： */
    M_BIG_INT w1, w2, p;
    M_BIG_INT *x, *y, *z;

    x = xt;
    y = yt;
    z = zt;

    bigset(&w1, 0);
    bigset(&w2, 0);
    bigcpy(&p, &curv[0]);

    if (bigBits(z) == 1)
    {
        return;    /* if z==1,return */
    }

    BigModMulBig(z->auValue, z->auValue, p.auValue, w1.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w1=z^2 mod p*/
    BigModMulBig(w1.auValue, z->auValue, p.auValue, w2.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w2=z^3  mod p*/

    BigModInversBig(w1.auValue, p.auValue, w1.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w1=w1^(-1) mod p */
    BigModInversBig(w2.auValue, p.auValue, w2.auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* w2=w2^(-1) mod p */

    BigModMulBig(x->auValue, w1.auValue, p.auValue, x->auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* x=x/z^2 mod p */
    BigModMulBig(y->auValue, w2.auValue, p.auValue, y->auValue, ECC_BIGINT_MAXLEN * 4 * 8); /* y=y/z^3 mod p */

    bigset(z, 1);
    return;
}

//curv 曲线参数 p(模)  a  b    Gx  Gy  n(基点的阶) h
void generate_key_pair(M_BIG_INT *d, M_BIG_INT *x, M_BIG_INT *y, M_BIG_INT *curv)
{
    /* 这里产生256bit的随机数(mod n)，结果放在指针d所指的地址 */

    bigcpy(x, &curv[3]); /* p=G */
    bigcpy(y, &curv[4]);

    ecc_mult(d, x, y, curv); /* p=d*G */

    return;
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


void ECC_big(unsigned char *in, unsigned char *out)
{
	M_BIG_INT x, _x;
	ECCChar2BigInt(&x, ECC_BIGINT_MAXLEN, in, ECC_BIGINT_MAXLEN * 4);
	_big(&_x, &x);
	ECCBigInt2Char(out, ECC_BIGINT_MAXLEN * 4, &_x);
}









