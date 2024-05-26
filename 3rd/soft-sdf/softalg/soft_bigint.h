/**
 * @file 
 * @brief SM2算法接口
 * @author cws
 * @version 1.1
 * @date
 */

#ifndef __SOFT_BIGINT_H__
#define __SOFT_BIGINT_H__

/* Constants.
	 Note: MAX_BIG_LEN is long enough to hold any RSA modulus, plus
   one more digit as required by R_GeneratePEMKeys (for n and phiN,
   whose lengths must be even). All natural numbers have at most
   MAX_BIG_LEN digits, except for double-length intermediate values
	 in BIG_Mult (t), BIG_ModMult (t), BIG_ModInv (w), and BIG_Div (c).
*/

/* Length of digit in bits */
#define BIG_LEN 32
#define BIG_HALF_DIGIT_BITS 16

/* Maximum digits */
#define MAX_BIG_DIGIT 0xffffffff
#define MAX_BIG_HALF_DIGIT 0xffff


#ifndef MAX_BIG_LEN
#define MAX_BIG_LEN    20
#endif 

// Type definitions. 
typedef unsigned char *POINTER;
typedef unsigned int   BIG_INT;
typedef unsigned short   BIG_HALF_DIGIT;


/*
uLen		lenth of number 
reserved	reserved param
auValue		data of number

*/
typedef struct _BIG_INT_STRUCT
{
 	unsigned short   uLen;
 	unsigned short   reserved;
	unsigned int   auValue[MAX_BIG_LEN];
}M_BIG_INT,*PM_BIG_INT;

#ifdef __cplusplus
extern "C"
{
#endif

// BIG_INT*	is orderedfrom least to most significant

void     BIG_ModExp(BIG_INT *a, BIG_INT *b, BIG_INT *c,unsigned int cDigits, BIG_INT *d,unsigned int dDigits);
BIG_INT  BIG_DigitBits (BIG_INT a);
void     dmult( BIG_INT a,BIG_INT b,BIG_INT* high,BIG_INT* low);
BIG_INT  subdigitmult(BIG_INT* a,BIG_INT* b,BIG_INT c,BIG_INT* d,unsigned int  digits);
BIG_INT  BIG_Bits (BIG_INT *a,unsigned int  digits);
BIG_INT  BIG_Add (BIG_INT *a, BIG_INT *b,BIG_INT * c,unsigned int digits);
void     BIG_AssignZero (BIG_INT * a,unsigned int  digits);
BIG_INT  BIG_Sub (BIG_INT *a, BIG_INT *b, BIG_INT *c, unsigned int  digits);
void     Char2BigInt (BIG_INT *a,unsigned int  digits,unsigned char * b,unsigned int  len);
void     BIG_Mult (BIG_INT *a, BIG_INT *b, BIG_INT *c,unsigned int  digits);
void     BIG_Assign2Exp (BIG_INT *a,unsigned int  b,unsigned int  digits);
void     BIG_Div (BIG_INT *a,BIG_INT * b,BIG_INT * c,unsigned int cDigits, BIG_INT *d,unsigned int dDigits);
BIG_INT  BIG_Digits (BIG_INT * a, unsigned int digits);
BIG_INT  BIG_RShift (BIG_INT *a, BIG_INT *b,unsigned int  c,unsigned int  digits);
BIG_INT  BIG_LShift (BIG_INT *a, BIG_INT *b,unsigned int  c, unsigned int digits);
void     BigInt2Char (unsigned char *a, unsigned int len, BIG_INT *b, unsigned int digits);
void     BIG_Assign (BIG_INT *a, BIG_INT *b, unsigned int digits);
int      BIG_Cmp (BIG_INT *a, BIG_INT *b, unsigned int digits);
void     BIG_Mod (BIG_INT *a,BIG_INT * b,unsigned int  bDigits, BIG_INT * c, unsigned int cDigits);
void     BIG_ModMult (BIG_INT *a, BIG_INT *b, BIG_INT *c, BIG_INT *d, unsigned int digits);
void     BIG_ModInv (BIG_INT *a,BIG_INT * b,BIG_INT * c,unsigned int digits);
void     BIG_Gcd(BIG_INT *a ,BIG_INT *b ,BIG_INT *c, unsigned int digits);
int      BIG_Zero (BIG_INT *a, unsigned int digits);

int		 M_BIG_bits(M_BIG_INT *a);
int		 M_BIG_CmpZero(M_BIG_INT *a);
void	 M_BIG_align(M_BIG_INT *a, int len);	// ensure a->uLen = len



void ECCChar2BigInt (M_BIG_INT *a, unsigned int digits, unsigned char * b, unsigned int len);
void ECCBigInt2Char (unsigned char *a, unsigned int len, M_BIG_INT *b);

void ECCStr2BigInt(M_BIG_INT *a, char *num);


int BIG_AddMod(unsigned char *a, unsigned char *b, unsigned char *c, unsigned char *m, int len);		// a = (b + c) mod m
int BIG_SubMod(unsigned char *a, unsigned char *b, unsigned char *c, unsigned char *m, int len);		// a = (b - c) mod m
int BIG_MulMod(unsigned char *a, unsigned char *b, unsigned char *c, unsigned char *m, int len);		// a = (b * c) mod m
int BIG_PowMod(unsigned char *a, unsigned char *b, unsigned char *c, unsigned char *m, int len);		// a = (b ^ c) mod m
int BIG_Inverse(unsigned char *a, unsigned char *b, unsigned char *m, int len);							// a = (b ^ -1) mod m

#ifdef __cplusplus
}
#endif

#endif
