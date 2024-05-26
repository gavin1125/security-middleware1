/**
 * @file 
 * @brief SM2算法接口
 * @author cws
 * @version 1.1
 * @date
 */

#include <string.h>
#include "soft_bigint.h"
#include "softdef.h"

#define BIG_LT   -1
#define BIG_EQ   0
#define BIG_GT   1

/* Macros. */

#define LOW_HALF(x) ((x) & MAX_BIG_HALF_DIGIT)
#define HIGH_HALF(x) (((x) >> BIG_HALF_DIGIT_BITS) & MAX_BIG_HALF_DIGIT)
#define TO_HIGH_HALF(x) (((BIG_INT)(x)) << BIG_HALF_DIGIT_BITS)
#define DIGIT_MSB(x) (unsigned int)(((x) >> (BIG_LEN - 1)) & 1)
#define DIGIT_2MSB(x) (unsigned int)(((x) >> (BIG_LEN - 2)) & 3)


#define BIG_ASSIGN_DIGIT(a, b, digits) {BIG_AssignZero (a, digits); a[0] = b;}
#define BIG_EQUAL(a, b, digits) (! BIG_Cmp (a, b, digits))
#define BIG_EVEN(a, digits) (((digits) == 0) || ! (a[0] & 1))


void static  R_memset (POINTER output,int value,unsigned int len)                                    
{
	unsigned int i = 0;
	while( i < len)
	{
	  output[i++] = value;
	}
	return ;
}


/* Computes a = b^c mod d.

   Lengths: a[dDigits], b[dDigits], c[cDigits], d[dDigits].
   Assumes d > 0, cDigits > 0, dDigits < MAX_NN_DIGITS.
 */

void BIG_ModExp(BIG_INT *a, BIG_INT *b, BIG_INT *c,unsigned int cDigits, BIG_INT *d,unsigned int dDigits)
{
	BIG_INT bPower[3][MAX_BIG_LEN], ci, t[MAX_BIG_LEN];
	int i;
	unsigned int ciBits, j, s;

//	Store b, b^2 mod d, and b^3 mod d.

	BIG_Assign (bPower[0], b, dDigits);
	BIG_ModMult (bPower[1], bPower[0], b, d, dDigits);
	BIG_ModMult (bPower[2], bPower[1], b, d, dDigits);

	BIG_ASSIGN_DIGIT (t, 1, dDigits);

	cDigits = BIG_Digits (c, cDigits);
	for(i = cDigits - 1; i >= 0; i--)
	{
		ci = c[i];
		ciBits = BIG_LEN;

//		Scan past leading zero bits of most significant digit.
		if(i == (int)(cDigits - 1))
		{
			while (! DIGIT_2MSB (ci))
			{
				ci <<= 2;
				ciBits -= 2;
			}
		}

		for(j = 0; j < ciBits; j += 2, ci <<= 2)
		{
//			Compute t = t^4 * b^s mod d, where s = two MSB's of ci.

			BIG_ModMult (t, t, t, d, dDigits);
			BIG_ModMult (t, t, t, d, dDigits);
			if ((s = DIGIT_2MSB (ci)) != 0)
			{
				BIG_ModMult (t, t, bPower[s-1], d, dDigits);
			}
		}
	}

	BIG_Assign(a, t, dDigits);

	//* Zeroize potentially sensitive information.

	R_memset((POINTER)bPower, 0, sizeof (bPower));
	R_memset((POINTER)t, 0, sizeof (t));
}


/* Returns the significant length of a in bits, where a is a digit. */
BIG_INT BIG_DigitBits (BIG_INT a)
{
	BIG_INT i;

	for (i = 0; i < BIG_LEN; i++, a >>= 1)
		if (a == 0)
			break;
	return (i);
}


/* Computes a * b, result stored in high and low. */
void dmult( BIG_INT a,BIG_INT b,BIG_INT* high,BIG_INT* low)
{
	BIG_HALF_DIGIT al, ah, bl, bh;
	BIG_INT m1, m2, m, ml, mh, carry = 0;

	al = (BIG_HALF_DIGIT)LOW_HALF(a);
	ah = (BIG_HALF_DIGIT)HIGH_HALF(a);
	bl = (BIG_HALF_DIGIT)LOW_HALF(b);
	bh = (BIG_HALF_DIGIT)HIGH_HALF(b);

	*low = (BIG_INT) al*bl;
	*high = (BIG_INT) ah*bh;

	m1 = (BIG_INT) al*bh;
	m2 = (BIG_INT) ah*bl;
	m = m1 + m2;

	if(m < m1)
        carry = 1L << (BIG_LEN / 2);

	ml = (m & MAX_BIG_HALF_DIGIT) << (BIG_LEN / 2);
	mh = m >> (BIG_LEN / 2);

	*low += ml;

	if(*low < ml)
		carry++;

	*high += carry + mh;
}


BIG_INT subdigitmult(BIG_INT* a,BIG_INT* b,BIG_INT c,BIG_INT* d,unsigned int  digits)
{
	BIG_INT borrow, thigh, tlow;
	unsigned int i;

	borrow = 0;

	if(c != 0) {
		for(i = 0; i < digits; i++) {
			dmult(c, d[i], &thigh, &tlow);
			if((a[i] = b[i] - borrow) > (MAX_BIG_DIGIT - borrow))
				borrow = 1;
			else
				borrow = 0;
			if((a[i] -= tlow) > (MAX_BIG_DIGIT - tlow))
				borrow++;
			borrow += thigh;
		}
	}

	return (borrow);
}


BIG_INT BIG_Bits (BIG_INT *a,unsigned int  digits)
{
	if ((digits = BIG_Digits (a, digits)) == 0)
		return (0);

	return ((digits - 1) * BIG_LEN + BIG_DigitBits (a[digits-1]));
}


/* Computes a = b + c. Returns carry.

	 Lengths: a[digits], b[digits], c[digits].
 */
BIG_INT BIG_Add (BIG_INT *a, BIG_INT *b,BIG_INT * c,unsigned int digits)
{
	BIG_INT temp, carry = 0;

	if(digits)
		do {
			if((temp = (*b++) + carry) < carry)
				temp = *c++;
            else {      /* Patch to prevent bug for Sun CC */
                if((temp += *c) < *c)
					carry = 1;
				else
					carry = 0;
                c++;
            }
			*a++ = temp;
		}while(--digits);

	return (carry);
}


/* Assigns a = 0. */
void BIG_AssignZero (BIG_INT * a,unsigned int  digits)
{
	if(digits) {
		do {
			*a++ = 0;
		}while(--digits);
	}
}


/* Computes a = b - c. Returns borrow.

	 Lengths: a[digits], b[digits], c[digits].
 */
BIG_INT BIG_Sub (BIG_INT *a, BIG_INT *b, BIG_INT *c, unsigned int  digits)
{
	BIG_INT temp, borrow = 0;

	if(digits)
		do {
            /* Bug fix 16/10/95 - JSK, code below removed, caused bug with
               Sun Compiler SC4.

			if((temp = (*b++) - borrow) == MAX_BIG_DIGIT)
                temp = MAX_BIG_DIGIT - *c++;
            */

            temp = *b - borrow;
            b++;
            if(temp == MAX_BIG_DIGIT) {
                temp = MAX_BIG_DIGIT - *c;
                c++;
            }else {      /* Patch to prevent bug for Sun CC */
                if((temp -= *c) > (MAX_BIG_DIGIT - *c))
					borrow = 1;
				else
					borrow = 0;
                c++;
            }
			*a++ = temp;
		}while(--digits);

	return(borrow);
}


/* Decodes character string b into a, where character string is ordered
	 from most to least significant.

	 Lengths: a[digits], b[len].
	 Assumes b[i] = 0 for i < len - digits * BIG_DIGIT_LEN. (Otherwise most
	 significant bytes are truncated.)
 */
void Char2BigInt (BIG_INT *a,unsigned int  digits,unsigned char * b,unsigned int  len)
{
  BIG_INT t;
  unsigned int i, u;
  int j;
  

  for (i = 0, j = len - 1; i < digits && j >= 0; i++) {
    t = 0;
    for (u = 0; j >= 0 && u < BIG_LEN; j--, u += 8)
			t |= ((BIG_INT)b[j]) << u;
		a[i] = t;
  }
  
  for (; i < digits; i++)
    a[i] = 0;
}


/* Computes a = b * c.

	 Lengths: a[2*digits], b[digits], c[digits].
	 Assumes digits < MAX_BIG_LEN.
*/
void BIG_Mult (BIG_INT *a, BIG_INT *b, BIG_INT *c,unsigned int  digits)
{
	BIG_INT t[2*MAX_BIG_LEN];
	BIG_INT dhigh, dlow, carry;
	unsigned int bDigits, cDigits, i, j;

	BIG_AssignZero (t, 2 * digits);

	bDigits = BIG_Digits (b, digits);
	cDigits = BIG_Digits (c, digits);

	for (i = 0; i < bDigits; i++) {
		carry = 0;
		if(*(b+i) != 0) {
			for(j = 0; j < cDigits; j++) {
				dmult(*(b+i), *(c+j), &dhigh, &dlow);
				if((*(t+(i+j)) = *(t+(i+j)) + carry) < carry)
					carry = 1;
				else
					carry = 0;
				if((*(t+(i+j)) += dlow) < dlow)
					carry++;
				carry += dhigh;
			}
		}
		*(t+(i+cDigits)) += carry;
	}


	BIG_Assign(a, t, 2 * digits);
}


/* Assigns a = 2^b.

   Lengths: a[digits].
	 Requires b < digits * BIG_LEN.
 */
void BIG_Assign2Exp (BIG_INT *a,unsigned int  b,unsigned int  digits)
{
  BIG_AssignZero (a, digits);

	if (b >= digits * BIG_LEN)
    return;

  a[b / BIG_LEN] = (BIG_INT)1 << (b % BIG_LEN);
}


/* Computes a = c div d and b = c mod d.

	 Lengths: a[cDigits], b[dDigits], c[cDigits], d[dDigits].
	 Assumes d > 0, cDigits < 2 * MAX_BIG_LEN,
					 dDigits < MAX_BIG_LEN.
*/
void BIG_Div (BIG_INT *a,BIG_INT * b,BIG_INT * c,unsigned int cDigits, BIG_INT *d,unsigned int dDigits)
{
	BIG_INT ai, cc[2*MAX_BIG_LEN+1], dd[MAX_BIG_LEN], s;
	BIG_INT t[2], u, v, *ccptr;
	BIG_HALF_DIGIT aHigh, aLow, cHigh, cLow;
	int i;
	unsigned int ddDigits, shift;

	ddDigits = BIG_Digits (d, dDigits);
	if(ddDigits == 0)
		return;

	shift = BIG_LEN - BIG_DigitBits (d[ddDigits-1]);
	BIG_AssignZero (cc, ddDigits);
	cc[cDigits] = BIG_LShift (cc, c, shift, cDigits);
	BIG_LShift (dd, d, shift, ddDigits);
	s = dd[ddDigits-1];

	BIG_AssignZero (a, cDigits);

	for (i = cDigits-ddDigits; i >= 0; i--) {
		if (s == MAX_BIG_DIGIT)
			ai = cc[i+ddDigits];
		else {
			ccptr = &cc[i+ddDigits-1];

			s++;
			cHigh = (BIG_HALF_DIGIT)HIGH_HALF (s);
			cLow = (BIG_HALF_DIGIT)LOW_HALF (s);

			*t = *ccptr;
			*(t+1) = *(ccptr+1);

			if (cHigh == MAX_BIG_HALF_DIGIT)
				aHigh = (BIG_HALF_DIGIT)HIGH_HALF (*(t+1));
			else
				aHigh = (BIG_HALF_DIGIT)(*(t+1) / (cHigh + 1));
			u = (BIG_INT)aHigh * (BIG_INT)cLow;
			v = (BIG_INT)aHigh * (BIG_INT)cHigh;
			if ((*t -= TO_HIGH_HALF (u)) > (MAX_BIG_DIGIT - TO_HIGH_HALF (u)))
				t[1]--;
			*(t+1) -= HIGH_HALF (u);
			*(t+1) -= v;

			while ((*(t+1) > cHigh) ||
						 ((*(t+1) == cHigh) && (*t >= TO_HIGH_HALF (cLow)))) {
				if ((*t -= TO_HIGH_HALF (cLow)) > MAX_BIG_DIGIT - TO_HIGH_HALF (cLow))
					t[1]--;
				*(t+1) -= cHigh;
				aHigh++;
			}

			if (cHigh == MAX_BIG_HALF_DIGIT)
				aLow = (BIG_HALF_DIGIT)LOW_HALF (*(t+1));
			else
				aLow =
			(BIG_HALF_DIGIT)((TO_HIGH_HALF (*(t+1)) + HIGH_HALF (*t)) / (cHigh + 1));
			u = (BIG_INT)aLow * (BIG_INT)cLow;
			v = (BIG_INT)aLow * (BIG_INT)cHigh;
			if ((*t -= u) > (MAX_BIG_DIGIT - u))
				t[1]--;
			if ((*t -= TO_HIGH_HALF (v)) > (MAX_BIG_DIGIT - TO_HIGH_HALF (v)))
				t[1]--;
			*(t+1) -= HIGH_HALF (v);

			while ((*(t+1) > 0) || ((*(t+1) == 0) && *t >= s)) {
				if ((*t -= s) > (MAX_BIG_DIGIT - s))
					t[1]--;
				aLow++;
			}

			ai = TO_HIGH_HALF (aHigh) + aLow;
			s--;
		}

		cc[i+ddDigits] -= subdigitmult(&cc[i], &cc[i], ai, dd, ddDigits);

		while (cc[i+ddDigits] || (BIG_Cmp (&cc[i], dd, ddDigits) >= 0)) {
			ai++;
			cc[i+ddDigits] -= BIG_Sub (&cc[i], &cc[i], dd, ddDigits);
		}

		a[i] = ai;
	}

	BIG_AssignZero (b, dDigits);
	BIG_RShift (b, cc, shift, ddDigits);
}


/* Returns the significant length of a in digits. */
BIG_INT  BIG_Digits (BIG_INT * a, unsigned int digits)
{
	if(digits) {
		digits--;
		do {
			if(a[digits])break;
		}while(digits--);

		return(digits + 1);
	}
	return(digits);
}


/* Computes a = c div 2^c (i.e., shifts right c bits), returning carry.

	 Requires: c < BIG_LEN. */
BIG_INT BIG_RShift (BIG_INT *a, BIG_INT *b,unsigned int  c,unsigned int  digits)
{
	BIG_INT temp, carry = 0;
	unsigned int t;

	if(c < BIG_LEN)
		if(digits) {

			t = BIG_LEN - c;

			do {
				digits--;
				temp = *(b+digits);
				*(a+digits) = (temp >> c) | carry;
				carry = c ? (temp << t) : 0;
			}while(digits);
		}

	return (carry);
}


/* Computes a = b * 2^c (i.e., shifts left c bits), returning carry.

	 Requires c < BIG_LEN. */
BIG_INT BIG_LShift (BIG_INT *a, BIG_INT *b,unsigned int  c, unsigned int digits)
{
	BIG_INT temp, carry = 0;
	unsigned int t;

	if(c < BIG_LEN)
		if(digits) {

			t = BIG_LEN - c;

			do {
				temp = *b++;
				*a++ = (temp << c) | carry;
				carry = c ? (temp >> t) : 0;
			}while(--digits);
		}

	return (carry);
}


/* Encodes b into character string a, where character string is ordered
   from most to least significant.

	 Lengths: a[len], b[digits].
	 Assumes BIG_Bits (b, digits) <= 8 * len. (Otherwise most significant
	 digits are truncated.)
 */
void BigInt2Char (unsigned char *a, unsigned int len, BIG_INT *b, unsigned int digits)
{
	BIG_INT t;
    unsigned int i, u;
    int j;

            /* @##$ unsigned/signed bug fix added JSAK - Fri  31/05/96 18:09:11 */
    for (i = 0, j = len - 1; i < digits && j >= 0; i++) {
		t = b[i];
        for (u = 0; j >= 0 && u < BIG_LEN; j--, u += 8)
			a[j] = (unsigned char)(t >> u);
	}

    for (; j >= 0; j--)
		a[j] = 0;
}


/* Assigns a = b. */
void BIG_Assign (BIG_INT *a, BIG_INT *b, unsigned int digits)
{
	if(digits) {
		do {
			*a++ = *b++;
		}while(--digits);
	}
}


/* Returns sign of a - b. */
int BIG_Cmp (BIG_INT *a, BIG_INT *b, unsigned int digits)
{
	if(digits) {
		do {
			digits--;
			if( a[digits] > b[digits] )return(1);
			if( a[digits] < b[digits] )return(-1);
		}while(digits);
	}
	return (0);
}


/* Computes a = b mod c.

	 Lengths: a[cDigits], b[bDigits], c[cDigits].
	 Assumes c > 0, bDigits < 2 * MAX_BIG_LEN, cDigits < MAX_BIG_LEN.
*/
void BIG_Mod (BIG_INT *a,BIG_INT * b,unsigned int  bDigits, BIG_INT * c, unsigned int cDigits)
{
    BIG_INT t[2 * MAX_BIG_LEN];
  
	BIG_Div (t, a, b, bDigits, c, cDigits);
}


/* Computes a = b * c mod d.

   Lengths: a[digits], b[digits], c[digits], d[digits].
   Assumes d > 0, digits < MAX_BIG_LEN.
 */
void BIG_ModMult (BIG_INT *a, BIG_INT *b, BIG_INT *c, BIG_INT *d, unsigned int digits)
{
    BIG_INT t[2*MAX_BIG_LEN];

	BIG_Mult (t, b, c, digits);
    BIG_Mod (a, t, 2 * digits, d, digits);
}


/* Compute a = 1/b mod c, assuming inverse exists.
   
   Lengths: a[digits], b[digits], c[digits].
	 Assumes gcd (b, c) = 1, digits < MAX_BIG_LEN.
 */
void BIG_ModInv (BIG_INT *a,BIG_INT * b,BIG_INT * c,unsigned int digits)
{
    BIG_INT q[MAX_BIG_LEN], t1[MAX_BIG_LEN], t3[MAX_BIG_LEN],
		u1[MAX_BIG_LEN], u3[MAX_BIG_LEN], v1[MAX_BIG_LEN],
		v3[MAX_BIG_LEN], w[2*MAX_BIG_LEN];
    int u1Sign;

    /* Apply extended Euclidean algorithm, modified to avoid negative
       numbers.
    */
    BIG_ASSIGN_DIGIT (u1, 1, digits);
	BIG_AssignZero (v1, digits);
    BIG_Assign (u3, b, digits);
	BIG_Assign (v3, c, digits);
    u1Sign = 1;

	while (! BIG_Zero (v3, digits)) {
        BIG_Div (q, t3, u3, digits, v3, digits);
        BIG_Mult (w, q, v1, digits);
		BIG_Add (t1, u1, w, digits);
        BIG_Assign (u1, v1, digits);
		BIG_Assign (v1, t1, digits);
		BIG_Assign (u3, v3, digits);
		BIG_Assign (v3, t3, digits);
		u1Sign = -u1Sign;
	}

    /* Negate result if sign is negative. */
	if (u1Sign < 0)
		BIG_Sub (a, c, u1, digits);
	else
		BIG_Assign (a, u1, digits);
}


/* Computes a = gcd(b, c).

	 Assumes b > c, digits < MAX_BIG_LEN.
*/

#define iplus1  ( i==2 ? 0 : i+1 )      /* used by Euclid algorithms */
#define iminus1 ( i==0 ? 2 : i-1 )      /* used by Euclid algorithms */
#define g(i) (  &(t[i][0])  )

void BIG_Gcd(BIG_INT *a ,BIG_INT *b ,BIG_INT *c, unsigned int digits)
{
	short i;
	BIG_INT t[3][MAX_BIG_LEN];

	BIG_Assign(g(0), c, digits);
	BIG_Assign(g(1), b, digits);

	i=1;

	while(!BIG_Zero(g(i),digits)) {
		BIG_Mod(g(iplus1), g(iminus1), digits, g(i), digits);
		i = iplus1;
	}

	BIG_Assign(a , g(iminus1), digits);
}


/* Returns nonzero iff a is zero. */
int BIG_Zero (BIG_INT *a, unsigned int digits)
{
	if(digits) {
		do {
			if(*a++)return(0);
		}while(--digits);
	}
	return (1);
}

//=================================================================================================

/* Decodes character string b into a, where character string is ordered
	 from most to least significant.

	 Lengths: a[digits], b[len].
	 Assumes b[i] = 0 for i < len - digits * BIG_DIGIT_LEN. (Otherwise most
	 significant bytes are truncated.)
 */
void ECCChar2BigInt(M_BIG_INT *a, unsigned int digits, unsigned char * b, unsigned int len)
{
    unsigned int t;
    unsigned int i, u;
    int j;
    for (i = 0, j = len - 1; i < digits && j >= 0; i++)
    {
        t = 0;

        for (u = 0; j >= 0 && u < BIG_LEN; j--, u += 8)
        {
            t |= ((unsigned int)b[j]) << u;
        }
        a->auValue[i] = t;
    }
    for (; i < digits; i++)
    {
        a->auValue[i] = 0;
    }

    a->uLen = (len + 3) / 4;
}

//=================================================================================================

/* Encodes b into character string a, where character string is ordered
   from most to least significant.

	 Lengths: a[len], b[digits].
	 Assumes BIG_Bits (b, digits) <= 8 * len. (Otherwise most significant
	 digits are truncated.)
 */
void ECCBigInt2Char (unsigned char *a, unsigned int len, M_BIG_INT *b)
{
    unsigned int t;
    unsigned int i, u;
    int j;
    for (i = 0, j = len - 1; i < b->uLen && j >= 0; i++)
    {
        t = b->auValue[i];
        for (u = 0; j >= 0 && u < BIG_LEN; j--, u += 8)
        {
            a[j] = (unsigned char)(t >> u);
        }
    }
    for (; j >= 0; j--)
    {
        a[j] = 0;
    }
}

 // return bits
 int	M_BIG_bits(M_BIG_INT *a)
 {
	 unsigned int i, num, bits;

	 bits = 0;
	 for(i=a->uLen - 1; i >=0; i++)
	 {
		 num = a->auValue[i];
		 if(num > 0)
		 {
			 bits = i * 32 + 1;
			 while(num >>= 1) bits++;

			 break;
		 }
	 }

	 return bits;
 }

 // check if a is zero
 int M_BIG_CmpZero(M_BIG_INT *a)
 {
	 int i, zero = 0;
	 for(i=0; i<a->uLen; i++)
	 {
		 if(a->auValue[i])
		 {
			 zero = 1;
			 break;
		 }
	 }

	 return zero;
 }

 // ensure a->uLen = len
 void M_BIG_align(M_BIG_INT *a, int len)
 {
	 int i;
	 if(a->uLen < len)
	 {
		 for(i=a->uLen; i<len; i++)
		 {
			 a->auValue[i] = 0;
		 }
		 a->uLen = len;
	 }
 }

 //=================================================================================================
 // ×Ö·ûŽ®×ª»»ÎªŽóÕûÊý
 static int Char2Int(char ch)
 {
	 if(ch >= '0' && ch <= '9')
	 {
		 return ch - '0';
	 }
	 else if(ch >= 'A' && ch <= 'F')
	 {
		 return ch - 'A' + 10;
	 }
	 else if(ch >= 'a' && ch <= 'f')
	 {
		 return ch - 'a' + 10;
	 }
	 else
	 {
		 return 0;
	 }
 }
 void ECCStr2BigInt(M_BIG_INT *a, char *num)
 {
	 int i;
	 char* p;
	 unsigned char data[MAX_BIG_LEN * sizeof(unsigned int)];
	 int len = (int)strlen(num);
	 if(len == 0)
	 {
		 a->uLen = 1;
		 a->auValue[0] = 0;
		 return;
	 }

	 if(len % 2)
	 {
		 data[0] = Char2Int(num[0]);
		 p = num + 1;
	 }
	 else
	 {
		 data[0] = Char2Int(num[0]) * 16 + Char2Int(num[1]);
		 p = num + 2;
	 }

	 len = (len+1)/2;
	 for(i=1; i<len; i++)
	 {
		 data[i] = Char2Int(p[0]) * 16 + Char2Int(p[1]);
		 p += 2;
	 }

	 ECCChar2BigInt(a, (len + 3)/4, data, len);
 }

/*
	ŽóÊýÔËËãµŒ³öœÓ¿Ú
*/

//static void Char2BigInt(BIG_INT *big, int digits, unsigned char * num, unsigned int len)
//{
//	 unsigned int t;
//	 unsigned int i, u;
//	 int j;
//	 for (i = 0, j = len - 1; i < digits && j >= 0; i++)
//	 {
//		 t = 0;
//
//		 for (u = 0; j >= 0 && u < BIG_LEN; j--, u += 8)
//		 {
//			 t |= ((unsigned int)num[j]) << u;
//		 }
//		 big[i] = t;
//	 }
//	 for (; i < digits; i++)
//	 {
//		 big[i] = 0;
//	 }
//}
//
//static void BigInt2Char(unsigned char *a, unsigned int len, BIG_INT *b, int digits)
//{
//	unsigned int t;
//	unsigned int i, u;
//	int j;
//	for (i = 0, j = len - 1; i < digits && j >= 0; i++)
//	{
//		t = b[i];
//		for (u = 0; j >= 0 && u < BIG_LEN; j--, u += 8)
//		{
//			a[j] = (unsigned char)(t >> u);
//		}
//	}
//	for (; j >= 0; j--)
//	{
//		a[j] = 0;
//	}
//}

 // a = (b + c) mod m
int BIG_AddMod(unsigned char *a, unsigned char *b, unsigned char *c, unsigned char *m, int len)
{
	BIG_INT carry;
	BIG_INT bigA[MAX_BIG_LEN], bigB[MAX_BIG_LEN], bigC[MAX_BIG_LEN], bigM[MAX_BIG_LEN], bigMax[MAX_BIG_LEN+1];

	int mlen = (len+3) / 4; 
	if(mlen > MAX_BIG_LEN)
	{
		return XALGR_DATA_LEN;
	}

	Char2BigInt(bigB, mlen, b, len);
	Char2BigInt(bigC, mlen, c, len);
	Char2BigInt(bigM, mlen, m, len);

	carry = BIG_Add(bigMax, bigB, bigC, mlen);
	if(carry)
	{
		bigMax[mlen] = carry;
		BIG_Mod(bigA, bigMax, mlen+1, bigM, mlen);
	}
	else
	{
		BIG_Mod(bigA, bigMax, mlen, bigM, mlen);
	}

	BigInt2Char(a, len, bigA, mlen);
	return XALGR_OK;
}

// a = (b - c) mod m
int BIG_SubMod(unsigned char *a, unsigned char *b, unsigned char *c, unsigned char *m, int len)
{
	BIG_INT bigA[MAX_BIG_LEN], bigB[MAX_BIG_LEN], bigC[MAX_BIG_LEN], bigM[MAX_BIG_LEN], bigRet[MAX_BIG_LEN], bigRet1[MAX_BIG_LEN];

	int mlen = (len+3) / 4; 
	if(mlen > MAX_BIG_LEN)
	{
		return XALGR_DATA_LEN;
	}

	Char2BigInt(bigB, mlen, b, len);
	Char2BigInt(bigC, mlen, c, len);
	Char2BigInt(bigM, mlen, m, len);

	if (BIG_Cmp(bigB, bigC, mlen) == 1)  // b > c
	{
		BIG_Sub(bigRet, bigB, bigC, mlen);
		BIG_Mod(bigA,bigRet,mlen,bigM,mlen);
	}
	else
	{
		// b <= c
		BIG_Sub(bigRet, bigC, bigB, mlen);         // b-a
		BIG_Mod(bigRet1,bigRet,mlen,bigM,mlen);   // t2 = (b-a)mod m
		BIG_Sub(bigA,bigM,bigRet1,mlen);  //   pstuC=m-t2
	}

	BigInt2Char(a, len, bigA, mlen);
	return XALGR_OK;
}

// a = (b * c) mod m
int BIG_MulMod(unsigned char *a, unsigned char *b, unsigned char *c, unsigned char *m, int len)
{
	BIG_INT bigA[MAX_BIG_LEN], bigB[MAX_BIG_LEN], bigC[MAX_BIG_LEN], bigM[MAX_BIG_LEN];

	int mlen = (len+3) / 4; 
	if(mlen > MAX_BIG_LEN)
	{
		return XALGR_DATA_LEN;
	}

	Char2BigInt(bigB, mlen, b, len);
	Char2BigInt(bigC, mlen, c, len);
	Char2BigInt(bigM, mlen, m, len);

	BIG_ModMult(bigA, bigB, bigC, bigM, mlen);
	
	BigInt2Char(a, len, bigA, mlen);
	return XALGR_OK;
}

// a = (b ^ c) mod m
int BIG_PowMod(unsigned char *a, unsigned char *b, unsigned char *c, unsigned char *m, int len)
{
	BIG_INT bigA[MAX_BIG_LEN], bigB[MAX_BIG_LEN], bigC[MAX_BIG_LEN], bigM[MAX_BIG_LEN];

	int mlen = (len+3) / 4; 
	if(mlen > MAX_BIG_LEN)
	{
		return XALGR_DATA_LEN;
	}

	Char2BigInt(bigB, mlen, b, len);
	Char2BigInt(bigC, mlen, c, len);
	Char2BigInt(bigM, mlen, m, len);

	BIG_ModExp(bigA, bigB, bigC, mlen, bigM, mlen);

	BigInt2Char(a, len, bigA, mlen);
	return XALGR_OK;
}

// a = (b ^ -1) mod m
int BIG_Inverse(unsigned char *a, unsigned char *b, unsigned char *m, int len)
{
	BIG_INT bigA[MAX_BIG_LEN], bigB[MAX_BIG_LEN], bigM[MAX_BIG_LEN];

	int mlen = (len+3) / 4; 
	if(mlen > MAX_BIG_LEN)
	{
		return XALGR_DATA_LEN;
	}

	Char2BigInt(bigB, mlen, b, len);
	Char2BigInt(bigM, mlen, m, len);

	BIG_ModInv(bigA, bigB, bigM, mlen);

	BigInt2Char(a, len, bigA, mlen);
	return XALGR_OK;
}


// a = b ^ c mod n ÒªÊµÏÖ
//void PowMod(unsigned int *a, unsigned int *b ,unsigned int *c ,unsigned int *n,unsigned short uBits)
//{
//	
//}
