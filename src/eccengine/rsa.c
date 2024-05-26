

/* NN.C - natural numbers routines
*/

/* Copyright (C) 1991-2 RSA Laboratories, a division of RSA Data
Security, Inc. All rights reserved.
*/
#include "rsa.h"

#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "sha1.h"


/* Type definitions.
*/

/* POINTER defines a generic pointer type */
typedef unsigned char *POINTER;

/* UINT2 defines a two byte word */
typedef unsigned short int UINT2;

/* UINT4 defines a four byte word */
typedef unsigned int UINT4;


typedef UINT4 NN_DIGIT;
typedef UINT2 NN_HALF_DIGIT;

/* Constants.

	Note: MAX_NN_DIGITS is long enough to hold any RSA modulus, plus
	one more digit as required by R_GeneratePEMKeys (for n and phiN,
	whose lengths must be even). All natural numbers have at most
	MAX_NN_DIGITS digits, except for double-length intermediate values
	in NN_Mult (t), NN_ModMult (t), NN_ModInv (w), and NN_Div (c).
*/
/* Length of digit in bits */
#define NN_DIGIT_BITS 32
#define NN_HALF_DIGIT_BITS 16
/* Length of digit in bytes */
#define NN_DIGIT_LEN (NN_DIGIT_BITS / 8)
/* Maximum length in digits */
#define MAX_NN_DIGITS ((MAX_RSA_MODULUS_LEN + NN_DIGIT_LEN - 1) / NN_DIGIT_LEN + 1)
/* Maximum digits */
#define MAX_NN_DIGIT 0xffffffff
#define MAX_NN_HALF_DIGIT 0xffff

/* Macros.
*/
#define LOW_HALF(x) (NN_HALF_DIGIT)((x) & MAX_NN_HALF_DIGIT)
#define HIGH_HALF(x) (NN_HALF_DIGIT)(((x) >> NN_HALF_DIGIT_BITS) & MAX_NN_HALF_DIGIT)
#define TO_HIGH_HALF(x) (((NN_DIGIT)(x)) << NN_HALF_DIGIT_BITS)
#define DIGIT_MSB(x) (unsigned int)(((x) >> (NN_DIGIT_BITS - 1)) & 1)
#define DIGIT_2MSB(x) (unsigned int)(((x) >> (NN_DIGIT_BITS - 2)) & 3)

static void NN_Decode (NN_DIGIT *a, unsigned int digits, const unsigned char * b, unsigned int   len);
static void NN_Encode (unsigned char *a, unsigned int len, NN_DIGIT *b, unsigned int digits);

static void NN_Assign (NN_DIGIT *a, NN_DIGIT *b, unsigned int digits);
static void NN_AssignZero (NN_DIGIT *a, unsigned int digits);
//static void NN_Assign2Exp (NN_DIGIT *a,unsigned int b, unsigned int digits);

static NN_DIGIT NN_Add (NN_DIGIT *a, NN_DIGIT *b, NN_DIGIT *c, unsigned int digits);
static NN_DIGIT NN_Sub (NN_DIGIT *a, NN_DIGIT *b, NN_DIGIT *c, unsigned int digits);

static void NN_Mult (NN_DIGIT *a, NN_DIGIT *b, NN_DIGIT  *c, unsigned int digits);
static void NN_Mod (NN_DIGIT *a, NN_DIGIT *b, unsigned int bDigits, NN_DIGIT *c, unsigned int cDigits);

static void NN_ModMult (NN_DIGIT *a, NN_DIGIT *b, NN_DIGIT *c, NN_DIGIT *d, unsigned int digits);

static void NN_ModExp (NN_DIGIT *a, NN_DIGIT *b, NN_DIGIT *c, unsigned int cDigits, NN_DIGIT *d, unsigned int dDigits);

static void NN_ModInv (NN_DIGIT *a, NN_DIGIT *b, NN_DIGIT *c, unsigned int digits);

static void NN_Gcd (NN_DIGIT *a, NN_DIGIT *b, NN_DIGIT *c, unsigned int digits);

static int NN_Cmp (NN_DIGIT *a, NN_DIGIT *b, unsigned int digits);

static int NN_Zero (NN_DIGIT *a, unsigned int digits);

//static unsigned int NN_Bits (NN_DIGIT *a,unsigned int digits);
static unsigned int NN_Digits (NN_DIGIT *a, unsigned int digits);

#define NN_ASSIGN_DIGIT(a, b, digits) {NN_AssignZero (a, digits); a[0] = b;}
#define NN_EQUAL(a, b, digits) (! NN_Cmp (a, b, digits))
#define NN_EVEN(a, digits) ((0==(digits)) || ! (a[0] & 1))

static void NN_DigitMult (NN_DIGIT a[2], NN_DIGIT  b, NN_DIGIT c);
static void NN_DigitDiv (NN_DIGIT *a, NN_DIGIT b[2], NN_DIGIT c);


static unsigned int NN_DigitBits (NN_DIGIT a);
static NN_DIGIT     NN_AddDigitMult (NN_DIGIT *a, NN_DIGIT *b, NN_DIGIT c, NN_DIGIT *d, unsigned int digits);
static NN_DIGIT     NN_SubDigitMult (NN_DIGIT *a, NN_DIGIT *b, NN_DIGIT c, NN_DIGIT *d, unsigned int digits);
static void         NN_Div (NN_DIGIT *a, NN_DIGIT *b, NN_DIGIT *c, unsigned int  cDigits, NN_DIGIT *d, unsigned int dDigits);


static void R_memset (POINTER output, int value, unsigned int len)
{
    if (len)
    {
        memset (output, value, len);
    }
}

// static void R_memcpy (POINTER output, POINTER input,unsigned int len)
// {
// 	if(len)
// 		memcpy (output, input, len);
// }
//
// static int R_memcmp (POINTER firstBlock, POINTER secondBlock, unsigned int len)
// {
// 	if(len)
// 		return (memcmp (firstBlock, secondBlock, len));
// 	else
// 		return (0);
// }

/* Decodes character string b into a, where character string is ordered
from most to least significant.

Length: a[digits], b[len].
Assumes b[i] = 0 for i < len - digits * NN_DIGIT_LEN. (Otherwise most
significant bytes are truncated.)
*/
void NN_Decode (NN_DIGIT *a, unsigned int digits, const unsigned char * b, unsigned int   len)
{
    NN_DIGIT t = 0;
    int j = 0;
    unsigned int i = 0, u = 0;

    for (i = 0, j = len - 1; j >= 0; i++)
    {
        t = 0;
        for (u = 0; j >= 0 && u < NN_DIGIT_BITS; j--, u += 8)
        {
            t |= ((NN_DIGIT)b[j]) << u;
        }
        a[i] = t;
    }

    for (; i < digits; i++)
    {
        a[i] = 0;
    }
}

/* Encodes b into character string a, where character string is ordered
from most to least significant.

Lengths: a[len], b[digits].
Assumes NN_Bits (b, digits) <= 8 * len. (Otherwise most significant
digits are truncated.)
*/
void NN_Encode (unsigned char *a, unsigned int len, NN_DIGIT *b, unsigned int digits)
{
    NN_DIGIT t = 0;
    int j = 0;
    unsigned int i = 0, u = 0;

    for (i = 0, j = len - 1; i < digits; i++)
    {
        t = b[i];
        for (u = 0; j >= 0 && u < NN_DIGIT_BITS; j--, u += 8)
        {
            a[j] = (unsigned char)(t >> u);
        }
    }

    for (; j >= 0; j--)
    {
        a[j] = 0;
    }
}

/* Assigns a = 0.

Lengths: a[digits], b[digits].
*/
void NN_Assign (NN_DIGIT *a, NN_DIGIT *b, unsigned int digits)
{
    unsigned int i = 0;

    for (i = 0; i < digits; i++)
    {
        a[i] = b[i];
    }
}

/* Assigns a = 0.

Lengths: a[digits].
*/
void NN_AssignZero (NN_DIGIT *a, unsigned int digits)
{
    unsigned int i = 0;

    for (i = 0; i < digits; i++)
    {
        a[i] = 0;
    }
}

/* Assigns a = 2^b.

Lengths: a[digits].
Requires b < digits * NN_DIGIT_BITS.
*/
// static void NN_Assign2Exp (NN_DIGIT *a,unsigned int b, unsigned int digits)
// {
// 	NN_AssignZero (a, digits);
//
// 	if(b >= digits * NN_DIGIT_BITS)
// 		return;
//
// 	a[b / NN_DIGIT_BITS] = (NN_DIGIT)1 << (b % NN_DIGIT_BITS);
// }

/* Computes a = b + c. Returns carry.

Lengths: a[digits], b[digits], c[digits].
*/
NN_DIGIT NN_Add (NN_DIGIT *a, NN_DIGIT *b, NN_DIGIT *c, unsigned int digits)
{
    NN_DIGIT ai = 0, carry = 0;
    unsigned int i = 0;

    carry = 0;

    for (i = 0; i < digits; i++)
    {
        if ((ai = b[i] + carry) < carry)
        {
            ai = c[i];
        }
        else if ((ai += c[i]) < c[i])
        {
            carry = 1;
        }
        else
        {
            carry = 0;
        }
        a[i] = ai;
    }

    return (carry);
}

/* Computes a = b - c. Returns borrow.

Lengths: a[digits], b[digits], c[digits].
*/
NN_DIGIT NN_Sub (NN_DIGIT *a, NN_DIGIT *b, NN_DIGIT *c, unsigned int digits)
{
    NN_DIGIT ai = 0, borrow = 0;
    unsigned int i = 0;

    borrow = 0;

    for (i = 0; i < digits; i++)
    {
        if ((ai = b[i] - borrow) > (MAX_NN_DIGIT - borrow))
        {
            ai = MAX_NN_DIGIT - c[i];
        }
        else if ((ai -= c[i]) > (MAX_NN_DIGIT - c[i]))
        {
            borrow = 1;
        }
        else
        {
            borrow = 0;
        }
        a[i] = ai;
    }

    return (borrow);
}

/* Computes a = b * c.

Lengths: a[2*digits], b[digits], c[digits].
Assumes digits < MAX_NN_DIGITS.
*/
void NN_Mult (NN_DIGIT *a, NN_DIGIT *b, NN_DIGIT  *c, unsigned int digits)
{
    NN_DIGIT t[2 * MAX_NN_DIGITS] = {0};
    unsigned int bDigits = 0, cDigits = 0, i = 0;

    NN_AssignZero (t, 2 * digits);

    bDigits = NN_Digits (b, digits);
    cDigits = NN_Digits (c, digits);

    for (i = 0; i < bDigits; i++)
    {
        t[i + cDigits] += NN_AddDigitMult (&t[i], &t[i], b[i], c, cDigits);
    }

    NN_Assign (a, t, 2 * digits);

    /* Zeroize potentially sensitive information.
    */
    R_memset ((POINTER)t, 0, sizeof (t));
}

/* Computes a = b mod c.

Lengths: a[cDigits], b[bDigits], c[cDigits].
Assumes c > 0, bDigits < 2 * MAX_NN_DIGITS, cDigits < MAX_NN_DIGITS.
*/
void NN_Mod (NN_DIGIT *a, NN_DIGIT *b, unsigned int bDigits, NN_DIGIT *c, unsigned int cDigits)
{
    NN_DIGIT t[2 * MAX_NN_DIGITS] = {0};

    NN_Div (t, a, b, bDigits, c, cDigits);

    /* Zeroize potentially sensitive information.
    */
    R_memset ((POINTER)t, 0, sizeof (t));
}

/* Computes a = b * c mod d.

Lengths: a[digits], b[digits], c[digits], d[digits].
Assumes d > 0, digits < MAX_NN_DIGITS.
*/
void NN_ModMult (NN_DIGIT *a, NN_DIGIT *b, NN_DIGIT *c, NN_DIGIT *d, unsigned int digits)
{
    NN_DIGIT t[2 * MAX_NN_DIGITS] = {0};

    NN_Mult (t, b, c, digits);
    NN_Mod (a, t, 2 * digits, d, digits);

    /* Zeroize potentially sensitive information.
    */
    R_memset ((POINTER)t, 0, sizeof (t));
}


/*
* PGP 2.6's mpilib contains a faster modular exponentiation routine,
* mp_modexp.  If USEMPILIB is defined, NN_ModExp is replaced in the
* PGP 2.6 sources with a stub call to mp_modexp.  If USEMPILIB is
* not defined, we'll get a pure (albeit slower) RSAREF
* implementation.
*
* The RSAREF license, clause 1(c), permits "...modify[ing] the
* Program in any manner for porting or performance improvement
* purposes..."
*/
#ifndef USEMPILIB
/* Computes a = b^c mod d.

Lengths: a[dDigits], b[dDigits], c[cDigits], d[dDigits].
Assumes b < d, d > 0, cDigits > 0, dDigits > 0,
dDigits < MAX_NN_DIGITS.
*/
void NN_ModExp (NN_DIGIT *a, NN_DIGIT *b, NN_DIGIT *c, unsigned int cDigits, NN_DIGIT *d, unsigned int dDigits)
{
    NN_DIGIT bPower[3][MAX_NN_DIGITS] = {0}, ci = 0, t[MAX_NN_DIGITS] = {0};
    int i = 0;
    unsigned int ciBits = 0, j = 0, s = 0;

    /* Store b, b^2 mod d, and b^3 mod d.
    */
    NN_Assign (bPower[0], b, dDigits);
    NN_ModMult (bPower[1], bPower[0], b, d, dDigits);
    NN_ModMult (bPower[2], bPower[1], b, d, dDigits);

    NN_ASSIGN_DIGIT (t, 1, dDigits);

    cDigits = NN_Digits (c, cDigits);
    for (i = cDigits - 1; i >= 0; i--)
    {
        ci = c[i];
        ciBits = NN_DIGIT_BITS;

        /* Scan past leading zero bits of most significant digit.
        */
        if ((int)(cDigits - 1) == i )
        {
            while (! DIGIT_2MSB (ci))
            {
                ci <<= 2;
                ciBits -= 2;
            }
        }

        for (j = 0; j < ciBits; j += 2, ci <<= 2)
        {
            /* Compute t = t^4 * b^s mod d, where s = two MSB's of d.
            */
            NN_ModMult (t, t, t, d, dDigits);
            NN_ModMult (t, t, t, d, dDigits);
            if ((s = DIGIT_2MSB (ci)))
            {
                NN_ModMult (t, t, bPower[s - 1], d, dDigits);
            }
        }
    }

    NN_Assign (a, t, dDigits);

    /* Zeroize potentially sensitive information.
    */
    R_memset ((POINTER)bPower, 0, sizeof (bPower));
    R_memset ((POINTER)t, 0, sizeof (t));
}
#endif

/* Compute a = 1/b mod c, assuming inverse exists.

Lengths: a[digits], b[digits], c[digits].
Assumes gcd (b, c) = 1, digits < MAX_NN_DIGITS.
*/
static void NN_ModInv (NN_DIGIT *a, NN_DIGIT *b, NN_DIGIT *c, unsigned int digits)
{
    NN_DIGIT q[MAX_NN_DIGITS] = {0}, t1[MAX_NN_DIGITS] = {0}, t3[MAX_NN_DIGITS] = {0},
                                u1[MAX_NN_DIGITS] = {0}, u3[MAX_NN_DIGITS] = {0}, v1[MAX_NN_DIGITS] = {0},
                                        v3[MAX_NN_DIGITS] = {0}, w[2 * MAX_NN_DIGITS] = {0};
    int u1Sign = 0;

    /* Apply extended Euclidean algorithm, modified to avoid negative
    numbers.
    */
    NN_ASSIGN_DIGIT (u1, 1, digits);
    NN_AssignZero (v1, digits);
    NN_Assign (u3, b, digits);
    NN_Assign (v3, c, digits);
    u1Sign = 1;

    while (! NN_Zero (v3, digits))
    {
        NN_Div (q, t3, u3, digits, v3, digits);
        NN_Mult (w, q, v1, digits);
        NN_Add (t1, u1, w, digits);
        NN_Assign (u1, v1, digits);
        NN_Assign (v1, t1, digits);
        NN_Assign (u3, v3, digits);
        NN_Assign (v3, t3, digits);
        u1Sign = -u1Sign;
    }

    /* Negate result if sign is negative.
    */
    if (u1Sign < 0)
    {
        NN_Sub (a, c, u1, digits);
    }
    else
    {
        NN_Assign (a, u1, digits);
    }

    /* Zeroize potentially sensitive information.
    */
    R_memset ((POINTER)q, 0, sizeof (q));
    R_memset ((POINTER)t1, 0, sizeof (t1));
    R_memset ((POINTER)t3, 0, sizeof (t3));
    R_memset ((POINTER)u1, 0, sizeof (u1));
    R_memset ((POINTER)u3, 0, sizeof (u3));
    R_memset ((POINTER)v1, 0, sizeof (v1));
    R_memset ((POINTER)v3, 0, sizeof (v3));
    R_memset ((POINTER)w, 0, sizeof (w));
}

/* Computes a = gcd(b, c).

Lengths: a[digits], b[digits], c[digits].
Assumes b > c, digits < MAX_NN_DIGITS.
*/
void NN_Gcd (NN_DIGIT *a, NN_DIGIT *b, NN_DIGIT *c, unsigned int digits)
{
    NN_DIGIT t[MAX_NN_DIGITS] = {0}, u[MAX_NN_DIGITS] = {0}, v[MAX_NN_DIGITS] = {0};

    NN_Assign (u, b, digits);
    NN_Assign (v, c, digits);

    while (! NN_Zero (v, digits))
    {
        NN_Mod (t, u, digits, v, digits);
        NN_Assign (u, v, digits);
        NN_Assign (v, t, digits);
    }

    NN_Assign (a, u, digits);

    /* Zeroize potentially sensitive information.
    */
    R_memset ((POINTER)t, 0, sizeof (t));
    R_memset ((POINTER)u, 0, sizeof (u));
    R_memset ((POINTER)v, 0, sizeof (v));
}

/* Returns sign of a - b.

Lengths: a[digits], b[digits].
*/
int NN_Cmp (NN_DIGIT *a, NN_DIGIT *b, unsigned int digits)
{
    int i = 0;

    for (i = digits - 1; i >= 0; i--)
    {
        if (a[i] > b[i])
        {
            return (1);
        }
        if (a[i] < b[i])
        {
            return (-1);
        }
    }

    return (0);
}

/* Returns nonzero iff a is zero.

Lengths: a[digits].
*/
int NN_Zero (NN_DIGIT *a, unsigned int digits)
{
    unsigned int i = 0;

    for (i = 0; i < digits; i++)
        if (a[i])
        {
            return (0);
        }

    return (1);
}

/* Returns the significant length of a in bits.

Lengths: a[digits].
*/
// unsigned int NN_Bits (NN_DIGIT *a,unsigned int digits)
// {
// 	if( 0==(digits = NN_Digits (a, digits)) )
// 		return (0);
//
// 	return ((digits - 1) * NN_DIGIT_BITS + NN_DigitBits (a[digits-1]));
// }

/* Returns the significant length of a in digits.

Lengths: a[digits].
*/
unsigned int NN_Digits (NN_DIGIT *a, unsigned int digits)
{
    int i = 0;

    for (i = digits - 1; i >= 0; i--)
        if (a[i])
        {
            break;
        }

    return (i + 1);
}

/* Computes a = b * 2^c (i.e., shifts left c bits), returning carry.

Lengths: a[digits], b[digits].
Requires c < NN_DIGIT_BITS.
*/
static NN_DIGIT NN_LShift (NN_DIGIT *a, NN_DIGIT *b, unsigned int c, unsigned int digits)
{
    NN_DIGIT bi = 0, carry = 0;
    unsigned int i = 0, t = 0;

    if (c >= NN_DIGIT_BITS)
    {
        return (0);
    }

    t = NN_DIGIT_BITS - c;

    carry = 0;

    for (i = 0; i < digits; i++)
    {
        bi = b[i];
        a[i] = (bi << c) | carry;
        carry = c ? (bi >> t) : 0;
    }

    return (carry);
}

/* Computes a = c div 2^c (i.e., shifts right c bits), returning carry.

Lengths: a[digits], b[digits].
Requires: c < NN_DIGIT_BITS.
*/
static NN_DIGIT NN_RShift (NN_DIGIT *a, NN_DIGIT *b, unsigned int c, unsigned int digits)
{
    NN_DIGIT bi = 0, carry = 0;
    int i = 0;
    unsigned int t = 0;

    if (c >= NN_DIGIT_BITS)
    {
        return (0);
    }

    t = NN_DIGIT_BITS - c;

    carry = 0;

    for (i = digits - 1; i >= 0; i--)
    {
        bi = b[i];
        a[i] = (bi >> c) | carry;
        carry = c ? (bi << t) : 0;
    }

    return (carry);
}

/* Computes a = c div d and b = c mod d.

Lengths: a[cDigits], b[dDigits], c[cDigits], d[dDigits].
Assumes d > 0, cDigits < 2 * MAX_NN_DIGITS,
dDigits < MAX_NN_DIGITS.
*/
static void NN_Div (NN_DIGIT *a, NN_DIGIT *b, NN_DIGIT *c, unsigned int  cDigits, NN_DIGIT *d, unsigned int dDigits)
{
    NN_DIGIT ai = 0, cc[2 * MAX_NN_DIGITS + 1] = {0}, dd[MAX_NN_DIGITS] = {0}, t = 0;
    int i = 0;
    unsigned int ddDigits = 0, shift = 0;

    ddDigits = NN_Digits (d, dDigits);
    if ( 0 == ddDigits )
    {
        return;
    }

    /* Normalize operands.
    */
    shift = NN_DIGIT_BITS - NN_DigitBits (d[ddDigits - 1]);
    NN_AssignZero (cc, ddDigits);
    cc[cDigits] = NN_LShift (cc, c, shift, cDigits);
    NN_LShift (dd, d, shift, ddDigits);
    t = dd[ddDigits - 1];

    NN_AssignZero (a, cDigits);

    for (i = cDigits - ddDigits; i >= 0; i--)
    {
        /* Underestimate quotient digit and subtract.
        */
        if (MAX_NN_DIGIT == t )
        {
            ai = cc[i + dDigits];
        }
        else
        {
            NN_DigitDiv (&ai, &cc[i + ddDigits - 1], t + 1);
        }
        cc[i + ddDigits] -= NN_SubDigitMult (&cc[i], &cc[i], ai, dd, ddDigits);

        /* Correct estimate.
        */
        while (cc[i + ddDigits] || (NN_Cmp (&cc[i], dd, ddDigits) >= 0))
        {
            ai++;
            cc[i + ddDigits] -= NN_Sub (&cc[i], &cc[i], dd, ddDigits);
        }

        a[i] = ai;
    }

    /* Restore result.
    */
    NN_AssignZero (b, dDigits);
    NN_RShift (b, cc, shift, ddDigits);

    /* Zeroize potentially sensitive information.
    */
    R_memset ((POINTER)cc, 0, sizeof (cc));
    R_memset ((POINTER)dd, 0, sizeof (dd));
}

/* Computes a = b + c*d, where c is a digit. Returns carry.

Lengths: a[digits], b[digits], d[digits].
*/
static NN_DIGIT NN_AddDigitMult (NN_DIGIT *a, NN_DIGIT *b, NN_DIGIT c, NN_DIGIT *d, unsigned int digits)
{
    NN_DIGIT carry = 0, t[2] = {0};
    unsigned int i = 0;

    if (0 == c )
    {
        return (0);
    }

    carry = 0;
    for (i = 0; i < digits; i++)
    {
        NN_DigitMult (t, c, d[i]);
        if ((a[i] = b[i] + carry) < carry)
        {
            carry = 1;
        }
        else
        {
            carry = 0;
        }
        if ((a[i] += t[0]) < t[0])
        {
            carry++;
        }
        carry += t[1];
    }

    return (carry);
}

/* Computes a = b - c*d, where c is a digit. Returns borrow.

Lengths: a[digits], b[digits], d[digits].
*/
static NN_DIGIT NN_SubDigitMult (NN_DIGIT *a, NN_DIGIT *b, NN_DIGIT c, NN_DIGIT *d, unsigned int digits)
{
    NN_DIGIT borrow = 0, t[2] = {0};
    unsigned int i = 0;

    if (0 == c)
    {
        return (0);
    }

    borrow = 0;
    for (i = 0; i < digits; i++)
    {
        NN_DigitMult (t, c, d[i]);
        if ((a[i] = b[i] - borrow) > (MAX_NN_DIGIT - borrow))
        {
            borrow = 1;
        }
        else
        {
            borrow = 0;
        }
        if ((a[i] -= t[0]) > (MAX_NN_DIGIT - t[0]))
        {
            borrow++;
        }
        borrow += t[1];
    }

    return (borrow);
}

/* Returns the significant length of a in bits, where a is a digit.
*/
static unsigned int NN_DigitBits (NN_DIGIT a)
{
    unsigned int i = 0;

    for (i = 0; i < NN_DIGIT_BITS; i++, a >>= 1)
        if (0 == a)
        {
            break;
        }

    return (i);
}



/* Computes a = b * c, where b and c are digits.

Lengths: a[2].
*/
void NN_DigitMult (NN_DIGIT a[2], NN_DIGIT b, NN_DIGIT c)
{
    NN_DIGIT t = 0, u = 0;
    NN_HALF_DIGIT bHigh = 0, bLow = 0, cHigh = 0, cLow = 0;

    bHigh = HIGH_HALF (b);
    bLow = LOW_HALF (b);
    cHigh = HIGH_HALF (c);
    cLow = LOW_HALF (c);

    a[0] = (NN_DIGIT)bLow * (NN_DIGIT)cLow;
    t = (NN_DIGIT)bLow * (NN_DIGIT)cHigh;
    u = (NN_DIGIT)bHigh * (NN_DIGIT)cLow;
    a[1] = (NN_DIGIT)bHigh * (NN_DIGIT)cHigh;

    if ((t += u) < u)
    {
        a[1] += TO_HIGH_HALF (1);
    }
    u = TO_HIGH_HALF (t);

    if ((a[0] += u) < u)
    {
        a[1]++;
    }
    a[1] += HIGH_HALF (t);
}

/* Sets a = b / c, where a and c are digits.

Lengths: b[2].
Assumes b[1] < c and HIGH_HALF (c) > 0. For efficiency, c should be
normalized.
*/
void NN_DigitDiv (NN_DIGIT *a, NN_DIGIT  b[2], NN_DIGIT c)
{
    NN_DIGIT t[2] = {0}, u = 0, v = 0;
    NN_HALF_DIGIT aHigh = 0, aLow = 0, cHigh = 0, cLow = 0;

    cHigh = HIGH_HALF (c);
    cLow = LOW_HALF (c);

    t[0] = b[0];
    t[1] = b[1];

    /* Underestimate high half of quotient and subtract.
    */
    if (MAX_NN_HALF_DIGIT == cHigh)
    {
        aHigh = HIGH_HALF (t[1]);
    }
    else
    {
        aHigh = (NN_HALF_DIGIT)(t[1] / (cHigh + 1));
    }
    u = (NN_DIGIT)aHigh * (NN_DIGIT)cLow;
    v = (NN_DIGIT)aHigh * (NN_DIGIT)cHigh;
    if ((t[0] -= TO_HIGH_HALF (u)) > (MAX_NN_DIGIT - TO_HIGH_HALF (u)))
    {
        t[1]--;
    }
    t[1] -= HIGH_HALF (u);
    t[1] -= v;

    /* Correct estimate.
    */
    while ((t[1] > cHigh) ||
            ((t[1] == cHigh) && (t[0] >= TO_HIGH_HALF (cLow))))
    {
        if ((t[0] -= TO_HIGH_HALF (cLow)) > MAX_NN_DIGIT - TO_HIGH_HALF (cLow))
        {
            t[1]--;
        }
        t[1] -= cHigh;
        aHigh++;
    }

    /* Underestimate low half of quotient and subtract.
    */
    if (MAX_NN_HALF_DIGIT == cHigh)
    {
        aLow = LOW_HALF (t[1]);
    }
    else
        aLow =
                (NN_HALF_DIGIT)
                ((NN_DIGIT)(TO_HIGH_HALF (t[1]) + HIGH_HALF (t[0])) / (cHigh + 1));
    u = (NN_DIGIT)aLow * (NN_DIGIT)cLow;
    v = (NN_DIGIT)aLow * (NN_DIGIT)cHigh;
    if ((t[0] -= u) > (MAX_NN_DIGIT - u))
    {
        t[1]--;
    }
    if ((t[0] -= TO_HIGH_HALF (v)) > (MAX_NN_DIGIT - TO_HIGH_HALF (v)))
    {
        t[1]--;
    }
    t[1] -= HIGH_HALF (v);

    /* Correct estimate.
    */
    while ((t[1] > 0) || ((0 == t[1]) && t[0] >= c))
    {
        if ((t[0] -= c) > (MAX_NN_DIGIT - c))
        {
            t[1]--;
        }
        aLow++;
    }

    *a = TO_HIGH_HALF (aHigh) + aLow;
}

/* Returns nonzero iff a and b are relatively prime.

   Lengths: a[aDigits], b[bDigits].
   Assumes aDigits >= bDigits, aDigits < MAX_NN_DIGITS.
 */
static int RelativelyPrime (NN_DIGIT *a, unsigned int aDigits, NN_DIGIT *b, unsigned int bDigits)
{
    int status = 0;
    NN_DIGIT t[MAX_NN_DIGITS] = {0}, u[MAX_NN_DIGITS] = {0};

    NN_AssignZero (t, aDigits);
    NN_Assign (t, b, bDigits);
    NN_Gcd (t, a, t, aDigits);
    NN_ASSIGN_DIGIT (u, 1, aDigits);

    status = NN_EQUAL (t, u, aDigits);

    /* Zeroize sensitive information.
     */
    R_memset ((POINTER)t, 0, sizeof (t));

    return (status);
}

/* Returns nonzero iff GCD (a-1, b) = 1.

   Lengths: a[aDigits], b[bDigits].
   Assumes aDigits < MAX_NN_DIGITS, bDigits < MAX_NN_DIGITS.
 */
static int RSAFilter (NN_DIGIT *a, unsigned int aDigits, NN_DIGIT *b, unsigned int bDigits)
{
    int status = 0;
    NN_DIGIT aMinus1[MAX_NN_DIGITS] = {0}, t[MAX_NN_DIGITS] = {0};

    NN_ASSIGN_DIGIT (t, 1, aDigits);
    NN_Sub (aMinus1, a, t, aDigits);

    status = RelativelyPrime (aMinus1, aDigits, b, bDigits);

    /* Zeroize sensitive information.
     */
    R_memset ((POINTER)aMinus1, 0, sizeof (aMinus1));

    return (status);
}

int R_GenerateBytes (unsigned char *block, unsigned int blockLen, R_RANDOM_STRUCT *randomStruct)
{
    sha1_context context = {0};
    unsigned char digest[20];
    unsigned int available = 0, i = 0;

    if (randomStruct->bytesNeeded)
    {
        return (RE_NEED_RANDOM);
    }

    available = randomStruct->outputAvailable;

    while (blockLen > available)
    {
        memcpy((POINTER)block, (POINTER)&randomStruct->output[16 - available], available);
        block += available;
        blockLen -= available;

        /* generate new output */
        sha1_init (&context);
        sha1_update (&context, randomStruct->state, 16);
        sha1_final (digest, &context);
        available = 16;

        memcpy(randomStruct->output, digest, 16);
        /* increment state */
        for (i = 0; i < 16; i++)
            if (randomStruct->state[15 - i]++)
            {
                break;
            }
    }

    memcpy((POINTER)block, (POINTER)&randomStruct->output[16 - available], blockLen);
    randomStruct->outputAvailable = available - blockLen;

    return (0);
}

/* Returns nonzero iff a passes Fermat's test for witness 2.
   (All primes pass the test, and nearly all composites fail.)

   Lengths: a[aDigits].
   Assumes aDigits < MAX_NN_DIGITS.
 */
static int FermatTest (NN_DIGIT *a, unsigned int  aDigits)
{
    int status = 0;
    NN_DIGIT t[MAX_NN_DIGITS] = {0}, u[MAX_NN_DIGITS] = {0};

    NN_ASSIGN_DIGIT (t, 2, aDigits);
    NN_ModExp (u, t, a, aDigits, a, aDigits);

    status = NN_EQUAL (t, u, aDigits);

    /* Zeroize sensitive information.
     */
    R_memset ((POINTER)u, 0, sizeof (u));

    return (status);
}

/* Returns nonzero iff a has a prime factor in SMALL_PRIMES.

   Lengths: a[aDigits].
   Assumes aDigits < MAX_NN_DIGITS.
 */
static int SmallFactor (NN_DIGIT *a, unsigned int aDigits)
{
    int status = 0;
    NN_DIGIT t[1] = {0};
    unsigned int i = 0;

    status = 0;

    for (i = 0; i < SMALL_PRIME_COUNT; i++)
    {
        NN_ASSIGN_DIGIT (t, SMALL_PRIMES[i], 1);
        if ((1 == aDigits) && ! NN_Cmp (a, t, 1))
        {
            break;
        }
        NN_Mod (t, a, aDigits, t, 1);
        if (NN_Zero (t, 1))
        {
            status = 1;
            break;
        }
    }

    /* Zeroize sensitive information.
     */
    i = 0;
    R_memset ((POINTER)t, 0, sizeof (t));

    return (status);
}

/* Returns nonzero iff a is a probable prime.

   Lengths: a[aDigits].
   Assumes aDigits < MAX_NN_DIGITS.
 */
static int ProbablePrime (NN_DIGIT *a, unsigned int aDigits)
{
    return (! SmallFactor (a, aDigits) && FermatTest (a, aDigits));
}



/* Generates a probable prime a between b and c such that a-1 is
   divisible by d.

   Lengths: a[digits], b[digits], c[digits], d[digits].
   Assumes b < c, digits < MAX_NN_DIGITS.

   Returns RE_NEED_RANDOM if randomStruct not seeded, RE_DATA if
   unsuccessful.
 */
static int GeneratePrime (NN_DIGIT *a, NN_DIGIT *b, NN_DIGIT *c, NN_DIGIT *d, unsigned int digits, R_RANDOM_STRUCT * randomStruct)
{
    int status = 0;
    unsigned char block[MAX_NN_DIGITS * NN_DIGIT_LEN] = {0};
    NN_DIGIT t[MAX_NN_DIGITS] = {0}, u[MAX_NN_DIGITS] = {0};

    /* Generate random number between b and c.
     */
    if (status = R_GenerateBytes (block, digits * NN_DIGIT_LEN, randomStruct))
    {
        return (status);
    }
    NN_Decode (a, digits, block, digits * NN_DIGIT_LEN);
    NN_Sub (t, c, b, digits);
    NN_ASSIGN_DIGIT (u, 1, digits);
    NN_Add (t, t, u, digits);
    NN_Mod (a, a, digits, t, digits);
    NN_Add (a, a, b, digits);

    /* Adjust so that a-1 is divisible by d.
     */
    NN_Mod (t, a, digits, d, digits);
    NN_Sub (a, a, t, digits);
    NN_Add (a, a, u, digits);
    if (NN_Cmp (a, b, digits) < 0)
    {
        NN_Add (a, a, d, digits);
    }
    if (NN_Cmp (a, c, digits) > 0)
    {
        NN_Sub (a, a, d, digits);
    }

    /* Search to c in steps of d.
     */
    NN_Assign (t, c, digits);
    NN_Sub (t, t, d, digits);

    while (! ProbablePrime (a, digits))
    {
        if (NN_Cmp (a, t, digits) > 0)
        {
            return (RE_DATA);
        }
        NN_Add (a, a, d, digits);
    }

    return (0);
}

/* Assigns a = 2^b.

   Lengths: a[digits].
   Requires b < digits * NN_DIGIT_BITS.
 */
void NN_Assign2Exp (NN_DIGIT *a, unsigned int b, unsigned int digits)
{
    NN_AssignZero (a, digits);

    if (b >= digits * NN_DIGIT_BITS)
    {
        return;
    }

    a[b / NN_DIGIT_BITS] = (NN_DIGIT)1 << (b % NN_DIGIT_BITS);
}

int RandomUpdate (R_RANDOM_STRUCT * randomStruct, unsigned char * block, unsigned int blockLen)                                 /* length of block */
{
    sha1_context context = {0};
    unsigned char digest[16] = {0};
    unsigned int i = 0, x = 0;

    sha1_init (&context);
    sha1_update (&context, block, blockLen);
    sha1_final (digest, &context);

    /* add digest to state */
    x = 0;
    for (i = 0; i < 16; i++)
    {
        x += randomStruct->state[15 - i] + digest[15 - i];
        randomStruct->state[15 - i] = (unsigned char)x;
        x >>= 8;
    }

    if (randomStruct->bytesNeeded < blockLen)
    {
        randomStruct->bytesNeeded = 0;
    }
    else
    {
        randomStruct->bytesNeeded -= blockLen;
    }

    /* Zeroize sensitive information.
     */
    memset (digest, 0, sizeof (digest));
    x = 0;

    return (0);
}


/* Generates an RSA key pair with a given length and public exponent.
 */
int RSAGenerateKeys(unsigned int bits, R_RSA_PUBLIC_KEY *publicKey, R_RSA_PRIVATE_KEY *privateKey)
{
    NN_DIGIT d[MAX_NN_DIGITS], dP[MAX_NN_DIGITS], dQ[MAX_NN_DIGITS],
             e[MAX_NN_DIGITS], n[MAX_NN_DIGITS], p[MAX_NN_DIGITS], phiN[MAX_NN_DIGITS],
             pMinus1[MAX_NN_DIGITS], q[MAX_NN_DIGITS], qInv[MAX_NN_DIGITS],
             qMinus1[MAX_NN_DIGITS], t[MAX_NN_DIGITS], u[MAX_NN_DIGITS],
             v[MAX_NN_DIGITS];
    int status;
    unsigned int nDigits, pBits, pDigits, qBits, i;
    unsigned char temp;
    R_RANDOM_STRUCT   randomStruct;
    unsigned int useFermat4 = 1;

#ifdef WINCE
    srand(timeGetTime(0));
#else
    srand((unsigned int)time(0));
#endif
    randomStruct.bytesNeeded = RANDOM_BYTES_NEEDED;
    memset (randomStruct.state, 0, sizeof (randomStruct.state));
    randomStruct.outputAvailable = 0;
    for (i = 0; i < RANDOM_BYTES_NEEDED; i++)
    {
        temp = rand();
        RandomUpdate(&randomStruct, (unsigned char *)&temp, 1);
    }

    if ((bits < MIN_RSA_MODULUS_BITS) || (bits > MAX_RSA_MODULUS_BITS))
    {
        return (RE_MODULUS_LEN);
    }
    nDigits = (bits + NN_DIGIT_BITS - 1) / NN_DIGIT_BITS;
    pDigits = (nDigits + 1) / 2;
    pBits = (bits + 1) / 2;
    qBits = bits - pBits;

    /* NOTE: for 65537, this assumes NN_DIGIT is at least 17 bits. */
    NN_ASSIGN_DIGIT
    (e, useFermat4 ? (NN_DIGIT)65537 : (NN_DIGIT)3, nDigits);

    /* Generate prime p between 3*2^(pBits-2) and 2^pBits-1, searching
         in steps of 2, until one satisfies gcd (p-1, e) = 1.
     */
    NN_Assign2Exp (t, pBits - 1, pDigits);
    NN_Assign2Exp (u, pBits - 2, pDigits);
    NN_Add (t, t, u, pDigits);
    NN_ASSIGN_DIGIT (v, 1, pDigits);
    NN_Sub (v, t, v, pDigits);
    NN_Add (u, u, v, pDigits);
    NN_ASSIGN_DIGIT (v, 2, pDigits);
    do
    {
        if (status = GeneratePrime (p, t, u, v, pDigits, &randomStruct))
        {
            return (status);
        }
    } while (! RSAFilter (p, pDigits, e, 1));

    /* Generate prime q between 3*2^(qBits-2) and 2^qBits-1, searching
         in steps of 2, until one satisfies gcd (q-1, e) = 1.
     */
    NN_Assign2Exp (t, qBits - 1, pDigits);
    NN_Assign2Exp (u, qBits - 2, pDigits);
    NN_Add (t, t, u, pDigits);
    NN_ASSIGN_DIGIT (v, 1, pDigits);
    NN_Sub (v, t, v, pDigits);
    NN_Add (u, u, v, pDigits);
    NN_ASSIGN_DIGIT (v, 2, pDigits);
    do
    {
        if (status = GeneratePrime (q, t, u, v, pDigits, &randomStruct))
        {
            return (status);
        }
    } while (! RSAFilter (q, pDigits, e, 1));

    /* Sort so that p > q. (p = q case is extremely unlikely.)
     */
    if (NN_Cmp (p, q, pDigits) < 0)
    {
        NN_Assign (t, p, pDigits);
        NN_Assign (p, q, pDigits);
        NN_Assign (q, t, pDigits);
    }

    /* Compute n = pq, qInv = q^{-1} mod p, d = e^{-1} mod (p-1)(q-1),
       dP = d mod p-1, dQ = d mod q-1.
     */
    NN_Mult (n, p, q, pDigits);
    NN_ModInv (qInv, q, p, pDigits);

    NN_ASSIGN_DIGIT (t, 1, pDigits);
    NN_Sub (pMinus1, p, t, pDigits);
    NN_Sub (qMinus1, q, t, pDigits);
    NN_Mult (phiN, pMinus1, qMinus1, pDigits);

    NN_ModInv (d, e, phiN, nDigits);
    NN_Mod (dP, d, nDigits, pMinus1, pDigits);
    NN_Mod (dQ, d, nDigits, qMinus1, pDigits);

    publicKey->bits = privateKey->bits = bits;
    NN_Encode (publicKey->modulus, MAX_RSA_MODULUS_LEN, n, nDigits);
    NN_Encode (publicKey->exponent, MAX_RSA_MODULUS_LEN, e, 1);
    memcpy((POINTER)privateKey->modulus, (POINTER)publicKey->modulus, MAX_RSA_MODULUS_LEN);
    memcpy((POINTER)privateKey->publicExponent, (POINTER)publicKey->exponent, MAX_RSA_MODULUS_LEN);
    NN_Encode (privateKey->exponent, MAX_RSA_MODULUS_LEN, d, nDigits);
    NN_Encode (privateKey->prime[0], MAX_RSA_PRIME_LEN, p, pDigits);
    NN_Encode (privateKey->prime[1], MAX_RSA_PRIME_LEN, q, pDigits);
    NN_Encode (privateKey->primeExponent[0], MAX_RSA_PRIME_LEN, dP, pDigits);
    NN_Encode (privateKey->primeExponent[1], MAX_RSA_PRIME_LEN, dQ, pDigits);
    NN_Encode (privateKey->coefficient, MAX_RSA_PRIME_LEN, qInv, pDigits);

    /* Zeroize sensitive information.
     */
    R_memset ((POINTER)d, 0, sizeof (d));
    R_memset ((POINTER)dP, 0, sizeof (dP));
    R_memset ((POINTER)dQ, 0, sizeof (dQ));
    R_memset ((POINTER)p, 0, sizeof (p));
    R_memset ((POINTER)phiN, 0, sizeof (phiN));
    R_memset ((POINTER)pMinus1, 0, sizeof (pMinus1));
    R_memset ((POINTER)q, 0, sizeof (q));
    R_memset ((POINTER)qInv, 0, sizeof (qInv));
    R_memset ((POINTER)qMinus1, 0, sizeof (qMinus1));
    R_memset ((POINTER)t, 0, sizeof (t));

    return (0);
}

/* Raw RSA public-key operation. Output has same length as modulus.

Assumes inputLen < length of modulus.
Requires input < modulus.
*/
int RSAPublicBlock (unsigned char *output, unsigned int *outputLen, const unsigned char *input, unsigned int inputLen, R_RSA_PUBLIC_KEY *publicKey)
{

    NN_DIGIT c[MAX_NN_DIGITS], e[MAX_NN_DIGITS], m[MAX_NN_DIGITS], n[MAX_NN_DIGITS];
    unsigned int eDigits, nDigits;
    // 	int ss=MAX_NN_DIGITS;
    // 	int mm=MAX_RSA_MODULUS_LEN;

    NN_Decode (m, MAX_NN_DIGITS, input, inputLen);
    NN_Decode (n, MAX_NN_DIGITS, publicKey->modulus, MAX_RSA_MODULUS_LEN);
    NN_Decode (e, MAX_NN_DIGITS, publicKey->exponent, MAX_RSA_MODULUS_LEN);
    nDigits = NN_Digits (n, MAX_NN_DIGITS);
    eDigits = NN_Digits (e, MAX_NN_DIGITS);

    if (NN_Cmp (m, n, nDigits) >= 0)
    {
        return (RE_DATA);
    }

    /* Compute c = m^e mod n.
    */
    NN_ModExp (c, m, e, eDigits, n, nDigits);

    *outputLen = (publicKey->bits + 7) / 8;
    NN_Encode (output, *outputLen, c, nDigits);

    /* Zeroize sensitive information.
    */
    R_memset ((POINTER)c, 0, sizeof (c));
    R_memset ((POINTER)m, 0, sizeof (m));

    return (0);
}

/* Raw RSA private-key operation. Output has same length as modulus.

Assumes inputLen < length of modulus.
Requires input < modulus.
*/
int RSAPrivateBlock (unsigned char *output, unsigned int *outputLen, unsigned char *input, unsigned int inputLen, R_RSA_PRIVATE_KEY *privateKey  )
{
    NN_DIGIT c[MAX_NN_DIGITS], cP[MAX_NN_DIGITS], cQ[MAX_NN_DIGITS],
             dP[MAX_NN_DIGITS], dQ[MAX_NN_DIGITS], mP[MAX_NN_DIGITS],
             mQ[MAX_NN_DIGITS]/*, n[MAX_NN_DIGITS]*/, p[MAX_NN_DIGITS], q[MAX_NN_DIGITS],
             qInv[MAX_NN_DIGITS], t[MAX_NN_DIGITS];
    unsigned int cDigits, nDigits, pDigits;

    NN_Decode (c, MAX_NN_DIGITS, input, inputLen);
    //NN_Decode (n, MAX_NN_DIGITS, privateKey->modulus, MAX_RSA_MODULUS_LEN);
    NN_Decode (p, MAX_NN_DIGITS, privateKey->prime[0], MAX_RSA_PRIME_LEN);
    NN_Decode (q, MAX_NN_DIGITS, privateKey->prime[1], MAX_RSA_PRIME_LEN);
    NN_Decode (dP, MAX_NN_DIGITS, privateKey->primeExponent[0], MAX_RSA_PRIME_LEN);
    NN_Decode (dQ, MAX_NN_DIGITS, privateKey->primeExponent[1], MAX_RSA_PRIME_LEN);
    NN_Decode (qInv, MAX_NN_DIGITS, privateKey->coefficient, MAX_RSA_PRIME_LEN);
    cDigits = NN_Digits (c, MAX_NN_DIGITS);
    nDigits = inputLen / 4; //NN_Digits (n, MAX_NN_DIGITS);   ˽Կ\BDṹ\CC\E5\D6\D0\CE\DE\D0\E8\CC\EEдn\C4\DA\C8\DD
    pDigits = NN_Digits (p, MAX_NN_DIGITS);

    /*
    if(NN_Cmp (c, n, nDigits) >= 0)
    	return (RE_DATA);
    */

    /* Compute mP = cP^dP mod p  and  mQ = cQ^dQ mod q. (Assumes q has
    length at most pDigits, i.e., p > q.)
    */
    NN_Mod (cP, c, cDigits, p, pDigits);
    NN_Mod (cQ, c, cDigits, q, pDigits);
    NN_ModExp (mP, cP, dP, pDigits, p, pDigits);
    NN_AssignZero (mQ, nDigits);
    NN_ModExp (mQ, cQ, dQ, pDigits, q, pDigits);

    /* Chinese Remainder Theorem:
    m = ((((mP - mQ) mod p) * qInv) mod p) * q + mQ.
    */
    if (NN_Cmp (mP, mQ, pDigits) >= 0)
    {
        NN_Sub (t, mP, mQ, pDigits);
    }
    else
    {
        NN_Sub (t, mQ, mP, pDigits);
        NN_Mod (t, t, pDigits, p, pDigits); //avoid t > p
        NN_Sub (t, p, t, pDigits);
    }
    NN_ModMult (t, t, qInv, p, pDigits);
    NN_Mult (t, t, q, pDigits);
    NN_Add (t, t, mQ, nDigits);

    *outputLen = (privateKey->bits + 7) / 8;
    NN_Encode (output, *outputLen, t, nDigits);

    /* Zeroize sensitive information.
    */
    R_memset ((POINTER)c, 0, sizeof (c));
    R_memset ((POINTER)cP, 0, sizeof (cP));
    R_memset ((POINTER)cQ, 0, sizeof (cQ));
    R_memset ((POINTER)dP, 0, sizeof (dP));
    R_memset ((POINTER)dQ, 0, sizeof (dQ));
    R_memset ((POINTER)mP, 0, sizeof (mP));
    R_memset ((POINTER)mQ, 0, sizeof (mQ));
    R_memset ((POINTER)p, 0, sizeof (p));
    R_memset ((POINTER)q, 0, sizeof (q));
    R_memset ((POINTER)qInv, 0, sizeof (qInv));
    R_memset ((POINTER)t, 0, sizeof (t));

    return (0);
}
