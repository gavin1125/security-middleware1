/**
 * @file rsa.h
 * @date 20220608
 */

#ifndef _RSAHEADER_H_
#define _RSAHEADER_H_

#ifdef __cplusplus
extern "C" {
#endif



//RSA�㷨��Կ����
#define MIN_RSA_MODULUS_BITS 508
#define MAX_RSA_MODULUS_BITS 2048
#define MAX_RSA_MODULUS_LEN ((MAX_RSA_MODULUS_BITS + 7) / 8)
#define MAX_RSA_PRIME_BITS ((MAX_RSA_MODULUS_BITS + 1) / 2)
#define MAX_RSA_PRIME_LEN ((MAX_RSA_PRIME_BITS + 7) / 8)



//������
#define RE_CONTENT_ENCODING 0x0400
#define RE_DATA 0x0401
#define RE_DIGEST_ALGORITHM 0x0402
#define RE_ENCODING 0x0403
#define RE_KEY 0x0404
#define RE_KEY_ENCODING 0x0405
#define RE_LEN 0x0406
#define RE_MODULUS_LEN 0x0407
#define RE_NEED_RANDOM 0x0408
#define RE_PRIVATE_KEY 0x0409
#define RE_PUBLIC_KEY 0x040a
#define RE_SIGNATURE 0x040b
#define RE_SIGNATURE_ENCODING 0x040c

static unsigned int SMALL_PRIMES[] = { 3, 5, 7, 11 };
#define SMALL_PRIME_COUNT 4
#define RANDOM_BYTES_NEEDED 256

//RSA��Կ�ṹ
typedef struct
{
    unsigned int bits;                           /* length in bits of modulus */
    unsigned char modulus[MAX_RSA_MODULUS_LEN];                    /* modulus */
    unsigned char exponent[MAX_RSA_MODULUS_LEN];           /* public exponent */
} R_RSA_PUBLIC_KEY;

//RSA˽Կ�ṹ
typedef struct
{
    unsigned int bits;                           /* length in bits of modulus */
    unsigned char modulus[MAX_RSA_MODULUS_LEN];                    /* modulus */
    unsigned char publicExponent[MAX_RSA_MODULUS_LEN];     /* public exponent */
    unsigned char exponent[MAX_RSA_MODULUS_LEN];          /* private exponent */
    unsigned char prime[2][MAX_RSA_PRIME_LEN];               /* prime factors */
    unsigned char primeExponent[2][MAX_RSA_PRIME_LEN];   /* exponents for CRT */
    unsigned char coefficient[MAX_RSA_PRIME_LEN];          /* CRT coefficient */
} R_RSA_PRIVATE_KEY;

//RSA������Կ�ṹ
typedef struct
{
    unsigned int bits;                           /* length in bits of modulus */
    int useFermat4;                        /* public exponent (1 = F4(65537), 0 = 3) */
} R_RSA_PROTO_KEY;

//RSA������ṹ
typedef struct
{
    unsigned int bytesNeeded;
    unsigned char state[16];
    unsigned int outputAvailable;
    unsigned char output[16];
} R_RANDOM_STRUCT;


/**
* @brief RSA��Կ����
*
* @param[out] output ������
* @param[out] outputLen ����������
* @param[in] input ����������
* @param[in] inputLen ���������ݳ���
* @param[in] publicKey RSA��Կ�ṹ
*
* @return 0
* @retval 0 �ɹ�
*/
int RSAPublicBlock (unsigned char *output, unsigned int *outputLen, const unsigned char *input, unsigned int inputLen, R_RSA_PUBLIC_KEY *publicKey) ;
/**
* @brief RSA˽Կ����
*
* @param[out] output ������
* @param[out] outputLen ����������
* @param[in] input ����������
* @param[in] inputLen ���������ݳ���
* @param[in] privateKey RSA˽Կ�ṹ
*
* @return 0
* @retval 0 �ɹ�
*/
int RSAPrivateBlock (unsigned char *output, unsigned int *outputLen, unsigned char *input, unsigned int inputLen, R_RSA_PRIVATE_KEY *privateKey)  ;
/**
* @brief ����RSA��Կ��
*
* @param[in] bits ������
* @param[in] publicKey ����������
* @param[in] privateKey RSA˽Կ�ṹ
*
* @return ������
* @retval 0 �㷨����ɹ�
*/
int RSAGenerateKeys(unsigned int bits, R_RSA_PUBLIC_KEY *publicKey, R_RSA_PRIVATE_KEY *privateKey);

#ifdef __cplusplus
}
#endif

#endif
