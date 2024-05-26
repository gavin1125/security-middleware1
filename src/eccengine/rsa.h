/**
 * @file rsa.h
 * @date 20220608
 */

#ifndef _RSAHEADER_H_
#define _RSAHEADER_H_

#ifdef __cplusplus
extern "C" {
#endif



//RSA算法密钥长度
#define MIN_RSA_MODULUS_BITS 508
#define MAX_RSA_MODULUS_BITS 2048
#define MAX_RSA_MODULUS_LEN ((MAX_RSA_MODULUS_BITS + 7) / 8)
#define MAX_RSA_PRIME_BITS ((MAX_RSA_MODULUS_BITS + 1) / 2)
#define MAX_RSA_PRIME_LEN ((MAX_RSA_PRIME_BITS + 7) / 8)



//错误码
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

//RSA公钥结构
typedef struct
{
    unsigned int bits;                           /* length in bits of modulus */
    unsigned char modulus[MAX_RSA_MODULUS_LEN];                    /* modulus */
    unsigned char exponent[MAX_RSA_MODULUS_LEN];           /* public exponent */
} R_RSA_PUBLIC_KEY;

//RSA私钥结构
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

//RSA保护密钥结构
typedef struct
{
    unsigned int bits;                           /* length in bits of modulus */
    int useFermat4;                        /* public exponent (1 = F4(65537), 0 = 3) */
} R_RSA_PROTO_KEY;

//RSA随机数结构
typedef struct
{
    unsigned int bytesNeeded;
    unsigned char state[16];
    unsigned int outputAvailable;
    unsigned char output[16];
} R_RANDOM_STRUCT;


/**
* @brief RSA公钥计算
*
* @param[out] output 运算结果
* @param[out] outputLen 运算结果长度
* @param[in] input 待处理数据
* @param[in] inputLen 待处理数据长度
* @param[in] publicKey RSA公钥结构
*
* @return 0
* @retval 0 成功
*/
int RSAPublicBlock (unsigned char *output, unsigned int *outputLen, const unsigned char *input, unsigned int inputLen, R_RSA_PUBLIC_KEY *publicKey) ;
/**
* @brief RSA私钥计算
*
* @param[out] output 运算结果
* @param[out] outputLen 运算结果长度
* @param[in] input 待处理数据
* @param[in] inputLen 待处理数据长度
* @param[in] privateKey RSA私钥结构
*
* @return 0
* @retval 0 成功
*/
int RSAPrivateBlock (unsigned char *output, unsigned int *outputLen, unsigned char *input, unsigned int inputLen, R_RSA_PRIVATE_KEY *privateKey)  ;
/**
* @brief 产生RSA密钥对
*
* @param[in] bits 运算结果
* @param[in] publicKey 运算结果长度
* @param[in] privateKey RSA私钥结构
*
* @return 错误码
* @retval 0 算法运算成功
*/
int RSAGenerateKeys(unsigned int bits, R_RSA_PUBLIC_KEY *publicKey, R_RSA_PRIVATE_KEY *privateKey);

#ifdef __cplusplus
}
#endif

#endif
