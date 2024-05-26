/**
 * @file AES.h
 * @brief AES算法代码，实现了ECB\CBC\CFB\CTR\CCM等模式
 * @version 1.0.0
 * @date 2024-03-12
 */
#ifndef _SOFTSM4_INC_H
#define _SOFTSM4_INC_H

//加密模式
#define SM4_ENCRYPT     1
#define SM4_DECRYPT     0

//错误代码
#define  SM4_RES_OK            0    //成功
#define  SM4_RES_FAILED       -1
#define  SM4_RES_PARAM_ERR    -2
#define  SM4_RES_TAG_ERR      -3	//CCM 或者 GCM解密tag比较失败


/**
 * @brief          SM4 context structure
 */
typedef struct
{
    int mode;                   /*!<  encrypt/decrypt   */
    unsigned int sk[32];       /*!<  SM4 subkeys       */
}
sm4_context;


#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief          SM4 key schedule (128-bit, encryption)
 *
 * @param ctx      SM4 context to be initialized
 * @param key      16-byte secret key
 */
void sm4_setkey( sm4_context *ctx, unsigned char key[16] );

/**
 * @brief          SM4-ECB block encryption/decryption
 *
 * @param ctx      SM4 context
 * @param mode     SM4_ENCRYPT or SM4_DECRYPT
 * @param length   length of the input data
 * @param input    input block
 * @param output   output block
 */
void sm4_crypt_ecb( sm4_context *ctx,
				     int mode,
					 int length,
                     unsigned char *input,
                     unsigned char *output);

/**
 * @brief          SM4-CBC buffer encryption/decryption
 *
 * @param ctx      SM4 context
 * @param mode     SM4_ENCRYPT or SM4_DECRYPT
 * @param length   length of the input data
 * @param iv       initialization vector (updated after use)
 * @param input    buffer holding the input data
 * @param output   buffer holding the output data
 */
void sm4_crypt_cbc( sm4_context *ctx,
                     int mode,
                     int length,
                     unsigned char iv[16],
                     unsigned char *input,
                     unsigned char *output );

/**
* @brief          SM4-OFB buffer encryption/decryption
*
* @param ctx      SM4 context
* @param mode     SM4_ENCRYPT or SM4_DECRYPT
* @param length   length of the input data
* @param iv       initialization vector (updated after use)
* @param input    buffer holding the input data
* @param output   buffer holding the output data
*/
void sm4_crypt_cfb( sm4_context *ctx,
                    int mode,
                    int length,
                    unsigned char iv[16],
                    unsigned char *input,
                    unsigned char *output );

/**
* @brief          SM4-OFB buffer encryption/decryption
*
* @param ctx      SM4 context
* @param mode     SM4_ENCRYPT or SM4_DECRYPT
* @param length   length of the input data
* @param iv       initialization vector (updated after use)
* @param input    buffer holding the input data
* @param output   buffer holding the output data
*/
void sm4_crypt_ofb( sm4_context *ctx,
                    int mode,
                    int length,
                    unsigned char iv[16],
                    unsigned char *input,
                    unsigned char *output );

/**
* @brief          SM4-OFB buffer encryption/decryption
*
* @param ctx      SM4 context
* @param mode     SM4_ENCRYPT or SM4_DECRYPT
* @param length   length of the input data
* @param iv       initialization vector (updated after use)
* @param input    buffer holding the input data
* @param output   buffer holding the output data
*/
void sm4_crypt_ctr( sm4_context *ctx,
                    int mode,
                    int length,
                    unsigned char iv[16],
                    unsigned char *input,
                    unsigned char *output );


/**
 * @brief sm4ccm运算
 *
 * @param[in]     pDataIn	  输入数据
 * @param[in]     dataLen     输入数据长度，单位：字节
 * @param[in]     mode        工作模式 1:encrypt,0:decrypt
 * @param[out]    pDataOut	  输出数据
 * @param[in]     iv          初始化向量nonce
 * @param[in]     Add         CCM模式的附加消息
 * @param[in]     lAdd        CCM中附加消息的长度，单位：字节（小于65536） 
 * @param[in/out] T           CCM模式中认证值, mode=1 输出  mode=0 输入
 * @param[in]     M           tag的长度，合法的值为：4, 6, 8, 10, 12, 14 和16。openssl中缺省的为12
 * @param[in]     L           长度域，取值为2~8 ，openssl中缺省的为8
 *
 * @return 错误码
 *   @retval 0 成功
 */
int sm4_crypt_ccm(sm4_context *ctx, unsigned char *pDataIn, unsigned long long dataLen,int mode,unsigned char *pDataOut,unsigned char *iv,unsigned char *Add,  unsigned long long lAdd,unsigned char* T,unsigned char M,unsigned char L);


#ifdef __cplusplus
}
#endif

#endif /* sm4.h */

