/**
 * @file AES.h
 * @brief AES算法代码，实现了ECB\CBC\CFB\CTR\CCM等模式
 * @version 1.0.0
 * @date 2023-04-19
 */

#ifndef _SOFTAES_INC_H
#define _SOFTAES_INC_H

#ifdef __cplusplus
extern "C" {
#endif

//加密模式
#ifndef OP_ENCRYPT
	#define OP_ENCRYPT 1
#endif
#ifndef OP_DECRYPT
	#define OP_DECRYPT 0
#endif

//错误代码
#define  AES_RES_OK            0        //成功
#define  AES_RES_FAILED       -1
#define  AES_RES_PARAM_ERR    -2
#define  AES_RES_TAG_ERR      -3	//CCM 或者 GCM解密tag比较失败


/**
 * @brief AESECB运算
 *
 * @param[in]     pDataIn	  输入数据
 * @param[in]     dataLen     输入数据长度，单位：字节
 * @param[in]     flag        工作模式 1:encrypt,0:decrypt
 * @param[out]    pDataOut	  输出数据
 * @param[in]     tmpkey      AES运算密钥
 * @param[in]     keylen      AES运算密钥长度，单位：字节
 *
 * @return 错误码
 *   @retval 0 成功
 */
int AesEcb(unsigned char *pDataIn,int dataLen,int flag,unsigned char *pDataOut,unsigned char* tmpkey,int keyLen);
/**
 * @brief AES运算CBC模式
 *
 * @param[in]     pDataIn	  输入数据
 * @param[in]     dataLen     输入数据长度，单位：字节
 * @param[in]     flag        工作模式 1:encrypt,0:decrypt
 * @param[out]    pDataOut	  输出数据
 * @param[in]     tmpkey      AES运算密钥
 * @param[in]     keylen      AES运算密钥长度，单位：字节
 * @param[in/out] iv          IV向量
 *
 * @return 错误码
 *   @retval 0 成功
 */
int AesCbc(unsigned char *pDataIn,int dataLen,int flag,unsigned char *pDataOut,unsigned char* tmpkey,int keyLen,unsigned char *iv);
/**
 * @brief AES运算CFB模式
 *
 * @param[in]     pDataIn	  输入数据
 * @param[in]     dataLen     输入数据长度，单位：字节
 * @param[in]     flag        工作模式 1:encrypt,0:decrypt
 * @param[out]    pDataOut	  输出数据
 * @param[in]     tmpkey      AES运算密钥
 * @param[in]     keylen      AES运算密钥长度，单位：字节
 * @param[in/out] iv          IV向量
 *
 * @return 错误码
 *   @retval 0 成功
 */
int AesCfb(unsigned char *pDataIn,int dataLen,int flag,unsigned char *pDataOut,unsigned char* tmpkey,int keyLen,unsigned char *iv);
/**
 * @brief AES运算OFB模式
 *
 * @param[in]     pDataIn	  输入数据
 * @param[in]     dataLen     输入数据长度，单位：字节
 * @param[in]     flag        工作模式 1:encrypt,0:decrypt
 * @param[out]    pDataOut	  输出数据
 * @param[in]     tmpkey      AES运算密钥
 * @param[in]     keylen      AES运算密钥长度，单位：字节
 * @param[in/out] iv          IV向量
 *
 * @return 错误码
 *   @retval 0 成功
 */
int AesOfb(unsigned char *pDataIn,int dataLen,int flag,unsigned char *pDataOut,unsigned char* tmpkey,int keyLen,unsigned char *iv);

/**
 * @brief AES运算CTR模式
 *
 * @param[in]     pDataIn	  输入数据
 * @param[in]     dataLen     输入数据长度，单位：字节
 * @param[in]     flag        工作模式 1:encrypt,0:decrypt
 * @param[out]    pDataOut	  输出数据
 * @param[in]     tmpkey      AES运算密钥
 * @param[in]     keylen      AES运算密钥长度，单位：字节
 * @param[in/out] iv          IV向量
 *
 * @return 错误码
 *   @retval 0 成功
 */
int AesCtr(unsigned char *pDataIn,int dataLen,int flag,unsigned char *pDataOut,unsigned char* tmpkey,int keyLen,unsigned char *iv);


/**
 * @brief AESCCM运算
 *
 * @param[in]     pDataIn	  输入数据
 * @param[in]     dataLen     输入数据长度，单位：字节
 * @param[in]     flag        工作模式 1:encrypt,0:decrypt
 * @param[out]    pDataOut	  输出数据
 * @param[in]     key         AES运算密钥
 * @param[in]     keylen      AES运算密钥长度， 单位：字节;合法的值为：16, 24, 32
 * @param[in]     iv          初始化向量nonce
 * @param[in]     Add         CCM模式的附加消息
 * @param[in]     lAdd        CCM中附加消息的长度，单位：字节（小于65536） 
 * @param[in/out] T           CCM模式中认证值, mode=1 输出  mode=0 输入
 * @param[in]     L           长度域，取值为2~8 ，openssl中缺省的为8
 * @param[in]     M           tag的长度，合法的值为：4, 6, 8, 10, 12, 14 和16。openssl中缺省的为12

 *
 * @return 错误码
 *   @retval 0 成功
 */
int AesCCM(unsigned char *pDataIn, unsigned long long dataLen,int flag,unsigned char *pDataOut,unsigned char* key,
		   int keyLen,unsigned char *iv,unsigned char *Add,  unsigned long long lAdd,unsigned char* T,unsigned char M,unsigned char L);
		   
		   
/**
 * @brief AES算法的GCM模式
 *
 * @param[in]   	key          密钥
 * @param[in]    	keyLen       密钥长度，单位是字节
 * @param[in]    	pAdd         附件数据
 * @param[in]    	addLen       附件数据长度，单位是字节
 * @param[int]   	pDataIn      输入数据
 * @param[in]    	dataLen      数据长度，单位是字节
 * @param[in/out]   pTag         MAC值, GCM模式中认证值, mode=1 输出  mode=0 输入
 * @param[in]       tagLen       支持的MAC长度
 * @param[in]    	mode         模式，1:加密  0 :解密 
 * @param[out]    	pDataOut     输出结果
 *
 * @return 错误码
 *   @retval 0 成功
 */	
int AesGCM(unsigned char* key,int keyLen, unsigned char* iv,unsigned int ivLen,unsigned char* pAdd,unsigned int addLen,unsigned char* pDataIn,
		unsigned int dataLen,unsigned char* pTag,unsigned int tagLen, unsigned char* pDataOut,int mode);


#ifdef __cplusplus
}
#endif


#endif /* aes.h */

