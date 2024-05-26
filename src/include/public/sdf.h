/*
* @Author: gm
* @Data: Do not edit
* @LastEditTime: 2024-03-27 14:30:13
* @LastEditor: gm
* @Description:
* @FileName: Do not edit
* @FilePath: \SecurityMiddlewares\doc\sdf_szgx.h
* @LastData:
*/
#define ECCref_MAX_BITS 512
#define ECCref_MAX_LEN ((ECCref_MAX_BITS + 7) / 8)
#define RSAref_MAX_BITS 2048
#define RSAref_MAX_LEN ((RSAref_MAX_BITS + 7) / 8)
#define RSAref_MAX_PBITS ((RSAref_MAX_BITS + 1) / 2)
#define RSAref_MAX_PLEN ((RSAref_MAX_PBITS + 7) / 8)

typedef struct DeviceInfo_st{
   unsigned char IssuerName[40];
   unsigned char DeviceName[16];
   unsigned char DeviceSerial[16]; /* 8-char date +
                                    * 3-char batch num +
                                    * 5-char serial num
                                    */
   unsigned int DeviceVersion;
   unsigned int StandardVersion;
   unsigned int AsymAlgAbility[2]; /* AsymAlgAbility[0] = algors
                                    * AsymAlgAbility[1] = modulus lens
                                    */
   unsigned int SymAlgAbility;
   unsigned int HashAlgAbility;
   unsigned int BufferSize;
} DEVICEINFO;

typedef struct RSArefPublicKey_st{
   unsigned int bits;
   unsigned char m[RSAref_MAX_LEN];
   unsigned char e[RSAref_MAX_LEN];
} RSArefPublicKey;

typedef struct RSArefPrivateKey_st{
   unsigned int bits;
   unsigned char m[RSAref_MAX_LEN];
   unsigned char e[RSAref_MAX_LEN];
   unsigned char d[RSAref_MAX_LEN];
   unsigned char prime[2][RSAref_MAX_PLEN];
   unsigned char pexp[2][RSAref_MAX_PLEN];
   unsigned char coef[RSAref_MAX_PLEN];
} RSArefPrivateKey;

//前填充后填充都行
typedef struct ECCrefPublicKey_st{
   unsigned int bits;
   unsigned char x[ECCref_MAX_LEN];
   unsigned char y[ECCref_MAX_LEN];
} ECCrefPublicKey;

typedef struct ECCrefPrivateKey_st{
   unsigned int bits;
   unsigned char K[ECCref_MAX_LEN];
} ECCrefPrivateKey;

typedef struct ECCCipher_st{
   unsigned char x[ECCref_MAX_LEN];
   unsigned char y[ECCref_MAX_LEN];
   unsigned char M[32];
   unsigned int L;
   unsigned char C[0];
} ECCCipher;

typedef struct ECCSignature_st{
   unsigned char r[ECCref_MAX_LEN];
   unsigned char s[ECCref_MAX_LEN];
} ECCSignature;

//缺少GBT SDF_ENVELOPEDKEYBLOB定义

//对称算法标识 GBT33560
#define SGD_SM1_ECB	    0x00000101	  //SM1算法ECB加密模式
#define SGD_SM1_CBC	    0x00000102	  //SM1算法CBC加密模式
#define SGD_SM1_CFB	    0x00000104	  //SM1算法CFB加密模式
#define SGD_SM1_OFB	    0x00000108	  //SM1算法OFB加密模式
#define SGD_SM1_MAC	    0x00000110	  //SM1算法MAC加密模式
//缺少SDF33相关

#define SGD_SM4_ECB		0x00000401	  //SM4算法ECB加密模式
#define SGD_SM4_CBC		0x00000402    //SM4算法CBC加密模式
#define SGD_SM4_CFB        0x00000404    //SM4算法CFB加密模式
#define SGD_SM4_OFB        0x00000408    //SM4算法OFB加密模式
#define SGD_SM4_MAC       0x00000410    //SM4算法MAC运算
//缺少ZUC相关

//非对称算法标识//与GBT33560不一致
#define SGD_RSA	        0x00010000	  //RSA算法
#define SGD_SM2_1	    0x00020100	  //椭圆曲线签名算法
#define SGD_SM2_2	    0x00020200	  //椭圆曲线密钥交换协议
#define SGD_SM2_3	    0x00020400	  //椭圆曲线加密算法
#define SGD_ECC_CV7_256 0x80000007    //7号曲线，256bit
//缺少SM9相关

//杂凑算法标识
#define SGD_SM3	        0x00000001	  //SM3杂凑算法
#define SGD_SHA1	    0x00000002	  //SHA1杂凑算法
#define SGD_SHA256	    0x00000004	  //SHA256杂凑算法
#define SGD_SHA384 	    0x00000006	  //SHA384杂凑算法//扩展
#define SGD_SHA512 	    0x00000008	  //SHA512杂凑算法//扩展

//缺少签名算法标识

//以下为扩展
#define SGD_AES128_ECB	    0x00000801	  //AES128算法ECB加密模式
#define SGD_AES128_CBC	    0x00000802	  //AES128算法CBC加密模式
#define SGD_AES128_CFB	    0x00000804	  //AES128算法CFB加密模式
#define SGD_AES128_OFB	    0x00000808	  //AES128算法OFB加密模式
#define SGD_AES128_MAC	    0x00000810	  //AES128算法MAC加密模式

#define SGD_AES256_ECB	    0x00000301	  //AES256算法ECB加密模式
#define SGD_AES256_CBC	    0x00000302	  //AES256算法CBC加密模式
#define SGD_AES256_CFB	    0x00000304	  //AES256算法CFB加密模式
#define SGD_AES256_OFB	    0x00000308	  //AES256算法OFB加密模式
#define SGD_AES256_MAC	    0x00000310	  //AES256算法MAC加密模式

#define SGD_AES192_ECB	    0x00000501	  //AES192算法ECB加密模式
#define SGD_AES192_CBC	    0x00000502	  //AES192算法CBC加密模式
#define SGD_AES192_CFB	    0x00000504	  //AES192算法CFB加密模式
#define SGD_AES192_OFB	    0x00000508	  //AES192算法OFB加密模式
#define SGD_AES192_MAC	    0x00000510	  //AES192算法MAC加密模式

#define SGD_3DES_ECB	    0x00000601	  //3DES算法ECB加密模式
#define SGD_3DES_CBC	    0x00000602	  //3DES算法CBC加密模式
#define SGD_3DES_CFB	    0x00000604	  //3DES算法CFB加密模式
#define SGD_3DES_OFB	    0x00000608	  //3DES算法OFB加密模式
// 对称算法类型uiAlgType：
#define ALG_SM1	         0x00000010	   //SM1算法
#define ALG_3DES	     0x00000011    //3DES算法
#define ALG_SM4          0x00000012    //SM4算法
#define ALG_AES128       0x00000013    //AES128算法
#define ALG_AES192       0x00000014    //AES196算法
#define ALG_AES256       0x00000015    //AES256算法

// 证书类型iCerType：
#define CER_SM2	         0x00000020    //SM2证书
#define CER_RSA2048	     0x00000021	   //RSA证书
#define CER_ECC          0x00000022	   //ECC证书


// 设备管理类
int SDF_OpenDevice(
       void **phDeviceHandle);
int SDF_CloseDevice(
       void *hDeviceHandle);
int SDF_OpenSession(
       void *hDeviceHandle,
       void **phSessionHandle);
//扩展
int SDF_ValidSessionHandle(
       void *hSessionHandle);

int SDF_CloseSession(
       void *hSessionHandle);

int SDF_GetDeviceInfo(
       void *hSessionHandle,
       DEVICEINFO *pstDeviceInfo);

int SDF_GenerateRandom(
       void *hSessionHandle,
       unsigned int uiLength,
       unsigned char *pucRandom);
//扩展
int SDF_VerifyPin(
       void *hSessionHandle,
       unsigned char *sPin,
       unsigned int iPinLen,
       unsigned int *piRetry);
//扩展
int SDF_ChangePIN(
       void *hSessionHandle,
       unsigned char *oldpin,
       unsigned int oldlen,
       unsigned char *newpin,
       unsigned int newlen);
//扩展
int SDF_UnlockPin(
       void *hSessionHandle,
       unsigned char *pbAdminPin,
       unsigned int iAdminPinLen,
       unsigned char *pbNewPin,
       unsigned int iNewPinLen);

// 密钥管理类
//导出RSA签名公钥
int SDF_ExportSignPublicKey_RSA(
       void *hSessionHandle,
       unsigned int uiKeyIndex,
       RSArefPublicKey *pucPublicKey);

//导出RSA加密公钥
int SDF_ExportEncPublicKey_RSA(
       void *hSessionHandle,
       unsigned int uiKeyIndex,
       RSArefPublicKey *pucPublicKey);

//产生RSA非对称密钥对并输出
int SDF_GenerateKeyPair_RSA(
       void *hSessionHandle,
       unsigned int uiKeyBits,
       RSArefPublicKey *pucPublicKey,
       RSArefPrivateKey *pucPrivateKey);
//扩展
//内部产生RSA密钥对
int SDF_CreateKeyPair_RSA(
       void *hSessionHandle,
       unsigned int bits,
       unsigned int uiKeyIndex); // 【BYD扩展】RSA位数支持1024,2048,3072

//缺失SDF_GenerateKeyWithIPK_RSA
//产生会话密钥并用内部RSA公钥加密输出

//缺失SDF_GenerateKeyWithEPK_RSA
//产生会话密钥并用外部RSA公钥加密输出

//缺失SDF_ImportKeyWithISK_RSA
//导入会话密钥并用内部RSA私钥解密

//缺失SDF_ExchangeDigitEnvelopeBaseOnRSA
//基于RSA算法的数字信封转换

//导出ECC签名公钥
int SDF_ExportSignPublicKey_ECC(
       void *hSessionHandle,
       unsigned int uiKeyIndex,
       ECCrefPublicKey *pucPublicKey);

//导出ECC加密公钥
int SDF_ExportEncPublicKey_ECC(
       void *hSessionHandle,
       unsigned int uiKeyIndex,
       ECCrefPublicKey *pucPublicKey);

//产生ECC非对称密钥对并输出
int SDF_GenerateKeyPair_ECC(
       void *hSessionHandle,
       unsigned int uiAlgID,
       unsigned int uiKeyBits,
       ECCrefPublicKey *pucPublicKey,
       ECCrefPrivateKey *pucPrivateKey);

//缺失SDF_GenerateKeyWithIPK_ECC
//产生会话密钥并用内部ECC公钥加密输出

//缺失SDF_GenerateKeyWithEPK_ECC
//产生会话密钥并用外部ECC公钥加密输出

//缺失SDF_ImportKeyWithISK_ECC
//导入会话密钥并用外部ECC公钥私钥解密

//缺失SDF_GenerateAgreementDataWithECC
//生成密钥协商参数并输出

//缺失SDF_GenerateKeyWithECC
//计算会话密钥

//缺失SDF_GenerateAgreementDataAndKeyWithECC
//产生协商数据并计算会话密钥

//缺失SDF_ExchangeDigitEnvelopeBaseOnECC
//基于ECC算法的数字信封转换

//缺失SDF_GenerateKeyWithKEK
//生成会话密钥并用密钥加密密钥加密输出

//缺失SDF_ImportKeyWithKEK
//导入会话密钥并用密钥加密密钥解密

//缺失SDF_GenerateKeyWithIKE
//计算IKE工作密钥

//缺失SDF_GenerateKeyWithEPK_IKE
//计算IKE工作密钥并用外部ECC公钥加密输出

//缺失SDF_GenerateKeyWithIPSEC
//计算IPSEC会话密钥

//缺失SDF_GenerateKeyWithEPK_IPSEC
//计算IPSEC会话密钥并用外部ECC公钥加密输出

//缺失SDF_GenerateKeyWithSSL
//计算SSL工作密钥

//缺失SDF_GenerateKeyWithEPK_SSL
//计算SSL工作密钥并用外部ECC公钥加密输出

//缺失SDF_GenerateKeyWithECDHE_SSL
//计算ECDHE工作密钥并用外部ECC公钥加密输出

//缺失SDF_GenerateKeyWithEPK_ECDHE_SSL
//计算SSL工作密钥并用外部ECC公钥加密输出（ECDHE）

//扩展
int SDF_ImportKey(
       void *hSessionHandle,
       unsigned char *pucKey,
       unsigned int uiKeyLength,
       void **phKeyHandle);

//扩展
int SDF_ImportKey_EX(
       void *hSessionHandle,
       unsigned int uiKeyIndex,
       unsigned char *pucKey,
       unsigned int uiKeyLen);

//扩展
int SDF_CreateSysmKey(
       void *hSessionHandle,
       unsigned int uiKeyIndex,
       unsigned int uiAlgType); // BYD扩展定义keyindex

//扩展
int SDF_GetKeyFromSE(
       void *hSessionHandle,
       unsigned int uiKeyIndex,
       void **phKeyHandle);

//扩展
int SDF_CreateKeyPairECC(
       void *hSessionHandle,
       unsigned int uiKeyIndex,
       unsigned int uiAlgID,
       unsigned int uiKeyBits); // uiKeyIndex使用范围0X200 - 0X2FF

//扩展
int SDF_GetIndexState(
       void *hSessionHandle,
       unsigned int uiKeyIndex);

//缺失SDF_DestroyKey

int SDF_ExternalPublicKeyOperation_RSA(
       void *hSessionHandle,
       RSArefPublicKey *pucPublicKey,
       unsigned char *pucDataInput,
       unsigned int uiInputLength,
       unsigned char *pucDataOutput,
       unsigned int *puiOutputLength);

int SDF_InternalPublicKeyOperation_RSA(
       void *hSessionHandle,
       unsigned int uiKeyIndex,
       unsigned char *pucDataInput,
       unsigned int uiInputLength,
       unsigned char *pucDataOutput,
       unsigned int *puiOutputLength);


int SDF_InternalPrivateKeyOperation_RSA(
       void *hSessionHandle,
       unsigned int uiKeyIndex,
       unsigned char *pucDataInput,
       unsigned int uiInputLength,
       unsigned char *pucDataOutput,
       unsigned int *puiOutputLength);

int SDF_ExternalVerify_ECC(
       void *hSessionHandle,
       unsigned int uiAlgID,
       ECCrefPublicKey *pucPublicKey,
       unsigned char *pucDataInput,
       unsigned int uiInputLength,
       ECCSignature *pucSignature);

//扩展
int SDF_ExternalVerify_ECC_EX(
       void *hSessionHandle,
       unsigned int uiAlgID,
       ECCrefPublicKey *pucPublicKey,
       unsigned char *pucDataInput,
       unsigned int uiInputLength,
       unsigned char *pucSignature,
       unsigned int pucSignLength);

int SDF_InternalSign_ECC(
       void *hSessionHandle,
       unsigned int uiISKIndex,
       unsigned int uiAlgID, //比GBT多了个参数
       unsigned char *pucData,
       unsigned int uiDataLength,
       ECCSignature *pucSignature);

//扩展
int SDF_InternalSign_ECC_EX(
       void *hSessionHandle,
       unsigned int uiISKIndex,
       unsigned int uiAlgID,
       unsigned char *pucData,
       unsigned int uiDataLength,
       unsigned char *pucSignature,
       unsigned int *pucSignLength);

int SDF_InternalVerify_ECC(
       void *hSessionHandle,
       unsigned int uiIPKIndex,
       unsigned int uiAlgID, //比GBT多了个参数
       unsigned char *pucData,
       unsigned int uiDataLength,
       ECCSignature *pucSignature);

//扩展
int SDF_InternalVerify_ECC_EX(
       void *hSessionHandle,
       unsigned int uiIPKIndex,
       unsigned int uiAlgID,
       unsigned char *pucData,
       unsigned int uiDataLength,
       unsigned char *pucSignature,
       unsigned int pucSignLength);

int SDF_ExternalEncrypt_ECC(
       void *hSessionHandle,
       unsigned int uiAlgID,
       ECCrefPublicKey *pucPublicKey,
       unsigned char *pucData,
       unsigned int uiDataLength,
       ECCCipher *pucEncData);
//扩展
int SDF_ExternalEncrypt_ECC_EX(
       void *hSessionHandle,
       unsigned int uiAlgID,
       ECCrefPublicKey *pucPublicKey,
       unsigned char *pucData,
       unsigned int uiDataLength,
       unsigned char *pucEncData,
       unsigned int *uiEncDataLength);

int SDF_InternalEncrypt_ECC(
       void *hSessionHandle,
       unsigned int uiIPKIndex,
       unsigned int uiAlgID,
       unsigned char *pucData,
       unsigned int uiDataLength,
       ECCCipher *pucEncData);

//扩展
int SDF_InternalEncrypt_ECC_EX(
       void *hSessionHandle,
       unsigned int uiIPKIndex,
       unsigned int uiAlgID,
       unsigned char *pucData,
       unsigned int uiDataLength,
       unsigned char *pucEncData,
       unsigned int *uiEncDataLength);

int SDF_InternalDecrypt_ECC(
       void *hSessionHandle,
       unsigned int uiISKIndex,
       unsigned int uiAlgID,
       ECCCipher *pucEncData,
       unsigned char *pucData,
       unsigned int *uiDataLength);

//扩展
int SDF_InternalDecrypt_ECC_EX(
       void *hSessionHandle,
       unsigned int uiISKIndex,
       unsigned int uiAlgID,
       unsigned char *pucEncData,
       unsigned int uiEncDataLength,
       unsigned char *pucData,
       unsigned int *uiDataLength);

int SDF_Encrypt(
       void *hSessionHandle,
       void *hKeyHandle,
       unsigned int uiAlgID,
       unsigned char *pucIV,

       unsigned char *pucData,
       unsigned int uiDataLength,
       unsigned char *pucEncData,
       unsigned int *puiEncDataLength);

int SDF_Decrypt(
       void *hSessionHandle,
       void *hKeyHandle,
       unsigned int uiAlgID,
       unsigned char *pucIV,
       unsigned char *pucEncData,
       unsigned int uiEncDataLength,
       unsigned char *pucData,
       unsigned int *puiDataLength);
// 对称算法类扩展
int SDF_EncryptInit(
       void *hSessionHandle,
       void *hKeyHandle,
       unsigned int uiAlgID,
       unsigned char *pucIV,
       unsigned int uiIVLen);

int SDF_EncryptUpdate(
       void *hSessionHandle,
       void *hKeyHandle,
       unsigned char *pucData,
       unsigned int uiDataLength,
       unsigned char *pucEncData,
       unsigned int *puiEncDataLength);

int SDF_EncryptFinal(
       void *hSessionHandle,
       void *hKeyHandle,
       unsigned char *pucEncData,
       unsigned int *puiEncDataLength);

int SDF_DecryptInit(
       void *hSessionHandle,
       void *hKeyHandle,
       unsigned int uiAlgID,
       unsigned char *pucIV,
       unsigned int uiIVLen);

int SDF_DecryptUpdate(
       void *hSessionHandle,
       void *hKeyHandle,
       unsigned char *pucEncData,
       unsigned int puiEncDataLength,
       unsigned char *pucData,
       unsigned int *uiDataLength);

int SDF_DecryptFinal(
       void *hSessionHandle,
       void *hKeyHandle,
       unsigned char *pucData,
       unsigned int *uiDataLength);

int SDF_CalculateMAC(
       void *hSessionHandle,
       void *hKeyHandle,
       unsigned int uiAlgID,
       unsigned char *pucIV,
       unsigned char *pucData,
       unsigned int uiDataLength,
       unsigned char *pucMAC,
       unsigned int *puiMACLength);
// 杂凑算法
int SDF_HashInit(
       void *hSessionHandle,
       unsigned int uiAlgID,
       ECCrefPublicKey *pucPublicKey,
       unsigned char *pucID,
       unsigned int uiIDLength);

int SDF_HashUpdate(
       void *hSessionHandle,
       unsigned char *pucData,
       unsigned int uiDataLength);

int SDF_HashFinal(void *hSessionHandle,
                 unsigned char *pucHash,
                 unsigned int *puiHashLength);

// 文件管理
int SDF_CreateFile(
       void *hSessionHandle,
       unsigned char *pucFileName,
       unsigned int uiNameLen,
       unsigned int uiFileSize);

int SDF_ReadFile(
       void *hSessionHandle,
       unsigned char *pucFileName,
       unsigned int uiNameLen,
       unsigned int uiOffset,
       unsigned int *puiReadLength,
       unsigned char *pucBuffer);
int SDF_WriteFile(
       void *hSessionHandle,
       unsigned char *pucFileName,
       unsigned int uiNameLen,
       unsigned int uiOffset,
       unsigned int uiFileLength,//GBT uiWriteLength
       unsigned char *pucBuffer);

int SDF_DeleteFile(
       void *hSessionHandle,
       unsigned char *pucFileName,
       unsigned int uiNameLen);

// OTA//扩展
int SDF_CosVerCmp();
int SDF_CosUpdate();
// P10 //扩展
int SDF_GenP10(
       void *hSessionHandle,
       unsigned char *country,
       unsigned char *province,
       unsigned char *city,
       unsigned char *organization,
       unsigned char *unit,
       unsigned int iCerType,
       unsigned int uiISKIndex,
       unsigned char *p10Info,
       unsigned int *p10InfoLen);

#define SDR_OK 0x0
#define SDR_BASE 0x01000000
#define SDR_UNKNOWERR SDR_BASE + 0x00000001
#define SDR_NOTSUPPORT SDR_BASE + 0x00000002
#define SDR_COMMFAIL SDR_BASE + 0x00000003
#define SDR_HARDFAIL SDR_BASE + 0x00000004
#define SDR_OPENDEVICE SDR_BASE + 0x00000005
#define SDR_OPENSESSION SDR_BASE + 0x00000006
#define SDR_PARDENY SDR_BASE + 0x00000007
#define SDR_KEYNOTEXIST SDR_BASE + 0x00000008
#define SDR_ALGNOTSUPPORT SDR_BASE + 0x00000009
#define SDR_ALGMODNOTSUPPORT SDR_BASE + 0x0000000A
#define SDR_PKOPERR SDR_BASE + 0x0000000B
#define SDR_SKOPERR SDR_BASE + 0x0000000C
#define SDR_SIGNERR SDR_BASE + 0x0000000D
#define SDR_VERIFYERR SDR_BASE + 0x0000000E
#define SDR_SYMOPERR SDR_BASE + 0x0000000F
#define SDR_STEPERR SDR_BASE + 0x00000010
#define SDR_FILESIZEERR SDR_BASE + 0x00000011
#define SDR_FILENOEXIST SDR_BASE + 0x00000012
#define SDR_FILEOFSERR SDR_BASE + 0x00000013
#define SDR_KEYTYPEERR SDR_BASE + 0x00000014
#define SDR_KEYERR SDR_BASE + 0x00000015
#define SDR_ENCDATAERR SDR_BASE + 0x00000016
//以下为扩展，17-1E不符合GBT定义
#define SDR_CLOSESESSION SDR_BASE + 0x00000017
#define SDR_DATA_LENGTH_ERR SDR_BASE + 0x00000018
#define SDR_BUFFER_TOO_SMALL SDR_BASE + 0x00000019
#define SDR_GEN_RSA_KEY_ERR SDR_BASE + 0x0000001A
#define SDR_GEN_SYMM_KEY_ERR SDR_BASE + 0x0000001C
#define SDR_GEN_RADOM_ERR SDR_BASE + 0x0000001D
#define SDR_ENC_SYMM_KEY_ERR SDR_BASE + 0x0000001E
#define SDR_MEMORY_ERR SDR_BASE + 0x0000001F
#define SDR_KEY_EXH_ERR SDR_BASE + 0x00000020
#define SDR_ENC_ERROR SDR_BASE + 0x00000021
#define SDR_DEC_ERROR SDR_BASE + 0x00000022
#define SDR_SHA1_INIT_ERR SDR_BASE + 0x00000024
#define SDR_SHA256_INIT_ERR SDR_BASE + 0x00000025
#define SDR_SHA1_UPDATE_ERR SDR_BASE + 0x00000027
#define SDR_SHA256_UPDATE_ERR SDR_BASE + 0x00000028
#define SDR_SHA1_FINAL_ERR SDR_BASE + 0x0000002A
#define SDR_SHA256_FINAL_ERR SDR_BASE + 0x0000002B
#define SDR_URFBC_ERR SDR_BASE + 0x0000002C
#define SDR_UWFBC_ERR SDR_BASE + 0x0000002D
#define SDR_URFBC_ERR_ReadIndex SDR_BASE + 0x0000002E
#define SDR_UWFBC_ERR_Create SDR_BASE + 0x0000002F
#define SDR_UNKNOWFile_ERR SDR_BASE + 0x00000030
#define SDR_URFBC_Number_ERR SDR_BASE + 0x00000031
#define SDR_KEY_LENGTH_ERR SDR_BASE + 0x00000032
#define SDR_INSERTLIST_ERR SDR_BASE + 0x00000033
#define SDR_OFFSET_ERROR SDR_BASE + 0x00000034
#define SDR_SESSIONHANDLE_ERR SDR_BASE + 0x00000035
#define SDR_KEYHANDLE_ERR SDR_BASE + 0x00000036
#define SDR_PARAMETER_ERR SDR_BASE + 0x00000037
#define SDR_FILEINDEX_TOO_LONG SDR_BASE + 0x00000038
#define SDR_CLOSEDEVICE SDR_BASE + 0x00000090



int SDF_Init();
int SDF_GetPrivateKeyAccessRight(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucPassword, unsigned int uiPwdLength);
int SDF_ImportSignPublicKey_RSA(void *hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey);
int SDF_ImportSignPrivateKey_RSA(void *hSessionHandle, unsigned int uiKeyIndex, RSArefPrivateKey *pucPrivateKey);
int SDF_ReleasePrivateKeyAccessRight(void *hSessionHandle, unsigned int uiKeyIndex);
int SDF_GetSoftVersion(unsigned char *version, int *verLen);
int SDF_ImportSignPublicKey_ECC(void *hSessionHandle, unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey);
int SDF_ImportSignPrivateKey_ECC(void *hSessionHandle, unsigned int uiKeyIndex, ECCrefPrivateKey *pucPrivateKey);
int SDF_ImportEncPublicKey_ECC(void *hSessionHandle, unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey);
int SDF_ImportEncPrivateKey_ECC(void *hSessionHandle, unsigned int uiKeyIndex, ECCrefPrivateKey *pucPrivateKey);
int SDF_ExternalSign_ECC_EX(void *hSessionHandle, unsigned int uiAlgID,ECCrefPrivateKey *pucPrivateKey, unsigned char *pucData, unsigned int uiDataLength, ECCSignature *pucSignature);
int SDF_ExternalDecrypt_ECC(void *hSessionHandle,
                            unsigned int uiAlgID,
                            ECCrefPrivateKey *pucPrivateKey,
                            ECCCipher *pucEncData,
                            unsigned char *pucData,
                            unsigned int *puiDataLength);

