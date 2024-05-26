

#ifndef _SOFT_H_INCLUDE_
#define _SOFT_H_INCLUDE_
#include <stdio.h>
#include <stdlib.h>

#define  HASH_LEN_SM3    32             

#define KEY_LEN_SM2       32


///设备中RSA运算的长度
#define CARD_RSA_LEN            128            
#define CARD_PRIME_LEN          64
#define MAX_RSA_MODULUS_BITS    2048
#define MAX_CARD_RSA_LEN        256
#define MIN_CARD_PRIME_LEN      128
///RSA公钥结构
typedef struct _SOFT_RSA_PUB_KEY
{
        unsigned int  bits;               //公钥模数长度，1024或2048
        unsigned char m[MAX_CARD_RSA_LEN];
        unsigned int  e;
}SOFT_RSA_PUB_KEY,*PSOFT_RSA_PUB_KEY;

///RSA私钥结构
typedef struct _SOFT_RSA_PRI_KEY {
	unsigned int bits;                //公钥模数长度
	unsigned char p[MIN_CARD_PRIME_LEN]; 
	unsigned char q[MIN_CARD_PRIME_LEN];
	unsigned char dp[MIN_CARD_PRIME_LEN];
	unsigned char dq[MIN_CARD_PRIME_LEN];
	unsigned char ce[MIN_CARD_PRIME_LEN];
} SOFT_RSA_PRI_KEY,*PSOFT_RSA_PRI_KEY;
///SM2曲线参数
typedef struct _SOFT_SM2_PARAM {
	unsigned char p[KEY_LEN_SM2];    //素数p
	unsigned char a[KEY_LEN_SM2];    //系数a
	unsigned char b[KEY_LEN_SM2];    //系数b
	unsigned char n[KEY_LEN_SM2];    //阶
	unsigned char x[KEY_LEN_SM2];    //基点G的x坐标
	unsigned char y[KEY_LEN_SM2];    //基点G的y坐标
} SOFT_SM2_PARAM,*PSOFT_SM2_PARAM;



/*SM2相关结构*/
#define SM2_MAX_BITS 256
#define CARD_SM2_LEN (SM2_MAX_BITS/8)
typedef struct _SOFT_SM2_KEY
{
	unsigned int   bits;				//bit 只支持256
	unsigned char  x[CARD_SM2_LEN];     //x
	unsigned char  y[CARD_SM2_LEN];     //y
	unsigned char  d[CARD_SM2_LEN];		//d , private key			
} SOFT_SM2_KEY,*PSOFT_SM2_KEY;

///sm2私钥结构
typedef struct _SOFT_SM2_PRIKEY{
    unsigned char d[KEY_LEN_SM2];
}SOFT_SM2_PRIKEY, *PSOFT_SM2_PRIKEY, *PSOFT_ECC_PRIKEY;

///sm2公钥结构
typedef struct _SOFT_SM2_PUBKEY{
    unsigned char x[KEY_LEN_SM2];
    unsigned char y[KEY_LEN_SM2];
}SOFT_SM2_PUBKEY, *PSOFT_SM2_PUBKEY, *PSOFT_ECC_PUBKEY;

typedef enum _CARD_TYPE
{
	CT_ALL          =0x0000,
	CT_SOFT         =0x0800,//单机版   

}CARD_TYPE;

typedef struct _SOFT_DEVICE
{
	int isGetRandom;
	char szFilePath[MAX_PATH];
	unsigned char ucRandom[MAX_PATH];
	HANDLE hFile;
	unsigned char ucCardState;
}SOFT_DEVICE,*PSOFT_DEVICE;


///设备信息
typedef struct _SOFT_DEVINFO
{
	unsigned char cardid[33];          //硬件编号,一般为长度32字节的字符串
	unsigned char cosver[65];          //COS版本号,不超过64字节的字符串
	CARD_TYPE cardtype;                //设备类型
	int  reserve;
}SOFT_DEVINFO,*PSOFT_DEVINFO;

typedef int HANDLE;
typedef void* SOFT_HANDLE;

int F_CheckFile(char* filepath);

int F_CheckHandle(HANDLE fd);

int CheckHandle(SOFT_HANDLE handle);


int DoUnlockDev();

int DoLockDev();


int F_OpenFile(char *filePath, HANDLE *fd);
int F_CloseFile(HANDLE *fd);

//打开文件,返回文件句柄
int SOFT_OpenDev(void ** hHandle);

int SOFT_CloseDev(void * hHandle);


int SOFT_GetDevInfo(SOFT_HANDLE hHandle,PSOFT_DEVINFO pDevInfo);

int SOFT_GenRandom( int len, unsigned char * pRandom );

int SOFT_Init();
int SOFT_WriteRsaPubKey(SOFT_HANDLE hHandle, const unsigned char * fid, PSOFT_RSA_PUB_KEY pPub);
int SOFT_WriteRsaPriKey(SOFT_HANDLE hHandle, const unsigned char * fid, PSOFT_RSA_PRI_KEY pPri);
int SOFT_ReadRsaPriKey(SOFT_HANDLE hHandle, const unsigned char * fid, PSOFT_RSA_PRI_KEY pPri);

int SOFT_ReadRsaPubKey(SOFT_HANDLE hHandle, const unsigned char * fid, PSOFT_RSA_PUB_KEY pPub);

int SOFT_WriteSM2PubKey( SOFT_HANDLE hHandle, const unsigned char * fid, PSOFT_SM2_PUBKEY pPub);
int SOFT_WriteSM2PriKey( SOFT_HANDLE hHandle, const unsigned char * fid, PSOFT_SM2_PRIKEY pPri);
int SOFT_ReadSM2PubKey(SOFT_HANDLE hHandle, const unsigned char * fid, PSOFT_SM2_PUBKEY pPub );
int SOFT_ReadSm2PriKey(SOFT_HANDLE hHandle,unsigned char* priid,SOFT_SM2_PRIKEY* pPri);
int SOFT_Symcrypto(void* hHandle, unsigned int operate, unsigned int uiAlgID, int uiKeyIndex, unsigned char *pucKey, unsigned int uiKeyLength, unsigned char *pucIV,unsigned char *pucDataIn, unsigned int uiDataInLen, unsigned char *pucDataOut, unsigned int *puiDataOutLen, unsigned int node);

int SOFT_CreateFile( SOFT_HANDLE hHandle,unsigned char *pucFileName, unsigned int uiNameLen, unsigned int uiFileSize);
int SOFT_ReadFile(SOFT_HANDLE hHandle,  unsigned char *pucFileName, unsigned int uiNameLen, unsigned int uiOffset, unsigned int *puiFileLength, unsigned char *pucBuffer);
int SOFT_WriteFile(SOFT_HANDLE hHandle, unsigned char *pucFileName, unsigned int uiNameLen, unsigned int uiOffset, unsigned int uiFileLength, unsigned char *pucBuffer);
int SOFT_DeleteFile(SOFT_HANDLE hHandle,unsigned char *pucFileName, unsigned int uiNameLen);

int SOFT_WriteKey(SOFT_HANDLE hHandle, unsigned int uiKeyIndex, unsigned char *pucKey, unsigned int uiKeyLen);
int SOFT_ReadKey(SOFT_HANDLE hHandle, unsigned int uiKeyIndex, unsigned char *pucKey, unsigned int *uiKeyLen);


#endif














