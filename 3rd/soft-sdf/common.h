/**
* @file common.h
* @brief 业务逻辑模块
* @date 20240408
* @note
*/

#ifndef _PCIE_COMMON_H
#define _PCIE_COMMON_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>


#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <memory.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include "sdf.h"
#include "log.h"
#include "tool.h"


enum FILE_STATE_TYPE
{
	FILE_READ_STATE			= 1,	
	FILE_WRITE_STATE		= 2,	
	FILE_USE_STATE			= 3
};
///定义SDK版本
#define SDF_VERSION "1.0.19.20240408"

#define KM_SOFT_PATH	"/collect2/softalg/key.bin"

#define TLOCK_TIMEOUT 60 //60s

#define ECC_KEY_OFFSET  32

///对称算法操作类型 加密 解密
#define OP_DECRYPT  0x00
#define OP_ENCRYPT  0x01
///对称算法操作模式  ECB  CBC
#define ECB_MODE    0x00
#define CBC_MODE    0x10
///对称算法模式类型标识
#define ECB_DECRYPT 0x00
#define ECB_ENCRYPT 0x01
#define CBC_DECRYPT 0x10
#define CBC_ENCRYPT 0x11


typedef void* SOFT_HANDLE;


typedef int HANDLE;
#define INVALID_HANDLE_VALUE -1
#define MAX_PATH 260

#define KEYPAIRE_INDEX_MAX 32 //max rsa sm2 keypair
#define MAX_KEY_NUM 255


#define SOFT_OK 0

#define SOFT_TLOCK_FAILD -1
#define SOFT_TLOCK_TIMEOUT -2

#define SOFT_NO_DEVICE -3
#define SOFT_INVALID_PARA -4
#define SOFT_WRITE_BIN -5

#define SOFT_CREATE_BIN -6
#define SOFT_SM2_SET_PARAM -7
#define SOFT_WRITE_KEY -8
#define SOFT_OPEN_FILE -9
#define SOFT_WRITE_FILE -10
#define SOFT_READ_FILE -11
#define SOFT_CREATE_FILE -12
#define SOFT_NO_POWER -13
#define SOFT_NO_FILE_SPACE -14
#define SOFT_BAD_PUBKEY -15
#define SOFT_NO_HANDLE -16
#define SOFT_FILE_TYPE -17
#define SOFT_BAD_PRIKEY -18



//

#define SGD_SM2 0x00020100	 //SM2椭圆曲线密码算法
#ifndef SDR_BASE
#define SDR_BASE 0x01000000
#endif
#define SDR_RANDERR 			SDR_BASE + 0x00000017	//随机数产生失败
#define SDR_PRKRERR 			SDR_BASE + 0x00000018	//私钥使用权限获取失败
#define SDR_MACERR 				SDR_BASE + 0x00000019	//MAC 运算失败
#define SDR_FILEEXISTS 			SDR_BASE + 0x0000001A	//指定文件已存在
#define SDR_FILEWERR 			SDR_BASE + 0x0000001B	//文件写入失败
#define SDR_NOBUFFER 			SDR_BASE + 0x0000001C	//存储空间不足
#define SDR_INARGERR 			SDR_BASE + 0x0000001D	//输入参数错误
#define SDR_OUTARGERR 			SDR_BASE + 0x0000001E	//输出参数错误

#define SDR_MALLOCERR			SDR_BASE + 0x00000021	// 申请内存失败
#define SDR_TIMEOUT				SDR_BASE + 0x00000029	// 通信超时
#define SDR_KEYNOEXIST			SDR_BASE + 0x0000002B	// 密钥不存在


//会话密钥结构体
typedef struct _SDF_SESSIONKEY
{
	int algId;    //对应的算法ID, SGD_SM1_ECB | SGD_SM1_ECB | SGD_SM4_ECB | SGD_SM4_CBC;
	char key[16]; //密钥   
}SDF_SESSIONKEY,*PSDF_SESSIONKEY;

//设备会话结构体
typedef struct _SDF_SESSIONDEV
{
	void *hDeviceHandle;	//设备句柄
	void *hHashHandle;		//Hash运算句柄 
	int valid;	//session 
	unsigned int hashAlgID;	//Hash算法id
}SDF_SESSIONDEV,*PSDF_SESSIONDEV;


//模块设备文件头结构体
typedef struct _SOFT_FS_HEARD_INFO
{
	unsigned char tag[32];		//文件标志，标记是否配套文件
	unsigned char devID[32];	//软卡卡号,32字节
	unsigned char hmacKey[32];	//HMAC计算密钥
	unsigned char hmacVal[32];	//HMAC值
	char		  szLabel[32];	//设备标签
}SOFT_FS_HEAD_INFO, *PSOFT_FS_HEAD_INFO;



//int CheckHandle(SOFT_HANDLE handle);
int DoLockDev();
int DoUnlockDev();

///节点加锁，进程线程互斥
int DoLock(void * hHandle);

///节点解锁，进程线程互斥
int DoUnLock(void * hHandle);

///从seesion句柄中过去设备句柄
int GetDeviceHandle(void* hSessionHandle, void **hHandle);

///检查设备句柄
int CheckHandle(void*  hHandle);

int InitDatFile(char* pszDllPath, char* pszDatPath, unsigned char* pin, int plen, unsigned char* pucDevIdent, int devIdentLen);

#endif
