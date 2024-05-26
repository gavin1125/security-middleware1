#ifndef __SOFT_FS_INC__
#define __SOFT_FS_INC__

#include "../common.h"

/************************************************************************/
/* 错误代码定义                                                          */
/************************************************************************/
#define FSR_BASE                         0
#define FSR_OK                           0x00000000                     //成功
#define FSR_MALLOC_FALID                 FSR_BASE-1                     //内存申请失败
#define FSR_OPEN_FILE	                 FSR_BASE-2                     //打开文件失败
#define FSR_READ_FILE	                 FSR_BASE-3                     //读文件失败
#define FSR_WRITE_FILE	                 FSR_BASE-4                     //写文件失败
#define FSR_BIT_FIND					 FSR_BASE-5                     //查找位操作失败
#define FSR_BIT_SET						 FSR_BASE-6                     //设置位操作失败
#define FSR_BIT_CLEAR					 FSR_BASE-7                     //清除位失败
#define FSR_KEY_NOT_EXIST	             FSR_BASE-8                     //密钥不存在
#define FSR_FILE_EXIST 	                 FSR_BASE-9                     //文件已存在
#define FSR_NO_FILE_SPACE	             FSR_BASE-10                    //文件无足够空间
#define FSR_FILE_NOT_EXIST	             FSR_BASE-11                    //文件不存在
#define FSR_NO_POWER					 FSR_BASE-12					//没有PIN权限

#define FSR_FILESIZEERR					 FSR_BASE-13					//文件长度超出限制





#define KEY_BLOCK_LEN			0x30	//密钥文件信息块大小
#define BIN_FAT_BLOCK_LEN		0x100	//文件头信息块大小  256
#define BIN_DATA_BLOCK_LEN		0x200	//文件数据区块大小  512

#define KEY_FILE_ADDRESS		0x1200	//密钥文件起始地址
#define BIN_FAT_FILE_ADDRESS		0x1A00	//FAT区文件起始地址
#define BIN_DATA_FILE_ADDRESS		0x14C00	//文件DATA区起始地址

#define BIN_BITMAP_FILE_ADDRESS		0x14A00	//文件BITMAP区起始地址
#define BIN_BITMAP_BLOCK_LEN		0x800	//BITMAP区，35字节可以表示所有的数据块占用情况

#define BIN_DATA_PRI_FILE_ADDRESS	0x37C00	//私钥文件DATA区起始地址
#define BIN_BITMAP_PRI_FILE_ADDRESS	0x14A23	//文件DATA区起始地址
#define BIN_BITMAP_PRI_BLOCK_LEN	0x100	//BITMAP区，5字节可以表示所有的数据块占用情况



#define FILE_FAT_BLOCK_LEN		0x100	//文件头信息块大小  256

#define FILE_DATA_BLOCK_LEN		0x200	//文件数据区块大小  512
#define FILE_FAT_FILE_ADDRESS		0x41A00	//文件起始地址  //todo 
#define FILEDATA_FILE_ADDRESS		0x44C00	//文件DATA区起始地址

#define FILE_BITMAP_FILE_ADDRESS		0x44A00	//文件BITMAP区起始地址
#define FILE_BITMAP_BLOCK_LEN		0x800	//BITMAP区，35字节可以表示所有的数据块占用情况

#define FILE_DATA_FILE_ADDRESS	        0x47C00	//私钥文件DATA区起始地址
#define FILE_BITMAP_PRI_BLOCK_LEN	0x100	//BITMAP区，5字节可以表示所有的数据块占用情况  16KB 32    1bit 512 1byte


#define SM2_PARAM_FILE_ADDRESS		0x3CC41
#define SM2_ID_FILE_ADDRESS		0x3CC00//从243K开始存放

#define ECC_NIST_CURVE_INDDEX		1
#define ECC_BRAINPOOL_CURVE_INDDEX	2
#define ECC_CURVE_SIZE			193		//1B长度+192B曲线参数

//预留20K
//#define DESERVED_FILE_ADDRESS	0x2D000//180K开始

#define FILE_NUM_MAX			32		//支持创建文件的最大个数
#define SHSM_FILE_SIZE			500*1024		//文件大小


#define FILENAME_MAX_SIZE			250*1024		//文件大小






//密钥结构体
typedef struct  __SOFT_FS_KEY
{   
	unsigned char	id; 		//密钥ID
	unsigned char	type;		//密钥类型
	unsigned char	use_Acl ; 	//使用权限
	unsigned char	update_Acl;	//更改权限
	unsigned char	new_state;	//后续状态
	unsigned char	try_num;	//尝试次数
	unsigned char	unlock_role;//解锁密钥可以解锁的role
	unsigned char	len;		//密钥长度
	unsigned char	key[32];	//密钥值
	unsigned char	reserve;	//保留位
}SOFT_FS_KEY, *PSOFT_FS_KEY;

//二进制文件结构体
typedef struct __SOFT_FS_FILE
{
	unsigned char	id[4];			//文件ID
	unsigned char	type;			//文件类型
	unsigned char	name[128];		//目录名称
	unsigned short	room;			//空间大小
	unsigned char	read_Acl;		//读取权限  对rsa私钥文件 该值无效，卡的私钥不允许读取
	unsigned char	write_Acl;		//写入权限
	unsigned char	use_Acl;		//使用权限 当为公私钥文件时有效
	unsigned int	start_address;	//起始地址
	unsigned char	block_num;		//占用块个数
	unsigned char	crc[4];			//校验值
}SOFT_FS_FILE, *PSOFT_FS_FILE;

///目录结构,后续待扩充
typedef struct _SOFT_FS_DIR
{	
	unsigned char       id[4];		//目录ID    应用目录时有效
	unsigned char       type;		//根目录、应用目录  
	unsigned short      room;		//空间大小 当应用目录时有效，最大16K
	unsigned char       create_Acl;	//创建权限：在目录下创建文件的权限 
	unsigned char       delete_Acl;	//删除权限：在目录下删除文件的权限
	unsigned char       name[8];	//目录名称
}SOFT_FS_DIR, *PSOFT_FS_DIR;



#ifdef __cplusplus
extern "C" {
#endif

//打开文件
int FS_OpenFile(char* filePath, HANDLE* fd);

//关闭文件
int FS_CloseFile(HANDLE fd);

// 读文件头
int FS_ReadFileInfo(HANDLE fd, PSOFT_FS_HEAD_INFO pHeardInfo);

// 写文件头
int FS_WriteFileInfo(HANDLE fd, SOFT_FS_HEAD_INFO heardInfo);

//删除密钥
int FS_DeleteKey(HANDLE fd, unsigned char kid);

// 读密钥 (kid)
int FS_ReadKey(HANDLE fd,int type, unsigned char kid, PSOFT_FS_KEY pKey);

// 写密钥 (kid)
int FS_WriteKey(HANDLE fd, int type, PSOFT_FS_KEY pKey);

//创建二进制文件
int FS_CreateBinary(HANDLE fd, PSOFT_FS_FILE pBin);

//删除二进制文件
int FS_DeleteBinary(HANDLE fd, unsigned char* fid);

// 读二进制文件 (fid)
int FS_ReadBinary(HANDLE fd, int isFat, unsigned char* fid, int offset, int readlen,unsigned char * pDataOut);

// 写二进制文件(fid)
int FS_WriteBinary(HANDLE fd, unsigned char* fid, int offset, unsigned char* pDataIn,int inlen);

//读SM2ID、SM2参数
int FS_ReadSM2Param(HANDLE fd, unsigned char* SM2id, unsigned char* idlen,unsigned char* SM2param);

//写SM2ID、参数
int FS_WriteSM2Param(HANDLE fd, unsigned char* SM2id,unsigned char idlen,unsigned char* SM2param,unsigned char plen);

//读ECC曲线参数
int FS_ReadECCParam(HANDLE fd, int index, unsigned char* ECCparam,unsigned char *plen);

//读ECC曲线参数
int FS_WriteECCParam(HANDLE fd, int index, unsigned char* ECCparam,unsigned char plen);

//写目录信息，目前只有根目录信息
int FS_WriteDirInfo(HANDLE fd, PSOFT_FS_DIR pDir);

//读目录信息
int FS_ReadDirInfo(HANDLE fd, PSOFT_FS_DIR pDir);

//获取二进制文件剩余空间
int FS_GetResidRoom(HANDLE fd,unsigned int * size);



//密文写入文件
int InitWrite(int flag,HANDLE fd,int offset,int size,unsigned char * buf, int keytype);

int FS_CreateFile(HANDLE fd, PSOFT_FS_FILE pBin);
int FS_DeleteFile(HANDLE fd, unsigned char* fileName ,unsigned int nameLen);
int FS_ReadFile( HANDLE fd, int isFat, unsigned char* fileName, unsigned int nameLen, int offset, int readlen,unsigned char * pDataOut );
int FS_WriteFile( HANDLE fd, unsigned char* fileName, unsigned int nameLen, int offset, unsigned char* pDataIn,int inlen );


#ifdef __cplusplus
}

#endif

#endif
