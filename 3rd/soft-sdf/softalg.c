#include <stdio.h>
#include <stdlib.h>

#include "common.h"

#include "softalg.h"
#include "sesskeymgr.h"
#include "sm4.h"
#include "aes.h"
#include "fs.h"

SOFT_DEVICE gSDevice = {0,"","",-1};


int threadCount = 0;

int F_CheckFile(char* filepath)
{
	int ret = 0;

	ret = access(filepath, 06);
	return ret;
}

int F_CheckHandle(HANDLE fd)
{	
	int ret;

	struct stat fsta;
	ret = fstat((int)fd, &fsta);
	return ret;
}

int CheckHandle(SOFT_HANDLE handle)
{
	SOFT_DEVICE* dev = (SOFT_DEVICE*)handle;
	if(!dev)
	{
		LOG_Write(NULL,"%s:%d dev = %p",__FUNCTION__,__LINE__,dev);
		return -1;
	}

	if (handle != &gSDevice)
	{
		LOG_Write(NULL,"%s:%d handle = %p，gSDevice = %p",__FUNCTION__,__LINE__,handle,&gSDevice);
		return -1;
	}

	if(memcmp(dev->szFilePath, gSDevice.szFilePath, strlen(gSDevice.szFilePath)) != 0)
	{
		LOG_Write(NULL,"%s:%d handle check error",__FUNCTION__,__LINE__);
		return -1;
	}

	//检查文件是否存在
	if(F_CheckFile(gSDevice.szFilePath)) 
	{
		LOG_Write(NULL,"%s:%d F_CheckFile error",__FUNCTION__,__LINE__);
		return SOFT_NO_DEVICE;
	}

	//检查文件句柄
	if(0 != F_CheckHandle(gSDevice.hFile))
	{
		LOG_Write(NULL,"%s:%d F_CheckHandle error",__FUNCTION__,__LINE__);
		return -1;
	}

	return 0;
}


static int g_mutex = -1;
int DoUnlockDev()
{
	int ret = 0;
	int i = 0;



	if(g_mutex == -1)
		return SOFT_OK;
	ret = flock(g_mutex,LOCK_UN);
	if(ret != 0)
	{
		SleepUs(10000);
		flock(g_mutex,LOCK_UN);
	}
	close(g_mutex);
	g_mutex = -1;

	return SOFT_OK;
}
int DoLockDev()
{
	int ret = SOFT_OK;
	int i = 0;
	HANDLE hmutex;	
	char name[MAX_PATH];
	int mutex = -1;


	mutex = open("/dev/null",O_RDONLY);
	if(-1 == mutex)
	{
		LOG_Write(NULL,"%s:%d create tlock failed, err=%d",__FUNCTION__,__LINE__,errno);
		return SOFT_TLOCK_FAILD;
	}
	for (i=0; i<TLOCK_TIMEOUT*1000; i++)
	{
		ret = flock(mutex, LOCK_EX | LOCK_NB);
		if(0 == ret)
		{
			while(g_mutex != -1)
			{
				SleepUs(10);
			}
			g_mutex = mutex;
			return SOFT_OK;
		}
		SleepUs(1000);
	}
	close(mutex);
	LOG_Write(NULL,"%s:%d tlock timeout.",__FUNCTION__,__LINE__);

	//超时,释放锁
	DoUnlockDev();

	return SOFT_TLOCK_TIMEOUT;

}


int F_OpenFile(char *filePath, HANDLE *fd)
{
	int err = 0;
	HANDLE handle = INVALID_HANDLE_VALUE;

	handle = open(filePath, O_RDWR | O_SYNC );
	if(INVALID_HANDLE_VALUE == handle)
	{
		LOG_Write(NULL,"%s,%d:open %s failed,errno=%d:%s.", __FUNCTION__, __LINE__,filePath, errno, strerror(errno));
		return -1;
	}
	*fd = handle;

	return 0;
}

int F_CloseFile(HANDLE *fd)
{
	int ret = 0;

	ret = close(*fd);
	*fd = INVALID_HANDLE_VALUE;

	return ret;
}

//打开文件,返回文件句柄
int SOFT_OpenDev(void ** hHandle)
{
	int ret = SOFT_OK;

	LOG_Write(NULL,"Call %s:%d",__FUNCTION__,__LINE__);

	*hHandle = &gSDevice;

	DoLockDev();

	if (threadCount > 0)
	{
		//保证现有句柄可用
		if(CheckHandle(*hHandle))
		{
			F_CloseFile(&gSDevice.hFile);
			gSDevice.hFile = INVALID_HANDLE_VALUE;
			threadCount = 0;
			ret = SOFT_NO_DEVICE;
		}
		else
		{
			threadCount++;
		}
		goto EXIT;
	}
	memcpy(gSDevice.szFilePath,KM_SOFT_PATH,sizeof(KM_SOFT_PATH));
	printf("gSDevice.szFilePath=%s\n",gSDevice.szFilePath);
	ret = F_OpenFile(gSDevice.szFilePath, &(gSDevice.hFile));
	if (ret)
	{

		goto EXIT;
	}
	threadCount = 1;

EXIT:
	DoUnlockDev();
	return ret;
}

int SOFT_CloseDev(void * hHandle)
{
	LOG_Write(NULL,"Call %s:%d",__FUNCTION__,__LINE__);

	DoLockDev();

	threadCount--;
	if (threadCount > 0)
	{

		goto EXIT;
	}
	if (threadCount < 0)
	{

		goto EXIT;
	}
	//恢复状态
	gSDevice.ucCardState = 0;
	if (INVALID_HANDLE_VALUE != gSDevice.hFile)
	{

		F_CloseFile(&gSDevice.hFile);
		gSDevice.hFile = INVALID_HANDLE_VALUE;
	}

EXIT:
	DoUnlockDev();
	
	return SOFT_OK;
}





int SOFT_GetDevInfo(SOFT_HANDLE hHandle,PSOFT_DEVINFO pDevInfo)
{
	int ret = SOFT_OK;
	SOFT_FS_HEAD_INFO headInfo = {0};


	LOG_Write(NULL,"Call %s",__FUNCTION__);

	if(CheckHandle(hHandle))
	{
		return SOFT_INVALID_PARA;
	}

	DoLockDev();

	//读设备头信息
	ret = FS_ReadFileInfo(((SOFT_DEVICE *)hHandle)->hFile, &headInfo);
	if (ret)
	{
		goto EXIT;
	}

	memset(pDevInfo->cardid, 0, sizeof(pDevInfo->cardid));
	memset(pDevInfo->cosver, 0, sizeof(pDevInfo->cosver));

	memcpy(pDevInfo->cardid, headInfo.devID, 32);

	memcpy(pDevInfo->cosver, (unsigned char*)SDF_VERSION, strlen(SDF_VERSION));

	pDevInfo->cardtype = CT_SOFT;

	pDevInfo->reserve = 0;

EXIT:

	DoUnlockDev();
	return ret;
}

int SOFT_GenRandom( int len, unsigned char * pRandom )
{
	int ret = 0;
	int pid = 0;
	pid = GETPID();
	srand(((unsigned int)time(NULL)+pid));

	for (int i = 0; i < len; i++) {
		pRandom[i] = (char)(rand() % 255 + 1);
	}

	return 0;
}


int SOFT_Init()
{
	int ret = 0;
	//1.文件判断是否存在，没有创建，如果有，返回


	//2.写入SN号码 ex:200035021PG3P52000005

		
	//3.生成主密钥


	//4.初始化存储区

	ret = InitDatFile("", KM_SOFT_PATH, "111111", 6, "123456", 6);
	//5.写入数据
	


	return ret;
}



int DoReadFile(int filetype, int filestate, SOFT_HANDLE hHandle,const unsigned char* fid,int readPos, int readLen,unsigned char * pDataout)
{
	int ret = SOFT_OK;
	int dataLen = 0;
	unsigned char ucLoAcl = 0;
	unsigned char ucHiAcl = 0;
	SOFT_FS_FILE fileInfo = {0};

	DoLockDev();


	//读取FAT区,查找文件，权限
	ret = FS_ReadBinary(((SOFT_DEVICE *)hHandle)->hFile, 1, (unsigned char*)fid, 0, 0, (unsigned char*)&fileInfo);
	if(ret != SOFT_OK)
	{
		//ret = CheckFSRetval(ret);
		goto EXIT;
	}
	if (FILE_READ_STATE == filestate)
	{
		ucLoAcl = (fileInfo.read_Acl&0x0F);
		ucHiAcl = (fileInfo.read_Acl&0xF0)>>4;
	}
	else
	{
		ucLoAcl = (fileInfo.use_Acl&0x0F);
		ucHiAcl = (fileInfo.use_Acl&0xF0)>>4;
	}




	if (readLen+readPos > fileInfo.room)
	{
		ret = SOFT_NO_FILE_SPACE;
		goto EXIT;
	}
	//读取文件DATA区
	ret = FS_ReadBinary(((SOFT_DEVICE *)hHandle)->hFile, 0, (unsigned char*)fid, readPos, readLen, pDataout);
	if(ret != SOFT_OK)
	{
		//ret = CheckFSRetval(ret);
		goto EXIT;
	}

EXIT:

	DoUnlockDev();
	return ret;
}


int DoWriteFile(int filetype, SOFT_HANDLE hHandle,const unsigned char* fid,int writePos, int writeLen, const unsigned char * pDatain)
{
	int ret = SOFT_OK;
	int dataLen = 0;
	unsigned char ucLoAcl = 0;
	unsigned char ucHiAcl = 0;
	SOFT_FS_FILE fileInfo = {0};

	DoLockDev();
	//读取FAT区,查找文件
	ret = FS_ReadBinary(((SOFT_DEVICE *)hHandle)->hFile, 1, (unsigned char*)fid, 0, 0, (unsigned char*)&fileInfo);
	if(ret != SOFT_OK)
	{
		LOG_Write(NULL, "%s:%d ret=%d", __FUNCTION__, __LINE__,ret);

		goto EXIT;
	}


	if (writeLen+writePos > fileInfo.room)
	{
		ret = SOFT_NO_FILE_SPACE;
		goto EXIT;
	}

	//写文件DATA区
	ret = FS_WriteBinary(((SOFT_DEVICE *)hHandle)->hFile, (unsigned char*)fid, writePos, (unsigned char*)pDatain, writeLen);
	if(ret != SOFT_OK)
	{
		goto EXIT;
	}


EXIT:
	DoUnlockDev();
	return ret;
}


static int DoReadRsaPubKey(SOFT_HANDLE hHandle,int filestate, const unsigned char * fid, PSOFT_RSA_PUB_KEY pPub)
{
	int ret = SOFT_OK;
	unsigned char ucLoAcl = 0;
	unsigned char ucHiAcl = 0;
	unsigned char buf[267] = {0};
	SOFT_FS_FILE fileInfo = {0};

	LOG_Write(NULL,"Call %s",__FUNCTION__);

	if(!fid||!pPub)
		return SOFT_INVALID_PARA;

	//读取文件DATA区
	ret=DoReadFile(0x3E, filestate, hHandle, fid, 0,265,buf);
	if(ret != SOFT_OK)
		return ret;	

	if(buf[0]!=0x6E)
		return SOFT_BAD_PUBKEY;
	if(buf[1] == 0x80 && buf[0x82]==0x65 && buf[0x83]==0x03) //RSA1024:  6e 80 + [n] + 65 03 01 00 01
	{
		pPub->bits = 1024;
		memcpy(pPub->m,buf+2,CARD_RSA_LEN);
		pPub->e = (*(buf+0x84) << 16) + (*(buf+0x85) << 8) + *(buf+0x86);
	}
	else if(buf[1] == 0x82 && buf[2] == 0x01 && buf[3] == 0x00 && buf[0x82+0x82] == 0x65 && buf[0x83+0x82] == 0x03)//RSA2048:  6e 82 01 00 + [n] + 65 03 01 00 01
	{
		pPub->bits = 2048;
		memcpy(pPub->m,buf+4,MAX_CARD_RSA_LEN);
		pPub->e = (*(buf+0x84+0x82) << 16) + (*(buf+0x85+0x82) << 8) + *(buf+0x86+0x82);
	}
	else if(buf[1] == 0x81 && buf[2] == 0x90 && buf[0x93] == 0x65 && buf[0x94] == 0x03) //RSA1152: 6e 81 90 + [n] + 65 03 01 00 01
	{
		pPub->bits = 1152;
		memcpy(pPub->m,buf+3,144);
		pPub->e = (*(buf+0x84+17) << 16) + (*(buf+0x85+17) << 8) + *(buf+0x86+17);;
	}
	else
		return SOFT_BAD_PUBKEY;

	return SOFT_OK;	
}
int SOFT_ReadRsaPubKey(SOFT_HANDLE hHandle, const unsigned char * fid, PSOFT_RSA_PUB_KEY pPub)
{
	return DoReadRsaPubKey(hHandle,FILE_READ_STATE, fid, pPub);
}

int SOFT_ReadRsaPriKey(SOFT_HANDLE hHandle, const unsigned char * fid, PSOFT_RSA_PRI_KEY pPri)

{
	int ret = SOFT_OK;
	int dataLen = 0;
	int modulus = 0;
	unsigned int i = 0;
	unsigned char ucLoAcl = 0;
	unsigned char ucHiAcl = 0;
	unsigned char ucBuf[1024] = {0};
	SOFT_FS_FILE fsPriFile = {0};
	int prilen = 0x40;

	LOG_Write(NULL,"Call %s",__FUNCTION__);

	if(!pPri||!fid)
		return SOFT_INVALID_PARA;


	if(CheckHandle(hHandle))
		return SOFT_NO_HANDLE;

	DoLockDev();


	//读取私钥文件属性
	ret = FS_ReadBinary(((SOFT_DEVICE *)hHandle)->hFile, 1, (unsigned char*)fid, 0, 0, (unsigned char*)&fsPriFile);
	if(ret != SOFT_OK)
	{

		goto EXIT;
	}

	if (0x3D != fsPriFile.type)
	{
		ret = SOFT_FILE_TYPE;
		goto EXIT;
	}
	//检查私钥使用权限
	ucLoAcl = (fsPriFile.use_Acl&0x0F);
	ucHiAcl = (fsPriFile.use_Acl&0xF0)>>4;

	//读取私钥文件Data区,取私钥值
	ret = FS_ReadBinary(((SOFT_DEVICE *)hHandle)->hFile, 0, (unsigned char*)fid, 0, 2, ucBuf);
	if(ret != SOFT_OK)
	{

		goto EXIT;
	}

	if (0x70 != ucBuf[0])
	{
		ret = SOFT_BAD_PRIKEY;
		goto EXIT;
	}
	dataLen = ucBuf[1]*5+5*2;


	pPri->bits =  ucBuf[1]*16;

	memset(ucBuf, 0, 1024);
	ret = FS_ReadBinary(((SOFT_DEVICE *)hHandle)->hFile, 0, (unsigned char*)fid, 0, dataLen, ucBuf);
	if(ret != SOFT_OK)
	{

		goto EXIT;
	}
	prilen =ucBuf[1];

	memcpy(pPri->p,ucBuf+2,prilen);
	memcpy(pPri->q,ucBuf+2+prilen+2,prilen);
	memcpy(pPri->dp,ucBuf+2+(prilen+2)*2,prilen);
	memcpy(pPri->dq,ucBuf+2+(prilen+2)*3,prilen);
	memcpy(pPri->ce,ucBuf+2+(prilen+2)*4,prilen);

EXIT:
	DoUnlockDev();
	return ret;
}

int SOFT_WriteRsaPubKey(SOFT_HANDLE hHandle, const unsigned char * fid, PSOFT_RSA_PUB_KEY pPub)
{
	int ret = SOFT_OK;
 	unsigned char cmdBuf[265] = {0};

	SOFT_FS_FILE fsFile = {0};
	LOG_Write(NULL,"Call %s",__FUNCTION__);

	if(CheckHandle(hHandle))
	{

		return SOFT_INVALID_PARA;
	}

	if(!fid || !pPub)
		return SOFT_INVALID_PARA;

    //创建文件
	memset(&fsFile, 0, sizeof(SOFT_FS_FILE));
	memcpy(fsFile.id+2, fid, 2);
	fsFile.type = 0x3E;
	fsFile.room = 0x0400;
	fsFile.read_Acl = 0xF0;
	fsFile.write_Acl = 0xF0;
	ret = FS_CreateBinary(((SOFT_DEVICE *)hHandle)->hFile, &fsFile);

	if (SOFT_OK != ret && FSR_FILE_EXIST != ret)
	{
		LOG_Write(NULL, "%s line%d:FS_CreateBinary error, err=%d", __FUNCTION__, __LINE__, ret);
		return SOFT_CREATE_BIN;
	}


	if(pPub->bits == 1024)
	{
		cmdBuf[0x00]=0x6E;//n
		cmdBuf[0x01]=0x80;
		memcpy(cmdBuf+2,pPub->m,CARD_RSA_LEN);
		cmdBuf[0x82]=0x65;//e
		cmdBuf[0x83]=0x03;
		cmdBuf[0x84]=((pPub->e) >>16 &0xFF);
		cmdBuf[0x85]=((pPub->e) >>8  &0xFF);
		cmdBuf[0x86]=((pPub->e)      &0xFF);
	
		ret=DoWriteFile(0x3E,hHandle,fid,0,0x87,cmdBuf);
	}
	else if(pPub->bits == 2048)
	{
		cmdBuf[0x00]=0x6E;
		cmdBuf[0x01]=0x82;
		cmdBuf[0x02]=0x01;
		cmdBuf[0x03]=0x00;
		memcpy(cmdBuf+4,pPub->m,MAX_CARD_RSA_LEN);
		cmdBuf[0x82+0x82]=0x65;
		cmdBuf[0x83+0x82]=0x03;
		cmdBuf[0x84+0x82]=((pPub->e) >>16 &0xFF);
		cmdBuf[0x85+0x82]=((pPub->e) >>8  &0xFF);
		cmdBuf[0x86+0x82]=((pPub->e)      &0xFF);

		ret=DoWriteFile(0x3E,hHandle,fid,0,265,cmdBuf);
	}
	else
		ret = SOFT_INVALID_PARA;

	return ret;
}

int SOFT_WriteRsaPriKey(SOFT_HANDLE hHandle, const unsigned char * fid, PSOFT_RSA_PRI_KEY pPri)
{
	int ret = SOFT_OK;
	int cmdlen = 0;
	unsigned char cmdBuf[1024] = {0};
	int prilen = 0x40;
	SOFT_FS_FILE fsFile = {0};

	LOG_Write(NULL,"Call %s",__FUNCTION__);

	if(CheckHandle(hHandle))
	{
		return SOFT_INVALID_PARA;
	}

	if(!fid || !pPri)
		return SOFT_INVALID_PARA;


    //创建文件
	memset(&fsFile, 0, sizeof(SOFT_FS_FILE));
	memcpy(fsFile.id+2, fid, 2);
	fsFile.type = 0x3D;//pri
	fsFile.room = 0x0400;
	fsFile.read_Acl = 0xF0;
	fsFile.write_Acl = 0xF0;
	ret = FS_CreateBinary(((SOFT_DEVICE *)hHandle)->hFile, &fsFile);
	if (SOFT_OK != ret && FSR_FILE_EXIST != ret)
	{
		LOG_Write(NULL, "%s line%d:FS_CreateBinary error, err=%d", __FUNCTION__, __LINE__, ret);
		return SOFT_CREATE_BIN;
	}

	prilen = pPri->bits / 16;

	cmdBuf[cmdlen++] = 0x70;//p
	cmdBuf[cmdlen++] = prilen;
	memcpy(cmdBuf+cmdlen, pPri->p, prilen);
	cmdlen += prilen;

	cmdBuf[cmdlen++] = 0x71;//p
	cmdBuf[cmdlen++] = prilen;
	memcpy(cmdBuf+cmdlen, pPri->q, prilen);
	cmdlen += prilen;

	cmdBuf[cmdlen++] = 0x50;//dp
	cmdBuf[cmdlen++] = prilen;
	memcpy(cmdBuf+cmdlen, pPri->dp, prilen);
	cmdlen += prilen;

	cmdBuf[cmdlen++] = 0x51;//dq
	cmdBuf[cmdlen++] = prilen;
	memcpy(cmdBuf+cmdlen, pPri->dq, prilen);
	cmdlen += prilen;

	cmdBuf[cmdlen++] = 0x49;//ce
	cmdBuf[cmdlen++] = prilen;
	memcpy(cmdBuf+cmdlen, pPri->ce, prilen);
	cmdlen += prilen;	
	//写私钥值
	ret = DoWriteFile(0x3D,hHandle,fid,0,cmdlen,cmdBuf);
	if (SOFT_OK != ret)
	{
		return ret;
	}

	return SOFT_OK;
}



int SOFT_WriteSM2PubKey( SOFT_HANDLE hHandle, const unsigned char * fid, PSOFT_SM2_PUBKEY pPub )
{
	int ret = SOFT_OK;
 	unsigned char buf[128] = {0};

	SOFT_FS_FILE fsFile = {0};
	LOG_Write(NULL,"Call %s",__FUNCTION__);

	if(CheckHandle(hHandle))
	{
		return SOFT_INVALID_PARA;
	}

	if(!fid || !pPub)
		return SOFT_INVALID_PARA;

	buf[0] = 0x78;//x
	buf[1] = 0x20;
	memcpy(buf+2, pPub->x, KEY_LEN_SM2);
	buf[KEY_LEN_SM2+2] = 0x79;//y
	buf[KEY_LEN_SM2+3] = 0x20;
	memcpy(buf+KEY_LEN_SM2+4, pPub->y, KEY_LEN_SM2);

 	//创建文件
	memset(&fsFile, 0, sizeof(SOFT_FS_FILE));
	memcpy(fsFile.id+2, fid, 2);
	fsFile.type = 0x3E;//pri
	fsFile.room = 0x0100;
	fsFile.read_Acl = 0xF0;
	fsFile.write_Acl = 0xF0;
	ret = FS_CreateBinary(((SOFT_DEVICE *)hHandle)->hFile, &fsFile);
	if (SOFT_OK != ret && FSR_FILE_EXIST != ret)
	{
		LOG_Write(NULL, "%s line%d:FS_CreateBinary error, err=%d", __FUNCTION__, __LINE__, ret);
		return SOFT_CREATE_BIN;
	}

	//写公钥值
	ret = DoWriteFile(0x3E,hHandle, fid, 0, 68, buf);
	if (SOFT_OK != ret)
	{
		return ret;
	}

	return SOFT_OK;
}




int SOFT_WriteSM2PriKey( SOFT_HANDLE hHandle, const unsigned char * fid, PSOFT_SM2_PRIKEY pPri )
{
	int ret = SOFT_OK;
 	unsigned char buf[64] = {0};
	SOFT_FS_FILE fsFile = {0};

	LOG_Write(NULL,"Call %s",__FUNCTION__);

	if(!fid || !pPri)
		return SOFT_INVALID_PARA;

	buf[0] = 0x64;//d
	buf[1] = KEY_LEN_SM2;
	memcpy(buf+2, pPri->d, KEY_LEN_SM2);


	//创建文件
	memset(&fsFile, 0, sizeof(SOFT_FS_FILE));
	memcpy(fsFile.id+2, fid, 2);
	fsFile.type = 0x3D;//pri
	fsFile.room = 0x0100;
	fsFile.read_Acl = 0xF0;
	fsFile.write_Acl = 0xF0;
	ret = FS_CreateBinary(((SOFT_DEVICE *)hHandle)->hFile, &fsFile);
	if (SOFT_OK != ret && FSR_FILE_EXIST != ret)
	{
		LOG_Write(NULL, "%s line%d:FS_CreateBinary error, err=%d", __FUNCTION__, __LINE__, ret);
		return SOFT_CREATE_BIN;
	}

	//写私钥值
	ret = DoWriteFile(0x3D,hHandle, fid, 0, KEY_LEN_SM2+2, buf);
	if (SOFT_OK != ret)
	{
		return ret;
	}

	return SOFT_OK;
}



static int DoReadSm2PubKey( SOFT_HANDLE hHandle,int filestate, const unsigned char * fid, PSOFT_SM2_PUBKEY pPub )
{
	int ret = SOFT_OK;
	unsigned char buf[128] = {0};
	SOFT_FS_FILE fileInfo = {0};


	if(!fid||!pPub)
		return SOFT_INVALID_PARA;

	ret=DoReadFile(0x3E, filestate, hHandle, fid, 0, 68, buf);

	if(ret != SOFT_OK)
		return ret;
	
	if(buf[0] == 0x78 && buf[1]==0x20 && buf[KEY_LEN_SM2+2] == 0x79 && buf[KEY_LEN_SM2+3] == 0x20) //sm2
	{

		memcpy( pPub->x, buf+2, KEY_LEN_SM2 );
		memcpy( pPub->y, buf+KEY_LEN_SM2+4, KEY_LEN_SM2 );
	}
	else
		return SOFT_BAD_PUBKEY;

	return SOFT_OK;
}

int SOFT_ReadSM2PubKey(SOFT_HANDLE hHandle, const unsigned char * fid, PSOFT_SM2_PUBKEY pPub )
{
	return DoReadSm2PubKey( hHandle, FILE_READ_STATE, fid, pPub );
}




int SOFT_ReadSm2PriKey(SOFT_HANDLE hHandle,unsigned char* priid,SOFT_SM2_PRIKEY* pPri)
{
	int ret;
	unsigned char buf[64] = {0};
	SOFT_FS_FILE fsPriFile = {0};

	ret = DoReadFile(0x3D, FILE_USE_STATE,hHandle,priid,0,34,buf);
	if (ret != SOFT_OK)
	{
		goto EXIT;
	}

	if(buf[0] == 0x64 && buf[1]==0x20) //sm2
	{
		memcpy( pPri->d, buf+2, KEY_LEN_SM2 );
	}
	else
	{
		ret = SOFT_BAD_PRIKEY;
		goto EXIT;
	}

	//pPri->bits = 256;

EXIT:

	return ret;
}




int SOFT_SM4KEY(const unsigned char *tmpkey, const unsigned char *pDataIn, int dataLen, int flag, unsigned char *pDataOut, unsigned char *pIV)
{
	int tag = 0;
	unsigned char ucSm4Key[16] = {0};
	sm4_context sm4ctx;	

	if(!tmpkey || !pDataIn|| dataLen%16 || !pDataOut)
		return SOFT_INVALID_PARA;

	if((flag&0xF0)==CBC_MODE && !pIV) //cbc模式,需要pIV	
		return SOFT_INVALID_PARA;	

	//长度为零 直接返回
	if(!dataLen)
		return SOFT_INVALID_PARA; 

	memcpy(ucSm4Key, tmpkey, 16);
	if((flag&0x0F)==OP_ENCRYPT)
	{
		sm4_setkey(&sm4ctx, ucSm4Key);
		tag = 1;
	}
	else
	{
		sm4_setkey(&sm4ctx, ucSm4Key);
		tag = 0;
	}

	if((flag&0xF0)==CBC_MODE)
	{
		sm4_crypt_cbc(&sm4ctx, tag, dataLen, pIV, (unsigned char *)pDataIn, pDataOut);
	}
	else
	{
		sm4_crypt_ecb(&sm4ctx, tag, dataLen, (unsigned char *)pDataIn, pDataOut);
	}

	return SOFT_OK;
}



int SOFT_AESKEY( const unsigned char *tmpkey, int keylen, const unsigned char *pDataIn, int dataLen, int flag, unsigned char *pDataOut, unsigned char *pIV)
{
	int ret = SOFT_OK;
	int tag = 0;

	LOG_Write(NULL,"Call %s",__FUNCTION__);

	if(!tmpkey || !pDataIn|| dataLen%16 || !pDataOut)
		return SOFT_INVALID_PARA;
	if((flag&0xF0)==CBC_MODE && !pIV) 
		return SOFT_INVALID_PARA;
	if(keylen != 16 && keylen != 24 && keylen != 32)
		return SOFT_INVALID_PARA;


	if((flag&0x0F)==OP_ENCRYPT)
		tag = 1;
	else
		tag = 0;

	if((flag&0xF0)==CBC_MODE)
		ret = AesCbc((unsigned char*)pDataIn,dataLen,tag,pDataOut,(unsigned char*)tmpkey,keylen,pIV);
	else
		ret = AesEcb((unsigned char*)pDataIn,dataLen,tag,pDataOut,(unsigned char*)tmpkey,keylen);


	return SOFT_OK;
}


///对称密钥计算调用SOFT
int SOFT_Symcrypto(void* hHandle, unsigned int operate, unsigned int uiAlgID, int uiKeyIndex, unsigned char *pucKey, unsigned int uiKeyLength, unsigned char *pucIV,
                     unsigned char *pucDataIn, unsigned int uiDataInLen, unsigned char *pucDataOut, unsigned int *puiDataOutLen, unsigned int node)
{
    int ret = SDR_OK;
    unsigned char algType = 0;
    unsigned char algMode = 0;
    unsigned char keyMode = 0;
    unsigned char key[64] = {0};
    int keyLen = 0;


    ret = CheckHandle(hHandle);
    if (SDR_OK != ret)
    {
        return ret;
    }

    if (-1 == uiKeyIndex && NULL == pucKey)
    {
        LOG_Write(NULL, "%s[%d] uiKeyIndex or pucKey error", __FUNCTION__, __LINE__);
        return SDR_INARGERR;
    }

    if (0x01 == ((uiAlgID >> 8) & 0xff))
    {
        algType = ALG_SM1;
        LOG_Write(NULL, "%s[%d] algType not support", __FUNCTION__, __LINE__);
        return SDR_INARGERR;
    }else  if (0x04 == ((uiAlgID >> 8) & 0xff))
    {
        algType = ALG_SM4;
    }else  if (0x08 == ((uiAlgID >> 8) & 0xff))
    {
        algType = ALG_AES128;
    }else  if (0x03 == ((uiAlgID >> 8) & 0xff))
    {
        algType = ALG_AES256;
    }else  if (0x05 == ((uiAlgID >> 8) & 0xff))
    {
        algType = ALG_AES192;
    }

    if (0x01 == (uiAlgID & 0xff) && OP_ENCRYPT == operate)
    {
        algMode = ECB_ENCRYPT;
    }
    else if (0x01 == (uiAlgID & 0xff) && OP_DECRYPT == operate)
    {
        algMode = ECB_DECRYPT;
    }
    else if (((0x02 == (uiAlgID & 0xff)) || (0x10 == (uiAlgID & 0xff))) && OP_ENCRYPT == operate)
    {
        algMode = CBC_ENCRYPT;
    }
    else if ((0x02 == (uiAlgID & 0xff)) && OP_DECRYPT == operate)
    {
        algMode = CBC_DECRYPT;
    }
    else
    {
        //CFB OFB now not support
        LOG_Write(NULL, "%s[%d] uiAlgID or operate is not support", __FUNCTION__, __LINE__);
        return SDR_NOTSUPPORT;
    }

    if (-1 != uiKeyIndex)
    {
        ret = ExportSessKey(hHandle, uiKeyIndex, key, &keyLen);
        if ( 0 != ret )
        {
            LOG_Write(NULL, "%s:%d ret = %08x", __FUNCTION__, __LINE__, ret);
            goto EXIT;
        }
    }
    else
    {
        memcpy(key, pucKey, uiKeyLength);
        keyLen = uiKeyLength;
    }
    
    if(algType == ALG_SM4)
    {

	ret =SOFT_SM4KEY((const unsigned char *)key, (const unsigned char *)pucDataIn, uiDataInLen, algMode, pucDataOut, pucIV);
    }else if(algType == ALG_AES128)
    {
	ret = SOFT_AESKEY((const unsigned char *)key, 16, (const unsigned char *)pucDataIn, uiDataInLen, algMode, pucDataOut, pucIV);
    }else if(algType == ALG_AES192)
    {
	ret = SOFT_AESKEY((const unsigned char *)key, 24, (const unsigned char *)pucDataIn, uiDataInLen, algMode, pucDataOut, pucIV);
    }else if(algType == ALG_AES256)
    {
	ret = SOFT_AESKEY((const unsigned char *)key, 32, (const unsigned char *)pucDataIn, uiDataInLen, algMode, pucDataOut, pucIV);
    }

    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d sym_crypto failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        goto EXIT;
    }

    *puiDataOutLen = uiDataInLen;
EXIT:


    return ret;
}




int SOFT_CreateFile( SOFT_HANDLE hHandle,unsigned char *pucFileName, unsigned int uiNameLen, unsigned int uiFileSize)
{
	int ret = SOFT_OK;
 	unsigned char buf[64] = {0};
	SOFT_FS_FILE fsFile = {0};

	LOG_Write(NULL,"Call %s",__FUNCTION__);

	if(!pucFileName)
		return SOFT_INVALID_PARA;


	//创建文件
	memset(&fsFile, 0, sizeof(SOFT_FS_FILE));
	memcpy(fsFile.id, "\x5D\x5D\x5D\x5D", 4);
	memcpy(fsFile.name,pucFileName,uiNameLen);
	fsFile.type = 0x5D;//file
	fsFile.room = ((uiFileSize+511)/512)*512;
	fsFile.read_Acl = 0xF0;
	fsFile.write_Acl = 0xF0;
	ret = FS_CreateFile(((SOFT_DEVICE *)hHandle)->hFile, &fsFile);
	if (SOFT_OK != ret && FSR_FILE_EXIST != ret)
	{
		LOG_Write(NULL, "%s line%d:FS_CreateBinary error, err=%d", __FUNCTION__, __LINE__, ret);
		return SOFT_CREATE_BIN;
	}


	return ret;
}




int SOFT_ReadFile(SOFT_HANDLE hHandle,  unsigned char *pucFileName, unsigned int uiNameLen, unsigned int uiOffset, unsigned int *puiFileLength, unsigned char *pucBuffer)
{
	int ret = SOFT_OK;
	int dataLen = 0;
	int modulus = 0;
	unsigned int i = 0;
	unsigned char ucLoAcl = 0;
	unsigned int readLen = 0;
	unsigned char ucHiAcl = 0;
	unsigned char ucBuf[1024*16] = {0};

	SOFT_FS_FILE fileInfo = {0};

	LOG_Write(NULL,"Call %s",__FUNCTION__);

	if(!pucFileName)
		return SOFT_INVALID_PARA;


	if(CheckHandle(hHandle))
		return SOFT_NO_HANDLE;


	//读取文件属性
	readLen=FILE_FAT_BLOCK_LEN;
	ret = FS_ReadFile(((SOFT_DEVICE *)hHandle)->hFile, 1, (unsigned char*)pucFileName, uiNameLen, uiOffset, readLen,(unsigned char*)&fileInfo);
	if(ret != SOFT_OK)
	{

		goto EXIT;
	}

	if (0x5D != fileInfo.type)
	{

		ret = SOFT_FILE_TYPE;
		goto EXIT;
	}


	//读取文件Data区,取私钥值
	readLen = *puiFileLength;
	ret = FS_ReadFile(((SOFT_DEVICE *)hHandle)->hFile, 0, (unsigned char*)pucFileName, uiNameLen, uiOffset, readLen,pucBuffer);
	if(ret != SOFT_OK)
	{

		goto EXIT;
	}


EXIT:

	return ret;
}

int SOFT_WriteFile(SOFT_HANDLE hHandle, unsigned char *pucFileName, unsigned int uiNameLen, unsigned int uiOffset, unsigned int uiFileLength, unsigned char *pucBuffer)
{
	int ret = SOFT_OK;
	SOFT_FS_FILE fileInfo = {0};
	unsigned int readLen = 0;
	DoLockDev();
	//读取FAT区,查找文件
	readLen=FILE_FAT_BLOCK_LEN;
	ret = FS_ReadFile(((SOFT_DEVICE *)hHandle)->hFile, 1, (unsigned char*)pucFileName, uiNameLen, uiOffset, readLen,(unsigned char*)&fileInfo);
	if(ret != SOFT_OK)
	{

		LOG_Write(NULL, "%s:%d ret=%d", __FUNCTION__, __LINE__,ret);

		goto EXIT;
	}


	if (uiFileLength+uiOffset > fileInfo.room)
	{

		ret = SOFT_NO_FILE_SPACE;
		goto EXIT;
	}

	//写文件DATA区
	ret = FS_WriteFile(((SOFT_DEVICE *)hHandle)->hFile, (unsigned char*)pucFileName, uiNameLen, uiOffset,pucBuffer,uiFileLength);
	if(ret != SOFT_OK)
	{
		goto EXIT;
	}

EXIT:
	DoUnlockDev();
	return ret;


}


int SOFT_DeleteFile(SOFT_HANDLE hHandle,unsigned char *pucFileName, unsigned int uiNameLen)
{
	int ret = SOFT_OK;


	ret = FS_DeleteFile(((SOFT_DEVICE *)hHandle)->hFile,pucFileName,uiNameLen);
	
	if(ret != SOFT_OK)
	{
		goto EXIT;
	}

EXIT:
	return ret;

}


int SOFT_WriteKey(SOFT_HANDLE hHandle, unsigned int uiKeyIndex, unsigned char *pucKey, unsigned int uiKeyLen)
{

 	int ret = SOFT_OK;
 	unsigned char buf[64] = {0};

	SOFT_FS_KEY fsKey = {0};

	LOG_Write(NULL,"Call %s",__FUNCTION__);

	if(!pucKey)
		return SOFT_INVALID_PARA;


	memset(&fsKey, 0, sizeof(SOFT_FS_KEY));

	fsKey.id = uiKeyIndex;
	fsKey.type = 
	fsKey.len = uiKeyLen;
	memcpy(fsKey.key, pucKey, uiKeyLen);
	
	ret = FS_WriteKey(((SOFT_DEVICE *)hHandle)->hFile, 0, &fsKey);//写密钥
	if (SOFT_OK != ret)
	{

		goto EXIT;
	}
EXIT:
	return ret;
}



int SOFT_ReadKey(SOFT_HANDLE hHandle, unsigned int uiKeyIndex, unsigned char *pucKey, unsigned int *uiKeyLen)
{

 	int ret = SOFT_OK;
 	unsigned char buf[64] = {0};

	SOFT_FS_KEY fsKey = {0};

	LOG_Write(NULL,"Call %s",__FUNCTION__);

	if(!pucKey)
		return SOFT_INVALID_PARA;


	memset(&fsKey, 0, sizeof(SOFT_FS_KEY));


	ret = FS_ReadKey(((SOFT_DEVICE *)hHandle)->hFile, 0,uiKeyIndex, &fsKey);//写密钥
	if (SOFT_OK != ret)
	{

		goto EXIT;
	}

	
	*uiKeyLen =fsKey.len;
	memcpy(pucKey, fsKey.key, *uiKeyLen);
	
EXIT:
	return ret;
}





