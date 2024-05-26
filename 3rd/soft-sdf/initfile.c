#include "filesystem/file.h"
#include "filesystem/fs.h"

#include "tool.h"

#include "log.h"
#include "softalg.h"


unsigned char ucSm2ID[32] = "\x31\x32\x33\x34\x35\x36\x37\x38\x31\x32\x33\x34\x35\x36\x37\x38";
unsigned char ucHmacKey[64] = "1122334455667788990011223344556677889900112233445566778899001122";

extern char g_szCardPath[MAX_PATH];


int InitDatFile(char* pszDllPath, char* pszDatPath, unsigned char* pin, int plen, unsigned char* pucDevIdent, int devIdentLen)
{
	int i = 0;
	int rv = 0;
	HANDLE hDll = 0;
	HANDLE hDat = 0;
	unsigned int uiDllFileSize = 0;
	unsigned int uiOffset = 0;
	unsigned int uiReadLen = 0;
	unsigned int uiRemainLen = 0;
	unsigned char ucFileHead[512] = {0};
	unsigned char ucWriteBuf[512] = {0};
	unsigned char ucReadBuf[512] = {0};
	unsigned char ucDataTmp[512] = {0};
	unsigned char cmdBuf[512] = {0};
	unsigned char ucDevTag[32] = {0};
	unsigned char ucCardID[64] = "softhsm";
	unsigned char ucFileData[SHSM_FILE_SIZE] = {0};

	SOFT_SM2_PARAM softSm2Param = {0};
	SOFT_FS_KEY fsKey = {0};
	SOFT_FS_DIR fsDir = {0};
	SOFT_FS_FILE fsFile = {0};
	int datFileSize;
	unsigned char pinhash[32]={0};
	unsigned char endatkey[32]={0};
	unsigned char datakey[32]={0};
	unsigned char rnum[32]={0xb8,0x47,0x2a,0x5a,0xd1,0xe9,0x67,0x0d,0xd6,0xf2,0xad,0x85,0x2f,0x7f,0x86,0x7a,0xd7,0x6c,0x1e,0x7a,0x07,0xe1,0x67,0xba,0x6e,0x5b,0xe1,0x1c,0xa7,0x84,0xce,0x1b};
	unsigned char sm3digst[32] = {0};
	unsigned char sm1digst[16] = { 0 };
	SOFT_FS_HEAD_INFO headInfo = {0};


	LOG_Write(NULL,"Call %s",__FUNCTION__);

	if (!pszDatPath || !pucDevIdent)
	{
		LOG_Write(NULL, "%s line%d:param error, DatPath:%s, DevIdent:%s!", __FUNCTION__, __LINE__, pszDatPath, pucDevIdent);
		return SOFT_INVALID_PARA;
	}

	//默认文件大小
	datFileSize = SHSM_FILE_SIZE;

	//创建文件
	rv = F_SHSMNewFile(pszDatPath);
	if (SOFT_OK != rv)
	{
		return SOFT_CREATE_FILE;
	}

	//填充uiFileSize个0xFF
	rv = F_SHSMOpenFile(pszDatPath, &hDat);
	if (SOFT_OK != rv)
	{
		return SOFT_OPEN_FILE;
	}

	while (1)
	{
		uiOffset = 512*i;
		if (uiOffset >= (unsigned int)datFileSize)
		{
			break;
		}

		memset(ucWriteBuf, 0xFF, 512);
		rv = F_SHSMWriteFileEx(hDat, ucWriteBuf, uiOffset, 512);
		if(0 != rv)
		{	
			return SOFT_WRITE_FILE;
		}

		i++;		
	}

	memcpy(headInfo.devID+11,"200035021PG3P52000005",sizeof("200035021PG3P52000005"));
	//dumpdata(&headInfo.devID,32);
	rv = FS_WriteFileInfo(hDat, headInfo);
	if(0 != rv)
	{
		return SOFT_WRITE_FILE;
	}

	//置bitmap区全零
	memset(ucWriteBuf, 0, 512); 
	rv = F_SHSMWriteFileEx(hDat, ucWriteBuf, BIN_BITMAP_FILE_ADDRESS, 512);
	if(0 != rv)
	{	
		return SOFT_WRITE_FILE;
	}

	//置bitmap区全零
	memset(ucWriteBuf, 0, 512); 
	rv = F_SHSMWriteFileEx(hDat, ucWriteBuf, FILE_BITMAP_FILE_ADDRESS, 512);
	if(0 != rv)
	{	
		return SOFT_WRITE_FILE;
	}

	//写MF信息
	memcpy(fsDir.id, "\x00\x00\x3F\x00", 4);
	fsDir.type = 0x38;
	fsDir.room = 0xFFFF;
	fsDir.create_Acl = 0xF1;
	fsDir.delete_Acl = 0xF1;
	memcpy(fsDir.name, "1PAY.SYS", strlen("1PAY.SYS"));

	rv = F_SHSMWriteFileEx(hDat, (unsigned char*)(&fsDir), BIN_FAT_FILE_ADDRESS, sizeof(SOFT_FS_DIR));
	if(0 != rv)
	{	
		return SOFT_WRITE_FILE;
	}

	//读取DAT文件数据
	rv = F_SHSMReadFileEx(hDat, ucFileData, 0, datFileSize);
	if (0 != rv)
	{
		return SOFT_READ_FILE;
	}


	F_SHSMCloseFile(&hDat);

	rv = FS_OpenFile(pszDatPath, &hDat);
	if (SOFT_OK != rv)
	{
		LOG_Write(NULL, "%s line%d: error, DatPath:%s, err=%d", __FUNCTION__, __LINE__, pszDatPath, rv);
		return rv;
	}
	//1.写文件头，使用固定密钥
	for(i=0;i<SM2_ID_FILE_ADDRESS;)
	{
		rv = InitWrite(0, hDat, i, 512, ucFileData+i, 0);
		if(0 != rv)
		{	
			LOG_Write(NULL, "%s line%d: error, err=%d", __FUNCTION__, __LINE__, rv);
			return SOFT_WRITE_FILE;
		}
		i=i+512;
	}
	
	
	


	//创建密钥文件
	fsKey.id = 0;
	fsKey.type = 0;
	fsKey.use_Acl = 0;
	fsKey.update_Acl = 1;
	fsKey.new_state = 0xF1;
	rv = FS_WriteKey(hDat, 1, &fsKey); //写密钥文件头
	if (SOFT_OK != rv)
	{
		LOG_Write(NULL, "%s line%d: error, err=%d", __FUNCTION__, __LINE__, rv);
		FS_CloseFile(hDat);
		return SOFT_WRITE_KEY;
	}

	


	//创建SM4加解密密钥(主密钥，由设备ID唯一确定)
	memset(&fsKey, 0, sizeof(SOFT_FS_KEY));
	fsKey.id = 0x06;
	fsKey.type = 0x03;
	fsKey.len = 0x10;
	fsKey.use_Acl = 0xF0;
	fsKey.update_Acl = 0xF0;
	fsKey.try_num = 0x55;
	memcpy(fsKey.key, ucCardID+8, fsKey.len);
	rv = FS_WriteKey(hDat, 0, &fsKey);//写密钥
	if (SOFT_OK != rv)
	{
		FS_CloseFile(hDat);
		return SOFT_WRITE_KEY;
	}




#if 1

	//创建卡名称文件
	memset(&fsFile, 0, sizeof(SOFT_FS_FILE));
	memcpy(fsFile.id, "\x00\x00\x00\x02", 4);
	fsFile.type = 0x28;
	fsFile.room = 0x0100;
	fsFile.read_Acl = 0xF0;
	fsFile.write_Acl = 0x21;
	rv = FS_CreateBinary(hDat, &fsFile);
	if (SOFT_OK != rv)
	{
		FS_CloseFile(hDat);
		return SOFT_CREATE_BIN;
	}



	rv = FS_WriteBinary(hDat, (unsigned char*)"\x00\x02", 0,(unsigned char*)"\x00\x10\x11\x00\x22\x00\x33\x00\x44\x00\x55\x00\x66\x00\x77\x00\x88\x00", 36);


	if (SOFT_OK != rv)
	{
		LOG_Write(NULL, "%s line%d:FS_WriteBinary error, err=%d", __FUNCTION__, __LINE__, rv);
		FS_CloseFile(hDat);
		return SOFT_WRITE_BIN;
	}
#endif
	//创建容器信息文件
	memset(&fsFile, 0, sizeof(SOFT_FS_FILE));
	memcpy(fsFile.id, "\x00\x00\x00\x03", 4);
	fsFile.type = 0x28;
	fsFile.room = 0x0100;
	fsFile.read_Acl = 0xF0;
	fsFile.write_Acl = 0x21;
	rv = FS_CreateBinary(hDat, &fsFile);
	if (SOFT_OK != rv)
	{
		LOG_Write(NULL, "%s line%d:FS_CreateBinary error, err=%d", __FUNCTION__, __LINE__, rv);
		FS_CloseFile(hDat);
		return SOFT_CREATE_BIN;
	}
	


	//设置SM2 ID
	rv = FS_WriteSM2Param(hDat, ucSm2ID, 0x10, NULL, 0);
	if (SOFT_OK != rv)
	{
		FS_CloseFile(hDat);
		return SOFT_SM2_SET_PARAM;
	}

	//设置SM2 曲线参数
	memcpy(softSm2Param.p, "\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 32);
	memcpy(softSm2Param.a, "\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC", 32);
	memcpy(softSm2Param.b, "\x28\xE9\xFA\x9E\x9D\x9F\x5E\x34\x4D\x5A\x9E\x4B\xCF\x65\x09\xA7\xF3\x97\x89\xF5\x15\xAB\x8F\x92\xDD\xBC\xBD\x41\x4D\x94\x0E\x93", 32);
	memcpy(softSm2Param.n, "\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x72\x03\xDF\x6B\x21\xC6\x05\x2B\x53\xBB\xF4\x09\x39\xD5\x41\x23", 32);
	memcpy(softSm2Param.x, "\x32\xC4\xAE\x2C\x1F\x19\x81\x19\x5F\x99\x04\x46\x6A\x39\xC9\x94\x8F\xE3\x0B\xBF\xF2\x66\x0B\xE1\x71\x5A\x45\x89\x33\x4C\x74\xC7", 32);
	memcpy(softSm2Param.y, "\xBC\x37\x36\xA2\xF4\xF6\x77\x9C\x59\xBD\xCE\xE3\x6B\x69\x21\x53\xD0\xA9\x87\x7C\xC6\x2A\x47\x40\x02\xDF\x32\xE5\x21\x39\xF0\xA0", 32);
	rv = FS_WriteSM2Param(hDat, NULL, 0, (unsigned char*)&softSm2Param, sizeof(SOFT_SM2_PARAM));
	if (SOFT_OK != rv)
	{
		FS_CloseFile(hDat);
		return SOFT_SM2_SET_PARAM;
	}

	FS_CloseFile(hDat);

	return SOFT_OK;
}
