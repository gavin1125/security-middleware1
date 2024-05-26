#include "fs.h"
#include "bit.h"
#include "file.h"



unsigned char g_xdSM2id[64]={0};
int HasReadSm2Id = 0;



static int fsRead(HANDLE fd,int offset,int size,unsigned char * buf, int keytype)
{
	unsigned char tempbuf[512]={0};
	unsigned char tempdebuf[512]={0};
	int ret=0,rsize=0,blocknum=0,i=0;
	int start_addr=0,cur_addr=0;
	int divisor=0,remainder=0;
	int ivpos,leftsize=size,already=0;

	divisor = offset/512;//iv 
	remainder = offset%512;

	start_addr = offset - remainder;
	blocknum = (size+remainder)/512;
	if ((size+remainder)%512)
	{
		blocknum++;
	}
	
	for (i=0;i<blocknum;i++)
	{
		ivpos = divisor + i;
		cur_addr = start_addr + i*512;
	
		ret = F_SHSMReadFileEx(fd,tempbuf,cur_addr,512);
		if (ret)
		{
			return FSR_READ_FILE;
		}
		memcpy(tempdebuf,tempbuf,512);
 		
		if (0 == i)//第一块
		{
			if (size <= 512-remainder)//第一块就读完
			{
				memcpy(buf,tempdebuf+remainder,size);
				already += size;
				leftsize -= size;
			}
			else//
			{
				memcpy(buf,tempdebuf+remainder,512-remainder);
				already += 512-remainder;
				leftsize -= (512-remainder);
			}
		}
		else
		{
			if (leftsize>512)
			{
				memcpy(buf+already,tempdebuf,512);
				already += 512;
				leftsize -= 512;
			}
			else
			{
				memcpy(buf+already,tempdebuf,leftsize);
				already += leftsize;
				leftsize -= leftsize;
			}
		}
	}

	return 0;
}

static int fsWrite(HANDLE fd,int offset,int size,unsigned char * buf, int keytype)
{
	return InitWrite(0, fd, offset, size, buf, keytype);
}
//flag==0x00;明文读文件-加密-写文件；flag==1;密文读文件-解密-加密-写文件
int InitWrite(int flag,HANDLE fd,int offset,int size,unsigned char * buf, int keytype)
{
	unsigned char tempbuf[512]={0};
	unsigned char tempdebuf[512]={0};
	unsigned char tempenbuf[512]={0};
	int ret=0,rsize=0,wsize=0,blocknum=0,i=0;
	int start_addr=0,cur_addr=0;
	int divisor=0,remainder=0;
	int ivpos,leftsize=size,already=0;

	divisor = offset/512;
	remainder = offset%512;

	start_addr = offset - remainder;
	blocknum = (size+remainder)/512;
	if ((size+remainder)%512)
	{
		blocknum++;
	}

	for (i=0;i<blocknum;i++)
	{
		ivpos = divisor + i;
		cur_addr = start_addr + i*512;
	
		ret = F_SHSMReadFileEx(fd,tempbuf,cur_addr,512);
		if (ret)
		{
			return FSR_READ_FILE;
		}
		if (0 == flag)
		{
			memcpy(tempdebuf,tempbuf,512);
		}
		else
		{
			//if (DataDec(keytype, tempbuf, 512, ivpos, tempdebuf))
			{
			//	return FSR_NO_POWER;
			}
		}
		if (0 == i)//第一块
		{
			if (size <= 512-remainder)//第一块就写完
			{
				memcpy(tempdebuf+remainder,buf,size);
				already += size;
				leftsize -= size;
			}
			else
			{
				memcpy(tempdebuf+remainder,buf,512-remainder);			
				already += 512-remainder;
				leftsize -= (512-remainder);
			}
		}
		else
		{
			if (leftsize>512)
			{
				memcpy(tempdebuf,buf+already,512);				
				already += 512;
				leftsize -= 512;
			}
			else
			{
				memcpy(tempdebuf,buf+already,leftsize);		
				already += leftsize;
				leftsize -= leftsize;
			}
		}
		//if (DataEnc(keytype, tempdebuf, 512,ivpos,tempenbuf))
		{
		//	return FSR_NO_POWER;
		}
		if (0 == flag)
		{
			memcpy(tempenbuf,tempdebuf,512);
		}
		//fseek(fd,cur_addr,SEEK_SET);
		//wsize = (int)fwrite(tempenbuf, 1, 512, fd);
		//if (wsize < 512)
		//{
		//	ret = FSR_WRITE_FILE;
		//	return ret;
		//}
		ret = F_SHSMWriteFileEx(fd,tempenbuf,cur_addr,512);
		if (ret)
		{
			return FSR_READ_FILE;
		}
	}

	return 0;
}

static int fs_malloc(HANDLE fd, int filetype,int blocksize,unsigned int * adr)
{

	unsigned char bitmap[BIN_BITMAP_BLOCK_LEN]={0};//BITMAP区,使用固定密钥加密
	unsigned char bitmap_pri[BIN_BITMAP_PRI_BLOCK_LEN]={0};//BITMAP区,使用固定密钥加密
	unsigned char* bitbuf = bitmap;
	int ret = 0;
	int offset = 0;
	unsigned int bit_startAddr = BIN_BITMAP_FILE_ADDRESS;
	int bitlen = BIN_BITMAP_BLOCK_LEN;
	unsigned int file_startAddr = BIN_DATA_FILE_ADDRESS;

	if (filetype == 0x3D)//私钥文件
	{

		bitbuf = bitmap_pri;
		bit_startAddr = BIN_BITMAP_PRI_FILE_ADDRESS;
		bitlen = BIN_BITMAP_PRI_BLOCK_LEN;
		file_startAddr = BIN_DATA_PRI_FILE_ADDRESS;
	}

	if (filetype == 0x5D)//文件 m
	{

		bitbuf = bitmap_pri;
		bit_startAddr = FILE_BITMAP_FILE_ADDRESS;
		bitlen = FILE_BITMAP_PRI_BLOCK_LEN;
		file_startAddr = FILE_DATA_FILE_ADDRESS;
	}
	
	ret = fsRead(fd,bit_startAddr,bitlen,bitbuf, 0);
	if (0 != ret)
		return ret;
	
	offset = bit_find(bitbuf,bitlen,blocksize,0,&ret);
	if (0 != ret)
		return FSR_BIT_FIND;
	
	*adr = file_startAddr + offset*BIN_DATA_BLOCK_LEN;

	ret = bit_set(bitbuf, offset, blocksize);
	if ( 0 != ret)
		return FSR_BIT_SET;

	ret = fsWrite(fd,bit_startAddr,bitlen,bitbuf, 0);
	if (0 != ret)
		return ret;
	
	return 0;
}

static int fs_free(HANDLE fd, int filetype,unsigned int adr,int blocksize, int keytype)
{
	unsigned char bitmap[BIN_BITMAP_BLOCK_LEN]={0};//BITMAP区,使用固定密钥加密
	unsigned char bitmap_pri[BIN_BITMAP_PRI_BLOCK_LEN]={0};//BITMAP区,使用固定密钥加密
	unsigned char* bitbuf = bitmap;
	unsigned char temp[BIN_DATA_BLOCK_LEN]={0};
	int ret=0,i=0;
	int offset = 0;
	unsigned int bit_startAddr = BIN_BITMAP_FILE_ADDRESS;
	int bitlen = BIN_BITMAP_BLOCK_LEN;
	unsigned int file_startAddr = BIN_DATA_FILE_ADDRESS;

	if (filetype == 0x3D)//私钥文件
	{
		bitbuf = bitmap_pri;
		bit_startAddr = BIN_BITMAP_PRI_FILE_ADDRESS;
		bitlen = BIN_BITMAP_PRI_BLOCK_LEN;
		file_startAddr = BIN_DATA_PRI_FILE_ADDRESS;
	}
	if (filetype == 0x5D)//文件 m
	{
		bitbuf = bitmap_pri;
		bit_startAddr = FILE_BITMAP_FILE_ADDRESS;
		bitlen = FILE_BITMAP_PRI_BLOCK_LEN;
		file_startAddr = FILE_DATA_FILE_ADDRESS;
	}
	

	ret = fsRead(fd,bit_startAddr,bitlen,bitbuf, 0);
	if (0 != ret)
		return ret;	

	offset = (adr - file_startAddr)/BIN_DATA_BLOCK_LEN;

	ret = bit_clear(bitbuf, offset, blocksize);
	if ( 0 != ret)
		return FSR_BIT_CLEAR;

	ret = fsWrite(fd,bit_startAddr,bitlen,bitbuf, 0);
	if (0 != ret)
		return ret;

	memset(temp,BIN_DATA_BLOCK_LEN,0xff);
	for (i=0;i<blocksize;i++)
	{
		ret = fsWrite(fd,file_startAddr+offset*BIN_DATA_BLOCK_LEN+i*BIN_DATA_BLOCK_LEN,BIN_DATA_BLOCK_LEN,temp, keytype);
		if (0 != ret)
			return ret;
	}

	return 0;
}

//打开文件
int FS_OpenFile(char* filePath, HANDLE* fd)
{
	//fp=fopen(filePath,"rb+");
	//if (NULL == fp)
	//	return FSR_OPEN_FILE;
	if (F_SHSMOpenFile(filePath,fd))
	{
		return FSR_OPEN_FILE;
	}

	return 0;
}

//关闭文件
int FS_CloseFile(HANDLE fd)
{
	F_SHSMCloseFile(&fd);
	return 0;
}

// 读文件头
int FS_ReadFileInfo(HANDLE fd, PSOFT_FS_HEAD_INFO pHeardInfo)
{
	int ret = 0;
	unsigned char headbuf[BIN_DATA_BLOCK_LEN]={0};

	ret = fsRead(fd,0,sizeof(SOFT_FS_HEAD_INFO),headbuf, 0);
	if (0!=ret)
		return ret;

	memcpy(pHeardInfo,headbuf,sizeof(SOFT_FS_HEAD_INFO));

	return 0;
}

// 写文件头
int FS_WriteFileInfo(HANDLE fd, SOFT_FS_HEAD_INFO heardInfo)
{
	int ret = 0;
	unsigned char headbuf[BIN_DATA_BLOCK_LEN]={0};

	memset(headbuf,0xff,BIN_DATA_BLOCK_LEN);
	memcpy(headbuf,&heardInfo,sizeof(SOFT_FS_HEAD_INFO));
	ret = fsWrite(fd,0,BIN_DATA_BLOCK_LEN,headbuf, 0);

	return ret;
}

// 读密钥 (kid)
int FS_ReadKey( HANDLE fd,int type, unsigned char kid, PSOFT_FS_KEY pKey )
{
	int ret=0;
	unsigned char keybuf[BIN_FAT_BLOCK_LEN]={0};
	unsigned int offset = KEY_FILE_ADDRESS;

	if (!type)
	{
		offset += kid*KEY_BLOCK_LEN;
	}

	ret =  fsRead(fd,offset,KEY_BLOCK_LEN,keybuf, 0);
	if (0!=ret)
		return ret;
	if(0==memcmp(keybuf,"\xff\xff",2))
	{
		return FSR_KEY_NOT_EXIST;
	}

	memcpy(pKey,keybuf,sizeof(SOFT_FS_KEY));	

	return 0;
}

// 写密钥 (kid)
int FS_WriteKey( HANDLE fd, int type, PSOFT_FS_KEY pKey )
{
	int ret=0;
	unsigned char keybuf[KEY_BLOCK_LEN]={0};
	unsigned char allkeybuf[2048] = {0};
	unsigned int offset = KEY_FILE_ADDRESS;
	unsigned int crc=0;
	unsigned int crcVerify = 0;

	if(!type)
	{
		offset += KEY_BLOCK_LEN*pKey->id;
	}


	memset(keybuf,0xff,KEY_BLOCK_LEN);
	memcpy(keybuf,pKey,sizeof(SOFT_FS_KEY));
	ret = fsWrite(fd,offset,sizeof(SOFT_FS_KEY),(unsigned char*)pKey, 0);
	if (0!=ret)
		return ret;	


	return 0;
}

//删除密钥
int FS_DeleteKey(HANDLE fd, unsigned char kid)
{
	int ret=0;
	unsigned char keybuf[KEY_BLOCK_LEN]={0};
	unsigned char allkeybuf[2048] = {0};
	unsigned int crc=0;
	unsigned int crcVerify = 0;

	memset(keybuf,0xff,KEY_BLOCK_LEN);
	ret = fsWrite(fd,KEY_FILE_ADDRESS+kid*KEY_BLOCK_LEN,KEY_BLOCK_LEN,keybuf, 0);
	if (0!=ret)
		return ret;	

	ret = fsRead(fd,KEY_FILE_ADDRESS+KEY_BLOCK_LEN,2000,allkeybuf, 0);
	if (0!=ret)
		return ret;	


	return ret;	
}

//创建二进制文件
int FS_CreateBinary(HANDLE fd, PSOFT_FS_FILE pBin)
{
	int ret=0,i=0;
	unsigned char fatbuf[BIN_FAT_BLOCK_LEN]={0};
	int blocksize=1;
	unsigned int startadd = BIN_FAT_FILE_ADDRESS+BIN_FAT_BLOCK_LEN;
	unsigned int start_address=0;

	//读FAT查找文件ID，如果文件不存在则创建
	for (i=0;i<FILE_NUM_MAX;i++)
	{
		ret = fsRead(fd,startadd+i*BIN_FAT_BLOCK_LEN,4,fatbuf, 0);
		if(0!=ret)
		{
			return ret;
		}
		if (0==memcmp(fatbuf,pBin->id,4))
		{
			return FSR_FILE_EXIST;//返回文件已存在
		}
	}

	//创建文件
	for (i=0;i<FILE_NUM_MAX;i++)
	{
		ret = fsRead(fd,startadd+i*BIN_FAT_BLOCK_LEN,4,fatbuf, 0);
		if(0!=ret)
		{
			return ret;
		}
		if ( 0==memcmp(fatbuf,"\x00\x00\x00\x00",4) || 0==memcmp(fatbuf,"\xff\xff\xff\xff",4))
		{
			blocksize = pBin->room/BIN_DATA_BLOCK_LEN;
			if (pBin->room%BIN_DATA_BLOCK_LEN)
			{
				blocksize++;
			}
			ret = fs_malloc(fd, pBin->type,blocksize,&start_address);
			if (0!=ret)
			{
				return ret;
			}
			pBin->block_num = blocksize;	
			pBin->start_address = start_address;

			break;//找到位置跳出
		}
	}
	if (FILE_NUM_MAX == i)
	{
		return FSR_NO_FILE_SPACE;//空间不足
	}
	//写FAT区
	ret = fsWrite(fd,startadd+i*BIN_FAT_BLOCK_LEN,sizeof(SOFT_FS_FILE), (unsigned char*)pBin, 0);
	if (0 != ret)
	{
		return ret;
	}

	return 0;
}

//删除二进制文件
int FS_DeleteBinary(HANDLE fd, unsigned char* fid)
{
	int ret=0,i=0;
	unsigned char fatbuf[BIN_FAT_BLOCK_LEN]={0};
	unsigned char mfid[4] = {0};
	SOFT_FS_FILE fsfile;
	unsigned int startadd = BIN_FAT_FILE_ADDRESS+BIN_FAT_BLOCK_LEN;
	int keytype=0;

	memcpy(mfid+2,fid,2);
	memset(&fsfile,0x00,sizeof(SOFT_FS_FILE));
	//读FAT查找文件ID
	for (i=0;i<FILE_NUM_MAX;i++)
	{
		ret = fsRead(fd,startadd+i*BIN_FAT_BLOCK_LEN,BIN_FAT_BLOCK_LEN,fatbuf, 0);
		if(0!=ret)
		{
			return ret;
		}
		if (0==memcmp(fatbuf,mfid,4))
		{
			memcpy(&fsfile,fatbuf,sizeof(SOFT_FS_FILE));
			break;//找到要删除的文件
		}
		else
		{
			continue;			
		}
	}
	if (FILE_NUM_MAX == i)
	{
		return FSR_FILE_NOT_EXIST;//文件不存在，或已经删除
	}

	if (0x3D == fsfile.type || 0x3F == fsfile.type)//对称密钥文件和私钥文件
	{
		keytype = 0;
	}

	memset(fatbuf,0x00,BIN_FAT_BLOCK_LEN);
	ret = fsWrite(fd,startadd+i*BIN_FAT_BLOCK_LEN,BIN_FAT_BLOCK_LEN,fatbuf, 0);
	if (0 != ret)
	{
		return ret;
	}
	ret = fs_free(fd, fsfile.type,fsfile.start_address, fsfile.block_num, keytype);
	if (0 != ret)
	{
		return ret;
	}

	return 0;
}

// 读二进制文件 (fid)
int FS_ReadBinary( HANDLE fd, int isFat, unsigned char* fid, int offset, int readlen,unsigned char * pDataOut )
{
	int ret=0,i=0;
	unsigned char fatbuf[BIN_FAT_BLOCK_LEN]={0};
	SOFT_FS_FILE fsfile;
	unsigned char mfid[4] = {0};
	unsigned int startadd = BIN_FAT_FILE_ADDRESS+BIN_FAT_BLOCK_LEN;
	int keytype=0;

	memcpy(mfid+2,fid,2);

	memset(&fsfile,0x00,sizeof(SOFT_FS_FILE));

	//读FAT查找文件ID
	for (i=0;i<FILE_NUM_MAX;i++)
	{

		ret = fsRead(fd,startadd+i*BIN_FAT_BLOCK_LEN,sizeof(SOFT_FS_FILE),fatbuf, 0);
		if(0!=ret)
		{

			return ret;
		}

		if (0==memcmp(fatbuf,mfid,4))
		{
			break;
		}
		else
		{
			continue;			
		}
	}
	if (FILE_NUM_MAX == i)
	{
		return FSR_FILE_NOT_EXIST;//文件不存在
	}
	if(isFat)//要读FAT区
	{

		memcpy(pDataOut,fatbuf,sizeof(SOFT_FS_FILE));
	}
	else
	{
		memcpy(&fsfile,fatbuf,sizeof(SOFT_FS_FILE));
		if (0x3D == fsfile.type || 0x3F == fsfile.type)//对称密钥文件和私钥文件
		{
			keytype = 0;
		}
		ret = fsRead(fd,fsfile.start_address+offset,readlen,pDataOut, keytype);
		if(0!=ret)
		{
			return ret;
		}
	}

	return 0;
}

// 写二进制文件(fid) 
int FS_WriteBinary( HANDLE fd, unsigned char* fid, int offset, unsigned char* pDataIn,int inlen )
{
	int ret=0,i=0;
	unsigned char fatbuf[BIN_FAT_BLOCK_LEN]={0};
	SOFT_FS_FILE fsfile;
	unsigned int crc=0;
	unsigned char mfid[4] = {0};
	unsigned int startadd = BIN_FAT_FILE_ADDRESS+BIN_FAT_BLOCK_LEN;
	unsigned int crcVerify = 0;
	int keytype=0;

	memcpy(mfid+2,fid,2);


	memset(&fsfile,0x00,sizeof(SOFT_FS_FILE));

	//读FAT查找文件ID

	for (i=0;i<FILE_NUM_MAX;i++)
	{

		ret = fsRead(fd,startadd+i*BIN_FAT_BLOCK_LEN,sizeof(SOFT_FS_FILE),fatbuf, 0);

		if(0!=ret)
		{
			return ret;
		}




		if (0==memcmp(fatbuf,mfid,4))
		{

			break;
		}
		else
		{

			continue;			
		}

	}

	if (FILE_NUM_MAX == i)
	{

		return FSR_FILE_NOT_EXIST;
	}

	memcpy(&fsfile,fatbuf,sizeof(SOFT_FS_FILE));
	if (0x3D == fsfile.type || 0x3F == fsfile.type)//对称密钥文件和私钥文件
	{
		keytype = 0;
	}
	ret = fsWrite(fd,fsfile.start_address+offset,inlen,pDataIn, 0);
	if(0!=ret)
	{
		return ret;
	}

	return ret;
}

int FS_ReadSM2Param( HANDLE fd, unsigned char* SM2id, unsigned char* idlen,unsigned char* SM2param )
{
	int ret;
	unsigned char len=0;

	if (NULL != SM2id)
	{
		if (0 == HasReadSm2Id)
		{
			ret = fsRead(fd,SM2_ID_FILE_ADDRESS,1,&len, 0);
			if (0 != ret)
			{
				return ret;
			}
			ret = fsRead(fd,SM2_ID_FILE_ADDRESS+1,len,SM2id, 0);
			if (0 != ret)
			{
				return ret;
			}
			*idlen = len;
			memcpy(g_xdSM2id,&len,1);
			memcpy(g_xdSM2id+1,SM2id,len);
		}
		else
		{
			*idlen = g_xdSM2id[0];
			memcpy(SM2id,g_xdSM2id+1,*idlen);
		}
	}
	if(NULL != SM2param)
	{
		ret = fsRead(fd,SM2_PARAM_FILE_ADDRESS,1,&len, 0);
		if (0 != ret)
		{
			return ret;
		}
		ret = fsRead(fd,SM2_PARAM_FILE_ADDRESS+1,len,SM2param, 0);
	}

	return ret;
}

int FS_WriteSM2Param( HANDLE fd, unsigned char* SM2id,unsigned char idlen,unsigned char* SM2param,unsigned char plen )
{
	int ret;

	if (NULL != SM2id)
	{
		ret = fsWrite(fd,SM2_ID_FILE_ADDRESS,1,&idlen, 0);
		if (0 != ret)
		{
			return ret;
		}
		ret = fsWrite(fd,SM2_ID_FILE_ADDRESS+1,idlen,SM2id, 0);
		if (0 != ret)
		{
			return ret;
		}
		memcpy(g_xdSM2id,&idlen,1);
		memcpy(g_xdSM2id+1,SM2id,idlen);
	}
	if(NULL != SM2param)
	{
		ret = fsWrite(fd,SM2_PARAM_FILE_ADDRESS,1,&plen, 0);
		if (0 != ret)
		{
			return ret;
		}
		ret = fsWrite(fd,SM2_PARAM_FILE_ADDRESS+1,plen,SM2param, 0);
	}
	return ret;
}

int FS_ReadECCParam( HANDLE fd, int index, unsigned char* ECCparam,unsigned char *plen )
{
	int ret;
	unsigned char len=0;

	ret = fsRead(fd,SM2_PARAM_FILE_ADDRESS+index*ECC_CURVE_SIZE,1,&len, 0);
	if (0 != ret)
	{
		return ret;
	}
	ret = fsRead(fd,SM2_PARAM_FILE_ADDRESS+index*ECC_CURVE_SIZE+1,len,ECCparam, 0);
	*plen = len;

	return ret;
}

int FS_WriteECCParam( HANDLE fd, int index, unsigned char* ECCparam,unsigned char plen )
{
	int ret;

	ret = fsWrite(fd,SM2_PARAM_FILE_ADDRESS+index*ECC_CURVE_SIZE,1,&plen, 0);
	if (0 != ret)
	{
		return ret;
	}
	ret = fsWrite(fd,SM2_PARAM_FILE_ADDRESS+index*ECC_CURVE_SIZE+1,plen,ECCparam, 0);

	return ret;
}

int FS_WriteDirInfo( HANDLE fd, PSOFT_FS_DIR pDir )
{
	int ret;

	ret = fsWrite(fd,BIN_FAT_FILE_ADDRESS,sizeof(SOFT_FS_DIR),(unsigned char*)pDir, 0);

	return ret;	
}

int FS_ReadDirInfo( HANDLE fd, PSOFT_FS_DIR pDir )
{
	int ret;

	ret = fsRead(fd,BIN_FAT_FILE_ADDRESS,sizeof(SOFT_FS_DIR),(unsigned char*)pDir, 0);

	return ret;	
}

int FS_GetResidRoom( HANDLE fd,unsigned int * size )
{
	int ret,i,sumblock=0;
	unsigned char bitmap[BIN_BITMAP_BLOCK_LEN] = {0};
	
	ret = fsRead(fd,BIN_BITMAP_FILE_ADDRESS,BIN_BITMAP_BLOCK_LEN,bitmap, 0);
	if (0 != ret)
	{
		return ret;
	}
	for (i=0;i<BIN_BITMAP_BLOCK_LEN*8;i++)
	{
		if (0 == bit_get(bitmap, i))
		{
			sumblock++;
		}
	}
	*size = sumblock*512;

	return 0;
}

int FS_GetPinTryCount( HANDLE fd,int * pintry )
{
	int ret=0;
	int count=-1;

	ret = fsRead(fd,32*4,4,(unsigned char *)&count, 0);
	if (0!=ret)
		return ret;

	*pintry = count;

	return 0;
}

int FS_SetPinTryCount( HANDLE fd,int pintry )
{
	return fsWrite(fd,32*4,4,(unsigned char *)&pintry, 0);
}



//创建文件 ,以文件名形式管理
int FS_CreateFile(HANDLE fd, PSOFT_FS_FILE pBin)
{
	int ret=0,i=0;
	unsigned char fatbuf[FILE_FAT_BLOCK_LEN]={0};
	int blocksize=1;
	unsigned int startadd = FILE_FAT_FILE_ADDRESS+FILE_FAT_BLOCK_LEN;//
	unsigned int start_address=0;

	//读FAT查找文件，如果文件不存在则创建
	for (i=0;i<FILE_NUM_MAX;i++)
	{

		ret = fsRead(fd,startadd+i*FILE_FAT_BLOCK_LEN,FILE_FAT_BLOCK_LEN,fatbuf, 0);
		if(0!=ret)
		{
			return ret;
		}
		if (0==memcmp(fatbuf+5,pBin->name,128))
		{

			return FSR_FILE_EXIST;//返回文件已存在
		}
	}

	//创建文件
	for (i=0;i<FILE_NUM_MAX;i++)
	{

		ret = fsRead(fd,startadd+i*FILE_FAT_BLOCK_LEN,4,fatbuf, 0);
		if(0!=ret)
		{
			return ret;
		}


		if ( 0==memcmp(fatbuf,"\x00\x00\x00\x00",4) || 0==memcmp(fatbuf,"\xff\xff\xff\xff",4))
		{
			blocksize = pBin->room/FILE_DATA_BLOCK_LEN;
			if (pBin->room%FILE_DATA_BLOCK_LEN)
			{
				blocksize++;
			}

			ret = fs_malloc(fd, pBin->type,blocksize,&start_address);
			if (0!=ret)
			{

				return ret;
			}
			pBin->block_num = blocksize;	
			pBin->start_address = start_address;

			break;//找到位置跳出
		}

	}
	if (FILE_NUM_MAX == i)
	{
		return FSR_NO_FILE_SPACE;//空间不足
	}
	//写FAT区
	ret = fsWrite(fd,startadd+i*FILE_FAT_BLOCK_LEN,sizeof(SOFT_FS_FILE), (unsigned char*)pBin, 0);
	if (0 != ret)
	{
		return ret;
	}

	return 0;
}


//删除二进制文件
int FS_DeleteFile(HANDLE fd, unsigned char* fileName ,unsigned int nameLen)
{
	int ret=0,i=0;
	unsigned char fatbuf[FILE_FAT_BLOCK_LEN]={0};
	unsigned char mfid[4] = {0};
	SOFT_FS_FILE fsfile;
	unsigned int startadd = FILE_FAT_FILE_ADDRESS+FILE_FAT_BLOCK_LEN;//
	int keytype=0;

	if (nameLen > FILENAME_MAX_SIZE)
	{
		return FSR_FILESIZEERR;//文件长度超出限制
	}
	memset(&fsfile,0x00,sizeof(SOFT_FS_FILE));
	//读FAT查找文件ID
	for (i=0;i<FILE_NUM_MAX;i++)
	{

		ret = fsRead(fd,startadd+i*FILE_FAT_BLOCK_LEN,FILE_FAT_BLOCK_LEN,fatbuf, 0);
		if(0!=ret)
		{
			return ret;
		}

		if (0==memcmp(fatbuf+5,fileName,nameLen))
		{
			if(nameLen<128 && (fatbuf[5+nameLen]!=0x00))
			{
				continue;//过滤名称 file_1 和file_11 匹配成功
			}

			memcpy(&fsfile,fatbuf,sizeof(SOFT_FS_FILE));
			break;//找到要删除的文件
		}
		else
		{
			continue;			
		}

	}
	if (FILE_NUM_MAX == i)
	{

		return FSR_FILE_NOT_EXIST;//文件不存在，或已经删除
	}


	memset(fatbuf,0x00,FILE_FAT_BLOCK_LEN);
	ret = fsWrite(fd,startadd+i*FILE_FAT_BLOCK_LEN,FILE_FAT_BLOCK_LEN,fatbuf, 0);
	if (0 != ret)
	{
		return ret;
	}

	ret = fs_free(fd, fsfile.type,fsfile.start_address, fsfile.block_num, 0);
	if (0 != ret)
	{
		return ret;
	}

	return 0;
}

// 读二进制文件 (fid)
int FS_ReadFile( HANDLE fd, int isFat, unsigned char* fileName, unsigned int nameLen, int offset, int readlen,unsigned char * pDataOut )
{
	int ret=0,i=0;
	unsigned char fatbuf[FILE_FAT_BLOCK_LEN]={0};
	SOFT_FS_FILE fsfile;
	unsigned char mfid[4] = {0};
	unsigned int startadd = FILE_FAT_FILE_ADDRESS+FILE_FAT_BLOCK_LEN;
	int keytype=0;


	if (nameLen > FILENAME_MAX_SIZE)
	{
		return FSR_FILESIZEERR;//文件长度超出限制
	}
	memset(&fsfile,0x00,sizeof(SOFT_FS_FILE));

	//读FAT查找文件ID
	for (i=0;i<FILE_NUM_MAX;i++)
	{
		ret = fsRead(fd,startadd+i*FILE_FAT_BLOCK_LEN,FILE_FAT_BLOCK_LEN,fatbuf, 0);
		if(0!=ret)
		{

			return ret;
		}

		if (0==memcmp(fatbuf+5,fileName,nameLen))
		{
			if(nameLen<128 && (fatbuf[5+nameLen]!=0x00))
			{
				continue;//过滤名称 file_1 和file_11 匹配成功
			}

			memcpy(&fsfile,fatbuf,sizeof(SOFT_FS_FILE));
			break;//找到要删除的文件
		}
		else
		{
			continue;			
		}
	}

	if (FILE_NUM_MAX == i)
	{
		return FSR_FILE_NOT_EXIST;//文件不存在
	}
	if(fsfile.room < (offset+readlen))
	{

		return FSR_NO_FILE_SPACE;
	}

	if(isFat)//要读FAT区
	{

		memcpy(pDataOut,fatbuf,sizeof(SOFT_FS_FILE));
	}
	else
	{
		memcpy(&fsfile,fatbuf,sizeof(SOFT_FS_FILE));
	
		ret = fsRead(fd,fsfile.start_address+offset,readlen,pDataOut, 0);
		if(0!=ret)
		{
			return ret;
		}
	}

	return 0;
}

// 写二进制文件(fid) 
int FS_WriteFile( HANDLE fd, unsigned char* fileName, unsigned int nameLen, int offset, unsigned char* pDataIn,int inlen )
{
	int ret=0,i=0;
	unsigned char fatbuf[FILE_FAT_BLOCK_LEN]={0};
	SOFT_FS_FILE fsfile;
	unsigned int crc=0;
	unsigned char mfid[4] = {0};
	unsigned int startadd = FILE_FAT_FILE_ADDRESS+FILE_FAT_BLOCK_LEN;
	unsigned int crcVerify = 0;
	int keytype=0;

	if (nameLen > FILENAME_MAX_SIZE)
	{
		return FSR_FILESIZEERR;//文件长度超出限制
	}
	memset(&fsfile,0x00,sizeof(SOFT_FS_FILE));

	//读FAT查找文件ID
	for (i=0;i<FILE_NUM_MAX;i++)
	{
		ret = fsRead(fd,startadd+i*FILE_FAT_BLOCK_LEN,FILE_FAT_BLOCK_LEN,fatbuf, 0);
		if(0!=ret)
		{
			return ret;
		}

		if (0==memcmp(fatbuf+5,fileName,nameLen))
		{
			if(nameLen<128 && (fatbuf[5+nameLen]!=0x00))
			{
				continue;//过滤名称 file_1 和file_11 匹配成功
			}

			memcpy(&fsfile,fatbuf,sizeof(SOFT_FS_FILE));
			break;//找到要删除的文件
		}
		else
		{
			continue;			
		}
	}
	if (FILE_NUM_MAX == i)
	{

		return FSR_FILE_NOT_EXIST;
	}

	memcpy(&fsfile,fatbuf,sizeof(SOFT_FS_FILE));

	if(fsfile.room < (offset+inlen))
	{

		return FSR_NO_FILE_SPACE;
	}


	ret = fsWrite(fd,fsfile.start_address+offset,inlen,pDataIn, 0);
	if(0!=ret)
	{
		return ret;
	}

	return ret;
}




