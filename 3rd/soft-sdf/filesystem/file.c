#include "file.h"
#include "tool.h"
#include "common.h"
#include "log.h"



int F_SHSMCheckFile(char* filepath)
{
	int ret = 0;

	ret = access(filepath, 06);

	return ret;
}

int F_SHSMCreateFolder( char* FolderName )
{
	int ret;

	ret = access(FolderName,0);
	if (-1 == ret)
	{

		if(mkdir(FolderName, 0755) == -1)
			return -1;

	}

	return 0;
}

int F_SHSMCheckHandle(HANDLE fd)
{	
	int ret;

	struct stat fsta;
	ret = fstat((int)fd, &fsta);
	return ret;

}

int F_SHSMOpenFile(char *filePath, HANDLE *fd)
{
	int err = 0;
	HANDLE handle = INVALID_HANDLE_VALUE;

	handle = open(filePath, O_RDWR | O_SYNC /*O_DIRECT  | O_NONBLOCK | */);//新加一个O_SYNC选项，防止数据在某些环境下传输时丢失
	if(INVALID_HANDLE_VALUE == handle)
	{
		LOG_Write(NULL,"%s,%d:open %s failed,errno=%d:%s.", __FUNCTION__, __LINE__,filePath, errno, strerror(errno));
		return -1;
	}
	*fd = handle;


	return 0;
}


int F_SHSMNewFile(char *filePath)
{
	HANDLE handle = INVALID_HANDLE_VALUE;

	handle = open(filePath, O_CREAT | O_RDWR, 0777);
	if(INVALID_HANDLE_VALUE == handle)
	{
		LOG_Write(NULL, "%s,%d:open %s failed,err=%d:%s.", __FUNCTION__, __LINE__, filePath, errno, strerror(errno));
		return -1;
	}
	close(handle);

	return 0;
}
int F_SHSMCloseFile(HANDLE *fd)
{
	int ret = 0;
	ret = close(*fd);
	*fd = INVALID_HANDLE_VALUE;


	return ret;
}

int F_SHSMDeleteFile(char *filepath)
{

	if(remove(filepath))
		return -1;

	return 0;
}


int F_SHSMReadFileEx(HANDLE fd,  unsigned char* outBuf,int start, int len)
{
	int ret = 0;

	lseek(fd, start, SEEK_SET);
	ret = read(fd, outBuf, len);
	if(len == ret)
	{
		ret = 0;
	}
	else// if(-1 == ret)
	{
		LOG_Write(NULL, "%s,%d:read failed, ret=%d, start=%d, len=%d, errno=%d:%s.", __FUNCTION__, __LINE__, ret, start, len, errno, strerror(errno));
	}


	return ret;
}

int F_SHSMWriteFileEx(HANDLE fd,  unsigned char* buf, int start,int bufLen)
{
	int ret=0;
	int err = 0;
	ret = lseek(fd, start, SEEK_SET);
	if(ret != start)
	{
		LOG_Write(NULL, "%s,%d:lseek failed, ret=%d, start=%d,err=%d:%s.", __FUNCTION__, __LINE__,ret, start,errno, strerror(errno));
		return  ret;
	}
	ret = write(fd, buf, bufLen);	
	if(ret == bufLen)
	{
		ret = 0;
	}
	else// if(-1 == ret)
	{
		LOG_Write(NULL, "%s,%d:write failed, ret=%d, buflen=%d,err=%d:%s.", __FUNCTION__, __LINE__,ret, bufLen,errno, strerror(errno));
	}

	return ret;
}
int F_SHSMReadFile(HANDLE fd,unsigned char* outBuf, int len)
{
	return F_SHSMReadFileEx(fd,outBuf,0,len);
}
int F_SHSMWriteFile(HANDLE fd, unsigned char* buf, int bufLen)
{
	return F_SHSMWriteFileEx(fd, buf, 0, bufLen);
}
				



