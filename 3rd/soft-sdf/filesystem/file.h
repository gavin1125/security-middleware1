/** 
 * @file 
 * @brief 文件IO模块接口
 * @date 20240409
 */
#ifndef _SOFT_FILE_WIN_H_INCLUDE_
#define _SOFT_FILE_WIN_H_INCLUDE_



#include "common.h"

/**
* @brief 判断文件是否存在
*
* @param[in] filePath 文件路径
*
* @retval 0 存在
*/
int F_SHSMCheckFile(char* filePath);


/**
* @brief 创建文件夹
*
* @param[in] FolderName 文件夹全路径
*
* @retval 0 存在
*/
int F_SHSMCreateFolder(char* FolderName);

/**
* @brief 检查句柄是否有效
*
* @param[out] fd      文件句柄
*
* @retval 0 成功
*/
int F_SHSMCheckHandle(HANDLE fd);

/**
* @brief 打开存在
*
* @param[in] filePath 文件路径
* @param[out] fd      文件句柄
*
* @retval 0 成功
*/
int F_SHSMOpenFile(char* filePath, HANDLE *fd);

/**
* @brief 打开存在
*
* @param[in] filePath 文件路径
*
* @retval 0 成功
*/
int F_SHSMNewFile(char* filePath);
/**
* @brief 关闭文件
*
* @param[in] fd    文件句柄
*
* @retval 0 成功
*/
int F_SHSMCloseFile(HANDLE *fd);
/**
* @brief 删除文件
*
* @param[in] filepath    文件路径
*
* @retval 0 成功
*/
int F_SHSMDeleteFile(char *filepath);

/**
* @brief 读取指定文件
*
* @param[in] filePath  文件路径
* @param[out] outBuf   读取的文件内容
* @param[in] len       读取内容长度
*
*/
int F_SHSMReadFile(HANDLE fd,unsigned char* outBuf, int len);
int F_SHSMReadFileEx(HANDLE fd,unsigned char* outBuf,int start, int len);

/**
* @brief 写文件并返回fd，当入参fd!=null时直接使用fd访问文件
*
* @param[in] filePath  文件路径
* @param[in] buf       写入的文件内容
* @param[in] buflen    写入长度
*
*/
int F_SHSMWriteFile(HANDLE fd, unsigned char* buf, int bufLen);
int F_SHSMWriteFileEx(HANDLE fd, unsigned char* buf, int start,int bufLen);

/**
* @brief 检查句柄是否有效
*
* @param[in] fd        句柄
* @param[in] dataLen   读取长度  //uk驱动是0，替他是512
*
* @retval 0 成功
*/
//int F_CheckHandle(HANDLE fd, int dataLen);

/**
* @brief 加锁
*
* @param[in] param   参数
* @param[in] timeout 超时秒数
*
* @retval lock句柄,用于Unlock
*/
HANDLE F_Lock(unsigned char * param);
HANDLE F_LockEx(unsigned char * param, int timeout);
/**
* @brief 解锁
*
* @param[in] fd  句柄对象
*
*/
int F_Unlock(HANDLE fd);


#endif


