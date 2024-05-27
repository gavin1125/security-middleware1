/**
* @file file.h
 * @brief 日志模块接口
 * @author byd
 * @version 1.0.0.1
 * @date 20240408
 */
#ifndef _LOG_H_INCLUDE_
#define _LOG_H_INCLUDE_

#define SOURCENAME "BYD_LOG"//系统日志资源名称

#define LOG_NAME    "softalg.log"
#define LOG_SEGMID "log"
#define LOG_KEYID  "path"

#define PRINTFLOG
#define SYSLOG
#define FILELOG

#define MSG_BAD_COMMAND                  ((DWORD)0xC0020001L)
/**
* @brief 设置日志文件路径
*
* @param[in] path  日志文件路径
*
*/
void LOG_SetPath_(const char* path);

/**
* @brief 设置日志文件大小
*
* @param[in] size  文件大小
*
*/
void LOG_SetSize_(const unsigned int size);

/**
* @brief 从配置文件中读取日志文件路径
*
* @param[in] path  日志文件路径
*
*/
//void LOG_GetPathFromCfg(char* path);

/**
* @brief 写日志。每次只能写540字符
*
* @param[in] path  日志文件路径
* @param[in] format 格式化
*
*/
void LOG_Write(char* path, char* format, ...);

/**
* @brief 写日志以二进制方式。每次只能写200字节
*
* @param[in] path  日志文件路径
* @param[in] buf   日志数据
* @param[in] path  日志数据长度
*
*/
void LOG_WriteHex_(char * path, unsigned char* buf, int bufLen);

#endif
