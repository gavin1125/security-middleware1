/**
* @file tool.h
* @brief 通用工具类函数
* @date 20210121
* @note
*/
#ifndef _PCIE_TOOL_H
#define _PCIE_TOOL_H

///微秒延时
void SleepUs(int waitus);

///获取进程ID
int GETPID();

///获取线程ID
int GETTID();

///打印16进制数据
void dumpdata(unsigned char* data, int len);

///打印带buffer名称的16进制数据
void dumpbuffer(const char *name, unsigned char* data, int len);

///字符串转16进制
int str2hex( const char str[], unsigned char *hex, int hlen );

///16进制转字符串
int hex2str( const unsigned char *hex, int len, char *str, int slen );

///数据4字节翻转
void data_revers(unsigned char* buf, int len);

//字节序翻转
void invert_buffer(unsigned char* pBuffer, int BufferLen);

#ifdef LINUX
    ///获取滴答数量
    long GetTickCount();
#endif
//计算CRC
unsigned short Crc(int crc_num, unsigned char array[]);
unsigned int mpeg_crc32_(unsigned int crc, unsigned int *pu32data, int len);

///进程和线程互斥加锁
int lock_card(int index, void *mutext, void *pthread_mutex);

///进程和线程互斥解锁
int unlock_card(int index, void *pthread_mutex);

/// 计算参数num 中bit位为'1'的bit的个数
unsigned int count_bit(int num);

/// 计算长度 len 按照 base 字节对齐，需要填充的数值。其中 base 必须是2 的正整数次幂
/// 如：PADDING(5, 4) 结果为3
///     PADDING(11, 8) 结果为5
#define PADDING(len, base) (~((len)&((base)-1)) + 1 & ((base)-1))

/// 计算长度 len 按照 base 字节对齐后的数值。其中 base 必须是2 的正整数次幂
/// 如：ALIGN(5, 4) 结果为8
///     ALIGN(11, 8) 结果为16
#define ALIGN(len, base) ((len) + PADDING(len, base))

#endif
