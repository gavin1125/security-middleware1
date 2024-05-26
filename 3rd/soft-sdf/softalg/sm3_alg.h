/**
 * @file sm3_alg.h
 * @brief SM3算法接口
 * @author cws
 * @version 1.1
 * @date
 */
#ifndef _SOFT_SM3_H
#define _SOFT_SM3_H

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef  XU32
typedef unsigned int XU32;
#endif
#ifndef  XU64
typedef unsigned long long XU64;
#endif


typedef struct
{
    XU32  regw[8];   //8个字寄存器
    XU64  nblocks; //当前处理过的分组数目
    unsigned char buf[64]; //在update时 保存剩余消息 与下次运算合并
    XU32   count; //msg中的有效字节数目
} SM3_CONTEXT;


void SM3_Init(SM3_CONTEXT *hd);
void SM3_Update(SM3_CONTEXT *hd, const unsigned char *inbuf, int inlen);
void SM3_Final(unsigned char *digest, SM3_CONTEXT *hd);

#ifdef __cplusplus
}
#endif

#endif


