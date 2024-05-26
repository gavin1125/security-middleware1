/** 
* @file softdef.h
* @brief 定义头文件
* @author
* @version 1.0.0.1
* @date 20240412
*/
#ifndef __SOFT_DEF_H__
#define __SOFT_DEF_H__


#ifdef WIN32
#ifdef SOFTALG_EXPORTS
#define SOFTALGAPI __declspec(dllexport)
#elif defined SOFTALG_IMPORT
#define SOFTALGAPI __declspec(dllimport)
#else
#define SOFTALGAPI	
#endif
#else
#define SOFTALGAPI	
#endif

/************************************************************************/
/* 错误代码定义                                                          */
/************************************************************************/

#define XALGR_BASE                         0//0x0003A000
#define XALGR_OK						   0x00000000                     //成功
#define XALGR_NO_SPACE					   XALGR_BASE-1                   //空间不足
#define XALGR_DATA_LEN					   XALGR_BASE-2                   //数据长度错误
#define XALGR_RANDOM					   XALGR_BASE-3                   //产生随机数错误
#define XALGR_VERIFY					   XALGR_BASE-4                   //验签失败
#define XALGR_ZERO_ERROR				   XALGR_BASE-5                   //运算中间数据是0，计算失败
#define XALGR_MALLOC					   XALGR_BASE-6                   //内存申请错误
#define XALGR_INTER_CALCU				   XALGR_BASE-7                   //数据比较错误
#define XALGR_DECRYPT					   XALGR_BASE-8                   //解密失败
#define XALGR_CTXISNULL                    XALGR_BASE-9                   //CTX为空
#define XALGR_RETRYMAX                     XALGR_BASE-10                  //运算产生随机数，超过最大重试次数 
#define XALGR_ERRORPARAM                   XALGR_BASE-11                  //参数错误      


#endif  // __SOFT_DEF_H__



