/** 
 * @file bit.h
 * @brief 位操作
 * @version 1.0.0.1
 * @date 2024-04-09
 */
#ifndef _BIT_H_
#define _BIT_H_

typedef unsigned char uint8_t;
typedef unsigned int uint32_t;

/**
 * @defgroup bit
 * @brief bit
 *
 * @{
 */

#define BIT_BYTE 8 ///<每BYTE含bit数

/** 
 * @brief 设置偏移offset的位为bit
 * 
 * @param[in] buf    缓冲区
 * @param[in] offset 偏移
 * @param[in] bit    bit值
 * 
 * @retval 0 成功
 */
int bit_put(uint8_t * buf, uint32_t offset, unsigned bit);

/** 
 * @brief 连续size位 置1
 * 
 * @param[in] buf    缓冲区
 * @param[in] offset 偏移
 * @param[in] size   连续size位
 * 
 * @retval 0 成功
 */
int bit_set(uint8_t * buf, uint32_t offset, uint32_t size);

/** 
 * @brief 连续size位清0
 * 
 * @param[in] buf    缓冲区
 * @param[in] offset 偏移
 * @param[in] size   连续size位
 * 
 * @retval 0 成功
 */
int bit_clear(uint8_t * buf,uint32_t offset, uint32_t size);

/** 
 * @brief 连续size位取反
 * 
 * @param[in] buf    缓冲区
 * @param[in] offset 偏移
 * @param[in] size   连续size位
 * 
 * @retval 0 成功
 */
int bit_not(uint8_t * buf,uint32_t offset, uint32_t size);

/** 
 * @brief 获取偏移offset的位
 * 
 * @param[in] buf    缓冲区
 * @param[in] offset 偏移
 * 
 * @return bit值
 */
unsigned bit_get(uint8_t * buf, uint32_t offset);

//成功ret返回0
/** 
 * @brief 获取连续size位bit的偏移
 * 
 * @param[in] buf        缓冲区
 * @param[in] buf_len    缓冲区长度
 * @param[in] size       连续size位
 * @param[in] bit        位的值
 * @param[out] ret        成功ret为1
 * 
 * @return 偏移
 */
uint32_t bit_find(uint8_t * buf, uint32_t buf_len, uint32_t size, unsigned bit, int * ret);

///@}
#endif
