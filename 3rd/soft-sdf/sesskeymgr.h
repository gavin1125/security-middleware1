/**
 * @file sesskeymgr.h
 * @brief 会话密钥管理
 * @author cws
 * @version 1.0.0.1
 * @date 2020-11-20
 */
#ifndef _PCIE_SESSIONKEY_MGR_H_
#define _PCIE_SESSIONKEY_MGR_H_

/**
 * @brief 导入会话密钥
 *
 * @param[in] key        密钥值
 * @param[in] keyLen     密钥长度
 * @param[out] phKeyHandle     返回密钥索引句柄
 *
 * @retval 0 成功
 */
int ImportSessKey(void* hHandle, unsigned char * key, unsigned int keyLen, void **phKeyHandle);

/**
 * @brief 导出会话密钥
 *
 * @param[in] index       密钥索引
 * @param[out] key        返回密钥值
 * @param[out] keyLen     返回密钥长度
 *
 * @retval 0 成功
 */
int ExportSessKey(void* hHandle, unsigned int index, unsigned char * key, unsigned int * keyLen);

/**
 * @brief 销毁会话密钥
 *
 * @param[in] index       密钥索引
 *
 * @retval 0 成功
 */
int DestroySessKey(void* hHandle, unsigned int index);


#endif
