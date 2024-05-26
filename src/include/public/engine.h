#ifdef __cplusplus
extern "C" {
#endif
#ifndef SECURITY_MIDDLEWARE_ENGINE_H
#define SECURITY_MIDDLEWARE_ENGINE_H

#include <openssl/engine.h>

const char *const kSecurityEngineId = "security_engine";

/**
 * @brief  load security engine
 * @return 0 failed ;1 success
 */
int LoadSecurityEngine();

/**
 * @brief  get security engine by id
 * @param id id of engine need to be get
 * @return  NULL failed ;ENGINE * success
 */
ENGINE *GetSecurityEngine(const char *id);

/**
 * @brief  release resource of security engine
 * @param[in] id  id of engine need to be released
 * @return  0 failed ;1 success
 */
int FreeSecurityEngine(const char *id);

#endif//SECURITY_MIDDLEWARE_ENGINE_H

#ifdef __cplusplus
}
#endif
