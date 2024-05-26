#ifdef __cplusplus
extern "C" {
#endif
#ifndef SECURITY_MIDDLEWARE_ENGINE_H
#define SECURITY_MIDDLEWARE_ENGINE_H

#include <openssl/engine.h>

#define SECURITY_ENGINE_TYPE_GHY 0
#define SECURITY_ENGINE_TYPE_GCY 1

/**
 * @brief  load security engine
 * @return 0 failed ;1 success
 */
int LoadSecurityEngine(int type);

int LoadCert(SSL_CTX *ctx, int type);

/**
 * @brief  release resource of security engine
 * @param[in] id  id of engine need to be released
 * @return  0 failed ;1 success
 */
int FreeSecurityEngine(int type);

#endif // SECURITY_MIDDLEWARE_ENGINE_H

#ifdef __cplusplus
}
#endif
