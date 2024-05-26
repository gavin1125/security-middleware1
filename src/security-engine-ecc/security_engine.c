#include <openssl/engine.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>

#include "public/sdf.h"
#include "public/security_engine.h"

#include "front.h"

static char *GHY_SECURITY_ENGINE_ID = "ghy_security_engine_id";
static char *GCY_SECURITY_ENGINE_ID = "gcy_security_engine_id";

static void *phDeviceHandle = NULL;
static void *phSessionHandle = NULL;

char *GetEngineIdByType(int type) {
  if (type == SECURITY_ENGINE_TYPE_GHY) {
    return GHY_SECURITY_ENGINE_ID;
  } else {
    return GCY_SECURITY_ENGINE_ID;
  }
}

ENGINE *GetSecurityEngine(int type) {
  if (type != SECURITY_ENGINE_TYPE_GHY && type != SECURITY_ENGINE_TYPE_GCY) {
    printf("get engine error,type[%d] not correct\n", type);
    return NULL;
  }

  char *engine_id = GetEngineIdByType(type);

  return ENGINE_by_id(engine_id);
  ;
}

int LoadSecurityEngine(int type) {
  if (type != SECURITY_ENGINE_TYPE_GHY && type != SECURITY_ENGINE_TYPE_GCY) {
    printf("load engine error,type[%d] not correct\n", type);
    return 0;
  }
  ENGINE *engine = NULL;
  engine = GetSecurityEngine(type);

  if (engine != NULL) {
    return 1;
  }
  engine = ENGINE_new();
  if (NULL == engine) {
    printf("load engine error,engine is NULL\n");
    return 0;
  }

  char *engine_id = GetEngineIdByType(type);

  if (!OPTEE_ENG_bind(engine, engine_id)) {
    printf("load engine error,bind engine failed\n");
    ENGINE_free(engine);
    return 0;
  }

  ENGINE_add(engine);
  printf("load engine success, engine type:%d\n", type);
  return 1;
}

int LoadCert(SSL_CTX *ctx, int type) {
  SSL_CTX_load_verify_locations(ctx, "/vagrant/cert/ecc/all/ca.crt", NULL);

  ENGINE *pSt = GetSecurityEngine(type);
  SSL_CTX_set_client_cert_engine(ctx, pSt);
  return 1;
}

int FreeSecurityEngine(int type) {
  ENGINE *engine = GetSecurityEngine(type);

  if (NULL != engine) {
    ENGINE_free(engine);
  }

  return 1;
}