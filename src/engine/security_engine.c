#include <openssl/engine.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "public/sdf.h"
#include "public/security_engine.h"

static char *GHY_SECURITY_ENGINE_ID = "ghy_security_engine_id";
static char *GCY_SECURITY_ENGINE_ID = "gcy_security_engine_id";

static RSA_METHOD *safe_rsa_method = NULL;

static void *phDeviceHandle = NULL;
static void *phSessionHandle = NULL;

int LoadCaCert(int type, char *ssl_ca_cert, int *ssl_ca_cert_size) {
  if (type != SECURITY_ENGINE_TYPE_GHY && type != SECURITY_ENGINE_TYPE_GCY) {
    printf("load engine error,type[%d] not correct\n", type);
    return 0;
  }
  *ssl_ca_cert_size = 3806;
  if (SDF_ReadFile(phSessionHandle, "ca.crt", strlen("ca.crt"), 0,
                   ssl_ca_cert_size, ssl_ca_cert) != 0) {
    printf("SDF_ReadFile ca.crt error\n");
    return 0;
  }

  return 1;
}

static int EngineDestroy(ENGINE *e) {
  if (NULL != safe_rsa_method) {
    RSA_meth_free(safe_rsa_method);
    safe_rsa_method = NULL;
  }

  printf("EngineDestroy\n");
  return 1;
}

static int EngineFinish(ENGINE *e) {
  if (phSessionHandle != NULL) {
    if (SDF_CloseSession(phSessionHandle) != 0) {
    }
  }

  if (phDeviceHandle != NULL) {
    if (SDF_CloseDevice(phDeviceHandle) != 0) {
    }
  }
  printf("EngineFinish\n");
  return 1;
}

long write_content_to_file(const char *path, unsigned char *content, int len) {
  FILE *fp = fopen(path, "w");
  if (fp == NULL) {
    return -1;
  }
  fputs(content, fp);

  (void)fclose(fp);
  return 1;
}

static int EngineInit(ENGINE *e) {

  if (SDF_OpenDevice(&phDeviceHandle) != 0) {
    printf("SDF_OpenDevice error\n");
  }
  if (SDF_OpenSession(phDeviceHandle, &phSessionHandle) != 0) {
    printf("SDF_OpenSession error\n");
  }

  char *ca_path = "./ca.crt";
  if (access(ca_path, F_OK) != 0) {
    char ssl_ca_cert[4096] = {0};
    int ssl_ca_cert_size = 0;
    if (LoadCaCert(SECURITY_ENGINE_TYPE_GHY, ssl_ca_cert, &ssl_ca_cert_size) !=
        1) {
      return 0;
    }

    write_content_to_file(ca_path, ssl_ca_cert, ssl_ca_cert_size);
  }

  printf("EngineInit\n");
  return 1;
}

static X509 *LoadClientCert() {
  unsigned char *ssl_client_cert[1493] = {0};
  int readLen = 1493;
  if (SDF_ReadFile(phSessionHandle, "client.crt", strlen("client.crt"), 0,
                   &readLen, (unsigned char *)ssl_client_cert) != 0) {
    printf("SDF_ReadFile client.crt error\n");
    return NULL;
  }

  BIO *bio_mem = BIO_new(BIO_s_mem());
  BIO_puts(bio_mem, (const char *)ssl_client_cert);
  X509 *cert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
  printf("load cert success\n");
  return cert;
}

static int LoadClientKeyAndCert(ENGINE *e, SSL *ssl,
                                STACK_OF(X509_NAME) * ca_dn, X509 **pcert,
                                EVP_PKEY **pkey, STACK_OF(X509) * *pother,
                                UI_METHOD *ui_method, void *callback_data) {
  printf("LoadClientKeyAndCert\n");
  SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  SSL_CTX_load_verify_locations(ctx, "/tmp/root.crt", NULL);

  X509 *cert = LoadClientCert();
  if (NULL == cert) {
    return 0;
  }
  *pcert = cert;

  EVP_PKEY *pubkey = X509_get_pubkey(cert);

  *pkey = pubkey;
  return 1;
}

static int RsaEncrypt(int flen, const unsigned char *from, unsigned char *to,
                      RSA *rsa, int padding) {
  unsigned int outLen = 0;
  int ret = SDF_InternalPrivateKeyOperation_RSA(phSessionHandle, 6, from, flen,
                                                to, &outLen);
  if (ret != 0) {
    printf("rsa encrypt error");
  }

  printf("RsaEncrypt11111111111111111111,%d\n", outLen);

  return outLen;
}

static RSA_METHOD *GetRsaMethod() {
  if (NULL != safe_rsa_method) {
    return safe_rsa_method;
  }

  safe_rsa_method = RSA_meth_dup(RSA_get_default_method());
  if (!safe_rsa_method) {
    printf("ENGINE_set_RSA failed");
    return NULL;
  }

  RSA_meth_set1_name(safe_rsa_method, "security engine RSA method");
  RSA_meth_set_flags(safe_rsa_method, 0);
  RSA_meth_set_priv_enc(safe_rsa_method, RsaEncrypt);
  return safe_rsa_method;
}

static int BindEngine(ENGINE *e, char *engine_id) {
  if (!ENGINE_set_id(e, engine_id) || !ENGINE_set_name(e, engine_id) ||
      !ENGINE_set_init_function(e, EngineInit) ||
      !ENGINE_set_load_ssl_client_cert_function(e, LoadClientKeyAndCert) ||
      !ENGINE_set_destroy_function(e, EngineDestroy) ||
      !ENGINE_set_finish_function(e, EngineFinish)) {
    return 0;
  }

  RSA_METHOD *meth = GetRsaMethod();
  if (!ENGINE_set_RSA(e, meth)) {
    printf("ENGINE_set_RSA failed");
    return 0;
  }

  if (!ENGINE_set_default(e, ENGINE_METHOD_RSA)) {
    ENGINE_free(e);
    RSA_meth_free(safe_rsa_method);
    return 1;
  }

  return 1;
}

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

  if (!BindEngine(engine, engine_id)) {
    printf("load engine error,bind engine failed\n");
    ENGINE_free(engine);
    return 0;
  }

  ENGINE_add(engine);
  ENGINE_free(engine);
  ERR_clear_error();
  printf("load engine success, engine type:%d\n", type);
  return 1;
}

int LoadCert(SSL_CTX *ctx, int type) {
  SSL_CTX_load_verify_locations(ctx, "./ca.crt", NULL);

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