#include <openssl/engine.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "public/sdf.h"
#include "public/security_engine.h"

#define UNUSED(x) (void)(x)
#define GCY_RSA_SECURITY_ENGINE  "gcy_rsa_security_engine";
#define GHY_RSA_SECURITY_ENGINE  "ghy_rsa_security_engine";

static RSA_METHOD *safe_rsa_method = NULL;

static void *phDeviceHandle = NULL;
static void *phSessionHandle = NULL;

typedef struct {
    unsigned char *ca_file_name;
    unsigned int ca_content_len;

    unsigned char *client_cert_file_name;
    unsigned int client_cert_content_len;

    int client_key_index;
} SdfParam;


static SdfParam ghy_rsa_sdf_param = {(unsigned char *) "ca.crt", 3868, (unsigned char *) "client.crt", 1518, 6};
static SdfParam gcy_rsa_sdf_param = {(unsigned char *) "ca_gcy.crt", 13538, (unsigned char *) "client_gcy.crt", 5018,
                                     8};
static SdfParam *sdf_param;

void InitSdf(int type) {
    if (type == SECURITY_ENGINE_TYPE_GHY_RSA) {
        sdf_param = &ghy_rsa_sdf_param;
    } else if (type == SECURITY_ENGINE_TYPE_GCY_RSA) {
        sdf_param = &gcy_rsa_sdf_param;
    }
}

int LoadCaCert(int type, unsigned char *ssl_ca_cert, unsigned int *ssl_ca_cert_size) {
    if (type != SECURITY_ENGINE_TYPE_GHY_RSA && type != SECURITY_ENGINE_TYPE_GCY_RSA) {
        printf("load engine error,type[%d] not correct\n", type);
        return 0;
    }
    *ssl_ca_cert_size = sdf_param->ca_content_len;
    if (SDF_ReadFile(phSessionHandle, sdf_param->ca_file_name, strlen((char *) sdf_param->ca_file_name), 0,
                     ssl_ca_cert_size, ssl_ca_cert) != 0) {
        printf("SDF_ReadFile ca.crt error\n");
        return 0;
    }

    return 1;
}

static int EngineDestroy(ENGINE *e) {
    UNUSED(e);
    if (NULL != safe_rsa_method) {
        RSA_meth_free(safe_rsa_method);
        safe_rsa_method = NULL;
    }

    printf("EngineDestroy\n");
    return 1;
}

static int EngineFinish(ENGINE *e) {
    UNUSED(e);
    if (phSessionHandle != NULL) {
        if (SDF_CloseSession(phSessionHandle) != 0) {
        }
    }

    if (phDeviceHandle != NULL) {
        if (SDF_CloseDevice(phDeviceHandle) != 0) {
        }
    }

    char *ca_path = "/tmp/ca.crt";
    if (remove(ca_path) != 0) {
        printf("remove %s error\n", ca_path);
    }


    printf("EngineFinish\n");
    return 1;
}

long write_content_to_file(const char *path, unsigned char *content) {
    FILE *fp = fopen(path, "w");
    if (fp == NULL) {
        return -1;
    }
    fputs((char *) content, fp);

    (void) fclose(fp);
    return 1;
}

static int EngineInit(ENGINE *e) {
    UNUSED(e);
    if (SDF_OpenDevice(&phDeviceHandle) != 0) {
        printf("SDF_OpenDevice error\n");
    }
    if (SDF_OpenSession(phDeviceHandle, &phSessionHandle) != 0) {
        printf("SDF_OpenSession error\n");
    }

    char *ca_path = "/tmp/ca.crt";
    if (access(ca_path, F_OK) != 0) {
        unsigned char ssl_ca_cert[13538] = {0};
        unsigned int ssl_ca_cert_size = 0;
        if (LoadCaCert(SECURITY_ENGINE_TYPE_GHY_RSA, ssl_ca_cert, &ssl_ca_cert_size) !=
            1) {
            return 0;
        }

        write_content_to_file(ca_path, ssl_ca_cert);
    }

    printf("EngineInit\n");
    return 1;
}

static X509 *LoadClientCert() {
    unsigned char *ssl_client_cert[1518] = {0};
    unsigned int readLen = sdf_param->client_cert_content_len;
    if (SDF_ReadFile(phSessionHandle, sdf_param->client_cert_file_name,
                     strlen((char *) sdf_param->client_cert_file_name), 0,
                     &readLen, (unsigned char *) ssl_client_cert) != 0) {
        printf("SDF_ReadFile client.crt error\n");
        return NULL;
    }

    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, (const char *) ssl_client_cert);
    X509 *cert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
    printf("load cert success\n");
    return cert;
}

static int LoadClientKeyAndCert(ENGINE *e, SSL *ssl,
                                STACK_OF(X509_NAME) *ca_dn, X509 **pX509,
                                EVP_PKEY **pkey, STACK_OF(X509) **pother,
                                UI_METHOD *ui_method, void *callback_data) {
    UNUSED(e);
    UNUSED(ssl);
    UNUSED(ca_dn);
    UNUSED(pother);
    UNUSED(ui_method);
    UNUSED(callback_data);
    printf("LoadClientKeyAndCert\n");

    X509 *cert = LoadClientCert();
    if (NULL == cert) {
        return 0;
    }
    *pX509 = cert;

    EVP_PKEY *pubkey = X509_get_pubkey(cert);

    *pkey = pubkey;
    return 1;
}

static int RsaEncrypt(int length, const unsigned char *from, unsigned char *to,
                      RSA *rsa, int padding) {
    UNUSED(rsa);
    UNUSED(padding);
    unsigned int outLen = 0;
    int ret = SDF_InternalPrivateKeyOperation_RSA(phSessionHandle, sdf_param->client_key_index, (unsigned char *) from,
                                                  length,
                                                  to, &outLen);
    if (ret != 0) {
        printf("rsa encrypt error");
    }

    printf("RsaEncrypt11111111111111111111,%d\n", outLen);

    return (int) outLen;
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

int BindEngine(ENGINE *e, char *engine_id) {
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
    if (type == SECURITY_ENGINE_TYPE_GHY_RSA) {
        return GHY_RSA_SECURITY_ENGINE;
    }
    return GCY_RSA_SECURITY_ENGINE;
}

ENGINE *GetSecurityEngine(int type) {
    if (type != SECURITY_ENGINE_TYPE_GHY_RSA && type != SECURITY_ENGINE_TYPE_GCY_RSA) {
        printf("get engine error,type[%d] not correct\n", type);
        return NULL;
    }

    char *engine_id = GetEngineIdByType(type);

    return ENGINE_by_id(engine_id);
}

int LoadSecurityEngine(int type) {
    if (type != SECURITY_ENGINE_TYPE_GHY_RSA && type != SECURITY_ENGINE_TYPE_GCY_RSA) {
        printf("load engine error,type[%d] not correct\n", type);
        return 0;
    }
    ENGINE *engine = NULL;
    engine = GetSecurityEngine(type);

    if (engine != NULL) {
        return 1;
    }

    InitSdf(type);

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
    SSL_CTX_load_verify_locations(ctx, "/tmp/ca.crt", NULL);

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