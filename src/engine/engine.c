#include <openssl/engine.h>
#include <unistd.h>
#include "public/sdf.h"
#include "public/security_engine.h"
#include "sdf_interface.h"
#include "rsa.h"
#include "ecc.h"
#include "log.h"

#define GCY_RSA_SECURITY_ENGINE  "gcy_rsa_security_engine";
#define GHY_RSA_SECURITY_ENGINE  "ghy_rsa_security_engine";
#define GHY_ECC_SECURITY_ENGINE  "ghy_ecc_security_engine";


static int EngineInit(ENGINE *e) {
    NOP(e);
    SdfInit();
    info("EngineInit");
    return 1;
}

static int EngineFinish(ENGINE *e) {
    NOP(e);
    SdfFinish();
    info("EngineFinish");
    return 1;
}


static int EngineDestroy(ENGINE *e) {
    NOP(e);
    FreeRsaMethod();
    printf("EngineDestroy\n");
    return 1;
}

static int LoadClientKeyAndCert(ENGINE *e,
                                SSL *ssl,
                                STACK_OF(X509_NAME) *ca_dn,
                                X509 **pX509,
                                EVP_PKEY **pkey,
                                STACK_OF(X509) **pother,
                                UI_METHOD *ui_method,
                                void *callback_data) {
    NOP(e);
    NOP(ssl);
    NOP(ca_dn);
    NOP(pother);
    NOP(ui_method);
    NOP(callback_data);
    info("LoadClientKeyAndCert");

    X509 *cert = LoadClientCert();
    if (NULL == cert) {
        return 0;
    }
    *pX509 = cert;

    EVP_PKEY *pubkey = X509_get_pubkey(cert);

    *pkey = pubkey;
    return 1;
}


char *GetEngineIdByType(int type) {
    if (type == SECURITY_ENGINE_TYPE_GHY_RSA) {
        return GHY_RSA_SECURITY_ENGINE;
    } else if (type == SECURITY_ENGINE_TYPE_GCY_RSA) {
        return GCY_RSA_SECURITY_ENGINE;
    } else {
        return GHY_ECC_SECURITY_ENGINE;
    }
}


int BindEngine(ENGINE *e, int type) {
    char *engine_id = GetEngineIdByType(type);

    if (!ENGINE_set_id(e, engine_id) || !ENGINE_set_name(e, engine_id) ||
        !ENGINE_set_init_function(e, EngineInit) ||
        !ENGINE_set_load_ssl_client_cert_function(e, LoadClientKeyAndCert) ||
        !ENGINE_set_destroy_function(e, EngineDestroy) ||
        !ENGINE_set_finish_function(e, EngineFinish)) {
        return 0;
    }

    if (type == SECURITY_ENGINE_TYPE_GHY_ECC) {
        BindEcc(e);

    } else {
        if (BindRSA(e) != 1) {
            return 0;
        }
    }

    return 1;
}


ENGINE *GetSecurityEngine(int type) {
    char *engine_id = GetEngineIdByType(type);
    return ENGINE_by_id(engine_id);
}

int CheckType(int type) {
    if (type != SECURITY_ENGINE_TYPE_GHY_RSA &&
        type != SECURITY_ENGINE_TYPE_GCY_RSA &&
        type != SECURITY_ENGINE_TYPE_GHY_ECC) {
        info("engine error,type[%d] not correct", type);
        return 0;
    }
    return 1;
}

int LoadSecurityEngine(int type) {
    if (CheckType(type) != 1) {
        return 0;
    }
    ENGINE *engine = NULL;
    engine = GetSecurityEngine(type);

    if (engine != NULL) {
        return 1;
    }

    SdfParamInit(type);

    engine = ENGINE_new();
    if (NULL == engine) {
        info("load engine error,engine is NULL");
        return 0;
    }

    if (!BindEngine(engine, type)) {
        info("load engine error,bind engine failed");
        ENGINE_free(engine);
        return 0;
    }

    ENGINE_add(engine);
    ENGINE_free(engine);
    ERR_clear_error();
    info("load engine success, engine type:%d", type);
    return 1;
}


int LoadCert(SSL_CTX *ctx, int type) {
    if (CheckType(type) != 1) {
        return 0;
    }
    SSL_CTX_load_verify_locations(ctx, "/tmp/ca.crt", NULL);

    ENGINE *pSt = GetSecurityEngine(type);
    SSL_CTX_set_client_cert_engine(ctx, pSt);
    return 1;
}

int FreeSecurityEngine(int type) {
    if (CheckType(type) != 1) {
        return 0;
    }
    ENGINE *engine = GetSecurityEngine(type);

    if (NULL != engine) {
        ENGINE_free(engine);
    }

    return 1;
}