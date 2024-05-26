#include <openssl/engine.h>
#include "sdf_interface.h"

static RSA_METHOD *safe_rsa_method = NULL;

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


int BindRSA(ENGINE *e) {
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

void FreeRsaMethod() {
    if (NULL != safe_rsa_method) {
        RSA_meth_free(safe_rsa_method);
        safe_rsa_method = NULL;
    }

}