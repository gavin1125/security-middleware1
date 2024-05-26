//
// Created by vagrant on 5/26/24.
//
#include <openssl/engine.h>
#include "sdf_interface.h"

static int (*orig_pkey_ec_sign_init)(EVP_PKEY_CTX *ctx);

static int (*orig_pkey_ec_sign)(EVP_PKEY_CTX *ctx,
                                unsigned char *sig, size_t *siglen,
                                const unsigned char *tbs, size_t tbslen);

int pkey_ec_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                 const unsigned char *tbs, size_t tbslen) {
    int ret, type;
//    unsigned int sltmp;
//    EC_PKEY_CTX *dctx = ctx->data;
//    EVP_PKEY *pSt = ctx->pkey;
//    EC_KEY *ec = pSt->pkey.ec;
//    const int sig_sz = ECDSA_size(ec);
//
//    /* ensure cast to size_t is safe */
////    if (!ossl_assert(sig_sz > 0))
////        return 0;
//
//    if (sig == NULL) {
//        *siglen = (size_t)sig_sz;
//        return 1;
//    }
//
//    if (*siglen < (size_t)sig_sz) {
//        ECerr(EC_F_PKEY_EC_SIGN, EC_R_BUFFER_TOO_SMALL);
//        return 0;
//    }
//
//    type = (dctx->md != NULL) ? EVP_MD_type(dctx->md) : NID_sha1;
//
//    ret = ECDSA_sign(type, tbs, tbslen, sig, &sltmp, ec);
//
//    if (ret <= 0)
//        return ret;
//    *siglen = (size_t)sltmp;
    return 1;
}

static int reg_nids[1] = {EVP_PKEY_EC};

static int OPTEE_ENG_pkey_meths(
        ENGINE *e,
        EVP_PKEY_METHOD **pmeth,
        const int **nids,
        int nid) {


    if (!pmeth) {
        // Return list of registered NIDs
        *nids = reg_nids;
        return 1;
    }

    const EVP_PKEY_METHOD *orig_meth;
    EVP_PKEY_METHOD *new_meth;

    orig_meth = EVP_PKEY_meth_find(EVP_PKEY_EC);
    if (!orig_meth) {
        return 0;
    }

    new_meth = EVP_PKEY_meth_new(EVP_PKEY_EC, 0);
    EVP_PKEY_meth_copy(new_meth, orig_meth);

    EVP_PKEY_meth_get_sign(orig_meth,
                           &orig_pkey_ec_sign_init, &orig_pkey_ec_sign);

    // Bind function pointers of PKEY and ASN1 methods
//    EVP_PKEY_meth_set_digestsign(new_meth, OPTEE_ENG_evp_cb_sign);


    EVP_PKEY_meth_set_sign(new_meth,
                           orig_pkey_ec_sign_init, pkey_ec_sign);

    *pmeth = new_meth;
    return 1;
}


int BindEcc(ENGINE *e) {
    ENGINE_set_pkey_meths(e, OPTEE_ENG_pkey_meths);
    return 1;
}