#ifndef SECURITY_MIDDLEWARE_RSAENGINE_H
#define SECURITY_MIDDLEWARE_RSAENGINE_H

#include <openssl/crypto.h>
#include <openssl/ecdh.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/socket.h>

#include <openssl/ssl.h>


struct evp_md_st {
    int type;
    int pkey_type;
    int md_size;
    unsigned long flags;

    int (*init)(EVP_MD_CTX *ctx);

    int (*update)(EVP_MD_CTX *ctx, const void *data, size_t count);

    int (*final)(EVP_MD_CTX *ctx, unsigned char *md);

    int (*copy)(EVP_MD_CTX *to, const EVP_MD_CTX *from);

    int (*cleanup)(EVP_MD_CTX *ctx);

    int block_size;
    int ctx_size; /* how big does the ctx->md_data need to be */
    /* control function */
    int (*md_ctrl)(EVP_MD_CTX *ctx, int cmd, int p1, void *p2);
} /* EVP_MD */;

struct evp_md_ctx_st {
    const EVP_MD *digest;
    ENGINE *engine; /* functional reference if 'digest' is
                                 * ENGINE-provided */
    unsigned long flags;
    void *md_data;
    /* Public key context for sign/verify */
    EVP_PKEY_CTX *pctx;

    /* Update function: usually copied from EVP_MD */
    int (*update)(EVP_MD_CTX *ctx, const void *data, size_t count);
} /* EVP_MD_CTX */;

typedef struct {
    /* Key gen parameters */
    int nbits;
    BIGNUM *pub_exp;
    int primes;
    /* Keygen callback info */
    int gentmp[2];
    /* RSA padding mode */
    int pad_mode;
    /* message digest */
    const EVP_MD *md;
    /* message digest for MGF1 */
    const EVP_MD *mgf1md;
    /* PSS salt length */
    int saltlen;
    /* Minimum salt length or -1 if no PSS parameter restriction */
    int min_saltlen;
    /* Temp buffer */
    unsigned char *tbuf;
    /* OAEP label */
    unsigned char *oaep_label;
    size_t oaep_labellen;
} RSA_PKEY_CTX;

struct evp_pkey_ctx_st {
    /* Method associated with this operation */
    const EVP_PKEY_METHOD *pmeth;
    /* Engine that implements this method or NULL if builtin */
    ENGINE *engine;
    /* Key: may be NULL */
    EVP_PKEY *pkey;
    /* Peer key for key agreement, may be NULL */
    EVP_PKEY *peerkey;
    /* Actual operation */
    int operation;
    /* Algorithm specific data */
    void *data;
    /* Application specific data */
    void *app_data;
    /* Keygen callback */
    EVP_PKEY_gen_cb *pkey_gencb;
    /* implementation specific keygen data */
    int *keygen_info;
    int keygen_info_count;
} /* EVP_PKEY_CTX */;

#define ED448_KEYLEN 57
#define MAX_KEYLEN ED448_KEYLEN
typedef struct {
    unsigned char pubkey[MAX_KEYLEN];
    unsigned char *privkey;
} ECX_KEY;

typedef _Atomic int CRYPTO_REF_COUNT;
struct evp_pkey_st {
    int type;
    int save_type;
    CRYPTO_REF_COUNT references;
    const EVP_PKEY_ASN1_METHOD *ameth;
    ENGINE *engine;
    ENGINE *pmeth_engine; /* If not NULL public key ENGINE to use */
    union {
        void *ptr;
#ifndef OPENSSL_NO_RSA
        struct rsa_st *rsa; /* RSA */
#endif
#ifndef OPENSSL_NO_DSA
        struct dsa_st *dsa; /* DSA */
#endif
#ifndef OPENSSL_NO_DH
        struct dh_st *dh; /* DH */
#endif
#ifndef OPENSSL_NO_EC
        struct ec_key_st *ec; /* ECC */
        ECX_KEY *ecx;         /* X25519, X448, Ed25519, Ed448 */
#endif
    } pkey;
    int save_parameters;
    STACK_OF(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
    CRYPTO_RWLOCK *lock;
} /* EVP_PKEY */;

struct rsa_st {
    /*
     * The first parameter is used to pickup errors where this is passed
     * instead of an EVP_PKEY, it is set to 0
     */
    int pad;
    int32_t version;
    const RSA_METHOD *meth;
    /* functional reference if 'meth' is ENGINE-provided */
    ENGINE *engine;
    BIGNUM *n;
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *dmp1;
    BIGNUM *dmq1;
    BIGNUM *iqmp;
    /* for multi-prime RSA, defined in RFC 8017 */
    STACK_OF(RSA_PRIME_INFO) *prime_infos;
    /* If a PSS only key this contains the parameter restrictions */
    RSA_PSS_PARAMS *pss;
    /* be careful using this if the RSA structure is shared */
    CRYPTO_EX_DATA ex_data;
    CRYPTO_REF_COUNT references;
    int flags;
    /* Used to cache montgomery values */
    BN_MONT_CTX *_method_mod_n;
    BN_MONT_CTX *_method_mod_p;
    BN_MONT_CTX *_method_mod_q;
    /*
     * rsa BIGNUM values are actually in the following data, if it is not
     * NULL
     */
    char *bignum_data;
    BN_BLINDING *blinding;
    BN_BLINDING *mt_blinding;
    CRYPTO_RWLOCK *lock;
};

#define ECCref_MAX_BITS 512
#define ECCref_MAX_LEN ((ECCref_MAX_BITS + 7) / 8)
#define RSAref_MAX_BITS 2048
#define RSAref_MAX_LEN ((RSAref_MAX_BITS + 7) / 8)
#define RSAref_MAX_PBITS ((RSAref_MAX_BITS + 1) / 2)
#define RSAref_MAX_PLEN ((RSAref_MAX_PBITS + 7) / 8)
typedef struct RSArefPublicKey_st {
    unsigned int bits;
    unsigned char m[RSAref_MAX_LEN];
    unsigned char e[RSAref_MAX_LEN];
} RSArefPublicKey;

typedef struct RSArefPrivateKey_st {
    unsigned int bits;
    unsigned char m[RSAref_MAX_LEN];
    unsigned char e[RSAref_MAX_LEN];
    unsigned char d[RSAref_MAX_LEN];
    unsigned char prime[2][RSAref_MAX_PLEN];
    unsigned char pexp[2][RSAref_MAX_PLEN];
    unsigned char coef[RSAref_MAX_PLEN];
} RSArefPrivateKey;

struct rsa_meth_st {
    char *name;

    int (*rsa_pub_enc)(int flen, const unsigned char *from,
                       unsigned char *to, RSA *rsa, int padding);

    int (*rsa_pub_dec)(int flen, const unsigned char *from,
                       unsigned char *to, RSA *rsa, int padding);

    int (*rsa_priv_enc)(int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding);

    int (*rsa_priv_dec)(int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding);

    /* Can be null */
    int (*rsa_mod_exp)(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx);

    /* Can be null */
    int (*bn_mod_exp)(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                      const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);

    /* called at new */
    int (*init)(RSA *rsa);

    /* called at free */
    int (*finish)(RSA *rsa);

    /* RSA_METHOD_FLAG_* things */
    int flags;
    /* may be needed! */
    char *app_data;

    /*
     * New sign and verify functions: some libraries don't allow arbitrary
     * data to be signed/verified: this allows them to be used. Note: for
     * this to work the RSA_public_decrypt() and RSA_private_encrypt() should
     * *NOT* be used RSA_sign(), RSA_verify() should be used instead.
     */
    int (*rsa_sign)(int type,
                    const unsigned char *m, unsigned int m_length,
                    unsigned char *sigret, unsigned int *siglen,
                    const RSA *rsa);

    int (*rsa_verify)(int dtype, const unsigned char *m,
                      unsigned int m_length, const unsigned char *sigbuf,
                      unsigned int siglen, const RSA *rsa);

    /*
     * If this callback is NULL, the builtin software RSA key-gen will be
     * used. This is for behavioural compatibility whilst the code gets
     * rewired, but one day it would be nice to assume there are no such
     * things as "builtin software" implementations.
     */
    int (*rsa_keygen)(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);

    int (*rsa_multi_prime_keygen)(RSA *rsa, int bits, int primes,
                                  BIGNUM *e, BN_GENCB *cb);
};

typedef struct rsa_prime_info_st {
    BIGNUM *r;
    BIGNUM *d;
    BIGNUM *t;
    /* save product of primes prior to this one */
    BIGNUM *pp;
    BN_MONT_CTX *m;
} RSA_PRIME_INFO;

#endif//SECURITY_MIDDLEWARE_RSAENGINE_H
