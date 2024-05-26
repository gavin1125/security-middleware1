#ifndef BACK_H_
#define BACK_H_

#include <stddef.h>
#include <stdint.h>
#include <openssl/ossl_typ.h>

EVP_PKEY* OPTEE_ENG_load_private_key(
    ENGINE *	e,
    const char *key_id,
    UI_METHOD *	ui_method,
    void *		callback_data);

int OPTEE_ENG_evp_cb_sign(
	EVP_MD_CTX *       ctx,
	unsigned char *      sig,
	size_t *             sigsz,
	const unsigned char *tb,
	size_t               tbsz);


int LoadClientKeyAndCert(ENGINE *e, SSL *ssl,
                         STACK_OF(X509_NAME) *ca_dn,
                         X509 **pX509, EVP_PKEY **pkey,
                         STACK_OF(X509) **pother,
                         UI_METHOD *ui_method,
                         void *callback_data);


int pkey_ec_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                 const unsigned char *tbs, size_t tbslen);


typedef struct {
    /* Key and paramgen group */
    EC_GROUP *gen_group;
    /* message digest */
    const EVP_MD *md;
    /* Duplicate key if custom cofactor needed */
    EC_KEY *co_key;
    /* Cofactor mode */
    signed char cofactor_mode;
    /* KDF (if any) to use for ECDH */
    char kdf_type;
    /* Message digest to use for key derivation */
    const EVP_MD *kdf_md;
    /* User key material */
    unsigned char *kdf_ukm;
    size_t kdf_ukmlen;
    /* KDF output length */
    size_t kdf_outlen;
} EC_PKEY_CTX;

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

typedef volatile int CRYPTO_REF_COUNT;
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
    STACK_OF(X509_ATTRIBUTE) * attributes; /* [ 0 ] */
    CRYPTO_RWLOCK *lock;
} /* EVP_PKEY */;
#endif // BACK_H_
