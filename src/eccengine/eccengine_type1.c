#include "eccengine.h"
#include "rsa.h"
#include <unistd.h>


long read_content_from_file(const char *path, unsigned char **outContent) {
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        return -1;
    }
    (void) fseek(fp, SEEK_SET, SEEK_END);
    long size = ftell(fp);
    (void) fseek(fp, SEEK_SET, SEEK_SET);
    *outContent = (unsigned char *) malloc(size + 1);
    if (*outContent == NULL) {
        (void) fclose(fp);
        return -2;
    }
    (void) memset(*outContent, 0x0, size + 1);
    (void) fread(*outContent, 1u, size, fp);
    (void) fclose(fp);
    return size;
}

static int rsa_ossl_private_encrypt3(int flen, const unsigned char *from,
                                     unsigned char *to, RSA *rsa1, int padding) {

    char *ssl_client_key = NULL;
    unsigned int len = read_content_from_file("/vagrant/cert/all/client.key", &ssl_client_key);
    RSA *privateRsa = NULL;
    BIO *bio = NULL;
    if ((bio = BIO_new_mem_buf(ssl_client_key, -1)) == NULL) {
        return 0;
    }
    if ((privateRsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL)) == NULL) {
        BIO_free_all(bio);
        return 0;
    }
    BIO_free_all(bio);

    R_RSA_PRIVATE_KEY privateKey = {0};
    privateKey.bits = RSA_bits(privateRsa);
    BN_bn2bin(privateRsa->n, privateKey.modulus);
    BN_bn2bin(privateRsa->e, privateKey.publicExponent);
    BN_bn2bin(privateRsa->d, privateKey.exponent);
    BN_bn2bin(privateRsa->p, privateKey.prime[0]);
    BN_bn2bin(privateRsa->q, privateKey.prime[1]);
    BN_bn2bin(privateRsa->dmp1, privateKey.primeExponent[0]);
    BN_bn2bin(privateRsa->dmq1, privateKey.primeExponent[1]);
    BN_bn2bin(privateRsa->iqmp, privateKey.coefficient);

    int outLen;


    printf("%s\n", "RSAPrivateBlock1111111111111111111");
    RSAPrivateBlock(to, &outLen, from, flen, &privateKey);
    printf("%s:%d\n", "RSAPrivateBlock1111111111111111111",outLen);

    return 256;
}


#define CACERT "/vagrant/cert/ecc/all/ca.crt"
#define CLIENT_CRT "/vagrant/cert/ecc/all/client.crt"
#define CLIENT_KEY "/vagrant/cert/ecc/all/client.key"

#define SERVER_ADDR "127.0.0.1"//输入自己的IP地址
#define PORT 20001

#define LBXX_ENGINE_RSA_ID "engine_rsa_id"
static RSA_METHOD *engine_rsa_method = NULL;

ENGINE *GetSecurityEngine(const char *id) {
    ENGINE *engine = NULL;

    if (NULL == id) {
        printf("NULL == id");
        return NULL;
    }

    engine = ENGINE_by_id(id);
    if (NULL == engine) {
        printf("NULL == engine");
        return NULL;
    }

    return engine;
}

SSL_CTX *InitSSL(char *ca_path, char *client_crt_path, char *client_key_path ) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

    if (ctx == NULL) {
        printf("SSL_CTX_new error\n");
        return NULL;
    }

    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_load_verify_locations(ctx, ca_path, NULL);
    SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384");
    ENGINE *pSt = GetSecurityEngine(LBXX_ENGINE_RSA_ID);

    SSL_CTX_set_client_cert_engine(ctx, pSt);

    return ctx;
}


static EVP_PKEY *LoadClientKey() {
    char *ssl_client_key = NULL;
    unsigned int len = read_content_from_file("/vagrant/cert/ecc/all/client.key", &ssl_client_key);

    RSA *privateRsa = NULL;
    BIO *bio = NULL;
    if ((bio = BIO_new_mem_buf(ssl_client_key, -1)) == NULL) {
        return NULL;
    }
    if ((privateRsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL)) == NULL) {
        BIO_free_all(bio);
        return NULL;
    }
    BIO_free_all(bio);
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pkey, privateRsa);

    RSA_free(privateRsa);
    if (pkey == NULL) {
        return NULL;
    }
    return pkey;
}

static X509 *LoadClientCert() {
    char *ssl_client_cert = NULL;
    unsigned int len = read_content_from_file("/vagrant/cert/ecc/all/client.crt", &ssl_client_cert);

    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, (const char *) ssl_client_cert);
    X509 *cert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
    return cert;
}


static int LoadClientKeyAndCert(ENGINE *e, SSL *ssl,
                                STACK_OF(X509_NAME) *ca_dn,
                                X509 **pcert, EVP_PKEY **pkey,
                                STACK_OF(X509) **pother,
                                UI_METHOD *ui_method,
                                void *callback_data) {
    X509 *cert = LoadClientCert();
    if (NULL == cert) {
        return 0;
    }
    *pcert = cert;

    EVP_PKEY *pkey1 = LoadClientKey();
    if (NULL == pkey1) {
        return 0;
    }
    *pkey = pkey1;
    return 1;
}

static int EngineInit(ENGINE *e) {

    printf("EngineInit\n");
    return 1;
}

static int EngineDestroy(ENGINE *e) {


    printf("EngineDestroy\n");
    return 1;
}


int load_engine() {
    ENGINE *e = NULL;
    if ((e = ENGINE_new()) == NULL) {
        return 0;
    }


    if (!ENGINE_set_id(e, LBXX_ENGINE_RSA_ID) ||
        !ENGINE_set_name(e, LBXX_ENGINE_RSA_ID) ||
        !ENGINE_set_destroy_function(e, EngineDestroy) ||
        !ENGINE_set_init_function(e, EngineInit) ||
        !ENGINE_set_load_ssl_client_cert_function(e, LoadClientKeyAndCert)) {
        return 0;
    }


    engine_rsa_method = RSA_meth_dup(RSA_get_default_method());
    if (!engine_rsa_method)
        return 0;
    RSA_meth_set1_name(engine_rsa_method, "libp11 RSA method");
    RSA_meth_set_flags(engine_rsa_method, 0);


    RSA_meth_set_priv_enc(engine_rsa_method, rsa_ossl_private_encrypt3);


    ENGINE_set_RSA(e, engine_rsa_method);

    /* 设置到全局引擎表中 */
    if (!ENGINE_set_default(e, ENGINE_METHOD_RSA)) {
        ENGINE_free(e);
        RSA_meth_free(engine_rsa_method);
        return 0;
    }

    ENGINE_add(e);

    ENGINE_free(e);
    return 1;
}

int main() {
    load_engine();

    int sd;
    int confd = 0;
    SSL *ssl = NULL;
    SSL_CTX *ctx = NULL;
    struct sockaddr_in sa = {0};
    ctx = InitSSL(CACERT, CLIENT_CRT, CLIENT_KEY);
    if (ctx == NULL) return -1;

    printf("Begin tcp socket...\n");

    sd = socket(AF_INET, SOCK_STREAM, 0);
    if (sd <= 0) {
        perror("socket");
        goto exit;
    }

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(SERVER_ADDR); /* Server IP */
    sa.sin_port = htons(PORT);                   /* Server Port number */
    confd = connect(sd, (struct sockaddr *) &sa, sizeof(sa));
    if (confd < 0) {
        printf("connect error=%d\n", confd);
        goto exit;
    }

    printf("Begin SSL negotiation \n");

    ssl = SSL_new(ctx);
    if (ssl <= 0) {
        printf("Error creating SSL new \n");
        goto exit;
    }

    SSL_set_fd(ssl, sd);
    SSL_connect(ssl);
    printf("链接已建立.开始 SSL 握手过程 \n");


    printf("SSL connection using %s\n", SSL_get_cipher(ssl));

    X509 *server_cert = SSL_get_peer_certificate(ssl);
    printf("Server certificate:\n");

    char *str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
    printf("/t subject: %s\n", str);
    free(str);

    str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
    printf("/t issuer: %s\n", str);
    free(str);

    X509_free(server_cert); /*如不再需要,需将证书释放 */

    printf("Begin SSL data exchange\n");

    unsigned char buf[300] = "sfsfsfsfsf\n";
    SSL_write(ssl, buf, sizeof(buf));
    memset(buf, 0, sizeof(buf));
    SSL_read(ssl, buf, sizeof(buf));
    printf("Received: %s\n", buf);

    SSL_shutdown(ssl);
    shutdown(sd, 2);
    exit:
    if (sd > 0) close(sd);
    if (confd > 0) close(confd);
    SSL_CTX_free(ctx);
    if (ssl) SSL_free(ssl);
    return 0;
}
