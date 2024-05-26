#include "eccengine.h"
#include <unistd.h>


#define CACERT "/vagrant/cert/ecc/all/ca.crt"
#define CLIENT_CRT "/vagrant/cert/ecc/all/client.crt"
#define CLIENT_KEY "/vagrant/cert/ecc/all/client.key"

#define SERVER_ADDR "127.0.0.1"//输入自己的IP地址
#define PORT 20001
#define LBXX_ENGINE_PKEY_RSA_ID "aaaa502"

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

SSL_CTX *InitSSL(char *ca_path, char *client_crt_path, char *client_key_path) {
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


    ENGINE *pSt = GetSecurityEngine(LBXX_ENGINE_PKEY_RSA_ID);

    SSL_CTX_set_client_cert_engine(ctx, pSt);
//    int i = SSL_CTX_use_certificate_file(ctx, client_crt_path, SSL_FILETYPE_PEM);
//    if (i <= 0) {
//        printf("SSL_CTX_use_certificate_file error: %d\n", i);
//        goto exit;
//    }
//
//    int file = SSL_CTX_use_PrivateKey_file(ctx, client_key_path, SSL_FILETYPE_PEM);
//    if (file <= 0) {
//        printf("SSL_CTX_use_PrivateKey_file error:%d\n", file);
//        goto exit;
//    }

    return ctx;

    exit:
    if (ctx) SSL_CTX_free(ctx);
    return NULL;
}




static int (*orig_pkey_ec_sign_init)(EVP_PKEY_CTX *ctx);

static int (*orig_pkey_ec_sign)(EVP_PKEY_CTX *ctx,
                                unsigned char *sig, size_t *siglen,
                                const unsigned char *tbs, size_t tbslen);


int pkey_ec_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                 const unsigned char *tbs, size_t tbslen) {
    int ret, type;
    unsigned int sltmp;
    EC_PKEY_CTX *dctx = ctx->data;
    EVP_PKEY *pSt = ctx->pkey;
    EC_KEY *ec = pSt->pkey.ec;
    const int sig_sz = ECDSA_size(ec);


    if (sig == NULL) {
        *siglen = (size_t) sig_sz;
        return 1;
    }

    if (*siglen < (size_t) sig_sz) {
        ECerr(EC_F_PKEY_EC_SIGN, EC_R_BUFFER_TOO_SMALL);
        return 0;
    }

    type = (dctx->md != NULL) ? EVP_MD_type(dctx->md) : NID_sha1;

    ret = ECDSA_sign(type, tbs, tbslen, sig, &sltmp, ec);

    if (ret <= 0)
        return ret;
    *siglen = (size_t) sltmp;
    return 1;
}
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

static EVP_PKEY *LoadClientKey() {
    char *ssl_client_key = NULL;
    unsigned int len = read_content_from_file("/vagrant/cert/ecc/all/client.key", &ssl_client_key);

    EVP_PKEY *key;
    BIO *bio = NULL;
    if ((bio = BIO_new_mem_buf(ssl_client_key, -1)) == NULL) {
        return NULL;
    }
    if ((key = PEM_read_bio_PrivateKey(bio, 0, 0, 0)) == NULL) {
        BIO_free_all(bio);
        return NULL;
    }

    return key;
}


int pkey_ec_sign1(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                 const unsigned char *tbs, size_t tbslen) {
    int ret, type;
    unsigned int sltmp;
    EC_PKEY_CTX *dctx = ctx->data;


    EVP_PKEY *pSt = LoadClientKey();


    EC_KEY *ec = pSt->pkey.ec;
    const int sig_sz = ECDSA_size(ec);


    if (sig == NULL) {
        *siglen = (size_t) sig_sz;
        return 1;
    }

    if (*siglen < (size_t) sig_sz) {
        ECerr(EC_F_PKEY_EC_SIGN, EC_R_BUFFER_TOO_SMALL);
        return 0;
    }

    type = (dctx->md != NULL) ? EVP_MD_type(dctx->md) : NID_sha1;

    ret = ECDSA_sign(type, tbs, tbslen, sig, &sltmp, ec);

    if (ret <= 0)
        return ret;
    *siglen = (size_t) sltmp;
    return 1;
}


static int reg_nids[1] = {EVP_PKEY_EC};
static int ENGINE_evp_pkey_meth(
        ENGINE *          e,
        EVP_PKEY_METHOD **pmeth,
        const int **      nids,
        int               nid) {


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


    EVP_PKEY_meth_set_sign(new_meth,
                           orig_pkey_ec_sign_init, pkey_ec_sign1);

    *pmeth = new_meth;
    return 1;
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


    EVP_PKEY *pubkey = X509_get_pubkey(cert);

    *pkey = pubkey;

//    EVP_PKEY *pkey1 = LoadClientKey();
//    if (NULL == pkey1) {
//        return 0;
//    }
//    *pkey = pkey1;
    return 1;
}

int lbxx_engine_rsa2() {
    ENGINE *e = NULL;
    if ((e = ENGINE_new()) == NULL) {
        return 1;
    }
    if (!ENGINE_set_id(e, LBXX_ENGINE_PKEY_RSA_ID)) {
        printf("ENGINE_set_id error \n");
        ENGINE_free(e);
        return 1;
    }

    if(!ENGINE_set_name(e,LBXX_ENGINE_PKEY_RSA_ID)){
        printf("ENGINE_set_name error \n");
        ENGINE_free(e);
        return 1;
    }

    if(!ENGINE_set_load_ssl_client_cert_function(e, LoadClientKeyAndCert)){
        printf("ENGINE_set_load_ssl_client_cert_function error \n");
        ENGINE_free(e);
        return 1;
    }

    if(!ENGINE_set_pkey_meths(e, ENGINE_evp_pkey_meth)){
        printf("ENGINE_set_pkey_meths error \n");
        ENGINE_free(e);
        return 1;
    }

    ENGINE_add(e);
    ENGINE_free(e);
    return 0;
}

int main() {

    lbxx_engine_rsa2();

    int sd = 0;
    int confd = 0;
    SSL *ssl = NULL;
    SSL_CTX *ctx = NULL;
    struct sockaddr_in sa = {0};
    ctx = InitSSL(CACERT, CLIENT_CRT, CLIENT_KEY);
    if (ctx == NULL) return -1;

    /* 指定加密器类型 */
    //SSL_CTX_set_cipher_list (ctx, "ECDHE-RSA-AES256-SHA");
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

    /*以下是正常的TCP socket建立过程 .............................. */
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


    /* TCP 链接已建立.开始 SSL 握手过程.......................... */
    printf("Begin SSL negotiation \n");

    /*申请一个SSL套接字*/
    ssl = SSL_new(ctx);
    if (ssl <= 0) {
        printf("Error creating SSL new \n");
        goto exit;
    }

    /*绑定读写套接字*/
    SSL_set_fd(ssl, sd);
    SSL_connect(ssl);
    printf("链接已建立.开始 SSL 握手过程 \n");


    /*打印所有加密算法的信息(可选)*/
    printf("SSL connection using %s\n", SSL_get_cipher(ssl));

    /*得到服务端的证书并打印些信息(可选) */
    X509 *server_cert = SSL_get_peer_certificate(ssl);
    printf("Server certificate:\n");

    char *str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
    printf("/t subject: %s\n", str);
    free(str);

    str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
    printf("/t issuer: %s\n", str);
    free(str);

    X509_free(server_cert); /*如不再需要,需将证书释放 */

    /* 数据交换开始,用SSL_write,SSL_read代替write,read */
    printf("Begin SSL data exchange\n");

    unsigned char buf[300] = "sfsfsfsfsf";
    int ret = SSL_write(ssl, buf, sizeof(buf));
    memset(buf, 0, sizeof(buf));

    SSL_read(ssl, buf, sizeof(buf));
    printf("Received: %s\n", buf);
    SSL_shutdown(ssl); /* send SSL/TLS close_notify */
    /* 收尾工作 */
    shutdown(sd, 2);
    exit:
    if (sd > 0) close(sd);
    if (confd > 0) close(confd);
    if (ctx) SSL_CTX_free(ctx);
    if (ssl) SSL_free(ssl);
    return 0;

    // 清理引擎资源
    //    ENGINE_finish(e);
    //    ENGINE_free(e);
}
