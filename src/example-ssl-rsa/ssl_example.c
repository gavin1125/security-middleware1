#include "ssl_example.h"
#include "public/security_engine.h"
#include <unistd.h>

#define SERVER_ADDR "127.0.0.1"
#define PORT 20001

static int type = SECURITY_ENGINE_TYPE_GCY_RSA;

SSL_CTX *InitSSL() {
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
    SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES128-GCM-SHA256");

    LoadCert(ctx, type);
    return ctx;
}

int main() {
    LoadSecurityEngine(type);

    int sd;
    int confd = 0;
    SSL *ssl = NULL;
    SSL_CTX *ctx = NULL;
    struct sockaddr_in sa = {0};
    ctx = InitSSL();
    if (ctx == NULL)
        return -1;
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
    FreeSecurityEngine(type);
    exit:
    if (sd > 0)
        close(sd);
    if (confd > 0)
        close(confd);
    SSL_CTX_free(ctx);
    if (ssl)
        SSL_free(ssl);
    FreeSecurityEngine(type);

    return 0;
}
