#include "ssl_example.h"
#include "public/security_engine.h"
#include <unistd.h>

#define CACERT "/vagrant/cert/ecc/all/ca.crt"
#define CLIENT_CRT "/vagrant/cert/ecc/all/client.crt"
#define CLIENT_KEY "/vagrant/cert/ecc/all/client.key"
#define SERVER_ADDR "127.0.0.1"
#define PORT 20001

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
//  SSL_CTX_load_verify_locations(ctx, ca_path, NULL);

//  SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384");


  LoadCert(ctx, SECURITY_ENGINE_TYPE_GHY);

  int i = SSL_CTX_use_certificate_file(ctx, client_crt_path, SSL_FILETYPE_PEM);
  if (i <= 0) {
    printf("SSL_CTX_use_certificate_file error: %d\n", i);
    goto exit;
  }

//  int file =
//      SSL_CTX_use_PrivateKey_file(ctx, client_key_path, SSL_FILETYPE_PEM);
//  if (file <= 0) {
//    printf("SSL_CTX_use_PrivateKey_file error:%d\n", file);
//    goto exit;
//  }

  return ctx;

exit:
  if (ctx)
    SSL_CTX_free(ctx);
  return NULL;
}

int main() {
  LoadSecurityEngine(SECURITY_ENGINE_TYPE_GHY);

  int sd;
  int confd = 0;
  SSL *ssl = NULL;
  SSL_CTX *ctx = NULL;
  struct sockaddr_in sa = {0};
  ctx = InitSSL(CACERT, CLIENT_CRT, CLIENT_KEY);
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
  confd = connect(sd, (struct sockaddr *)&sa, sizeof(sa));
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
//  FreeSecurityEngine(SECURITY_ENGINE_TYPE_GHY);
exit:
  if (sd > 0)
    close(sd);
  if (confd > 0)
    close(confd);
  SSL_CTX_free(ctx);
  if (ssl)
    SSL_free(ssl);
  //  FreeSecurityEngine(SECURITY_ENGINE_TYPE_GHY);

  return 0;
}
