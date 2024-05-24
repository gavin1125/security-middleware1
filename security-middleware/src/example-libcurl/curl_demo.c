#include "public/security_engine.h"
#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>

static CURLcode sslctxfun(CURL *curl, void *sslctx, void *parm) {
  int ret = 0;
  SSL_CTX *ctx = (SSL_CTX *)sslctx;

  LoadCert(ctx, SECURITY_ENGINE_TYPE_GHY);

  ret = SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES128-GCM-SHA256");
  if (1 != ret) {
    printf("SSL_CTX_set_cipher_list failed\n");
    return CURLE_SSL_CERTPROBLEM;
  }

  return CURLE_OK;
}

size_t handlerResponseHeader(void *ptr, size_t size, size_t count,
                             char *response) {

  size_t len = size * count;
  char *ptrbuff = (char *)ptr;
  char line[512] = {0};
  int copy = len > 512 ? 512 : len;
  for (int i = 0; i < copy; i++) {
    if (ptrbuff[i] == '\r' || ptrbuff[i] == '\n') {
      break;
    }
    line[i] = ptrbuff[i];
  }
  line[511] = 0;
  printf("%s \n", line);

  return len;
}

int main(int argc, char *argv[]) {
  int ret = LoadSecurityEngine(SECURITY_ENGINE_TYPE_GHY);
  if (1 != ret) {
    printf("SAFE_EngineLoad failed\n");
    goto END;
  }

  curl_global_init(CURL_GLOBAL_DEFAULT);
  CURL *curl = curl_easy_init();
  curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, sslctxfun);
  curl_easy_setopt(curl, CURLOPT_SSLENGINE_DEFAULT, 1L);
  curl_easy_setopt(curl, CURLOPT_URL,
                   "https://10.167.76.188:30018/api/vsoc/front/secure/time");
  curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(curl, CURLOPT_NOBODY, 1);
  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "HEAD");
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &handlerResponseHeader);
  curl_easy_setopt(curl, CURLOPT_HEADERDATA, NULL);
  curl_easy_setopt(curl, CURLOPT_CAINFO, NULL);

  CURLcode res = curl_easy_perform(curl);

  if (res != CURLE_OK) {
    fprintf(stderr, "curl_easy_perform() failed: %s\n",
            curl_easy_strerror(res));
  }

  curl_easy_cleanup(curl);
  curl_global_cleanup();

END:
  FreeSecurityEngine(SECURITY_ENGINE_TYPE_GHY);
  return 0;
}