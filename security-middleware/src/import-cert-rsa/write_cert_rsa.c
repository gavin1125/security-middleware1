#include "public/rsa.h"
#include "public/sdf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

long read_content_from_file(const char *path, unsigned char **outContent) {
  FILE *fp = fopen(path, "rb");
  if (fp == NULL) {
    return -1;
  }
  (void)fseek(fp, SEEK_SET, SEEK_END);
  long size = ftell(fp);
  (void)fseek(fp, SEEK_SET, SEEK_SET);
  *outContent = (unsigned char *)malloc(size + 1);
  if (*outContent == NULL) {
    (void)fclose(fp);
    return -2;
  }
  (void)memset(*outContent, 0x0, size + 1);
  (void)fread(*outContent, 1u, size, fp);
  (void)fclose(fp);
  return size;
}

int ImportClientKey(void *hSessionHandle) {
  int ret;
  int bits;
  int i, j;
  unsigned int uiKeyIndex = 6;
  RSArefPublicKey publicKey = {0};
  RSArefPrivateKey privateKey = {0};
  unsigned char datain[2 * 1024] = {0};
  unsigned char dataout[2 * 1024] = {0};
  char *password = "soft1234";
  unsigned int pswlen = 0;
  unsigned int outlen = 0;
  unsigned int verifylen = 0;

  bits = 2048;

  char *ssl_client_key = NULL;
  unsigned int len = read_content_from_file("/vagrant/cert/rsa/all/client.key",
                                            &ssl_client_key);

  RSA *privateRsa = NULL;
  BIO *bio = NULL;
  if ((bio = BIO_new_mem_buf(ssl_client_key, -1)) == NULL) {
    return 0;
  }
  if ((privateRsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL)) ==
      NULL) {
    BIO_free_all(bio);
    return 0;
  }
  BIO_free_all(bio);
  privateKey.bits = RSA_bits(privateRsa);
  BN_bn2binpad(privateRsa->n, privateKey.m, RSAref_MAX_LEN);
  BN_bn2binpad(privateRsa->e, privateKey.e, RSAref_MAX_LEN);
  BN_bn2binpad(privateRsa->d, privateKey.d, RSAref_MAX_LEN);
  BN_bn2binpad(privateRsa->p, privateKey.prime[0], RSAref_MAX_PLEN);
  BN_bn2binpad(privateRsa->q, privateKey.prime[1], RSAref_MAX_PLEN);
  BN_bn2binpad(privateRsa->dmp1, privateKey.pexp[0], RSAref_MAX_PLEN);
  BN_bn2binpad(privateRsa->dmq1, privateKey.pexp[1], RSAref_MAX_PLEN);
  BN_bn2binpad(privateRsa->iqmp, privateKey.coef, RSAref_MAX_PLEN);

  RSA_free(privateRsa);

  char *ssl_client_cert = NULL;
  int len1 = read_content_from_file("/vagrant/cert/rsa/all/client.crt",
                                    &ssl_client_cert);
  BIO *bio_mem = BIO_new(BIO_s_mem());
  BIO_puts(bio_mem, ssl_client_cert);
  X509 *cert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
  EVP_PKEY *pubkey = X509_get_pubkey(cert);
  RSA *rsa_public_key = EVP_PKEY_get1_RSA(pubkey);

  const BIGNUM *rsa_n;
  const BIGNUM *rsa_e;
  RSA_get0_key(rsa_public_key, &rsa_n, &rsa_e, NULL);
  publicKey.bits = RSA_bits(rsa_public_key);
  BN_bn2binpad(rsa_n, publicKey.m, RSAref_MAX_LEN);
  BN_bn2binpad(rsa_e, publicKey.e, RSAref_MAX_LEN);
  RSA_free(rsa_public_key);

  pswlen = (unsigned int)strlen(password);
  ret = SDF_GetPrivateKeyAccessRight(hSessionHandle, uiKeyIndex, password,
                                     pswlen);
  printf("SDF_GetPrivateKeyAccessRight, ret=0x%08x\n", ret);
  if (SDR_OK != ret) {
    printf("SDF_GetPrivateKeyAccessRight failed\n");
    goto EXIT;
  }
  ret = SDF_ImportSignPublicKey_RSA(hSessionHandle, uiKeyIndex, &publicKey);
  printf("SDF_ImportSignPublicKey_RSA ret=0x%08x\n", ret);
  if (SDR_OK != ret) {
    printf("SDF_ImportSignPublicKey_RSA\n");
    goto EXIT;
  }

  ret = SDF_ImportSignPrivateKey_RSA(hSessionHandle, uiKeyIndex, &privateKey);
  printf("SDF_ImportSignPrivateKey_RSA ret=0x%08x\n", ret);
  if (SDR_OK != ret) {
    printf("SDF_ImportSignPrivateKey_RSA\n");
    goto EXIT;
  }

  for (j = 0; j < 256; j++) {
    datain[j] = 'b';
  }

  // 内部公钥加密
  ret = SDF_InternalPublicKeyOperation_RSA(hSessionHandle, uiKeyIndex, datain,
                                           bits / 8, dataout, &outlen);
  printf("SDF_InternalPublicKeyOperation_RSA ret=0x%08x\n", ret);
  if (SDR_OK != ret) {
    printf("SDF_InternalPublicKeyOperation_RSA\n");
    goto EXIT;
  }

  unsigned char verify1[2 * 1024] = {0};
  // 内部私钥解密
  ret = SDF_InternalPrivateKeyOperation_RSA(hSessionHandle, uiKeyIndex, dataout,
                                            outlen, verify1, &verifylen);
  printf("SDF_InternalPrivateKeyOperation_RSA ret=0x%08x\n", ret);
  if (SDR_OK != ret) {
    printf("SDF_InternalPrivateKeyOperation_RSA\n");
    goto EXIT;
  }

  if (memcmp(datain, verify1, bits / 8)) {
    printf("Internal Enc Internal Dec failed\n");
    goto EXIT;
  } else {
    printf("Internal Enc Internal Dec ok\n");
  }

  ret = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, uiKeyIndex);
  printf("SDF_ReleasePrivateKeyAccessRight, ret=0x%08x\n", ret);
  if (SDR_OK != ret) {
    printf("SDF_ReleasePrivateKeyAccessRight failed\n");
    goto EXIT;
  }

EXIT:
  return ret;
}

int WriteClientCert(void *hSessionHandle) {
  int ret;

  char *ssl_client_ca = NULL;
  read_content_from_file("/vagrant/cert/rsa/all/client.crt", &ssl_client_ca);

  ret = SDF_CreateFile(hSessionHandle, "client.crt", strlen("client.crt"),
                       strlen(ssl_client_ca));
  printf("SDF_CreateFile ret=0x%08x\n", ret);
  if (SDR_OK != ret) {
    printf("SDF_CreateFile\n");
    goto EXIT;
  }

  ret = SDF_WriteFile(hSessionHandle, "client.crt", strlen("client.crt"), 0,
                      strlen(ssl_client_ca), ssl_client_ca);
  printf("SDF_WriteFile ret=0x%08x\n", ret);
  if (SDR_OK != ret) {
    printf("SDF_WriteFile\n");
    goto EXIT;
  }

  int readLen = strlen(ssl_client_ca); // 3868
  char ssl_client_key1[1518] = {0};
  ret = SDF_ReadFile(hSessionHandle, "client.crt", strlen("client.crt"), 0,
                     &readLen, ssl_client_key1);

  if (memcmp(ssl_client_ca, ssl_client_key1, readLen)) {
    printf("Internal Enc Internal Dec failed\n");
    goto EXIT;
  } else {
    printf("Internal Enc Internal Dec ok\n");
  }

EXIT:
  return ret;
}

int WriteCaCert(void *hSessionHandle) {
  int ret;

  char *ssl_client_ca = NULL;
  read_content_from_file("/vagrant/cert/rsa/all/ca.crt", &ssl_client_ca);

  ret = SDF_CreateFile(hSessionHandle, "ca.crt", strlen("ca.crt"),
                       strlen(ssl_client_ca));
  printf("SDF_CreateFile ret=0x%08x\n", ret);
  if (SDR_OK != ret) {
    printf("SDF_CreateFile\n");
    goto EXIT;
  }

  ret = SDF_WriteFile(hSessionHandle, "ca.crt", strlen("ca.crt"), 0,
                      strlen(ssl_client_ca), ssl_client_ca);
  printf("SDF_WriteFile ret=0x%08x\n", ret);
  if (SDR_OK != ret) {
    printf("SDF_WriteFile\n");
    goto EXIT;
  }

  int readLen = strlen(ssl_client_ca); // 3868
  char ssl_client_key1[3868] = {0};
  ret = SDF_ReadFile(hSessionHandle, "ca.crt", strlen("ca.crt"), 0, &readLen,
                     ssl_client_key1);

  if (memcmp(ssl_client_ca, ssl_client_key1, readLen)) {
    printf("Internal Enc Internal Dec failed\n");
    goto EXIT;
  } else {
    printf("Internal Enc Internal Dec ok\n");
  }

EXIT:
  return ret;
}

int WriteCert() {
  void *hDeviceHandle = NULL;
  DEVICEINFO devInfo;
  void *hSessionHandle = NULL;
  int ret = -1;
  int len = 0;
  char softVersion[128] = {0};

  ret = SDF_GetSoftVersion(softVersion, &len);
  if (SDR_OK != ret) {
    printf("SoftVersion=%s\n", softVersion);
    return -1;
  }

  ret = SDF_OpenDevice((void **)&hDeviceHandle);
  if (SDR_OK != ret || hDeviceHandle == NULL) {
    printf("SDF_OpenDevice error=%d\n", ret);
    return -1;
  }

  ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
  if (SDR_OK != ret || hDeviceHandle == NULL) {
    printf("SDF_OpenSession error=%d\n", ret);
    return -1;
  }

  memset(&devInfo, 0, sizeof(DEVICEINFO));
  memcpy(devInfo.DeviceSerial, "2024040900100001", strlen("2024040900100001"));

  ret = SDF_GetDeviceInfo(hSessionHandle, &devInfo);
  if (SDR_OK != ret) {
    printf("SDF_GetDeviceInfo error=%d\n", ret);
    return -1;
  }

  ret = WriteCaCert(hSessionHandle);

  if (SDR_OK != ret) {
    printf("WriteCaCert error=%d\n", ret);
    return -1;
  }

  ret = ImportClientKey(hSessionHandle);
  if (SDR_OK != ret) {
    printf("ImportClientKey error=%d\n", ret);
    return -1;
  }

  ret = WriteClientCert(hSessionHandle);

  if (SDR_OK != ret) {
    printf("WriteClientCert error=%d\n", ret);
    return -1;
  }

  ret = SDF_CloseSession(hSessionHandle);
  if (SDR_OK != ret) {
    printf("SDF_CloseSession error=%d\n", ret);
    return -1;
  }

  ret = SDF_CloseDevice(hDeviceHandle);
  if (SDR_OK != ret) {
    printf("SDF_CloseDevice ok=%d\n", ret);
  }

  return 0;
}

int main(int argc, char *argv[]) {
  int ret = SDF_Init();
  printf("SDF_Init, ret=0x%08x\n", ret);
  if (SDR_OK != ret) {
    return -1;
  }

  WriteCert();
  return 0;
}