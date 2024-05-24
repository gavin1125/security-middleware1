#include "sdf.h"
#include "tool.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <sys/time.h>
#include <time.h>

#define SUPPORT_IMPORT_KEY 1

int ECCTest(void *hSessionHandle) {
  int ret = 0;
  unsigned char datain[3072] = {0};
  unsigned char dataout[3072] = {0};
  unsigned char verify[3072] = {0};
  unsigned char dataout2[3072] = {0};
  unsigned int inlen = 0;
  unsigned int outlen = 0;
  unsigned int verifylen = 0;

  unsigned int uiAlgID = 0;
  unsigned int keyIndex = 2;
  char *password = "soft1234";
  unsigned int pswlen = 0;
  ECCrefPublicKey PublicKey;
  ECCrefPublicKey SignPublicKey;
  ECCrefPublicKey EncPublicKey;
  ECCrefPrivateKey PrivateKey;
  ECCrefPrivateKey PrivateKey1;
  ECCrefPublicKey PublicKey1;
  unsigned int uiKeyBits = 256;
  ECCSignature signature;
  unsigned int j = 0;

  // 产生卡外密钥对
  uiAlgID = SGD_ECC_CV7_256;
  ret = SDF_GenerateKeyPair_ECC(hSessionHandle, uiAlgID, uiKeyBits, &PublicKey,
                                &PrivateKey);
  printf("SDF_GenerateKeyPair_ECC, ret=0x%08x\n", ret);
  if (SDR_OK != ret) {
    printf("SDF_GenerateKeyPair_ECC failed\n");
    goto EXIT;
  }
#if 0
    memcpy((unsigned char *)&PublicKey,
           "\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe8\x24\xd1\x3b\xc1\xf3\x29\x94\xfb\x73\xca\x0d\x63\x03\xb9\x2a\x94\x21\xe6\x69\xee\xa9\x85\xee\xf1\xa9\x3b\x87\xde\x1f\xb8\x23\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x60\x9e\x3b\x12\xf6\xef\xb7\x9b\x43\x0f\x47\x95\x7d\xfc\xec\x92\x77\x38\x80\x1b\xde\x40\x6f\x1e\xbd\xc3\x15\x8f\xa6\x9f\x1e",
           sizeof(ECCrefPublicKey));
    memcpy((unsigned char *)&PrivateKey,
           "\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x2d\xff\x55\x52\xc2\xe8\x6b\xcc\x0a\xdc\x58\x05\x2c\x5d\xf9\x75\x17\xe2\x4c\x2a\x60\xbb\x05\x7a\x0c\xd1\xd9\xd1\x60\xe2\x5c\x58",
           sizeof(ECCrefPrivateKey));
    //dumpbuffer("public", &PublicKey, sizeof(ECCrefPublicKey));
    //dumpbuffer("private", &PrivateKey, sizeof(ECCrefPrivateKey));
#endif

  BIO *bp;
  EVP_PKEY *key;
  EC_KEY *ec_key;
  const EC_GROUP *group;
  BIGNUM *x, *y;

  bp = BIO_new(BIO_s_file());

  if (!BIO_read_filename(bp, "/vagrant/cert/ecc/all/client.key")) {
    fprintf(stderr, "Failed to open private key file %s", "sf");
  }

  key = PEM_read_bio_PrivateKey(bp, 0, 0, 0);

  BN_CTX *ctx = BN_CTX_new();

  // Get curve
  ec_key = EVP_PKEY_get1_EC_KEY(key);

  EC_POINT *ec_pub_key = EC_KEY_get0_public_key(ec_key);
  EC_GROUP *ec_group = EC_KEY_get0_group(ec_key);
  x = BN_new();
  y = BN_new();

  EC_POINT_get_affine_coordinates_GFp(ec_group, ec_pub_key, x, y, NULL);

  BN_bn2binpad(x, PublicKey1.x, ECCref_MAX_LEN);
  BN_bn2binpad(y, PublicKey1.y, ECCref_MAX_LEN);

  // Get private key
  BIGNUM *ec_prv_key = EC_KEY_get0_private_key(ec_key);
  PrivateKey1.bits = 256;
  BN_bn2binpad(ec_prv_key, PrivateKey1.K, ECCref_MAX_LEN);

  dumpbuffer("public", (unsigned char *)&PublicKey, sizeof(ECCrefPublicKey));
  dumpbuffer("private", (unsigned char *)&PrivateKey, sizeof(ECCrefPrivateKey));

#ifdef SUPPORT_IMPORT_KEY
  // 导入签名公钥
  ret = SDF_ImportSignPublicKey_ECC(hSessionHandle, keyIndex, &PublicKey1);
  printf("SDF_ImportSignPublicKey_ECC, ret=0x%08x\n", ret);
  if (SDR_OK != ret) {
    printf("SDF_ImportSignPublicKey_ECC failed\n");
    goto EXIT;
  }

  // 导入签名私钥
  ret = SDF_ImportSignPrivateKey_ECC(hSessionHandle, keyIndex, &PrivateKey1);
  printf("SDF_ImportSignPrivateKey_ECC, ret=0x%08x\n", ret);
  if (SDR_OK != ret) {
    printf("SDF_ImportSignPrivateKey_ECC failed\n");
    goto EXIT;
  }

  // 导入加密公钥
  ret = SDF_ImportEncPublicKey_ECC(hSessionHandle, keyIndex, &PublicKey1);
  printf("SDF_ImportEncPublicKey_ECC, ret=0x%08x\n", ret);
  if (SDR_OK != ret) {
    printf("SDF_ImportEncPublicKey_ECC failed\n");
    goto EXIT;
  }

  // 导入加密私钥
  ret = SDF_ImportEncPrivateKey_ECC(hSessionHandle, keyIndex, &PrivateKey1);
  printf("SDF_ImportEncPrivateKey_ECC, ret=0x%08x\n", ret);
  if (SDR_OK != ret) {
    printf("SDF_ImportEncPrivateKey_ECC failed\n");
    goto EXIT;
  }
#endif


  // 外部公钥加密
  inlen = 2048;
  uiAlgID = SGD_ECC_CV7_256;

  ret = SDF_GenerateRandom(hSessionHandle, inlen, datain);
  printf("SDF_GenerateRandom,ret=0x%08x\n", ret);
  if (SDR_OK != ret) {
    goto EXIT;
  }

  ret = SDF_ExternalEncrypt_ECC(hSessionHandle, uiAlgID, &PublicKey1, datain,
                                inlen, (ECCCipher *)dataout);
  printf("SDF_ExternalEncrypt_ECC, ret=0x%08x\n", ret);
  if (SDR_OK != ret) {
    printf("SDF_ExternalEncrypt_ECC failed\n");
    goto EXIT;
  }

  memset(verify, 0, 3072);
  ret = SDF_ExternalDecrypt_ECC(hSessionHandle, uiAlgID, &PrivateKey1,
                                (ECCCipher *)dataout, verify, &verifylen);
  printf("SDF_ExternalDecrypt_ECC, ret=0x%08x\n", ret);
  if (SDR_OK != ret) {
    printf("SDF_ExternalDecrypt_ECC failed\n");
    goto EXIT;
  }

  if (memcmp(datain, verify, inlen)) {
    printf("SDF_ExternalDecrypt_ECC verify failed\n");
    goto EXIT;
  }

  ret = SDF_InternalDecrypt_ECC(hSessionHandle, uiAlgID, keyIndex,
                                (ECCCipher *)dataout, verify, &verifylen);
  printf("SDF_InternalDecrypt_ECC default Enc, ret=0x%08x\n", ret);
  if (SDR_OK != ret) {
    printf("SDF_InternalDecrypt_ECC default Enc failed\n");
    goto EXIT;
  }

  if (memcmp(datain, verify, inlen)) {
    printf("SDF_InternalDecrypt_ECC default Enc verify failed\n");
    goto EXIT;
  }

  // 信封转换测试
  inlen = 16;
  ret = SDF_ExternalEncrypt_ECC(hSessionHandle, uiAlgID, &PublicKey1, datain,
                                inlen, (ECCCipher *)dataout);
  printf("SDF_ExternalEncrypt_ECC, ret=0x%08x\n", ret);
  if (SDR_OK != ret) {
    printf("SDF_ExternalEncrypt_ECC failed\n");
    goto EXIT;
  }

  memset(verify, 0, 32);
  ret = SDF_ExternalDecrypt_ECC(hSessionHandle, uiAlgID, &PrivateKey1,
                                (ECCCipher *)dataout, verify, &verifylen);
  printf("SDF_ExternalDecrypt_ECC, ret=0x%08x\n", ret);
  if (SDR_OK != ret) {
    printf("SDF_ExternalDecrypt_ECC failed\n");
    goto EXIT;
  }

  if (memcmp(datain, verify, inlen)) {
    printf("SDF_ExternalDecrypt_ECC verify failed\n");
    goto EXIT;
  }

  uiAlgID = SGD_ECC_CV7_256;
  inlen = 32;
  for (j = 0; j < 32; j++) {
    datain[j] = j + 1;
  }

  ret = SDF_InternalSign_ECC(hSessionHandle, keyIndex, uiAlgID, datain, inlen,
                             &signature);
  printf("SDF_InternalSign_ECC, ret=0x%08x\n", ret);

  if (SDR_OK != ret) {
    printf("SDF_InternalSign_ECC failed\n");
    goto EXIT;
  }

  ret = SDF_InternalVerify_ECC(hSessionHandle, keyIndex, uiAlgID, datain, inlen,
                               &signature);
  printf("SDF_InternalVerify_ECC, ret=0x%08x\n", ret);
  if (SDR_OK != ret) {
    printf("SDF_InternalVerify_ECC failed\n");
    goto EXIT;
  }

  // 外部公私钥验签
  ret = SDF_ExternalVerify_ECC(hSessionHandle, uiAlgID, &PublicKey1, datain,
                               inlen, &signature);
  printf("SDF_ExternalVerify_ECC, ret=0x%08x\n", ret);
  if (SDR_OK != ret) {
    printf("SDF_ExternalVerify_ECC failed\n");
    goto EXIT;
  }

  ret = SDF_ExternalSign_ECC_EX(hSessionHandle, uiAlgID, &PrivateKey1, datain,
                                inlen, &signature);
  printf("SDF_ExternalSign_ECC_EX, ret=0x%08x\n", ret);
  if (SDR_OK != ret) {
    printf("SDF_ExternalSign_ECC_EX failed\n");
    goto EXIT;
  }

  ret = SDF_InternalVerify_ECC(hSessionHandle, keyIndex, uiAlgID, datain, inlen,
                               &signature);
  printf("SDF_InternalVerify_ECC, ret=0x%08x\n", ret);
  if (SDR_OK != ret) {
    printf("SDF_InternalVerify_ECC failed\n");
    goto EXIT;
  }

  ret = SDF_ExternalVerify_ECC(hSessionHandle, uiAlgID, &PublicKey1, datain,
                               inlen, &signature);
  printf("SDF_ExternalVerify_ECC, ret=0x%08x\n", ret);
  if (SDR_OK != ret) {
    printf("SDF_ExternalVerify_ECC failed\n");
    goto EXIT;
  }


EXIT:
  return ret;
}

int sdf_funtest() {
  void *hDeviceHandle = NULL;
  DEVICEINFO devInfo;
  void *hSessionHandle = NULL;
  int ret = -1;
  int len = 0;
  char outBuf[2048];
  char softVersion[128] = {0};
  ret = SDF_Init();
  printf("SDF_Init, ret=0x%08x\n", ret);
  ret = SDF_GetSoftVersion(softVersion, &len);
  printf("SoftVersion=%s\n", softVersion);

  ret = SDF_OpenDevice((void **)&hDeviceHandle);
  printf("SDF_OpenDevice, ret=0x%08x\n", ret);
  if (SDR_OK != ret || hDeviceHandle == NULL) {
    printf("SDF_OpenDevice error=%d\n", ret);
    return -1;
  }

  ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
  printf("SDF_OpenSession, hDeviceHandle=%p, ret=0x%08x\n", hSessionHandle,
         ret);
  if (SDR_OK != ret || hDeviceHandle == NULL) {
    printf("SDF_OpenSession error=%d\n", ret);
    return -1;
  }

  memset(&devInfo, 0, sizeof(DEVICEINFO));
  memcpy(devInfo.DeviceSerial, "2024040900100001", strlen("2024040900100001"));

  ret = SDF_GetDeviceInfo(hSessionHandle, &devInfo);
  printf("SDF_GetDeviceInfo,ret=0x%08x\n", ret);
  if (SDR_OK != ret) {
    printf("SDF_GetDeviceInfo error=%d\n", ret);
    return -1;
  }
  dumpdata((unsigned char *)&devInfo, 128);

  ret = ECCTest(hSessionHandle);
  if (SDR_OK != ret) {
    printf("SM2Test error=%d\n", ret);
    return -1;
  }

  printf("----------------SDF_CloseSession test-----------------\n");
  ret = SDF_CloseSession(hSessionHandle);
  if (SDR_OK != ret) {
    printf("SDF_CloseSession error=%d\n", ret);
    return -1;
  }
  ret = SDF_CloseSession(hSessionHandle);
  if (SDR_OK == ret) {
    printf("SDF_CloseSession error=%d\n", ret);
    return -1;
  }
  printf("----------------SDF_CloseDevice test-----------------\n");
  ret = SDF_CloseDevice(hDeviceHandle);
  if (SDR_OK != ret) {
    printf("SDF_CloseDevice ok=%d\n", ret);
  }
  ret = SDF_CloseDevice(hDeviceHandle);
  if (SDR_OK != ret) {
    printf("SDF_CloseDevice ok=%d\n", ret);
    return 0;
  }
  return 0;
}

int main() { sdf_funtest(); }
