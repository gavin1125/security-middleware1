#include "public/sdf.h"
#include <stdio.h>
#include <string.h>
#include "sdf_interface.h"
#include <openssl/ssl.h>
#include <unistd.h>
#include "file.h"

#define UNUSED(x) (void)(x)
#define SECURITY_ENGINE_TYPE_GHY_RSA 0
#define SECURITY_ENGINE_TYPE_GCY_RSA 1
#define SECURITY_ENGINE_TYPE_GHY_ECC 2

static SdfParam ghy_rsa_sdf_param = {
        (unsigned char *) "ca.crt",
        3868,
        (unsigned char *) "client.crt",
        1518,
        6};
static SdfParam gcy_rsa_sdf_param = {
        (unsigned char *) "ca_gcy.crt",
        13538,
        (unsigned char *) "client_gcy.crt",
        5018,
        8};

static SdfParam ghy_ecc_sdf_param = {
        (unsigned char *) "ca_ecc.crt",
        13538,
        (unsigned char *) "client_ecc.crt",
        5018,
        10};

static SdfParam *sdf_param;

static void *phDeviceHandle = NULL;
static void *phSessionHandle = NULL;

void SdfParamInit(int type) {
    if (type == SECURITY_ENGINE_TYPE_GHY_RSA) {
        sdf_param = &ghy_rsa_sdf_param;
    } else if (type == SECURITY_ENGINE_TYPE_GCY_RSA) {
        sdf_param = &gcy_rsa_sdf_param;
    } else {
        sdf_param = &ghy_ecc_sdf_param;
    }
}

void SdfInit() {
    if (SDF_OpenDevice(&phDeviceHandle) != 0) {
        printf("SDF_OpenDevice error\n");
    }
    if (SDF_OpenSession(phDeviceHandle, &phSessionHandle) != 0) {
        printf("SDF_OpenSession error\n");
    }

    char *ca_path = "/tmp/ca.crt";
    if (access(ca_path, F_OK) == 0) {
        if (remove(ca_path) != 0) {
            printf("remove %s error\n", ca_path);
        }

    }
    unsigned char ssl_ca_cert[13538] = {0};
    unsigned int ssl_ca_cert_size = 0;
    if (LoadCaCert(ssl_ca_cert, &ssl_ca_cert_size) != 1) {
        return;
    }

    write_content_to_file(ca_path, ssl_ca_cert);
}

void SdfFinish() {
    if (phSessionHandle != NULL) {
        if (SDF_CloseSession(phSessionHandle) != 0) {
        }
    }

    if (phDeviceHandle != NULL) {
        if (SDF_CloseDevice(phDeviceHandle) != 0) {
        }
    }

    char *ca_path = "/tmp/ca.crt";
    if (remove(ca_path) != 0) {
        printf("remove %s error\n", ca_path);
    }
}

int RsaEncrypt(int length, const unsigned char *from, unsigned char *to,
               RSA *rsa, int padding) {
    UNUSED(rsa);
    UNUSED(padding);
    unsigned int outLen = 0;
    int ret = SDF_InternalPrivateKeyOperation_RSA(
            phSessionHandle,
            sdf_param->client_key_index,
            (unsigned char *) from,
            length,
            to, &outLen);
    if (ret != 0) {
        printf("rsa encrypt error");
    }

    return (int) outLen;
}

int LoadCaCert(unsigned char *ssl_ca_cert, unsigned int *ssl_ca_cert_size) {

    *ssl_ca_cert_size = sdf_param->ca_content_len;
    if (SDF_ReadFile(phSessionHandle,
                     sdf_param->ca_file_name,
                     strlen((char *) sdf_param->ca_file_name),
                     0,
                     ssl_ca_cert_size,
                     ssl_ca_cert) != 0) {
        printf("SDF_ReadFile ca.crt error\n");
        return 0;
    }

    return 1;
}

X509 *LoadClientCert() {
    unsigned char *ssl_client_cert[1518] = {0};
    unsigned int readLen = sdf_param->client_cert_content_len;
    if (SDF_ReadFile(phSessionHandle,
                     sdf_param->client_cert_file_name,
                     strlen((char *) sdf_param->client_cert_file_name),
                     0,
                     &readLen,
                     (unsigned char *) ssl_client_cert) != 0) {
        printf("SDF_ReadFile client.crt error\n");
        return NULL;
    }

    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, (const char *) ssl_client_cert);
    X509 *cert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
    printf("load cert success\n");
    return cert;
}