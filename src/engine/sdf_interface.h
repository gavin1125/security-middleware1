//
// Created by vagrant on 5/26/24.
//

#ifndef SECURITY_MIDDLEWARE_SDF_INTERFACE_H
#define SECURITY_MIDDLEWARE_SDF_INTERFACE_H

#include <openssl/ssl.h>

typedef struct {
    unsigned char *ca_file_name;
    unsigned int ca_content_len;

    unsigned char *client_cert_file_name;
    unsigned int client_cert_content_len;

    int client_key_index;
} SdfParam;

void SdfParamInit(int type);

void SdfInit();

void SdfFinish();

int LoadCaCert(unsigned char *ssl_ca_cert, unsigned int *ssl_ca_cert_size);

X509 *LoadClientCert();

int RsaEncrypt(int length, const unsigned char *from, unsigned char *to,
               RSA *rsa, int padding);

#endif //SECURITY_MIDDLEWARE_SDF_INTERFACE_H
