// hmac_sha2.h

#ifndef __HMAC_SHA2_H_INC__
#define __HMAC_SHA2_H_INC__

#include "hmac.h"
#include "sha2.h"

#ifdef __cplusplus
extern "C" {
#endif

const hash_param* sha224_param();
const hash_param* sha256_param();
const hash_param* sha384_param();
const hash_param* sha512_param();

#ifdef __cplusplus
}
#endif

#endif