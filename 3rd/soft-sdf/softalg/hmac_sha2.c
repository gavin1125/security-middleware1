// hmac_sha2.c

#include "hmac_sha2.h"

const hash_param hmac_sha224_param = {28, 64, (sha_init)sha224_init, (sha_update)sha224_update, (sha_final)sha224_final};
const hash_param hmac_sha256_param = {32, 64, (sha_init)sha256_init, (sha_update)sha256_update,  (sha_final)sha256_final};
const hash_param hmac_sha384_param = {48, 128, (sha_init)sha384_init, (sha_update)sha384_update,  (sha_final)sha384_final};
const hash_param hmac_sha512_param = {64, 128, (sha_init)sha512_init, (sha_update)sha512_update,  (sha_final)sha512_final};

const hash_param* sha224_param()
{
    return &hmac_sha224_param;
}
const hash_param* sha256_param()
{
    return &hmac_sha256_param;
}
const hash_param* sha384_param()
{
    return &hmac_sha384_param;
}
const hash_param* sha512_param()
{
    return &hmac_sha512_param;
}
