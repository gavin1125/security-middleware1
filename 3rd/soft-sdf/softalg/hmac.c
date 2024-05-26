// hmac.c

#include "hmac.h"

void hmac_init(hmac_context *hmac, const hash_param* param, const unsigned char *key, int length)
{
    int i;

    hmac->param = param;

    /* Prepare the inner hash key block, hashing the key if it's too long. */
    if (length <= hmac->param->bklen)
    {
        for (i = 0; i < length; ++i)
        {
            hmac->key[i] = key[i] ^ 0x36;
        }
        for (; i < hmac->param->bklen; ++i)
        {
            hmac->key[i] = 0x36;
        }
    }
    else
    {
        param->init(hmac->ctx);
        param->update(hmac->ctx, key, length);
        param->final(hmac->key, &hmac->ctx);

        for (i = 0; i < hmac->param->mdlen; ++i)
        {
            hmac->key[i] ^= 0x36;
        }
        for (; i < hmac->param->bklen; ++i)
        {
            hmac->key[i] = 0x36;
        }
    }

    /* Initialize the inner hash with the key block. */
    param->init(&hmac->ctx);
    param->update(&hmac->ctx, hmac->key, hmac->param->bklen);
}

void hmac_update(hmac_context *hmac, const void *data, int len)
{
    hmac->param->update(&hmac->ctx, data, len);
}

void hmac_final(void *mac, hmac_context *hmac)
{
    int i;

    /* Finalize the inner hash and store its value in the digest array. */
    hmac->param->final(hmac->digest, &hmac->ctx);

    /* Convert the inner hash key block to the outer hash key block. */
    for (i = 0; i < hmac->param->bklen; ++i)
    {
        hmac->key[i] ^= (0x36 ^ 0x5c);
    }

    /* Calculate the outer hash. */
    hmac->param->init(&hmac->ctx);
    hmac->param->update(&hmac->ctx, hmac->key, hmac->param->bklen);
    hmac->param->update(&hmac->ctx, hmac->digest, hmac->param->mdlen);
    hmac->param->final(mac, &hmac->ctx);
}
