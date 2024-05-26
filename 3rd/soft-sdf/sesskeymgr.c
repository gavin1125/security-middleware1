#include "common.h"
#include "sesskeymgr.h"

#define MAX_SESSIONKEY_NUM  52025
#define MAX_KEY_LEN         32
#define MAX_BITMAP_SIZE     (MAX_SESSIONKEY_NUM+7)/8

///会话密钥存储结构
typedef struct SESSIONKEY_st
{
    unsigned int keylen;
    unsigned char keybuf[MAX_KEY_LEN];
} SESSIONKEY;

//暂存会话密钥的内存
SESSIONKEY gKeyBuf[MAX_SESSIONKEY_NUM] = {0};

//暂存会话密钥索引
int gKeyIndex[MAX_SESSIONKEY_NUM] = {0};

//管理内存
unsigned char gKeyBitmap[MAX_BITMAP_SIZE] = {0};

#define BIT_BYTE 8 ///<每BYTE含bit数

unsigned char msbmask[] =
{
    0xFF, 0xFE, 0xFC, 0xF8,
    0xF0, 0xE0, 0xC0, 0x80
};

unsigned char lsbmask[] =
{
    0x01, 0x03, 0x07, 0x0F,
    0x1F, 0x3F, 0x7F, 0xFF
};

//连续size位置位1
static int bit_set(unsigned char * buf, unsigned int offset, unsigned int size)
{
    unsigned int i;
    unsigned int high;

    high = offset + size - 1;
    if (offset / BIT_BYTE < high / BIT_BYTE)
    {
        buf[offset / BIT_BYTE] |= msbmask[offset % BIT_BYTE];
        for (i = offset / BIT_BYTE + 1; i < high / BIT_BYTE; i++)
        {
            buf[i] = 0xFF;
        }
        buf[high / BIT_BYTE] |= lsbmask[high % BIT_BYTE];
    }
    else
    {
        for (i = 0; i < size; ++i)
        {
            buf[offset / BIT_BYTE] |= 1 << (offset % BIT_BYTE + i);
        }
    }
    return 0;
}

//连续size位清0
static int bit_clear(unsigned char * buf, unsigned int offset, unsigned int size)
{
    unsigned int i;
    unsigned int high;

    high = offset + size - 1;
    if (offset / BIT_BYTE < high / BIT_BYTE)
    {
        buf[offset / BIT_BYTE] &= ~(msbmask[offset % BIT_BYTE]);
        for (i = offset / BIT_BYTE + 1; i < high / BIT_BYTE; i++)
        {
            buf[i] = 0x00;
        }
        buf[high / BIT_BYTE] &= ~(lsbmask[high % BIT_BYTE]);
    }
    else
    {
        for (i = 0; i < size; ++i)
        {
            buf[offset / BIT_BYTE] &= ~(1 << (offset % BIT_BYTE + i));
        }
    }
    return 0;
}

//连续size位取反
static int bit_not(unsigned char * buf, unsigned int offset, unsigned int size)
{
    unsigned int i;
    unsigned int high;

    high = offset + size - 1;
    if (offset / BIT_BYTE < high / BIT_BYTE)
    {
        buf[offset / BIT_BYTE] ^= (msbmask[offset % BIT_BYTE]);
        for (i = offset / BIT_BYTE + 1; i < high / BIT_BYTE; i++)
        {
            buf[i] ^= 0xFF;
        }
        buf[high / BIT_BYTE] ^= lsbmask[high % BIT_BYTE];
    }
    else
    {
        for (i = 0; i < size; ++i)
        {
            buf[offset / BIT_BYTE] ^= 1 << (offset % BIT_BYTE + i);
        }
    }
    return 0;
}

//获取一位
static unsigned bit_get(unsigned char * buf, unsigned int offset)
{
    return (buf[offset / BIT_BYTE] >> (offset % BIT_BYTE)) & 1; //buf[offset/8] ^ (1<<buf[offset%8]);
}

//设置偏移offset的位为bit
static int bit_put(unsigned char * buf, unsigned int offset, unsigned bit)
{
    //chk param

    //
    if (bit == 1)
    {
        buf[offset / BIT_BYTE] |= 1 << (offset % BIT_BYTE);
    }
    else
    {
        buf[offset / BIT_BYTE] &= ~(1 << (offset % BIT_BYTE));
    }

    return offset;
}

//获取连续size位bit的偏移，成功ret返回0
static unsigned int bit_find(unsigned char * buf, unsigned int buf_len, unsigned int size, unsigned bit, int * ret)
{
    unsigned ret_bit;
    unsigned int offset, num;

    num = 0;
    for (offset = 0; offset < buf_len * BIT_BYTE; ++offset)
    {
        ret_bit = bit_get(buf, offset);
        if (ret_bit == bit)
        {
            num++;
            if (num == size)
            {
                offset -= (size - 1);
                *ret = 0;
                break;
            }
        }
        else
        {
            num = 0;
        }

    }
    if (offset == buf_len * BIT_BYTE)
    {
        *ret = -1;
    }

    return offset;
}

int ImportSessKey(void* hHandle, unsigned char * key, unsigned int keyLen, void **phKeyHandle)
{
    int ret = 0;
    int idle = -1;

    //0.参数检查
    if (keyLen > MAX_KEY_LEN)
    {
        LOG_Write(NULL, "%s:%d bit_find failed", __FUNCTION__, __LINE__);
        ret = SDR_INARGERR;
        return ret;
    }

  //  ret = DoLock(hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s[%d] error, ret[0x%08x]", __FUNCTION__, __LINE__);
        return ret;
    }

    //1.查找空闲块
    idle = bit_find(gKeyBitmap, MAX_BITMAP_SIZE, 1, 0, &ret);
    if (ret)
    {
        LOG_Write(NULL, "%s:%d bit_find failed", __FUNCTION__, __LINE__);
        ret = SDR_NOBUFFER;
        goto exit;
    }

    //2.标记占用
    bit_set(gKeyBitmap, idle, 1);
    //3.保存密钥
    gKeyBuf[idle].keylen = keyLen;
    memcpy(gKeyBuf[idle].keybuf, key, keyLen);
    gKeyIndex[idle] = idle;
    *phKeyHandle = &gKeyIndex[idle];
    ret = 0;
exit:
  //  DoUnLock(hHandle);
    return ret;
}

int ExportSessKey(void* hHandle, unsigned int index, unsigned char * key, unsigned int * keyLen)
{
    int bit = 0, ret = 0;

    //0.参数检查
    if (!key)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s[%d] error, ret[0x%08x]", __FUNCTION__, __LINE__, ret);
        return ret;
    }
    if (index > (MAX_SESSIONKEY_NUM - 1))
    {
        LOG_Write(NULL, "%s[%d] error, index[%d]", __FUNCTION__, __LINE__, index);
        return SDR_KEYNOEXIST;
    }

    //1.判断是否存在
    bit = bit_get(gKeyBitmap, index);
    if (0 == bit)
    {
        LOG_Write(NULL, "%s:%d bit_get = %d", __FUNCTION__, __LINE__, bit);
        ret = SDR_KEYNOEXIST;
        goto exit;
    }

    //2.读取密钥
    *keyLen = gKeyBuf[index].keylen;
    memcpy(key, gKeyBuf[index].keybuf, *keyLen);

exit:
    return ret;
}

int DestroySessKey(void* hHandle, unsigned int index)
{
    int bit = 0, ret = 0;
    if (index > (MAX_SESSIONKEY_NUM - 1))
    {
        LOG_Write(NULL, "%s[%d] error, index[%d]", __FUNCTION__, __LINE__, index);

        return SDR_KEYNOEXIST;
    }
    //ret = DoLock(hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s[%d] error, ret[0x%08x]", __FUNCTION__, __LINE__);
        return ret;
    }

    //1.判断是否存在
    bit = bit_get(gKeyBitmap, index);
    if (0 == bit)
    {
        LOG_Write(NULL, "%s:%d bit_get = %d", __FUNCTION__, __LINE__, ret);
        ret = SDR_KEYNOEXIST;
        goto exit;
    }
    //2.销毁密钥标记
    bit_clear(gKeyBitmap, index, 1);

    //3.销毁密钥数据
    memset(&gKeyBuf[index], 0x00, sizeof(SESSIONKEY));
    gKeyIndex[index] = -1;
exit:
   // DoUnLock(hHandle);
    return ret;
}
