#include "bit.h"



static uint8_t msbmask[] = {
	0xFF,0xFE,0xFC,0xF8,
	0xF0,0xE0,0xC0,0x80
};

static uint8_t lsbmask[] = {
	0x01,0x03,0x07,0x0F,
	0x1F,0x3F,0x7F,0xFF
};

//连续size位置位1
int bit_set(uint8_t * buf,uint32_t offset, uint32_t size)
{
	uint32_t i;
	uint32_t high;

	high = offset + size - 1;
	if(offset/BIT_BYTE < high/BIT_BYTE)
	{
		buf[offset/BIT_BYTE] |= msbmask[offset%BIT_BYTE];
		for(i=offset/BIT_BYTE+1; i<high/BIT_BYTE; i++)
			buf[i] = 0xFF;
		buf[high/BIT_BYTE] |= lsbmask[high%BIT_BYTE];
	}
	else
	{
		for (i=0; i<size; ++i)
			buf[offset/BIT_BYTE] |= 1<<(offset%BIT_BYTE+i);
	}
	return 0;
}

//连续size位清0
int bit_clear(uint8_t * buf,uint32_t offset, uint32_t size)
{
	uint32_t i;
	uint32_t high;

	high = offset + size - 1;
	if(offset/BIT_BYTE < high/BIT_BYTE)
	{
		buf[offset/BIT_BYTE] &= ~(msbmask[offset%BIT_BYTE]);
		for(i=offset/BIT_BYTE+1; i<high/BIT_BYTE; i++)
			buf[i] = 0x00;
		buf[high/BIT_BYTE] &= ~(lsbmask[high%BIT_BYTE]);
	}
	else
	{
		for(i=0; i<size; ++i)
			buf[offset/BIT_BYTE] &= ~(1<<(offset%BIT_BYTE+i));
	}
	return 0;
}

//连续size位取反
int bit_not(uint8_t * buf,uint32_t offset, uint32_t size)
{
	uint32_t i;
	uint32_t high;

	high = offset + size - 1;
	if(offset/BIT_BYTE < high/BIT_BYTE)
	{
		buf[offset/BIT_BYTE] ^= (msbmask[offset%BIT_BYTE]);
		for(i=offset/BIT_BYTE+1; i<high/BIT_BYTE; i++)
			buf[i] ^= 0xFF;
		buf[high/BIT_BYTE] ^= lsbmask[high%BIT_BYTE];
	}
	else
	{
		for(i=0; i<size; ++i)
			buf[offset/BIT_BYTE] ^= 1<<(offset%BIT_BYTE+i);
	}
	return 0;
}

//获取一位
unsigned bit_get(uint8_t * buf,uint32_t offset)
{
	return (buf[offset/BIT_BYTE] >> (offset%BIT_BYTE)) & 1;//buf[offset/8] ^ (1<<buf[offset%8]);
}

//设置偏移offset的位为bit
int bit_put(uint8_t * buf, uint32_t offset, unsigned bit)
{
	//chk param

	//
	if (bit == 1)
		buf[offset/BIT_BYTE] |= 1<<(offset%BIT_BYTE);
	else
		buf[offset/BIT_BYTE] &= ~(1<<(offset%BIT_BYTE));

	return offset;
}

//获取连续size位bit的偏移，成功ret返回0
uint32_t bit_find(uint8_t * buf, uint32_t buf_len, uint32_t size, unsigned bit, int * ret)
{
	unsigned ret_bit;
	uint32_t offset,num;

	num = 0;
	for (offset=0; offset<buf_len*BIT_BYTE; ++offset)
	{
		ret_bit = bit_get(buf,offset);
		if(ret_bit == bit)
		{
			num++;
			if(num == size)
			{
				offset -= (size-1);
				*ret = 0;
				break;
			}
		}
		else
			num = 0;
		
	}
	if(offset == buf_len * BIT_BYTE)
		*ret = -1;

	return offset;
}
