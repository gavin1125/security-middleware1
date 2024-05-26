#include "common.h"
#include "rsa.h"
#include "softalg.h"
#include "sm2_alg.h"
#include "sesskeymgr.h"
#include "sm3_alg.h"
#include "sha1.h"

int SDF_Init()
{
	int ret;
	ret = SOFT_Init();
	return ret;
}

int SDF_OpenDevice( void **phDeviceHandle )
{
	int ret;
	int devNum = 0;

	LOG_Write(NULL,"Call %s:%d",__FUNCTION__,__LINE__);

	
	ret = SOFT_OpenDev(phDeviceHandle);
	if(ret)
	{
		LOG_Write(NULL,"Call %s:%d SOFT_OpenDev ret = %d",__FUNCTION__,__LINE__,ret);
		return SDR_OPENDEVICE;
	}
	printf("hfile=%d\n",((SOFT_DEVICE *)*phDeviceHandle)->hFile);
	printf("szFilePath=%s \n",((SOFT_DEVICE *)*phDeviceHandle)->szFilePath);

	return SDR_OK;	
}



int GetDeviceHandle(void* hSessionHandle, void **hHandle)
{
    if (hSessionHandle == NULL)
    {
        return SDR_INARGERR;
    }

    if (!((SDF_SESSIONDEV*)hSessionHandle)->valid)
    {
        //printf("(SDF_SESSIONDEV*)hSessionHandle)->valid=%d\n",((SDF_SESSIONDEV*)hSessionHandle)->valid);
        return SDR_INARGERR;
    }

    *hHandle = ((SDF_SESSIONDEV*)hSessionHandle)->hDeviceHandle;
    return SDR_OK;
}


int SDF_OpenSession( void *hDeviceHandle, void **phSessionHandle )
{
	int ret;
	SDF_SESSIONDEV *devSession = NULL;

	LOG_Write(NULL,"Call %s:%d",__FUNCTION__,__LINE__);
	devSession = (SDF_SESSIONDEV *)malloc(sizeof(SDF_SESSIONDEV));
	if (NULL == devSession)
	{
		return SDR_UNKNOWERR;
	}
	devSession->hDeviceHandle = hDeviceHandle;
	devSession->hHashHandle = 0;
	devSession->hashAlgID = 0;
	devSession->valid = 1;
	*phSessionHandle = devSession;
	return SDR_OK;	
}

int SDF_CloseSession(void *hSessionHandle)
{
    int ret = SDR_OK;
    void* hHandle = NULL;

    //1.获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //2.释放session句柄
    ((SDF_SESSIONDEV*)hSessionHandle)->valid = 0;
    ((SDF_SESSIONDEV*)hSessionHandle)->hHashHandle = NULL;
    ((SDF_SESSIONDEV*)hSessionHandle)->hashAlgID = 0;
    ((SDF_SESSIONDEV*)hSessionHandle)->hDeviceHandle = NULL;
    sync();//如果没有，调用两次关闭，会崩溃

    if (NULL != hSessionHandle)
    {
        free(hSessionHandle);
        hSessionHandle = NULL;      
    }
  
    return SDR_OK;
}


int SDF_CloseDevice( void *hDeviceHandle )
{
    if (hDeviceHandle == NULL)
    {
        return SDR_INARGERR;
    }
	SOFT_CloseDev(hDeviceHandle);
	return SDR_OK;	
}



int SDF_GetDeviceInfo(void *hSessionHandle, DEVICEINFO *pstDeviceInfo)
{
    int ret = SDR_OK;
    void* hHandle = NULL;
    SOFT_DEVINFO devInfo = {0};
    //1.获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //2、调用实现获取设备信息

    ret = SOFT_GetDevInfo(hHandle,&devInfo);
    if(ret)
    {
        LOG_Write(NULL,"Call %s:%d SOFT_GetDevInfo ret = %d",__FUNCTION__,__LINE__,ret);
        return SDR_COMMFAIL;
    }
    memcpy(pstDeviceInfo->IssuerName, "BYD SOFT", sizeof("BYD SOFT"));
    pstDeviceInfo->DeviceVersion = 0x00000200;//2.0
    pstDeviceInfo->StandardVersion = 0x00000200;//2.0
    pstDeviceInfo->SymAlgAbility =  SGD_SM4_ECB | SGD_SM4_CBC | SGD_SM4_MAC;
    pstDeviceInfo->HashAlgAbility = SGD_SM3;
    pstDeviceInfo->BufferSize =  128 * 1024; //16K
    pstDeviceInfo->AsymAlgAbility[0] = SGD_RSA | SGD_SM2_1 | SGD_SM2_2 | SGD_SM2_3;
    pstDeviceInfo->AsymAlgAbility[1] = 2048 | 1024 | 256;

    memcpy(pstDeviceInfo->DeviceSerial,devInfo.cardid+16,16); 

    memcpy(pstDeviceInfo->DeviceName, "BYD HU", 16);



    return ret;
}



int SDF_GenerateRandom(void *hSessionHandle, unsigned int uiLength, unsigned char *pucRandom)
{
    int ret = SDR_OK;
    void* hHandle = NULL;

    //1、参数检查
    if (!pucRandom)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d pucRandom is NULL", __FUNCTION__, __LINE__);
        return ret;
    }

    if (0 == uiLength)
    {
        LOG_Write(NULL, "%s:%d uiLength is 0", __FUNCTION__, __LINE__);
        return ret;
    }

    //1、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }


    //random
    SOFT_GenRandom(uiLength,pucRandom);
    return ret;
}

int SDF_GetSoftVersion(unsigned char *version, int *verLen)
{
    strcpy(version, SDF_VERSION);
    *verLen = (int)strlen(SDF_VERSION);
    return SDR_OK;
}



int SDF_GetPrivateKeyAccessRight(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucPassword, unsigned int uiPwdLength)
{
    int ret = SDR_OK;
//todo
    return ret;
}
int SDF_ReleasePrivateKeyAccessRight(void *hSessionHandle, unsigned int uiKeyIndex)
{
    int ret = SDR_OK;
//todo
    return ret;
}

//KM

#define H2NL(t) ((t<<24)|(t<<8&0xFF0000)|(t>>8&0xFF00)|(t>>24&0xFF))

/*将SDF格式的RSA公钥格式 转换为 SOFT自己定义的RSA公钥格式*/
static int S2X_rsapub(SOFT_RSA_PUB_KEY* soft_pub,RSArefPublicKey *sdf_pub)
{
	int len = sdf_pub->bits/8;
	int i=0;
	
	memset(soft_pub,0,sizeof(SOFT_RSA_PUB_KEY));

	for(i =0;i<len-4;i++)
	{
		if(sdf_pub->e[i]) // the Exponent should not be more than 4bytes len
			return SDR_UNKNOWERR;
	}
	soft_pub->bits = sdf_pub->bits;

	memcpy(&soft_pub->e,sdf_pub->e+RSAref_MAX_LEN-4,4);//sdf_pub is net long
	soft_pub->e = H2NL(soft_pub->e);//host 

	memcpy(soft_pub->m,sdf_pub->m+RSAref_MAX_LEN-len,len);
	return 0;
}
/*将SOFT格式的RSA公钥格式 转换为 SDF 的RSA公钥格式*/
static int X2S_rsapub(RSArefPublicKey *sdf_pub,SOFT_RSA_PUB_KEY* soft_pub)
{
	int len = soft_pub->bits/8;

	unsigned int e;
	memset(sdf_pub,0,sizeof(RSArefPublicKey));

	sdf_pub->bits = soft_pub->bits;

	e = soft_pub->e;
	e = H2NL(e);
	memcpy(sdf_pub->e+RSAref_MAX_LEN-4,(unsigned char*)&e,4);

	memcpy(sdf_pub->m+RSAref_MAX_LEN-len,soft_pub->m,len);
	return 0;
}
static int S2X_rsapri(SOFT_RSA_PRI_KEY* soft_pri,RSArefPrivateKey* sdf_pri)
{	
	int len = sdf_pri->bits/8;
	int i=0;
	
	memset(soft_pri,0,sizeof(SOFT_RSA_PRI_KEY));

//	for(i =0;i<len-4;i++)
//	{
//		if(sdf_pri->e[i]) // the Exponent should not be more than 4bytes len
//			return SDR_UNKNOWERR;
//	}
	soft_pri->bits = sdf_pri->bits;
	//memcpy(soft_pri->d,sdf_pri->d+RSAref_MAX_LEN-len,len);
	memcpy(soft_pri->p,sdf_pri->prime[0]+RSAref_MAX_PLEN-len/2,len/2);
	memcpy(soft_pri->q,sdf_pri->prime[1]+RSAref_MAX_PLEN-len/2,len/2);
	memcpy(soft_pri->dp,sdf_pri->pexp[0]+RSAref_MAX_PLEN-len/2,len/2);
	memcpy(soft_pri->dq,sdf_pri->pexp[1]+RSAref_MAX_PLEN-len/2,len/2);
	memcpy(soft_pri->ce,sdf_pri->coef+RSAref_MAX_PLEN-len/2,len/2);
	return 0;
}
static int X2S_rsapri(RSArefPrivateKey* sdf_pri,SOFT_RSA_PRI_KEY* soft_pri)
{	
	int len = soft_pri->bits/8;

	memset(sdf_pri,0,sizeof(RSArefPrivateKey));

	sdf_pri->bits = soft_pri->bits ;
	//memcpy(sdf_pri->d+RSAref_MAX_LEN-len,soft_pri->d,len);
	memcpy(sdf_pri->prime[0]+RSAref_MAX_PLEN-len/2,soft_pri->p,len/2);
	memcpy(sdf_pri->prime[1]+RSAref_MAX_PLEN-len/2,soft_pri->q,len/2);
	memcpy(sdf_pri->pexp[0]+RSAref_MAX_PLEN-len/2,soft_pri->dp,len/2);
	memcpy(sdf_pri->pexp[1]+RSAref_MAX_PLEN-len/2,soft_pri->dq,len/2);
	memcpy(sdf_pri->coef+RSAref_MAX_PLEN-len/2,soft_pri->ce,len/2);
	return 0;
}

static int X2S_sm2pub(ECCrefPublicKey* sdf,SOFT_SM2_KEY* soft)
{	
	int len = soft->bits/8;

	if( len != 32)
		return SDR_INARGERR;
	
	memset(sdf,0,sizeof(ECCrefPublicKey));

	sdf->bits = soft->bits ;
	memcpy(sdf->x,soft->x,len);
	memcpy(sdf->y,soft->y,len);
	return 0;
}
static int S2X_sm2pub(SOFT_SM2_KEY* soft,ECCrefPublicKey* sdf)
{	
	int len = sdf->bits/8;

	if( len != 32)
		return SDR_INARGERR;
	
	memset(soft,0,sizeof(SOFT_SM2_KEY));

	soft->bits = sdf->bits ;
	memcpy(soft->x,sdf->x,len);
	memcpy(soft->y,sdf->y,len);
	return 0;
}
static int X2S_sm2pri(ECCrefPrivateKey* sdf,SOFT_SM2_KEY* soft)
{	
	int len = soft->bits/8;

	if( len != 32)
		return SDR_INARGERR;
	
	memset(sdf,0,sizeof(ECCrefPrivateKey));

	sdf->bits = soft->bits ;

	memcpy(sdf->K,soft->d,len);
	return 0;
}
static int S2X_sm2pri(SOFT_SM2_KEY* soft,ECCrefPrivateKey* sdf)
{	
	int len = sdf->bits/8;

	if( len != 32)
		return SDR_INARGERR;
	
	memset(soft,0,sizeof(SOFT_SM2_KEY));

	soft->bits = sdf->bits;
	memcpy(soft->d,sdf->K,len);
	return 0;
}




int SDF_GenerateKeyPair_RSA(void *hSessionHandle, unsigned int uiKeyBits, RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey)
{
    int ret = SDR_OK;
    void *hHandle = NULL;

    //1、参数检查
    if (!hSessionHandle || !pucPublicKey || !pucPrivateKey)
    {
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__);
        return SDR_INARGERR;
    }

    if (1024 != uiKeyBits && 2048 != uiKeyBits)
    {
        LOG_Write(NULL, "%s:%d invalid uiKeyBits, uiKeyBits=%d", __FUNCTION__, __LINE__, uiKeyBits);
        return SDR_INARGERR;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }
    memset(pucPublicKey->e, 0, 256);
    memset(pucPrivateKey->e, 0, 256);
    //3、调用SOFT实现RSA密钥对产生（R_RSA_PUBLIC_KEY=RSArefPublicKey， R_RSA_PRIVATE_KEY=pucPrivateKey）


    ret = RSAGenerateKeys(uiKeyBits, (R_RSA_PUBLIC_KEY *)pucPublicKey, (R_RSA_PRIVATE_KEY *)pucPrivateKey);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d cos_generateKeypair_rsa ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_UNKNOWERR;
    }

    return ret;
}


int SDF_ImportSignPublicKey_RSA(void *hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey)
{
    int ret = 0;
    void *hHandle = NULL;
    unsigned int keyIndex = 0;
    unsigned char uPubID[2] = {0};
    SOFT_RSA_PUB_KEY pPublicKey;
    //1、参数检查
    if (!pucPublicKey || !hSessionHandle)
    {
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__);
        return SDR_INARGERR;
    }

    if (KEYPAIRE_INDEX_MAX < uiKeyIndex || 0 == uiKeyIndex)
    {
        LOG_Write(NULL, "%s:%d uiKeyIndex invalid, uiKeyIndex=0x%08x]", __FUNCTION__, __LINE__, uiKeyIndex);
        return SDR_INARGERR;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //4、计算签名公钥id
    keyIndex = (uiKeyIndex + 1) * 4;

    //5、调用SOFT导入签名公钥

    uPubID[1]=keyIndex;

    ret = S2X_rsapub(&pPublicKey,pucPublicKey);


    ret = SOFT_WriteRsaPubKey(hHandle, uPubID, (PSOFT_RSA_PUB_KEY )&pPublicKey);

    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_KEYERR;
    }

    return ret;
}

int SDF_ImportEncPublicKey_RSA(void *hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey)
{
    int ret = 0;
    void *hHandle = NULL;
    unsigned int keyIndex = 0;
    unsigned char uPubID[2] = {0};
    SOFT_RSA_PUB_KEY pPublicKey;
    //1、参数检查
    if (!pucPublicKey || !hSessionHandle)
    {
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__);
        return SDR_INARGERR;
    }

    if (KEYPAIRE_INDEX_MAX < uiKeyIndex || 0 == uiKeyIndex)
    {
        LOG_Write(NULL, "%s:%d uiKeyIndex invalid, uiKeyIndex=0x%08x", __FUNCTION__, __LINE__, uiKeyIndex);
        return SDR_INARGERR;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //4、计算签名公钥id
    keyIndex = (uiKeyIndex + 1) * 4 + 2;

    //5、调用SOFT导入签名公钥
    uPubID[1]=keyIndex;
    ret = S2X_rsapub(&pPublicKey,pucPublicKey);

    ret = SOFT_WriteRsaPubKey(hHandle, uPubID, (PSOFT_RSA_PUB_KEY )&pPublicKey);

    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_KEYERR;
    }

    return ret;
}

int SDF_ImportSignPrivateKey_RSA(void *hSessionHandle, unsigned int uiKeyIndex, RSArefPrivateKey *pucPrivateKey)
{
    int ret = 0;
    void *hHandle = NULL;
    unsigned int keyIndex = 0;
    unsigned char uPriID[2] = {0};
   SOFT_RSA_PRI_KEY pPrivateKey;
    //1、参数检查，规避cos私钥全0时的问题
    if (!pucPrivateKey || !hSessionHandle)
    {
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__);
        return SDR_INARGERR;
    }

    if (KEYPAIRE_INDEX_MAX < uiKeyIndex || 0 == uiKeyIndex)
    {
        LOG_Write(NULL, "%s:%d uiKeyIndex invalid, uiKeyIndex=0x%08x", __FUNCTION__, __LINE__, uiKeyIndex);
        return SDR_INARGERR;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //4、计算签名私钥id
    keyIndex = (uiKeyIndex + 1) * 4 + 1 ;

    //5、调用SOFT明文导入签名私钥
    uPriID[1]=keyIndex;

    S2X_rsapri(&pPrivateKey,pucPrivateKey);
    ret = SOFT_WriteRsaPriKey(hHandle, uPriID, (PSOFT_RSA_PRI_KEY )&pPrivateKey);

    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_KEYERR;
    }

    return ret;
}

int SDF_ImportEncPrivateKey_RSA(void *hSessionHandle, unsigned int uiKeyIndex, RSArefPrivateKey *pucPrivateKey)
{
    int ret = 0;
    void *hHandle = NULL;
    unsigned int keyIndex = 0;
    unsigned char uPriID[2] = {0};
    SOFT_RSA_PRI_KEY pPrivateKey;
    //1、参数检查，规避cos私钥全0时的问题
    if (!pucPrivateKey || !hSessionHandle)
    {
        LOG_Write(NULL, "%s:%d invalid param", __FUNCTION__, __LINE__);
        return SDR_INARGERR;
    }

    if (KEYPAIRE_INDEX_MAX < uiKeyIndex || 0 == uiKeyIndex)
    {
        LOG_Write(NULL, "%s:%d uiKeyIndex invalid, uiKeyIndex=0x%08x", __FUNCTION__, __LINE__, uiKeyIndex);
        return SDR_INARGERR;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //4、计算签名私钥id
    keyIndex = (uiKeyIndex + 1) * 4 + 2 + 1;

    //5、调用SOFT明文导入签名私钥
    uPriID[1]=keyIndex;

    S2X_rsapri(&pPrivateKey,pucPrivateKey);

    ret = SOFT_WriteRsaPriKey(hHandle, uPriID, (PSOFT_RSA_PRI_KEY )&pPrivateKey);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_KEYERR;
    }

    return ret;
}




int SDF_ExportSignPublicKey_RSA(void *hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey)
{
    int ret = SDR_OK;
    void *hHandle = NULL;
    unsigned int keyIndex = 0;
    unsigned char uPubID[2] = {0};
    SOFT_RSA_PUB_KEY pPublicKey;
    //1、参数检查
    if (!hSessionHandle || !pucPublicKey)
    {
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__);
        return SDR_INARGERR;
    }

    if (KEYPAIRE_INDEX_MAX < uiKeyIndex || 0 == uiKeyIndex)
    {
        LOG_Write(NULL, "%s:%d uiKeyIndex invalid, uiKeyIndex=0x%08x", __FUNCTION__, __LINE__, uiKeyIndex);
        return SDR_INARGERR;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //3、调用SOFT导出签名公钥
    keyIndex = (uiKeyIndex + 1) * 4;
    memset((unsigned char *)pucPublicKey, 0, sizeof(R_RSA_PUBLIC_KEY));
    uPubID[1]=keyIndex;


    ret = SOFT_ReadRsaPubKey(hHandle, uPubID, (PSOFT_RSA_PUB_KEY )&pPublicKey);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    X2S_rsapub(pucPublicKey,&pPublicKey);
    return ret;
}

int SDF_ExportEncPublicKey_RSA(void *hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey)
{
    int ret = SDR_OK;
    void *hHandle = NULL;
    unsigned int keyIndex = 0;
    unsigned char uPubID[2] = {0};
    SOFT_RSA_PUB_KEY pPublicKey;
    //1、参数检查
    if (!hSessionHandle || !pucPublicKey)
    {
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__);
        return SDR_INARGERR;
    }

    if (KEYPAIRE_INDEX_MAX < uiKeyIndex || 0 == uiKeyIndex)
    {
        LOG_Write(NULL, "%s:%d uiKeyIndex invalid, uiKeyIndex=0x%08x", __FUNCTION__, __LINE__, uiKeyIndex);
        return SDR_INARGERR;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //3、调用SOFT导出加密公钥
    keyIndex = (uiKeyIndex + 1) * 4 + 2;
    memset((unsigned char *)pucPublicKey, 0, sizeof(R_RSA_PUBLIC_KEY));
    uPubID[1]=keyIndex;
    ret = SOFT_ReadRsaPubKey(hHandle, uPubID, (PSOFT_RSA_PUB_KEY )&pPublicKey);

    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_KEYERR;
    }
    X2S_rsapub(pucPublicKey,&pPublicKey);
    return ret;
}


//RSA

int SDF_ExternalPublicKeyOperation_RSA(void *hSessionHandle, RSArefPublicKey *pucPublicKey, unsigned char *pucDataInput, unsigned int uiInputLength, unsigned char *pucDataOutput,
                                       unsigned int *puiOutputLength)
{
    int ret = SDR_OK;
    void *hHandle = NULL;

    //1、参数检查
    if (!hSessionHandle || !pucPublicKey || !pucDataInput || !pucDataOutput || !puiOutputLength)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    if (0 == uiInputLength)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d uiInputLength = 0", __FUNCTION__, __LINE__);
        return ret;
    }

    if (1024 != pucPublicKey->bits && 2048 != pucPublicKey->bits)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d pucPublicKey bits invalid", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //3、调用软算法实现
    ret = RSAPublicBlock(pucDataOutput, puiOutputLength, pucDataInput, uiInputLength, (R_RSA_PUBLIC_KEY *)pucPublicKey);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d RSAPublicBlock failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_PKOPERR;
    }

    return ret;
}



int SDF_ExternalPrivateKeyOperation_RSA(void *hSessionHandle, RSArefPrivateKey *pucPrivateKey, unsigned char *pucDataInput, unsigned int uiInputLength, unsigned char *pucDataOutput,
                                        unsigned int *puiOutputLength)
{
    int ret = SDR_OK;
    void *hHandle = NULL;

    //1、参数检查
    if (!hSessionHandle || !pucPrivateKey || !pucDataInput || !pucDataOutput || !puiOutputLength)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    if (0 == uiInputLength)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d uiInputLength = 0", __FUNCTION__, __LINE__);
        return ret;
    }

    if (1024 != pucPrivateKey->bits && 2048 != pucPrivateKey->bits)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d pucPublicKey bits invalid", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //3、调用软算法实现
    ret = RSAPrivateBlock(pucDataOutput, puiOutputLength, pucDataInput, uiInputLength, (R_RSA_PRIVATE_KEY *)pucPrivateKey);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d RSAPrivateBlock failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_PKOPERR;
    }

    return ret;
}



int SDF_InternalPublicKeyOperation_RSA(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucDataInput, unsigned int uiInputLength, unsigned char *pucDataOutput,
                                       unsigned int *puiOutputLength)
{
    int ret = SDR_OK;
    void *hHandle = NULL;
    unsigned int keyIndex = 0;
    RSArefPublicKey pucPublicKey;
    unsigned char uPubID[2] = {0};
    SOFT_RSA_PUB_KEY pPublicKey;
    //1、参数检查
    if (!hSessionHandle || !pucDataInput || !pucDataOutput || !puiOutputLength || 0 == uiInputLength)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    if (KEYPAIRE_INDEX_MAX < uiKeyIndex || 0 == uiKeyIndex)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d uiKeyIndex invalid, uiKeyIndex=0x%08x", __FUNCTION__, __LINE__, uiKeyIndex);
        return ret;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //3、调用SOFT实现
    keyIndex = (uiKeyIndex + 1) * 4; 
  
    uPubID[1]=keyIndex;
    ret = SOFT_ReadRsaPubKey(hHandle, uPubID, (PSOFT_RSA_PUB_KEY )&pPublicKey);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d SOFT_ReadRsaPubKey failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_PKOPERR;
    } 

    X2S_rsapub(&pucPublicKey,&pPublicKey);

    ret = RSAPublicBlock(pucDataOutput, puiOutputLength, pucDataInput, uiInputLength, (R_RSA_PUBLIC_KEY *)&pucPublicKey);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d RSAPublicBlock failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_PKOPERR;
    } 

    *puiOutputLength = uiInputLength;
EXIT:
    return ret;
}

int SDF_InternalPrivateKeyOperation_RSA(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucDataInput, unsigned int uiInputLength, unsigned char *pucDataOutput,
                                        unsigned int *puiOutputLength)
{
    int ret = SDR_OK;
    void *hHandle = NULL;
    unsigned int keyIndex = 0;
    RSArefPrivateKey pucPrivateKey;
    unsigned char uPriID[2] = {0};
    SOFT_RSA_PRI_KEY pPrivateKey;
    //1、参数检查
    if (!hSessionHandle || !pucDataInput || !pucDataOutput || !puiOutputLength || 0 == uiInputLength)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    if (KEYPAIRE_INDEX_MAX < uiKeyIndex || 0 == uiKeyIndex)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d uiKeyIndex invalid, uiKeyIndex=0x%08x", __FUNCTION__, __LINE__, uiKeyIndex);
        return ret;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }


    //3、调用SOFT实现 priv
    keyIndex = (uiKeyIndex + 1) * 4 + 1; 

    uPriID[1]=keyIndex;
    ret = SOFT_ReadRsaPriKey(hHandle, uPriID, (PSOFT_RSA_PRI_KEY )&pPrivateKey);

    X2S_rsapri(&pucPrivateKey,&pPrivateKey);

    ret = RSAPrivateBlock(pucDataOutput, puiOutputLength, pucDataInput, uiInputLength, (R_RSA_PRIVATE_KEY *)&pucPrivateKey);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d RSAPrivateBlock failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_PKOPERR;
    }


    *puiOutputLength = uiInputLength;
EXIT:
    return ret;
}


int SDF_GenerateKeyPair_ECC(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiKeyBits, ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey)
{
    int ret = SDR_OK;
    void *hHandle = NULL;

    unsigned char k[64] = {0};
    SM2PublicKey publickKey = {0};
    SM2PrivateKey privateKey = {0};


    //1、参数检查
    if (!hSessionHandle || !pucPublicKey || !pucPrivateKey)
    {
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__);
        return SDR_INARGERR;
    }

    if (uiAlgID != SGD_SM2 && uiAlgID != SGD_SM2_1 && uiAlgID != SGD_SM2_2 && uiAlgID != SGD_SM2_3)
    {
        LOG_Write(NULL, "%s:%d uiAlgID not support, uiAlgID = 0x%08x", __FUNCTION__, __LINE__, uiAlgID);
        return SDR_ALGNOTSUPPORT;
    }

    //目前仅支持256位
    if (uiKeyBits != 256)
    {
        LOG_Write(NULL, "%s:%d uiKeyBits not support, uiKeyBits=0x%08x", __FUNCTION__, __LINE__, uiKeyBits);
        return SDR_INARGERR;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //3、
    ret = SM2_genkeypair(&publickKey, &privateKey);

    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d cos_generateKeypair_ecc failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
    }

    //4、密钥转换
    memset(pucPublicKey, 0, sizeof(ECCrefPublicKey));
    memset(pucPrivateKey, 0, sizeof(ECCrefPrivateKey));
    pucPublicKey->bits = publickKey.bits;
    pucPrivateKey->bits = privateKey.bits;
    memcpy(pucPublicKey->x + ECC_KEY_OFFSET, publickKey.x, SM2_MAX_LEN);
    memcpy(pucPublicKey->y + ECC_KEY_OFFSET, publickKey.y, SM2_MAX_LEN);
    memcpy(pucPrivateKey->K + ECC_KEY_OFFSET, privateKey.d, SM2_MAX_LEN);
    return ret;
}


int SDF_ImportSignPublicKey_ECC(void *hSessionHandle, unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey)
{
    int ret = 0;
    void *hHandle = NULL;
    unsigned char uPubID[2] = {0};
    SOFT_SM2_PUBKEY publicKey = {0};
    unsigned int keyIndex = 0;

    //1、参数检查
    if (!pucPublicKey || 0 == memcmp(pucPublicKey->x + ECC_KEY_OFFSET, "\x00\x00\x00\x00", 4) || 0 == memcmp(pucPublicKey->y + ECC_KEY_OFFSET, "\x00\x00\x00\x00", 4))
    {
        LOG_Write(NULL, "%s:%d invalid param", __FUNCTION__, __LINE__);
        return SDR_INARGERR;
    }

    if (KEYPAIRE_INDEX_MAX < uiKeyIndex)
    {
        LOG_Write(NULL, "%s:%d uiKeyIndex invalid, uiKeyIndex=0x%08x", __FUNCTION__, __LINE__, uiKeyIndex);
        return SDR_INARGERR;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //3、密钥转换
    //publicKey.bits = pucPublicKey->bits;
    memcpy(publicKey.x, pucPublicKey->x + ECC_KEY_OFFSET, SM2_MAX_LEN);
    memcpy(publicKey.y, pucPublicKey->y + ECC_KEY_OFFSET, SM2_MAX_LEN);

    //4、调用SOFT导入签名公钥
    //4、计算签名公钥id

    keyIndex = (uiKeyIndex + 1) * 4 ;

    //5、调用SOFT导入签名公钥
    uPubID[1]=keyIndex;

    ret = SOFT_WriteSM2PubKey(hHandle, uPubID, (SOFT_SM2_PUBKEY *)&publicKey);

    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d SOFT_WriteSM2PubKey failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_KEYERR;
    }

   
EXIT:
    return ret;
}



int SDF_ImportEncPublicKey_ECC(void *hSessionHandle, unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey)
{
      int ret = 0;
    void *hHandle = NULL;
    unsigned char uPubID[2] = {0};
    SOFT_SM2_PUBKEY publicKey = {0};
    unsigned int keyIndex = 0;

    //1、参数检查
    if (!pucPublicKey || 0 == memcmp(pucPublicKey->x + ECC_KEY_OFFSET, "\x00\x00\x00\x00", 4) || 0 == memcmp(pucPublicKey->y + ECC_KEY_OFFSET, "\x00\x00\x00\x00", 4))
    {
        LOG_Write(NULL, "%s:%d invalid param", __FUNCTION__, __LINE__);
        return SDR_INARGERR;
    }

    if (KEYPAIRE_INDEX_MAX < uiKeyIndex)
    {
        LOG_Write(NULL, "%s:%d uiKeyIndex invalid, uiKeyIndex=0x%08x", __FUNCTION__, __LINE__, uiKeyIndex);
        return SDR_INARGERR;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //3、密钥转换
    //publicKey.bits = pucPublicKey->bits;
    memcpy(publicKey.x, pucPublicKey->x + ECC_KEY_OFFSET, SM2_MAX_LEN);
    memcpy(publicKey.y, pucPublicKey->y + ECC_KEY_OFFSET, SM2_MAX_LEN);


    //4、计算签名公钥id

    keyIndex = (uiKeyIndex + 1) * 4 + 2 ;

    //5、调用SOFT导入签名公钥
    uPubID[1]=keyIndex;

    ret = SOFT_WriteSM2PubKey(hHandle, uPubID, (SOFT_SM2_PUBKEY *)&publicKey);

    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d SOFT_WriteSM2PubKey failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_KEYERR;
    }

   
EXIT:
    return ret;
}


int SDF_ImportSignPrivateKey_ECC(void *hSessionHandle, unsigned int uiKeyIndex, ECCrefPrivateKey *pucPrivateKey)
{
    int ret = 0;
    void *hHandle = NULL;
    unsigned char uPriID[2] = {0};
    SOFT_SM2_PRIKEY privateKey = {0};

    unsigned int keyIndex = 0;

    //1、参数检查，规避cos私钥全0时的问题
    if (!pucPrivateKey || 0 == memcmp(pucPrivateKey->K + ECC_KEY_OFFSET, "\x00\x00\x00\x00", 4))
    {
        LOG_Write(NULL, "%s:%d invalid param", __FUNCTION__, __LINE__);
        return SDR_INARGERR;
    }

    if (KEYPAIRE_INDEX_MAX < uiKeyIndex)
    {
        LOG_Write(NULL, "%s:%d uiKeyIndex invalid, uiKeyIndex=0x%08x", __FUNCTION__, __LINE__, uiKeyIndex);
        return SDR_INARGERR;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //3、密钥转换
   // privateKey.bits = pucPrivateKey->bits;
    memcpy(privateKey.d, pucPrivateKey->K + ECC_KEY_OFFSET, SM2_MAX_LEN);


    keyIndex = (uiKeyIndex + 1) * 4 + 1;

    //5、调用SOFT导入签名
    uPriID[1]=keyIndex;

    ret = SOFT_WriteSM2PriKey(hHandle, uPriID, (SOFT_SM2_PRIKEY *)&privateKey);

    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d SOFT_WriteSM2PubKey failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_KEYERR;
    }
 
EXIT:
    return ret;
}



int SDF_ImportEncPrivateKey_ECC(void *hSessionHandle, unsigned int uiKeyIndex, ECCrefPrivateKey *pucPrivateKey)
{
       int ret = 0;
    void *hHandle = NULL;
    unsigned char uPriID[2] = {0};
    SOFT_SM2_PRIKEY privateKey = {0};

    unsigned int keyIndex = 0;

    //1、参数检查，规避cos私钥全0时的问题
    if (!pucPrivateKey || 0 == memcmp(pucPrivateKey->K + ECC_KEY_OFFSET, "\x00\x00\x00\x00", 4))
    {
        LOG_Write(NULL, "%s:%d invalid param", __FUNCTION__, __LINE__);
        return SDR_INARGERR;
    }

    if (KEYPAIRE_INDEX_MAX < uiKeyIndex)
    {
        LOG_Write(NULL, "%s:%d uiKeyIndex invalid, uiKeyIndex=0x%08x", __FUNCTION__, __LINE__, uiKeyIndex);
        return SDR_INARGERR;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //3、密钥转换
   // privateKey.bits = pucPrivateKey->bits;
    memcpy(privateKey.d, pucPrivateKey->K + ECC_KEY_OFFSET, SM2_MAX_LEN);


    keyIndex = (uiKeyIndex + 1) * 4 + 3;

    //5、调用SOFT导入签名
    uPriID[1]=keyIndex;

    ret = SOFT_WriteSM2PriKey(hHandle, uPriID, (SOFT_SM2_PRIKEY *)&privateKey);

    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d SOFT_WriteSM2PubKey failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_KEYERR;
    }
 
EXIT:
    return ret;
}






int SDF_ExportSignPublicKey_ECC(void *hSessionHandle, unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey)
{
    int ret = SDR_OK;
    void *hHandle = NULL;
    unsigned int keyIndex = 0;
    SOFT_SM2_PUBKEY publickKey = {0};
    unsigned char uPubID[2] = {0};

    //1、参数检查
    if (!hSessionHandle || !pucPublicKey)
    {
        LOG_Write(NULL, "%s:%d invalid param", __FUNCTION__, __LINE__);
        return SDR_INARGERR;
    }

    if (KEYPAIRE_INDEX_MAX < uiKeyIndex)
    {
        LOG_Write(NULL, "%s:%d uiKeyIndex invalid, uiKeyIndex=0x%08x", __FUNCTION__, __LINE__, uiKeyIndex);
        return SDR_INARGERR;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //3、调用SOFT导出签名公钥

    keyIndex = (uiKeyIndex + 1) * 4 ;

    uPubID[1]=keyIndex;
    ret = SOFT_ReadSM2PubKey(hHandle, uPubID, (PSOFT_SM2_PUBKEY )&publickKey);

    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_KEYERR;
    }


    memset((unsigned char *)pucPublicKey, 0, sizeof(ECCrefPublicKey));
    pucPublicKey->bits = 256;//publickKey.bits;
    memcpy(pucPublicKey->x + ECC_KEY_OFFSET, publickKey.x, SM2_MAX_LEN);
    memcpy(pucPublicKey->y + ECC_KEY_OFFSET, publickKey.y, SM2_MAX_LEN);
    return ret;
}





int SDF_ExportEncPublicKey_ECC(void *hSessionHandle, unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey)
{
      int ret = SDR_OK;
    void *hHandle = NULL;
    unsigned int keyIndex = 0;
    SOFT_SM2_PUBKEY publickKey = {0};
    unsigned char uPubID[2] = {0};

    //1、参数检查
    if (!hSessionHandle || !pucPublicKey)
    {
        LOG_Write(NULL, "%s:%d invalid param", __FUNCTION__, __LINE__);
        return SDR_INARGERR;
    }

    if (KEYPAIRE_INDEX_MAX < uiKeyIndex/* || 0 == uiKeyIndex*/)
    {
        LOG_Write(NULL, "%s:%d uiKeyIndex invalid, uiKeyIndex=0x%08x", __FUNCTION__, __LINE__, uiKeyIndex);
        return SDR_INARGERR;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //3、调用SOFT导出签名公钥

    keyIndex = (uiKeyIndex + 1) * 4 + 2 ;

    uPubID[1]=keyIndex;
    ret = SOFT_ReadSM2PubKey(hHandle, uPubID, (PSOFT_SM2_PUBKEY )&publickKey);

    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_KEYERR;
    }


    memset((unsigned char *)pucPublicKey, 0, sizeof(ECCrefPublicKey));
    pucPublicKey->bits = 256;//publickKey.bits;
    memcpy(pucPublicKey->x + ECC_KEY_OFFSET, publickKey.x, SM2_MAX_LEN);
    memcpy(pucPublicKey->y + ECC_KEY_OFFSET, publickKey.y, SM2_MAX_LEN);
    return ret;
}



int SDF_ExternalEncrypt_ECC(void *hSessionHandle,
                            unsigned int uiAlgID,
                            ECCrefPublicKey *pucPublicKey,
                            unsigned char *pucData,
                            unsigned int uiDataLength,
                            ECCCipher *pucEncData)
{
    int ret = SDR_OK;
    void *hHandle = NULL;
    unsigned int outDataLength = 0;
    SM2PublicKey publickKey = {0};
    unsigned char outbuf[4096] = {0};


    //1、参数检查
    if (!hSessionHandle || !pucPublicKey || !pucData || !pucEncData)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__);
        return ret;
    }

    if (0 == uiDataLength)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d uiDataLength error, uiDataLength = 0x%08x", __FUNCTION__, __LINE__, uiDataLength);
        return ret;
    }

    if (SGD_SM2_3 != uiAlgID && SGD_SM2 != uiAlgID)
    {
        ret = SDR_ALGNOTSUPPORT;
        LOG_Write(NULL, "%s:%d uiAlgID not support, uiAlgID = 0x%08x", __FUNCTION__, __LINE__, uiAlgID);
        return ret;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }


    //3、密钥转换
    publickKey.bits = pucPublicKey->bits;
    memcpy(publickKey.x, pucPublicKey->x + ECC_KEY_OFFSET, 32);
    memcpy(publickKey.y, pucPublicKey->y + ECC_KEY_OFFSET, 32);

    //4、外部公钥加密
    ret = SM2_public_encrypt(NULL, &publickKey, pucData, uiDataLength,outbuf, &outDataLength);

    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d SM2_public_encrypt failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_PKOPERR;
    }
    

    memcpy(pucEncData->x + ECC_KEY_OFFSET, outbuf + 1, 32);
    memcpy(pucEncData->y + ECC_KEY_OFFSET, outbuf + 1 + 32, 32);
    memcpy(pucEncData->M, outbuf + outDataLength - 32, 32);
    pucEncData->L = uiDataLength;
    memcpy(pucEncData->C, outbuf + 1 + 64, pucEncData->L);

    return ret;
}


int SDF_ExternalDecrypt_ECC(void *hSessionHandle,
                            unsigned int uiAlgID,
                            ECCrefPrivateKey *pucPrivateKey,
                            ECCCipher *pucEncData,
                            unsigned char *pucData,
                            unsigned int *puiDataLength)
{
    int ret = SDR_OK;
    void *hHandle = NULL;
    unsigned int uiOutDataLength = 0;
    unsigned char *pucDataIn = NULL;
    SM2PrivateKey privateKey = {0};

    //1、参数检查
    if (!hSessionHandle || !pucPrivateKey || !pucEncData || !pucData || !puiDataLength)
    {
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__);
        return ret;
    }
    if (SGD_SM2_3 != uiAlgID && SGD_SM2 != uiAlgID)
    {
        ret = SDR_ALGNOTSUPPORT;
        LOG_Write(NULL, "%s:%d uiAlgID error, uiAlgID = %08x", __FUNCTION__, __LINE__, uiAlgID);
        return ret;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //3、密文转换
    pucDataIn = malloc(97 + pucEncData->L);
    if (NULL == pucDataIn)
    {
        ret = SDR_NOBUFFER;
        LOG_Write(NULL, "%s:%d malloc failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        goto EXIT;
    }

    memset(pucDataIn, 0, 97 + pucEncData->L);
    *pucDataIn = 0x04;
    memcpy(pucDataIn + 1, pucEncData->x + ECC_KEY_OFFSET, SM2_MAX_LEN);
    memcpy(pucDataIn + 1 + SM2_MAX_LEN, pucEncData->y + ECC_KEY_OFFSET, SM2_MAX_LEN);
    memcpy(pucDataIn + 1 + 2 * SM2_MAX_LEN, pucEncData->C, pucEncData->L);
    memcpy(pucDataIn + 1 + 2 * SM2_MAX_LEN + pucEncData->L, pucEncData->M, SM2_MAX_LEN);

    //私钥转换
    privateKey.bits = pucPrivateKey->bits;
    memcpy(privateKey.d, pucPrivateKey->K + ECC_KEY_OFFSET, SM2_MAX_LEN);

    //4、解密实现
 
    uiOutDataLength = pucEncData->L;
    ret = SM2_private_decrypt(NULL, &privateKey, pucDataIn, 97 + pucEncData->L, pucData, &uiOutDataLength);
    if (SDR_OK != ret)
    {
dumpdata(pucDataIn,pucEncData->L + 97);
            LOG_Write(NULL, "%s:%d Mix_SM2_decrypt failed, ret=0x%08x pucEncData->L+97=[%d]", __FUNCTION__, __LINE__, ret, pucEncData->L + 97);
            ret = SDR_SYMOPERR;
            goto EXIT;
    }
    *puiDataLength = uiOutDataLength;
    
EXIT:
    if (NULL != pucDataIn)
    {
        free(pucDataIn);
        pucDataIn = NULL;
    }

    return ret;
}


int SDF_ExternalSign_ECC(void *hSessionHandle, ECCrefPrivateKey *pucPrivateKey, unsigned char *pucData, unsigned int uiDataLength, ECCSignature *pucSignature)
{
    int ret = SDR_OK;
    void *hHandle = NULL;
    SM2PrivateKey privateKey = {0};
    SM2Signature signature = {0};
    unsigned int keyIndex = 0;
    unsigned int mode = 0;

    //1、参数检查
    if (!hSessionHandle || !pucPrivateKey || !pucData || !pucSignature || !uiDataLength || 32 != uiDataLength)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d param is invalid", __FUNCTION__, __LINE__);
        return ret;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //3、密钥转换
    privateKey.bits = pucPrivateKey->bits;
    memcpy(privateKey.d, pucPrivateKey->K + ECC_KEY_OFFSET, SM2_MAX_LEN);

    //4、外部私钥签名运算
    //int SM2_signature(SM2Curve *curve, SM2PublicKey *pub, SM2PrivateKey *priv, unsigned char *id, int idlen, unsigned char *message, int mlen, SM2Signature *value)
    ret = SM2_signature(NULL, NULL, &privateKey, NULL, 0, pucData, uiDataLength, &signature);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d external_sign_ecc failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_SKOPERR;
        return ret;
    }



    memcpy(pucSignature->r + ECC_KEY_OFFSET, signature.r, SM2_MAX_LEN);
    memcpy(pucSignature->s + ECC_KEY_OFFSET, signature.s, SM2_MAX_LEN);

    return ret;
}

int SDF_ExternalVerify_ECC(void *hSessionHandle,
                           unsigned int uiAlgID,
                           ECCrefPublicKey *pucPublicKey,
                           unsigned char *pucData,
                           unsigned int uiDataLength,
                           ECCSignature *pucSignature)
{
    int ret = SDR_OK;
    void *hHandle = NULL;
    SM2PublicKey publickKey = {0};
    SM2Signature signature = {0};


    //1、参数检查
    if (uiAlgID != SGD_SM2 && uiAlgID != SGD_SM2_1 && uiAlgID != SGD_SM2_2 && uiAlgID != SGD_SM2_3)
    {
        ret = SDR_ALGNOTSUPPORT;
        LOG_Write(NULL, "%s:%d invalid algorithem, uiAlgID = 0x%08x", __FUNCTION__, __LINE__, uiAlgID);
        return ret;
    }
    if (!hSessionHandle || !pucPublicKey || !pucData || !pucSignature || !uiDataLength || 32 != uiDataLength)
    {
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__);
        return SDR_INARGERR;;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }



    //3、外部公钥验签运算
    //签名值转换
    memcpy(signature.r, pucSignature->r + ECC_KEY_OFFSET, SM2_MAX_LEN);
    memcpy(signature.s, pucSignature->s + ECC_KEY_OFFSET, SM2_MAX_LEN);
    publickKey.bits = pucPublicKey->bits;
    memcpy(publickKey.x, pucPublicKey->x + ECC_KEY_OFFSET, SM2_MAX_LEN);
    memcpy(publickKey.y, pucPublicKey->y + ECC_KEY_OFFSET, SM2_MAX_LEN);
    //int SM2_verify(SM2Curve *curve, SM2PublicKey *pub, unsigned char *id, int idlen, unsigned char *message, int mlen, SM2Signature *value)
    ret = SM2_verify(NULL, &publickKey,  NULL, 0, pucData, uiDataLength, &signature);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d external_sign_ecc failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_SKOPERR;
        return ret;
    }

    return ret;
}

int SDF_InternalDecrypt_ECC(void *hSessionHandle,
                            unsigned int uiAlgID,
                            unsigned int uiKeyIndex,
                            ECCCipher *pucEncData,
                            unsigned char *pucData,
                            unsigned int *puiDataLength)
{
   
    int ret = SDR_OK;
    void *hHandle = NULL;
    unsigned char *pucDataIn = NULL;
    unsigned int keyIndex = 0;
    SOFT_SM2_PRIKEY pSoftPriKey = {0};
    unsigned int privateKeyLen = 0;
    unsigned char uPriID[2] = {0};
    SM2PrivateKey privateKey = {0};

    unsigned int uiOutDataLength = 0;
    //1、参数检查
    if (!pucEncData || !pucData || !puiDataLength)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d param error", __FUNCTION__, __LINE__);
        return ret;
    }

    if (SGD_SM2_3 != uiAlgID && SGD_SM2 != uiAlgID)
    {
        ret = SDR_ALGNOTSUPPORT;
        LOG_Write(NULL, "%s:%d uiAlgID error, uiAlgID = %08x", __FUNCTION__, __LINE__, uiAlgID);
        return ret;
    }

    if (KEYPAIRE_INDEX_MAX < uiKeyIndex/* || 0 == uiKeyIndex*/)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d uiKeyIndex invalid, uiKeyIndex=0x%08x", __FUNCTION__, __LINE__, uiKeyIndex);
        return ret;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //3、密文转换
    pucDataIn = malloc(97 + pucEncData->L);
    if (NULL == pucDataIn)
    {
        ret = SDR_NOBUFFER;
        LOG_Write(NULL, "%s:%d malloc failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        goto EXIT;
    }

    memset(pucDataIn, 0, 97 + pucEncData->L);
    *pucDataIn = 0x04;
    memcpy(pucDataIn + 1, pucEncData->x + ECC_KEY_OFFSET, SM2_MAX_LEN);
    memcpy(pucDataIn + 1 + SM2_MAX_LEN, pucEncData->y + ECC_KEY_OFFSET, SM2_MAX_LEN);
    memcpy(pucDataIn + 1 + 2 * SM2_MAX_LEN, pucEncData->C, pucEncData->L);
    memcpy(pucDataIn + 1 + 2 * SM2_MAX_LEN + pucEncData->L, pucEncData->M, SM2_MAX_LEN);

    //4、解密

    keyIndex = (uiKeyIndex + 1) * 4 + 3;
    uPriID[1]=keyIndex;
    ret = SOFT_ReadSm2PriKey(hHandle,uPriID,&pSoftPriKey);
    if (SDR_OK != ret)
    {
            LOG_Write(NULL, "%s:%d SOFT_ReadSm2PriKey failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
            ret = SDR_SYMOPERR;
            goto EXIT;
    }
    //私钥转换
    privateKey.bits = 256;
    memcpy(privateKey.d,pSoftPriKey.d,32);
    //4、解密实现
 
    uiOutDataLength = pucEncData->L;
    ret = SM2_private_decrypt(NULL, &privateKey, pucDataIn, 97 + pucEncData->L, pucData, &uiOutDataLength);
    if (SDR_OK != ret)
    {
            LOG_Write(NULL, "%s:%d Mix_SM2_decrypt failed, ret=0x%08x pucEncData->L+97=[%d]", __FUNCTION__, __LINE__, ret, pucEncData->L + 97);
            ret = SDR_SYMOPERR;
            goto EXIT;
    }
    *puiDataLength = uiOutDataLength;

EXIT:
    if (NULL != pucDataIn)
    {
        free(pucDataIn);
        pucDataIn = NULL;
    }

    return ret;
}




int SDF_InternalSign_ECC(void *hSessionHandle,
                         unsigned int uiISKIndex,
                         unsigned int uiAlgID,
                         unsigned char *pucData,
                         unsigned int uiDataLength,
                         ECCSignature *pucSignature)
{
    int ret = SDR_OK;
    void *hHandle = NULL;
    SOFT_SM2_PRIKEY pSoftPriKey = {0};
    unsigned int keyIndex = 0;
    unsigned int privateKeyLen = 0;
    SM2PrivateKey privateKey = {0};
    SM2Signature signature = {0};
    unsigned char uPriID[2] = {0};

    int index = 0;


    //1、参数检查
    if (!uiDataLength || !hSessionHandle || !pucData || !pucSignature || 32 != uiDataLength)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d param is invalid", __FUNCTION__, __LINE__);
        return ret;
    }

    if (KEYPAIRE_INDEX_MAX < uiISKIndex/* || 0 == uiISKIndex*/)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d uiISKIndex error, uiISKIndex=[0x%08x]", __FUNCTION__, __LINE__, uiISKIndex);
        return ret;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }


    //3、密钥转换

    keyIndex = (uiISKIndex + 1) * 4 + 1;
    uPriID[1]=keyIndex;
    ret = SOFT_ReadSm2PriKey(hHandle,uPriID,&pSoftPriKey);
    if (SDR_OK != ret)
    {
            LOG_Write(NULL, "%s:%d SOFT_ReadSm2PriKey failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
            ret = SDR_SYMOPERR;
            goto EXIT;
    }


    privateKey.bits = 256;
    memcpy(privateKey.d,pSoftPriKey.d,32);


    //4、外部私钥签名运算
    ret = SM2_signature(NULL, NULL, &privateKey, NULL, 0, pucData, uiDataLength, &signature);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d external_sign_ecc failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_SKOPERR;
        return ret;
    }


    memset(pucSignature, 0, sizeof(ECCSignature));
    memcpy(pucSignature->r + ECC_KEY_OFFSET, signature.r, SM2_MAX_LEN);
    memcpy(pucSignature->s + ECC_KEY_OFFSET, signature.s, SM2_MAX_LEN);

EXIT:


    return ret;
}


int SDF_InternalVerify_ECC(void *hSessionHandle,
                           unsigned int uiISKIndex,
                           unsigned int uiAlgID,                         
                           unsigned char *pucData,
                           unsigned int uiDataLength,
                           ECCSignature *pucSignature)
{
    int ret = SDR_OK;
    void *hHandle = NULL;
    unsigned int keyIndex = 0;

    SM2Signature signature = {0};
    SM2PublicKey publickKey = {0};
    SOFT_SM2_PUBKEY pucPublicKey;
    unsigned int mode = 0;
    unsigned char uPubID[2] = {0};

    //1、参数检查
    if (!hSessionHandle || !pucData || !uiDataLength || !pucSignature)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__);
        return ret;
    }

    if (KEYPAIRE_INDEX_MAX < uiISKIndex/* || 0 == uiISKIndex*/)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d uiISKIndex invalid, uiISKIndex=0x%08x", __FUNCTION__, __LINE__, uiISKIndex);
        return ret;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //3、内部公钥验签运算

    keyIndex = (uiISKIndex + 1) * 4;

    uPubID[1]=keyIndex;
    ret = SOFT_ReadSM2PubKey(hHandle, uPubID, (PSOFT_SM2_PUBKEY )&pucPublicKey);

    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_KEYERR;
    }

    //签名值转换
    memcpy(signature.r, pucSignature->r + ECC_KEY_OFFSET, SM2_MAX_LEN);
    memcpy(signature.s, pucSignature->s + ECC_KEY_OFFSET, SM2_MAX_LEN);
    
    publickKey.bits = 256;
    memcpy(publickKey.x, pucPublicKey.x , SM2_MAX_LEN);
    memcpy(publickKey.y, pucPublicKey.y, SM2_MAX_LEN);

    ret = SM2_verify(NULL, &publickKey,  NULL, 0, pucData, uiDataLength, &signature);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d external_sign_ecc failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_SKOPERR;
        return ret;
    }

    return ret;
}



//



int SDF_ImportKey(void *hSessionHandle, unsigned char *pucKey, unsigned int puiKeyLength, void **phKeyHandle)
{
    int ret = SDR_OK;
    void *hHandle = NULL;

    //1、参数检查
    if (!hSessionHandle || !pucKey || !puiKeyLength)
    {
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__);
        return SDR_INARGERR;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //3、导入会话密钥
    ret = ImportSessKey(hHandle, pucKey, puiKeyLength, phKeyHandle);
    if (0 != ret)
    {
        LOG_Write(NULL, "%s:%d ImportSessKey ret = 0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_UNKNOWERR;
    }

    return ret;
}

int SDF_DestroyKey(void *hSessionHandle, void *hKeyHandle)
{
    int index = 0, ret = SDR_OK;
    void *hHandle = NULL;

    //1、参数检查
    if (!hSessionHandle || !hKeyHandle)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__);
        return ret;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //3、获取索引值并释放索引对应的密钥
    index = *((int *)hKeyHandle);
    ret = DestroySessKey(hHandle, index);
    if (0 != ret)
    {
        LOG_Write(NULL, "%s:%d DestroySessKey ret=0x%08x", __FUNCTION__, __LINE__, ret);
    }

    return ret;
}





int SDF_ExternalEncrypt(void *hSessionHandle,
                        unsigned int uiAlgID,
                        unsigned char *pucKey,
                        unsigned int uiKeyLength,
                        unsigned char *pucIV,
                        unsigned char *pucData,
                        unsigned int uiDataLength,
                        unsigned char *pucEncData,
                        unsigned int *puiEncDataLength)
{
    int ret = SDR_OK;
    void* hHandle = NULL;
    unsigned int node = 0;

    //1、参数检查
    if (!hSessionHandle || !pucKey || !pucData || !pucEncData || !puiEncDataLength || 0 == uiDataLength)
    {
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__);
        return SDR_INARGERR;
    }

    if (0 != uiDataLength % 16)
    {
        LOG_Write(NULL, "%s:%d uiDataLength error", __FUNCTION__, __LINE__);
        return SDR_INARGERR;
    }

    if (SGD_AES128_ECB != uiAlgID && SGD_AES128_CBC != uiAlgID && SGD_SM1_CFB != uiAlgID && SGD_SM1_OFB != uiAlgID &&
            SGD_SM4_ECB != uiAlgID && SGD_SM4_CBC != uiAlgID && SGD_SM4_CFB != uiAlgID && SGD_SM4_OFB != uiAlgID)
    {
        LOG_Write(NULL, "%s:%d uiAlgID error", __FUNCTION__, __LINE__);
        return SDR_ALGNOTSUPPORT;
    }

    if (((0x02 == (uiAlgID & 0xff)) || (0x04 == (uiAlgID & 0xff)) || (0x08 == (uiAlgID & 0xff))) && !pucIV)
    {
        LOG_Write(NULL, "%s:%d pucIV is NULL", __FUNCTION__, __LINE__);
        return SDR_INARGERR;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //3、对称计算
    ret = SOFT_Symcrypto(hHandle, OP_ENCRYPT, uiAlgID, -1, pucKey, uiKeyLength, pucIV, pucData, uiDataLength, pucEncData, puiEncDataLength, node);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d SOFT_Symcrypto Encrypt failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_SYMOPERR;
    }

    return ret;
}

int SDF_ExternalDecrypt(void *hSessionHandle,
                        unsigned int uiAlgID,
                        unsigned char *pucKey,
                        unsigned int uiKeyLength,
                        unsigned char *pucIV,
                        unsigned char *pucEncData,
                        unsigned int uiEncDataLength,
                        unsigned char *pucData,
                        unsigned int *puiDataLength)
{
    int ret = SDR_OK;
    void* hHandle = NULL;
    unsigned int node = 0;

    //1、参数检查
    if (!hSessionHandle || !pucKey || !pucData || !pucEncData || !pucData || 0 == uiEncDataLength)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__);
        return ret;
    }

    if (0 != uiEncDataLength % 16)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d uiEncDataLength error", __FUNCTION__, __LINE__);
        return ret;
    }

    if (SGD_AES128_ECB != uiAlgID && SGD_AES128_CBC != uiAlgID && SGD_SM1_CFB != uiAlgID && SGD_SM1_OFB != uiAlgID &&
            SGD_SM4_ECB != uiAlgID && SGD_SM4_CBC != uiAlgID && SGD_SM4_CFB != uiAlgID && SGD_SM4_OFB != uiAlgID)
    {
        ret = SDR_ALGNOTSUPPORT;
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__);
        return ret;
    }

    if (((0x02 == (uiAlgID & 0xff)) || (0x04 == (uiAlgID & 0xff)) || (0x08 == (uiAlgID & 0xff))) && !pucIV)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__);
        return ret;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //3、对称计算
    ret = SOFT_Symcrypto(hHandle, OP_DECRYPT, uiAlgID, -1, pucKey, uiKeyLength, pucIV, pucEncData, uiEncDataLength, pucData, puiDataLength, node);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d SOFT_Symcrypto Decrypt failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_SYMOPERR;
    }

    return ret;
}

int SDF_Encrypt(
        void *hSessionHandle,
        void *hKeyHandle,
        unsigned int uiAlgID,
        unsigned char *pucIV,
        unsigned char *pucData,
        unsigned int uiDataLength,
        unsigned char *pucEncData,
        unsigned int *puiEncDataLength)
{
    int ret = SDR_OK;
    unsigned int index = 0;
    void* hHandle = NULL;
    unsigned int node = 0;

    //1、参数检查
    if (!hSessionHandle || !hKeyHandle || !pucData || !pucEncData || !uiDataLength || !puiEncDataLength || 0 == uiDataLength)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__);
        return ret;
    }

    if (SGD_AES128_ECB != uiAlgID && SGD_AES128_CBC != uiAlgID && SGD_SM1_CFB != uiAlgID && SGD_SM1_OFB != uiAlgID &&
            SGD_SM4_ECB != uiAlgID && SGD_SM4_CBC != uiAlgID && SGD_SM4_CFB != uiAlgID && SGD_SM4_OFB != uiAlgID)
    {
        ret = SDR_ALGNOTSUPPORT;
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__);
        return ret;
    }

    if (((0x02 == (uiAlgID & 0xff)) || (0x04 == (uiAlgID & 0xff)) || (0x08 == (uiAlgID & 0xff))) && !pucIV)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__);
        return ret;
    }

    if (0 != uiDataLength % 16)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d uiDataLength error", __FUNCTION__, __LINE__);
        return ret;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    index = *((unsigned int*)hKeyHandle);
    ret = SOFT_Symcrypto(hHandle, OP_ENCRYPT, uiAlgID, index, NULL, 0, pucIV, pucData, uiDataLength, pucEncData, puiEncDataLength, node);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d SOFT_Symcrypto Decrypt failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_SYMOPERR;
    }

    return ret;
}



int SDF_Decrypt(
        void *hSessionHandle,
        void *hKeyHandle,
        unsigned int uiAlgID,
        unsigned char *pucIV,
        unsigned char *pucEncData,
        unsigned int uiEncDataLength,
        unsigned char *pucData,
        unsigned int *puiDataLength)
{
    int ret = SDR_OK;
    unsigned int index = 0;
    void* hHandle = NULL;
    unsigned int node = 0;

    //1、参数检查
    if (!hSessionHandle || !hKeyHandle || !pucData || !pucEncData || !puiDataLength || 0 == uiEncDataLength)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__);
        return ret;
    }

    if (SGD_AES128_ECB != uiAlgID && SGD_AES128_CBC != uiAlgID && SGD_SM1_CFB != uiAlgID && SGD_SM1_OFB != uiAlgID &&
            SGD_SM4_ECB != uiAlgID && SGD_SM4_CBC != uiAlgID && SGD_SM4_CFB != uiAlgID && SGD_SM4_OFB != uiAlgID)
    {
        ret = SDR_ALGNOTSUPPORT;
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__);
        return ret;
    }

    if (((0x02 == (uiAlgID & 0xff)) || (0x04 == (uiAlgID & 0xff)) || (0x08 == (uiAlgID & 0xff))) && !pucIV)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__);
        return ret;
    }

    if (0 != uiEncDataLength % 16)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d uiEncDataLength error", __FUNCTION__, __LINE__);
        return ret;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //3、对称计算
    index = *((unsigned int*)hKeyHandle);
    ret = SOFT_Symcrypto(hHandle, OP_DECRYPT, uiAlgID, index, NULL, 0, pucIV, pucEncData, uiEncDataLength, pucData, puiDataLength, node);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d SOFT_Symcrypto Decrypt failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_SYMOPERR;
    }

    return ret;
}

int SDF_CalculateMAC(
        void *hSessionHandle,
        void *hKeyHandle,
        unsigned int uiAlgID,
        unsigned char *pucIV,
        unsigned char *pucData,
        unsigned int uiDataLength,
        unsigned char *pucMAC,
        unsigned int *puiMACLength)
{
    int ret = SDR_OK;
    unsigned int index = 0;
    void* hHandle = NULL;
    unsigned char *pucEncData = NULL;
    unsigned int uiOutLen = 0;
    unsigned int node = 0;

    //1、参数检查
    if (!hSessionHandle || !hKeyHandle || !pucData || !pucMAC || !uiDataLength || !puiMACLength || !pucIV || 0 == uiDataLength)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__);
        return ret;
    }

    if (SGD_AES128_MAC != uiAlgID && SGD_SM4_MAC != uiAlgID)
    {
        ret = SDR_ALGNOTSUPPORT;
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__);
        return ret;
    }

    if (0 != uiDataLength % 16)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d uiDataLength error", __FUNCTION__, __LINE__);
        return ret;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    pucEncData = malloc(uiDataLength);
    if (!pucEncData)
    {
        ret = SDR_MALLOCERR;
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__);
        return ret;
    }

    //3、对称计算
    index = *((unsigned int*)hKeyHandle);
    ret = SOFT_Symcrypto(hHandle, OP_ENCRYPT, uiAlgID, index, NULL, 0, pucIV, pucData, uiDataLength, pucEncData, &uiOutLen, node);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d SOFT_Symcrypto Decrypt failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_SYMOPERR;
        goto EXIT;
    }

    memcpy(pucMAC, pucEncData + uiDataLength - 16, 16);
    *puiMACLength = 16;
EXIT:
    if (pucEncData)
    {
        free(pucEncData);
        pucEncData = NULL;
    }
    return ret;
}





int SDF_HashInit( void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey, unsigned char *pucID, unsigned int uiIDLength )
{
	int ret;
	PSDF_SESSIONDEV devSession = (PSDF_SESSIONDEV)hSessionHandle;
	SM3_CONTEXT* sm3ctx=NULL;
	sha1_context* sha1ctx=NULL;
	SOFT_SM2_PARAM sm2para;
	unsigned char inbuf[2];
	unsigned char pucHash[32];
	unsigned short idlenbit  = 0;

	if (SGD_SM3 == uiAlgID)
	{
		sm3ctx = (SM3_CONTEXT*)malloc(sizeof(SM3_CONTEXT));
		if (NULL == sm3ctx)
			return SDR_UNKNOWERR;
		SM3_Init(sm3ctx);
		if (NULL!=pucPublicKey)
		{
			memcpy(sm2para.p, "\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 32);
			memcpy(sm2para.a, "\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC", 32);
			memcpy(sm2para.b, "\x28\xE9\xFA\x9E\x9D\x9F\x5E\x34\x4D\x5A\x9E\x4B\xCF\x65\x09\xA7\xF3\x97\x89\xF5\x15\xAB\x8F\x92\xDD\xBC\xBD\x41\x4D\x94\x0E\x93", 32);
			memcpy(sm2para.n, "\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x72\x03\xDF\x6B\x21\xC6\x05\x2B\x53\xBB\xF4\x09\x39\xD5\x41\x23", 32);
			memcpy(sm2para.x, "\x32\xC4\xAE\x2C\x1F\x19\x81\x19\x5F\x99\x04\x46\x6A\x39\xC9\x94\x8F\xE3\x0B\xBF\xF2\x66\x0B\xE1\x71\x5A\x45\x89\x33\x4C\x74\xC7", 32);
			memcpy(sm2para.y, "\xBC\x37\x36\xA2\xF4\xF6\x77\x9C\x59\xBD\xCE\xE3\x6B\x69\x21\x53\xD0\xA9\x87\x7C\xC6\x2A\x47\x40\x02\xDF\x32\xE5\x21\x39\xF0\xA0", 32);
	
			idlenbit = uiIDLength * 8;
			inbuf[0] = (unsigned char)( idlenbit>>8 );
			inbuf[1] = (unsigned char)idlenbit;
			SM3_Update(sm3ctx,inbuf,2);
			SM3_Update(sm3ctx,pucID,uiIDLength);
			SM3_Update(sm3ctx,sm2para.a,KEY_LEN_SM2);
			SM3_Update(sm3ctx,sm2para.b,KEY_LEN_SM2);
			SM3_Update(sm3ctx,sm2para.x,KEY_LEN_SM2);
			SM3_Update(sm3ctx,sm2para.y,KEY_LEN_SM2);
			SM3_Update(sm3ctx,pucPublicKey->x+ECCref_MAX_LEN-KEY_LEN_SM2,KEY_LEN_SM2);
			SM3_Update(sm3ctx,pucPublicKey->y+ECCref_MAX_LEN-KEY_LEN_SM2,KEY_LEN_SM2);

			SM3_Final(pucHash,sm3ctx);
			SM3_Init(sm3ctx);
			SM3_Update(sm3ctx,pucHash,KEY_LEN_SM2);	

		}
		devSession->hHashHandle = sm3ctx;
		devSession->hashAlgID = SGD_SM3;
	}
	else if (SGD_SHA1 == uiAlgID)
	{
		sha1ctx = (sha1_context*)malloc(sizeof(sha1_context));
		if (NULL == sha1ctx)
			return SDR_UNKNOWERR;
		sha1_init(sha1ctx);
		devSession->hHashHandle = sha1ctx;
		devSession->hashAlgID = SGD_SHA1;
	}
	else
		return SDR_INARGERR;

	return SDR_OK;	
}

int SDF_HashUpdate( void *hSessionHandle,unsigned char *pucData,unsigned int uiDataLength )
{
	PSDF_SESSIONDEV devSession = (PSDF_SESSIONDEV)hSessionHandle;

	if (SGD_SM3 == devSession->hashAlgID)
	{
		SM3_Update(devSession->hHashHandle,pucData,uiDataLength);
	}
	else if (SGD_SHA1 == devSession->hashAlgID)
	{
		sha1_update(devSession->hHashHandle,pucData,uiDataLength);
	}
	else
		return SDR_INARGERR;
	return SDR_OK;	
}

int SDF_HashFinal( void *hSessionHandle,unsigned char *pucHash,unsigned int *puiHashLength )
{
	PSDF_SESSIONDEV devSession = (PSDF_SESSIONDEV)hSessionHandle;
	SM3_CONTEXT* sm3ctx=NULL;
	sha1_context* sha1ctx=NULL;

	if (SGD_SM3 == devSession->hashAlgID)
	{
		SM3_Final(pucHash,devSession->hHashHandle);
		*puiHashLength = 32;
	}
	else if (SGD_SHA1 == devSession->hashAlgID)
	{
		sha1ctx = (sha1_context*)devSession->hHashHandle;
		//sha1_final(sha1ctx);
		sha1_final(pucHash, sha1ctx);
		//memcpy(pucHash,sha1ctx->buf,20);
		*puiHashLength = 20;
	}
	else
		return SDR_INARGERR;
	free(devSession->hHashHandle);
	return SDR_OK;	
}


//file 


int SDF_CreateFile(void *hSessionHandle, unsigned char *pucFileName, unsigned int uiNameLen, unsigned int uiFileSize)
{
    int ret = SDR_OK;
    void* hHandle = NULL;

    //1、参数检查，单个文件最大16kB
    if (!hSessionHandle || !pucFileName || 0 == uiNameLen || uiNameLen > 128 || 0 == uiFileSize || uiFileSize > 0x4000)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d ret = 0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    ret = SOFT_CreateFile(hHandle, pucFileName, uiNameLen, uiFileSize);

    if (SDR_OK != ret && -9 != ret)
    {
        LOG_Write(NULL, "%s:%d SOFT_CreateFile failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_UNKNOWERR;
        return ret;
    }

    if (-9 == ret) //文件已存在
    {
        ret = SDR_FILEEXISTS;
    }

    return ret;
}

int SDF_ReadFile(void *hSessionHandle, unsigned char *pucFileName, unsigned int uiNameLen, unsigned int uiOffset, unsigned int *puiFileLength, unsigned char *pucBuffer)
{
    int ret = SDR_OK;
    void* hHandle = NULL;
    //1、参数检查
    if (!hSessionHandle || !pucFileName || NULL == puiFileLength || !pucBuffer)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d ret = 0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }
    if (uiNameLen > 128)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d ret = %08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }
    ret = SOFT_ReadFile(hHandle, pucFileName, uiNameLen, uiOffset, puiFileLength, pucBuffer);

    if (SDR_OK == ret)
    {
        return ret;
    }

    if (-13 == ret)
    {
        ret = SDR_FILESIZEERR;
        LOG_Write(NULL, "%s:%d SDF_ReadFile failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
    }
    else if (-11 == ret)
    {
        ret = SDR_FILENOEXIST;
        LOG_Write(NULL, "%s:%d SDF_ReadFile failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
    }
    else
    {
        ret = SDR_UNKNOWERR;
        LOG_Write(NULL, "%s:%d SDF_ReadFile failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
    }

    return ret;
}

int SDF_WriteFile(void *hSessionHandle, unsigned char *pucFileName, unsigned int uiNameLen, unsigned int uiOffset, unsigned int uiFileLength, unsigned char *pucBuffer)
{
    int ret = SDR_OK;
    void* hHandle = NULL;
    //1、参数检查
    if (!hSessionHandle || !pucFileName || uiNameLen > 128 || 0 == uiFileLength || !pucBuffer)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d ret = 0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }
    ret =  SOFT_WriteFile(hHandle, pucFileName, uiNameLen, uiOffset, uiFileLength, pucBuffer);
    if (SDR_OK == ret)
    {
        return ret;
    }

    if (-13 == ret)
    {
        ret = SDR_FILESIZEERR;
        LOG_Write(NULL, "%s:%d SOFT_WriteFile failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
    }
    else if (-11 == ret)
    {
        ret = SDR_FILENOEXIST;
        LOG_Write(NULL, "%s:%d SOFT_WriteFile failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
    }
    else
    {
        ret = SDR_UNKNOWERR;
        LOG_Write(NULL, "%s:%d SOFT_WriteFile failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
    }

    return ret;
}

int SDF_DeleteFile(void *hSessionHandle, unsigned char *pucFileName, unsigned int uiNameLen)
{
    int ret = SDR_OK;
    void* hHandle = NULL;
    //1、参数检查
    if (!hSessionHandle || !pucFileName || 0 == uiNameLen || uiNameLen > 128)
    {
        ret = SDR_INARGERR;
        LOG_Write(NULL, "%s:%d ret = 0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }
    ret = SOFT_DeleteFile(hHandle, pucFileName, uiNameLen);

    if (SDR_OK == ret)
    {
        return ret;
    }

    if (-11 == ret)
    {
        ret = SDR_FILENOEXIST;
        LOG_Write(NULL, "%s:%d SOFT_DeleteFile failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
    }
    else
    {
        ret = SDR_UNKNOWERR;
        LOG_Write(NULL, "%s:%d SOFT_DeleteFile failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
    }

    return ret;
}


//扩展
// BYD扩展定义keyindex
int SDF_CreateSysmKey(void *hSessionHandle, unsigned int uiKeyIndex, unsigned int uiAlgType) 
{


    int ret = SDR_OK;
    void *hHandle = NULL;
    unsigned char pucKey[64] = {0};
    unsigned int uiKeyLen = 0;
    //1、参数检查
    if (!hSessionHandle)
    {
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__);
        return SDR_INARGERR;
    }


	
    if (uiKeyIndex > MAX_KEY_NUM)
    {
        LOG_Write(NULL, "%s:%d ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return SDR_INARGERR;
    }
    if (ALG_SM1 != uiAlgType && ALG_3DES != uiAlgType && ALG_SM4 != uiAlgType && ALG_AES128 != uiAlgType &&
            ALG_AES192 != uiAlgType && ALG_AES256 != uiAlgType )
    {
        LOG_Write(NULL, "%s:%d ret=0x%08x uiAlgType=0x%02x", __FUNCTION__, __LINE__, ret,uiAlgType);
        return SDR_INARGERR;
    }

    uiKeyLen = 16;
   if (ALG_AES192 == uiAlgType)
   {
        uiKeyLen = 24;
   }

   if (ALG_AES256 == uiAlgType)
   {
        uiKeyLen = 32;
   }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }



    if ((uiKeyLen != 16) && (uiKeyLen != 24) && (uiKeyLen != 32))
    {
        LOG_Write(NULL, "%s:%d uiKeyLen error, uiKeyLen=0x%08x", __FUNCTION__, __LINE__, uiKeyLen);
        return SDR_INARGERR;
    }

    SOFT_GenRandom(uiKeyLen,pucKey);

    //3、调用COS实现kek导入
    ret = SOFT_WriteKey(hHandle, uiKeyIndex, pucKey, uiKeyLen);

    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d cos_import_kek ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_UNKNOWERR;
    }

    return ret;

}



int SDF_ImportKey_EX(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucKey, unsigned int uiKeyLen)
{
    int ret = SDR_OK;
    void *hHandle = NULL;

    //1、参数检查
    if (!hSessionHandle || !pucKey || 0 == uiKeyLen)
    {
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__);
        return SDR_INARGERR;
    }

    if ((uiKeyLen != 16) && (uiKeyLen != 24) && (uiKeyLen != 32))
    {
        LOG_Write(NULL, "%s:%d uiKeyLen error, uiKeyLen=0x%08x", __FUNCTION__, __LINE__, uiKeyLen);
        return SDR_INARGERR;
    }

    if (uiKeyIndex > MAX_KEY_NUM)
    {
        LOG_Write(NULL, "%s:%d ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return SDR_INARGERR;
    }


    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }
    


    //3、调用COS实现kek导入
    ret = SOFT_WriteKey(hHandle, uiKeyIndex, pucKey, uiKeyLen);

    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d cos_import_kek ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_UNKNOWERR;
    }

    return ret;
}


int SDF_GetKeyFromSE(void *hSessionHandle, unsigned int uiKeyIndex,void **phKeyHandle)
{

    int ret = SDR_OK;
    void *hHandle = NULL;
    unsigned char pucKey[64] = {0};
    unsigned int uiKeyLen=0;
    //1、参数检查
    if (!hSessionHandle)
    {
        LOG_Write(NULL, "%s:%d param is NULL", __FUNCTION__, __LINE__);
        return SDR_INARGERR;
    }

    if (uiKeyIndex > MAX_KEY_NUM)
    {
        LOG_Write(NULL, "%s:%d ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return SDR_INARGERR;
    }

    //2、获取句柄
    ret = GetDeviceHandle(hSessionHandle, &hHandle);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d GetDeviceHandle failed, ret=0x%08x", __FUNCTION__, __LINE__, ret);
        return ret;
    }


    ret = SOFT_ReadKey(hHandle, uiKeyIndex, pucKey, &uiKeyLen);
    if (0 != ret)
    {
        LOG_Write(NULL, "%s:%d SOFT_ReadKey ret = 0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_UNKNOWERR;
    }
    //3、导入会话密钥
    ret = ImportSessKey(hHandle, pucKey, uiKeyLen, phKeyHandle);
    if (0 != ret)
    {
        LOG_Write(NULL, "%s:%d ImportSessKey ret = 0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_UNKNOWERR;
    }

    return ret;

}

//sign key ?

int SDF_CreateKeyPair_RSA(void *hSessionHandle, unsigned int bits, unsigned int uiKeyIndex)
{

    int ret = SDR_OK;
    void *hHandle = NULL;
    unsigned int uiKeyBits =bits;
    RSArefPublicKey pucPublicKey;
    RSArefPrivateKey pucPrivateKey;
    ret = SDF_GenerateKeyPair_RSA(hSessionHandle, uiKeyBits, &pucPublicKey, &pucPrivateKey);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d SDF_GenerateKeyPair_RSA ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_UNKNOWERR;
    }
    ret = SDF_ImportSignPublicKey_RSA(hSessionHandle, uiKeyIndex, &pucPublicKey);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d SDF_ImportSignPublicKey_RSA ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_UNKNOWERR;
    }
    ret = SDF_ImportSignPrivateKey_RSA(hSessionHandle, uiKeyIndex, &pucPrivateKey);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d SDF_ImportSignPrivateKey_RSA ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_UNKNOWERR;
    }
    return ret;


}


int SDF_CreateKeyPairECC(void *hSessionHandle, unsigned int uiKeyIndex, unsigned int uiAlgID, unsigned int uiKeyBits)
{
    int ret = SDR_OK;

    ECCrefPublicKey pucPublicKey;
    ECCrefPrivateKey pucPrivateKey;

    ret = SDF_GenerateKeyPair_ECC(hSessionHandle, uiAlgID, uiKeyBits, &pucPublicKey, &pucPrivateKey);
    {
        LOG_Write(NULL, "%s:%d SDF_ImportSignPrivateKey_RSA ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_UNKNOWERR;
    }

    ret = SDF_ImportSignPublicKey_ECC(hSessionHandle, uiKeyIndex, &pucPublicKey);
    {
        LOG_Write(NULL, "%s:%d SDF_ImportSignPrivateKey_RSA ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_UNKNOWERR;
    }

    ret = SDF_ImportSignPrivateKey_ECC(hSessionHandle, uiKeyIndex, &pucPrivateKey);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d SDF_ImportSignPrivateKey_RSA ret=0x%08x", __FUNCTION__, __LINE__, ret);
        ret = SDR_UNKNOWERR;
    }
    return ret;

}

//扩展
int SDF_InternalSign_ECC_EX(
                           void *hSessionHandle, 
                           unsigned int uiISKIndex, 
                           unsigned int uiAlgID, 
                           unsigned char *pucData, 
                           unsigned int uiDataLength, 
                           unsigned char *pucSignature, 
                           unsigned int *pucSignLength)
{
    int ret = SDR_OK;

    if (uiAlgID != SGD_SM2 && uiAlgID != SGD_SM2_1 && uiAlgID != SGD_SM2_2 && uiAlgID != SGD_SM2_3)
    {
        LOG_Write(NULL, "%s:%d uiAlgID not support, uiAlgID = 0x%08x", __FUNCTION__, __LINE__, uiAlgID);
        return SDR_ALGNOTSUPPORT;
    }

    memset(pucSignature, 0, sizeof(ECCSignature));
	
    ret = SDF_InternalSign_ECC(hSessionHandle,uiISKIndex, uiAlgID, pucData,uiDataLength,(ECCSignature *)pucSignature);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d SDF_InternalSign_ECC error", __FUNCTION__, __LINE__);
    }
    *pucSignLength =sizeof(ECCSignature) ;
    return ret;
}




//扩展
int SDF_InternalVerify_ECC_EX(
                           void *hSessionHandle, 
                           unsigned int uiIPKIndex, 
                           unsigned int uiAlgID, 
                           unsigned char *pucData, 
                           unsigned int uiDataLength, 
                           unsigned char *pucSignature, 
                           unsigned int pucSignLength)
{

    int ret = SDR_OK;

    if (uiAlgID != SGD_SM2 && uiAlgID != SGD_SM2_1 && uiAlgID != SGD_SM2_2 && uiAlgID != SGD_SM2_3)
    {
        LOG_Write(NULL, "%s:%d uiAlgID not support, uiAlgID = 0x%08x", __FUNCTION__, __LINE__, uiAlgID);
        return SDR_ALGNOTSUPPORT;
    }


    if (pucSignLength != sizeof(ECCSignature) )
    {
        LOG_Write(NULL, "%s:%d pucSignLength not support, uiAlgID = 0x%08x", __FUNCTION__, __LINE__, uiAlgID);
        return SDR_INARGERR;
    }


	
    ret = SDF_InternalVerify_ECC(hSessionHandle, uiIPKIndex, uiAlgID, pucData, uiDataLength,(ECCSignature *)pucSignature);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d SDF_InternalVerify_ECC error", __FUNCTION__, __LINE__);
    }
    
    return ret;

}


//扩展
int SDF_ExternalVerify_ECC_EX(
                           void *hSessionHandle, 
                           unsigned int uiAlgID, 
                           ECCrefPublicKey *pucPublicKey, 
                           unsigned char *pucDataInput, 
                           unsigned int uiInputLength, 
                           unsigned char *pucSignature, 
                           unsigned int pucSignLength)
{


    int ret = SDR_OK;

    if (uiAlgID != SGD_SM2 && uiAlgID != SGD_SM2_1 && uiAlgID != SGD_SM2_2 && uiAlgID != SGD_SM2_3)
    {
        LOG_Write(NULL, "%s:%d uiAlgID not support, uiAlgID = 0x%08x", __FUNCTION__, __LINE__, uiAlgID);
        return SDR_ALGNOTSUPPORT;
    }


    if (pucSignLength != sizeof(ECCSignature) )
    {
        LOG_Write(NULL, "%s:%d pucSignLength not support, uiAlgID = 0x%08x", __FUNCTION__, __LINE__, uiAlgID);
        return SDR_INARGERR;
    }

    ret = SDF_ExternalVerify_ECC(hSessionHandle, uiAlgID,pucPublicKey, pucDataInput, uiInputLength,(ECCSignature *)pucSignature);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d SDF_ExternalVerify_ECC error", __FUNCTION__, __LINE__);
    }

    return ret;

}


//扩展
int SDF_ExternalEncrypt_ECC_EX(
                           void *hSessionHandle,
                           unsigned int uiAlgID, 
                           ECCrefPublicKey *pucPublicKey, 
                           unsigned char *pucData, 
                           unsigned int uiDataLength, 
                           unsigned char *pucEncData, 
                           unsigned int *uiEncDataLength)
{
    int ret = SDR_OK;

    unsigned char pEncData[16*1024] = {0};

    ret = SDF_ExternalEncrypt_ECC(hSessionHandle, uiAlgID,pucPublicKey,pucData,uiDataLength,(ECCCipher *)pEncData);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d SDF_ExternalEncrypt_ECC error", __FUNCTION__, __LINE__);
    }

    memcpy(pucEncData, ((ECCCipher *)pEncData)->x + ECC_KEY_OFFSET, 32);
    memcpy(pucEncData + 32, ((ECCCipher *)pEncData)->y + ECC_KEY_OFFSET, 32);
    memcpy(pucEncData + 64, ((ECCCipher *)pEncData)->M, 32);
    memcpy(pucEncData + 96, ((ECCCipher *)pEncData)->C, ((ECCCipher *)pEncData)->L);
    *uiEncDataLength = ((ECCCipher *)pEncData)->L + 96;

    return ret;
}




//扩展
int SDF_InternalEncrypt_ECC(
                           void *hSessionHandle,
                           unsigned int uiIPKIndex, 
                           unsigned int uiAlgID, 
                           unsigned char *pucData, 
                           unsigned int uiDataLength, 
                           ECCCipher *pucEncData)
{
    int ret = SDR_OK;
    ECCrefPublicKey pucPublicKey;
    ret = SDF_ExportEncPublicKey_ECC(hSessionHandle, uiIPKIndex, &pucPublicKey);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d SDF_ExportEncPublicKey_ECC error", __FUNCTION__, __LINE__);
	goto EXIT;
    }

    ret = SDF_ExternalEncrypt_ECC(hSessionHandle,uiAlgID,&pucPublicKey,pucData,uiDataLength,pucEncData);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d SDF_ExternalEncrypt_ECC error", __FUNCTION__, __LINE__);
    }

EXIT:
    return ret;

}

//扩展
int SDF_InternalEncrypt_ECC_EX(
                           void *hSessionHandle,
                           unsigned int uiIPKIndex, 
                           unsigned int uiAlgID, 
                           unsigned char *pucData, 
                           unsigned int uiDataLength, 
                           unsigned char *pucEncData, 
                           unsigned int *uiEncDataLength)
{
    int ret = SDR_OK;
    ECCrefPublicKey pucPublicKey;
    ret = SDF_ExportEncPublicKey_ECC(hSessionHandle, uiIPKIndex, &pucPublicKey);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d SDF_ExportEncPublicKey_ECC error", __FUNCTION__, __LINE__);
	goto EXIT;
    }

    ret = SDF_ExternalEncrypt_ECC_EX(hSessionHandle,uiAlgID,&pucPublicKey,pucData,uiDataLength,pucEncData,uiEncDataLength);
    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d SDF_ExternalEncrypt_ECC_EX error", __FUNCTION__, __LINE__);
    }

EXIT:
    return ret;

}

//扩展
int SDF_InternalDecrypt_ECC_EX(
                           void *hSessionHandle,
                           unsigned int uiISKIndex, 
                           unsigned int uiAlgID,
                           unsigned char *pucEncData, 
                           unsigned int uiEncDataLength,
                           unsigned char *pucData, 
                           unsigned int *uiDataLength)
{
    int ret = SDR_OK;
    unsigned char pEncData[16*1024] = {0};


    memcpy(((ECCCipher *)pEncData)->x + ECC_KEY_OFFSET,pucEncData,  32);
    memcpy(((ECCCipher *)pEncData)->y + ECC_KEY_OFFSET,pucEncData + 32, 32);
    memcpy( ((ECCCipher *)pEncData)->M, pucEncData + 64, 32);
    memcpy(((ECCCipher *)pEncData)->C, pucEncData + 96,  ((ECCCipher *)pEncData)->L);
    ((ECCCipher *)pEncData)->L = uiEncDataLength;


    ret = SDF_InternalDecrypt_ECC( hSessionHandle,uiAlgID,uiISKIndex,(ECCCipher *)pEncData,pucData,uiDataLength);

    if (SDR_OK != ret)
    {
        LOG_Write(NULL, "%s:%d SDF_ExternalEncrypt_ECC_EX error", __FUNCTION__, __LINE__);
    }  
    return ret;
}


// P10 //扩展
int SDF_GenP10(
               void *hSessionHandle, 
               unsigned char *country, 
               unsigned char *province, 
               unsigned char *city, 
               unsigned char *organization, 
               unsigned char *unit, 
               unsigned int iCerType, 
               unsigned int uiISKIndex, 
               unsigned char *p10Info, 
               unsigned int *p10InfoLen)
{
//todo 
return 0;

}
















