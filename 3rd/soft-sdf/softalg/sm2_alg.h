/**
 * @file 
 * @brief SM2算法接口
 * @author cws
 * @version 1.1
 * @date
 */
#ifndef _SM2ALG_H_
#define _SM2ALG_H_


#define SM2_RES_OK      0     //成功
#define SM2_RES_ERR     -1    //错误
#define SM2_RES_PARAM   -2    //传入参数错误
#define SM2_RES_BUFFER  -3    //传入buffer空间不足
#define SM2_ENC_A3      -4    //加密A3错误，[h]P为无穷远点
#define SM2_ENC_A5      -5    //加密A5错误，t为0
#define SM2_DEC_DATA    -6    //SM2密文格式不正确(要求格式04 C1 C2 C3)
#define SM2_DEC_B1      -7    //解密B1步错误,C1不正确
#define SM2_DEC_B2      -8    //解密B2步错误,S为无穷远点
#define SM2_DEC_B4      -9	  //解密B4步错误,t为0
#define SM2_DEC_B6      -10   //解密B6步错误,C3验证失败
#define SM2_VRF_B1      -11   //验签B1步失败,r值不合法
#define SM2_VRF_B2      -12   //验签B2步失败,s值不合法
#define SM2_VRF_B5      -13   //验签B5步错误,t为0
#define SM2_VRF_B7      -14   //验签B5步失败,R!=r

#ifdef __cplusplus
extern "C"
{
#endif

#define SM2_MAX_BITS		256
#define SM2_MAX_LEN			(SM2_MAX_BITS / 8)
#define USER_CURVE          //是否支持自定义曲线
#define SM2_KEY_AGREE         //是否支持SM2密钥协商
#define MAX_CIPHER_LEN 4096    //支持的最大密文长度

#define INITIATOR 1 //密钥协商发起方
#define RESPONDER 0 //密钥协商响应方

///SM2公钥结构
typedef struct SM2PublicKey_st
{
    unsigned long  bits;
    unsigned char	x[SM2_MAX_LEN];
    unsigned char	y[SM2_MAX_LEN];
} SM2PublicKey, ECC256PublicKey;

///SM2私钥结构
typedef struct SM2PrivateKey_st
{
    unsigned long bits;
    unsigned char d[SM2_MAX_LEN];
} SM2PrivateKey, ECC256PrivateKey;

///SM2曲线参数
typedef struct SM2Curve_st
{
    unsigned char p[SM2_MAX_LEN];
    unsigned char a[SM2_MAX_LEN];
    unsigned char b[SM2_MAX_LEN];
    unsigned char n[SM2_MAX_LEN];
    unsigned char Gx[SM2_MAX_LEN];
    unsigned char Gy[SM2_MAX_LEN];
} SM2Curve, ECC256Curve;

///SM2签名结果
typedef struct SM2Signature_st
{
    unsigned char r[SM2_MAX_LEN];
    unsigned char s[SM2_MAX_LEN];
} SM2Signature, ECC256Signature;

//带长度标识的数据
typedef struct oct_string_t
{
    int len;
    unsigned char data[SM2_MAX_LEN];
} oct_string;
#define ex_random oct_string
#define ex_hash oct_string

extern SM2Curve default_sm2_curve;
extern SM2Curve nistp256_param;

/**
* @brief 初始化(兼容旧接口，无需调用)
*
* @param[in]  cb_malloc   传入NULL
* @param[in]  cb_free     传入NULL
* @param[in]  cb_random   传入NULL
*
* @return 错误码
* @retval SM2_RES_OK  成功
*/
void SM2_lib_init(void * cb_malloc, void * cb_free, void * cb_random);

/**
* @brief SM2签名
*
* @param[in]    curve;    params of elliptic curves,default NULL
* @param[in]	pub;      SM2 public key
* @param[in]	priv;     SM2 private key
* @param[in]	id;       user id
* @param[in]	idlen;    length of id
* @param[in]	message;  data need to signs, message 如果是经过预处理的e值，id和pub为NULL
* @param[in]	mlen;     length of message
* @param[out]	value;    signature
*
* @return 错误码
* @retval SM2_RES_OK  成功
*/
int SM2_signature(SM2Curve *curve, SM2PublicKey *pub, SM2PrivateKey *priv, unsigned char *id, int idlen, unsigned char *message, int mlen, SM2Signature *value);

/**
* @brief SM2验签
*
* @param[in]    curve;    params of elliptic curves,default NULL
* @param[in]	pub;      SM2 public key
* @param[in]	id;       This is the user id who signed the message
* @param[in]	idlen;    length of id
* @param[in]	message;  date need to signs，message 如果是经过预处理的e值，id和pub为NULL
* @param[in]	mlen;     length of message
* @param[in]	value;    signature
*
* @return 错误码
* @retval SM2_RES_OK  成功
*/
int SM2_verify(SM2Curve *curve, SM2PublicKey *pub, unsigned char *id, int idlen, unsigned char *message, int mlen, SM2Signature *value);

/**
* @brief SM2加密
*
* @param[in]    curve;      params of elliptic curves,default NULL
* @param[in]	pub;        SM2 public key
* @param[in]	datain;     data need to encrypt
* @param[in]	dlen;	    length of datain
* @param[in/out]	outlen;     length of buffer,length of ciphertext
* @param[in/out]	dataout;    buffer to store ciphertext,密文结构 04 C1 C2 C3
*
* @return 错误码
* @retval SM2_RES_OK  成功
*/
int SM2_public_encrypt(SM2Curve *curve, SM2PublicKey *pub, unsigned char *datain, int dlen, unsigned char *dataout, int *outlen);

/**
* @brief SM2解密
*
* @param[in]     curve;       params of elliptic curves,default NULL
* @param[in]	 priv;        SM2 private key
* @param[in]	 datain;      digest need to decrypt，密文结构 04 C1 C2 C3
* @param[in]	 dlen;        length of datain
* @param[in/out] outlen;      length of buffer, length of plaintext
* @param[in/out] dataout;     buffer to store plaintext
*
* @return 错误码
* @retval SM2_RES_OK  成功
*/
int SM2_private_decrypt(SM2Curve *curve, SM2PrivateKey *priv, unsigned char *datain, int dlen, unsigned char *dataout, int *outlen);

/**
* @brief ecc加密
*
* @param[in]    curve;      params of elliptic curves,default NULL
* @param[in]	pub;        ECC public key
* @param[in]	datain;     data need to encrypt
* @param[in]	dlen;	    length of datain
* @param[in/out]	outlen;     length of buffer,length of ciphertext
* @param[in/out]	dataout;    buffer to store ciphertext,密文结构 04 C1 C2 C3
*
* @return 错误码
* @retval SM2_RES_OK  成功
*/
int ECC_public_encrypt(ECC256Curve *curve, ECC256PublicKey *pub, unsigned char *datain, int dlen, unsigned char *dataout, int *outlen);

/**
* @brief ecc解密
*
* @param[in]     curve;       params of elliptic curves,default NULL
* @param[in]	 priv;        ECC private key
* @param[in]	 datain;      digest need to decrypt，密文结构 04 C1 C2 C3
* @param[in]	 dlen;        length of datain
* @param[in/out] outlen;      length of buffer, length of plaintext
* @param[in/out] dataout;     buffer to store plaintext
*
* @return 错误码
* @retval SM2_RES_OK  成功
*/
int ECC_private_decrypt(ECC256Curve *curve, ECC256PrivateKey *priv, unsigned char *datain, int dlen, unsigned char *dataout, int *outlen);

/**
* @brief ECC解密后半部分实现
*
* @param[in] xybuf		C1与私钥点乘结果
* @param[in] datain		密文数据
* @param[in] dlen		密文数据长度
* @param[out] dataout	明文buf
* @param[out] outlen	明文长度
*
* @return 错误码
* @retval SM2_RES_OK 成功
*/
int ECC_private_decrypt_final(unsigned char* xybuf, unsigned char *datain, int dlen, unsigned char *dataout, int *outlen);

/**
* @brief SM2解密后半部分实现
*
* @param[in] xybuf		C1与私钥点乘结果
* @param[in] datain		密文数据
* @param[in] dlen		密文数据长度
* @param[out] dataout	明文buf
* @param[out] outlen	明文长度
*
* @return 错误码
* @retval SM2_RES_OK 成功
*/
int SM2_private_decrypt_final(unsigned char* xybuf, unsigned char *datain, int dlen, unsigned char *dataout, int *outlen);

/**
* @brief SM2公钥压缩
*
* @param[in]     y;       公钥y值
*
* @return 压缩值（1bit）
*/
unsigned char  SM2_compress_y(unsigned char* y);

/**
* @brief SM2公钥解压缩
*
* @param[in]     curve;    params of elliptic curves,default NULL
* @param[out]	 x;        返回公钥x
* @param[out]	 y;        返回公钥y
* @param[in]     y_lsb;    有压缩值
*
* @return 错误码
* @retval SM2_RES_OK  成功
*/
int SM2_decomp_xy(SM2Curve *curve, unsigned char* x, unsigned char* y, unsigned char  y_lsb);

/**
* @brief ECC椭圆曲线点乘，Q = k*P
*
* @param[in]     curve;    params of elliptic curves,default NULL
* @param[in]	 k;        k倍点
* @param[in]	 P;        椭圆曲线上的点P
* @param[in/out] Q;        椭圆曲线上的点Q
*
* @return 错误码
* @retval SM2_RES_OK  成功
*/
int ECC_mult(ECC256Curve *curve, ECC256PrivateKey *k, ECC256PublicKey * P, ECC256PublicKey * Q);
/**
* @brief ECC椭圆曲线点加，Q = P1 + P2
*
* @param[in]     curve;    params of elliptic curves,default NULL
* @param[in]	 P1;       椭圆曲线上的点P1
* @param[in]	 P2;       椭圆曲线上的点P2
* @param[in/out] Q;        椭圆曲线上的点Q
*
* @return 错误码
* @retval SM2_RES_OK  成功
*/
int ECC_add(ECC256Curve *curve, ECC256PublicKey *P1, ECC256PublicKey * P2, ECC256PublicKey * Q);

#ifdef SM2_KEY_AGREE
/**
* @brief 产生SM2密钥对
*
* @param[in]     curve;    params of elliptic curves,default NULL
* @param[out]	 tpub;     返回SM2公钥
* @param[out]	 tpriv;    返回SM2私钥
*
* @return 错误码
* @retval SM2_RES_OK  成功
*/
int SM2_exchange_random(SM2Curve *curve, SM2PublicKey *tpub, SM2PrivateKey *tpriv);

/**
* @brief 产生SM2密钥对
*
* @param[in]	 curve;         params of elliptic curves,default NULL
* @param[in]	 mytpriv;       my temp private key
* @param[in]	 mytpub;        my temp public key
* @param[in]	 peertpub;      peer temp public key generated by SM2_exchange_random()
* @param[in]	 myid;          my user id
* @param[in]	 myidlen;		length of myid
* @param[in]	 peerid;        peer user id
* @param[in]	 peeridlen;		length of peerid
* @param[in]	 mypub;         my  SM2 publie key
* @param[in]	 mypriv;	    my  SM2 private key
* @param[in]	 peerpub;       peer SM2 publie key
* @param[in]	 keylen;        length of key
* @param[in]	 role;		    exchange initiator or responder
* @param[in]	 key            session key
* @param[in]	 s1             verify hash  1
* @param[in]     s2             verify hash  2
*
* @return 错误码
* @retval SM2_RES_OK  成功
*/
int SM2_exchange_cale(SM2Curve *curve, SM2PrivateKey *mytpriv, SM2PublicKey *mytpub, SM2PublicKey *peertpub, unsigned char *myid, int myidlen,
                      unsigned char *peerid, int peeridlen, SM2PublicKey *mypub, SM2PrivateKey *mypriv, SM2PublicKey *peerpub, int keylen, int role,
                      unsigned char *key, ex_hash *s1, ex_hash *s2);

#endif


/**
* @brief 产生SM2密钥对
*
* @param[in]	 curveType;     curve type 0 sm2, 1 nistp256
* @param[in]	 fBuf;			f1(ck, l)结果/f2(ek, l)结果
* @param[in]	 fBufLen;       BuferLen
* @param[in]	 seedPubKey;      peer temp public key generated by SM2_exchange_random()
* @param[in]	 extPubKey;          my user id
*
* @return 错误码
* @retval SM2_RES_OK  成功
*/
int ECC_BKCalcExtPubkey(int curveType, unsigned char *fBuf, unsigned int fBufLen, unsigned char *seedPubKey, unsigned char *extPubKey);

/**
* @brief SM2签名值检查
*
* @param[in]	 signature		签名值，r||s 共64字节 
*
* @return 错误码
* @retval SM2_RES_OK  成功
*/
int SM2_signature_check(unsigned char *signature);

/**
* @brief SM2公钥检查
*
* @param[in]	 pubkey			公钥，x||y 共64字节
*
* @return 错误码
* @retval SM2_RES_OK  成功
*/
int SM2_pubkey_check(unsigned char *pubkey);

/**
* @brief 检查点是否在曲线上
*
* @param[in]    curve   曲线参数
* @param[in]    x       点x缓冲区   
* @param[in]    y       点y缓冲区       
*
* @return 错误码
* @retval SM2_RES_OK  成功
*/
int check_point_in_curve(SM2Curve *curve, unsigned char *x, unsigned char *y);

/**
* @brief 检查是不是无穷远点
*
* @param[in]    x       点x缓冲区   
* @param[in]    y       点y缓冲区       
*
* @return 错误码
* @retval SM2_RES_OK  成功
*/
int check_point_infinity(unsigned char *x, unsigned char *y);


int SM2_genkeypair(SM2PublicKey *publickey, SM2PrivateKey *privatekey);

#ifdef __cplusplus
}
#endif

#endif


