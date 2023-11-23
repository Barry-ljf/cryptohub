#include "sm2.h"

// ECC椭圆曲线参数（SM2标准推荐参数）
static unsigned char SM2_p[32] = {
	0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static unsigned char SM2_a[32] = {
	0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC};
static unsigned char SM2_b[32] = {
	0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34, 0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
	0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92, 0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93};
static unsigned char SM2_n[32] = {
	0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	0x72, 0x03, 0xDF, 0x6B, 0x21, 0xC6, 0x05, 0x2B, 0x53, 0xBB, 0xF4, 0x09, 0x39, 0xD5, 0x41, 0x23};
static unsigned char SM2_Gx[32] = {
	0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
	0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1, 0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7};
static unsigned char SM2_Gy[32] = {
	0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
	0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40, 0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0};
static unsigned char SM2_h[32] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};


big para_p, para_a, para_b, para_n, para_Gx, para_Gy, para_h;
epoint *G;
miracl *mip;


/*
	功能：SM2算法椭圆曲线参数初始化
	输入：无
	输出：无
	返回：0成功 !0失败
*/
int SM2_standard_init(void)
{
	epoint *nG;

	mip = mirsys(10000, 16);
	mip->IOBASE = 16;

	para_p = mirvar(0);
	para_a = mirvar(0);
	para_b = mirvar(0);
	para_n = mirvar(0);
	para_Gx = mirvar(0);
	para_Gy = mirvar(0);
	para_h = mirvar(0);

	G = epoint_init();
	nG = epoint_init();

	bytes_to_big(SM2_NUMWORD, SM2_p, para_p);
	bytes_to_big(SM2_NUMWORD, SM2_a, para_a);
	bytes_to_big(SM2_NUMWORD, SM2_b, para_b);
	bytes_to_big(SM2_NUMWORD, SM2_n, para_n);
	bytes_to_big(SM2_NUMWORD, SM2_Gx, para_Gx);
	bytes_to_big(SM2_NUMWORD, SM2_Gy, para_Gy);
	bytes_to_big(SM2_NUMWORD, SM2_h, para_h);

	/*Initialises GF(p) elliptic curve.(MR_PROJECTIVE specifying projective coordinates)*/
	ecurve_init(para_a, para_b, para_p, MR_PROJECTIVE);

	/*initialise point G*/
	if (!epoint_set(para_Gx, para_Gy, 0, G)) return ERR_ECURVE_INIT;
	
	ecurve_mult(para_n, G, nG);
	
	/*test if the order of the point is n*/
	if (!point_at_infinity(nG)) return ERR_ORDER;

	return 0;
}


/*测试该点是否在SM2椭圆曲线上*/
int Test_Point(epoint* point)
{
	big x, y, x_3, tmp;
	
	x = mirvar(0);
	y = mirvar(0);
	x_3 = mirvar(0);
	tmp = mirvar(0);

	//test if y^2 = x^3 + ax + b
	epoint_get(point, x, y);
	power(x, 3, para_p, x_3);	//x_3 = x^3 mod p
	multiply(x, para_a, x); 	//x = a * x
	divide(x, para_p, tmp); 	//x = a * x mod p, tmp = a * x / p
	add(x_3, x, x);				//x = x^3 + ax
	add(x, para_b, x);			//x = x^3 + ax + b
	divide(x, para_p, tmp);		//x = x^3 + ax + b mod p
	power(y, 2, para_p, y);		//y = y^2 mod p
	
	if (mr_compare(x, y) != 0) return ERR_NOT_VALID_POINT;

	return 0;
}

/*测试公钥点有效性*/
int Test_PubKey(epoint *pubKey)
{
	big x, y, x_3, tmp;

	epoint *nP;
	x = mirvar(0);
	y = mirvar(0);
	x_3 = mirvar(0);
	tmp = mirvar(0);

	nP = epoint_init();

	if (point_at_infinity(pubKey)) return ERR_INFINITY_POINT;
	
	//test if x < p and y<p both hold
	epoint_get(pubKey, x, y);
	if ((mr_compare(x, para_p) != -1) || (mr_compare(y, para_p) != -1)) return ERR_NOT_VALID_ELEMENT;

	if (Test_Point(pubKey) != 0) return ERR_NOT_VALID_POINT;

	//test if the order of pubKey is equal to n
	//nP=[n]P if np is point NOT at infinity, return error
	ecurve_mult(para_n, pubKey, nP);
	if (!point_at_infinity(nP))	return ERR_ORDER;

	return 0;
}

/*测试私钥有效性 d range [1, n-2]*/
int Test_PrivKey(unsigned char privkey[])
{
	big one, decr_n;
	big d;

	one = mirvar(0);
	decr_n = mirvar(0);
	d = mirvar(0);

	SM2_standard_init();

	bytes_to_big(SM2_NUMWORD, privkey, d);

	convert(1, one);
	decr(para_n, 2, decr_n);

	if ((mr_compare(d, one) < 0) | (mr_compare(d, decr_n) > 0)) return 1;
	
	return 0;
}

/*测试大数是否在范围[1, n-1]内*/
int Test_Range(big x)
{
	big one, decr_n;

	one = mirvar(0);
	decr_n = mirvar(0);

	convert(1, one);
	decr(para_n, 1, decr_n);

	if ((mr_compare(x, one) < 0) | (mr_compare(x, decr_n) > 0)) return 1;
	
	return 0;
}

/* test if the given array is all zero */
int Test_Null(unsigned char array[], int len)
{
	int i;

	for (i = 0; i < len; i++) if (array[i] != 0x00) return 0;

	return 1;
}

/* test if the big x is zero */
int Test_Zero(big x)
{
	big zero;
	
	zero = mirvar(0);
	if (mr_compare(x, zero) == 0) return 1;

	return 0;
}

/* test if the big x is order n */
int Test_n(big x)
{
	if (mr_compare(x, para_n) == 0) return 1;

	return 0;
}

/* key derivation function */
void SM3_kdf(unsigned char Z[], unsigned short zlen, unsigned short klen, unsigned char K[])
{
	unsigned short i, j, t;
	unsigned int bitklen;
	SM3_STATE md;
	unsigned char Ha[SM2_NUMWORD];
	unsigned char ct[4] = {0, 0, 0, 1};

	bitklen = klen * 8;
	
	if (bitklen % SM2_NUMBITS)
		t = bitklen / SM2_NUMBITS + 1;
	else
		t = bitklen / SM2_NUMBITS;

	//s4: K = Ha1 || Ha2 || ...
	for (i = 1; i < t; i++)
	{
		//s2: Hai = Hv(Z || ct)
		SM3_init(&md);
		SM3_process(&md, Z, zlen);
		SM3_process(&md, ct, 4);
		SM3_done(&md, Ha);
		memcpy((K + SM2_NUMWORD * (i - 1)), Ha, SM2_NUMWORD);

		if (ct[3] == 0xff)
		{
			ct[3] = 0;
			if (ct[2] == 0xff)
			{
				ct[2] = 0;
				if (ct[1] == 0xff)
				{
					ct[1] = 0;
					ct[0]++;
				}
				else 
					ct[1]++;
			}
			else 
				ct[2]++;
		}
		else 
			ct[3]++;
	}

	//s3
	SM3_init(&md);
	SM3_process(&md, Z, zlen);
	SM3_process(&md, ct, 4);
	SM3_done(&md, Ha);

	if(bitklen % SM2_NUMBITS)
	{
		i = (SM2_NUMBITS - bitklen + SM2_NUMBITS * (bitklen / SM2_NUMBITS)) / 8;
		j = (bitklen - SM2_NUMBITS * (bitklen / SM2_NUMBITS)) / 8;
		memcpy((K + SM2_NUMWORD * (t - 1)), Ha, j);
	}
	else
	{
		memcpy((K + SM2_NUMWORD * (t - 1)), Ha, SM2_NUMWORD);
	}
}


/*
	功能：由私钥d生成公钥点G(x,y)
	输入：priKey私钥d
	输出：pubKey公钥点G(x,y)
	返回：0成功 !0失败
*/
int SM2_keygeneration_1(big priKey, epoint *pubKey)
{
	int i = 0;
	big x, y;
	
	x = mirvar(0);
	y = mirvar(0);

	//mip = mirsys(1000, 16);
	//mip->IOBASE = 16;

	ecurve_mult(priKey, G, pubKey);
	epoint_get(pubKey, x, y);

	if(0 != (i=Test_PubKey(pubKey))) return i;

	return 0;
}

/*
	功能：用公钥点G(x,y)对消息进行加密
	输入：randK随机数、pubKey公钥点、M明文、klen消息长度
	输出：C密文
	返回：0成功 !0失败
*/
int SM2_standard_encrypt(unsigned char* randK, epoint *pubKey, unsigned char M[], int klen, unsigned char C[])
{
	big C1x, C1y, x2, y2, rand;
	epoint *C1, *kP, *S;
	int i = 0;
	unsigned char x2y2[SM2_NUMWORD * 2] = {0};
	SM3_STATE md;
	
	C1x = mirvar(0);
	C1y = mirvar(0);
	x2 = mirvar(0);
	y2 = mirvar(0);
	rand = mirvar(0);
	C1 = epoint_init();
	kP = epoint_init();
	S = epoint_init();

	//step2. calculate C1 = [k]G = (rGx, rGy)
	bytes_to_big(SM2_NUMWORD, randK, rand);
	ecurve_mult(rand, G, C1);	//C1 = [k]G
	epoint_get(C1, C1x, C1y);
	big_to_bytes(SM2_NUMWORD, C1x, C, 1);
	big_to_bytes(SM2_NUMWORD, C1y, C + SM2_NUMWORD, 1);

	//step3. test if S = [h]pubKey if the point at infinity
	ecurve_mult(para_h, pubKey, S);
	if (point_at_infinity(S)) return ERR_INFINITY_POINT;

	//step4. calculate [k]PB = (x2, y2)
	ecurve_mult(rand, pubKey, kP);	//kP = [k]P
	epoint_get(kP, x2, y2);

	//step5. KDF(x2 || y2, klen)
	big_to_bytes(SM2_NUMWORD, x2, x2y2, 1);
	big_to_bytes(SM2_NUMWORD, y2, x2y2 + SM2_NUMWORD, 1);
	SM3_kdf(x2y2, SM2_NUMWORD * 2, klen, C + SM2_NUMWORD * 3);
	if (Test_Null(C + SM2_NUMWORD * 3, klen) != 0) return ERR_ARRAY_NULL;

	//step6. C2 = M^t
	for (i = 0; i < klen; i++) C[SM2_NUMWORD * 3 + i] = M[i] ^ C[SM2_NUMWORD * 3 + i];

	//step7. C3 = hash(x2, M, y2)
	SM3_init(&md);
	SM3_process(&md, x2y2, SM2_NUMWORD);
	SM3_process(&md, M, klen);
	SM3_process(&md, x2y2 + SM2_NUMWORD, SM2_NUMWORD);
	SM3_done(&md, C + SM2_NUMWORD * 2);
	
	return 0;
}


int SM2_standard_encrypt_2(unsigned char* randK, unsigned char px[], unsigned char py[], unsigned char M[], int klen, unsigned char C[])
{
	big x,y;
	epoint* pubkey;

	x = mirvar(0);
	y = mirvar(0);
	pubkey = epoint_init();

	bytes_to_big(SM2_NUMWORD, px, x);
	bytes_to_big(SM2_NUMWORD, py, y);
	epoint_set(x, y, 0, pubkey);

	return SM2_standard_encrypt(randK, pubkey, M, klen, C);
}


/*
	功能：用私钥d对消息进行解密
	输入：dB私钥、C密文、Clen密文长度
	输出：M明文
	返回：0成功 !0失败
*/
int SM2_standard_decrypt(big dB, unsigned char C[], int Clen, unsigned char M[])
{
	SM3_STATE md;
 	int i = 0;
	unsigned char x2y2[SM2_NUMWORD * 2] = {0};
	unsigned char hash[SM2_NUMWORD] = {0};
	big C1x, C1y, x2, y2;
	epoint *C1, *S, *dBC1;
	
	C1x = mirvar(0);
	C1y = mirvar(0);
	x2 = mirvar(0);
	y2 = mirvar(0);
	C1 = epoint_init();
	S = epoint_init();
	dBC1 = epoint_init();

	//step1. test if C1 fits the curve
	bytes_to_big(SM2_NUMWORD, C, C1x);
	bytes_to_big(SM2_NUMWORD, C + SM2_NUMWORD, C1y);
	epoint_set(C1x, C1y, 0, C1);

	if(0 != (i = Test_Point(C1))) return i;

	//step2. S = [h]C1 and test if S is the point at infinity
	ecurve_mult(para_h, C1, S);
	if (point_at_infinity(S)) return ERR_INFINITY_POINT;

	//step3. [dB]C1 = (x2, y2)
	ecurve_mult(dB, C1, dBC1);
	epoint_get(dBC1, x2, y2);
	big_to_bytes(SM2_NUMWORD, x2, x2y2, 1);
	big_to_bytes(SM2_NUMWORD, y2, x2y2 + SM2_NUMWORD, 1);

	//step4. t = KDF(x2 || y2, klen)
	SM3_kdf(x2y2, SM2_NUMWORD * 2, Clen - SM2_NUMWORD * 3, M);
	if (Test_Null(M, Clen - SM2_NUMWORD * 3) != 0) return ERR_ARRAY_NULL;
	
	//step5. M = C2^t
	for (i = 0; i < Clen - SM2_NUMWORD * 3; i++) M[i] = M[i] ^ C[SM2_NUMWORD * 3 + i];

	//step6. hash(x2, m, y2)
	SM3_init(&md);
	SM3_process(&md, x2y2, SM2_NUMWORD);
	SM3_process(&md, M, Clen - SM2_NUMWORD * 3);
	SM3_process(&md, x2y2 + SM2_NUMWORD, SM2_NUMWORD);
	SM3_done(&md, hash);
	
	if (memcmp(hash, C + SM2_NUMWORD * 2, SM2_NUMWORD) != 0) return ERR_C3_MATCH;
	
	return 0;
}

int SM2_standard_decrypt_2(unsigned char privkey[], unsigned char C[], int Clen, unsigned char M[])
{
	big d;

	d = mirvar(0);

	bytes_to_big(SM2_NUMWORD, privkey, d);

	return SM2_standard_decrypt(d, C, Clen, M);
}



/* test whether the SM2 calculation is correct by comparing the result with the standard data */
int SM2_enc_selftest()
{
	int tmp = 0, i = 0;
	unsigned char Cipher[115] = {0};
	unsigned char M[19] = {0};
	unsigned char kGxy[SM2_NUMWORD * 2] = {0};
	big ks, x, y;
	epoint *kG;

	//standard data
	unsigned char std_priKey[32] = {
		0x39, 0x45, 0x20, 0x8F, 0x7B, 0x21, 0x44, 0xB1, 0x3F, 0x36, 0xE3, 0x8A, 0xC6, 0xD3, 0x9F, 0x95,
		0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xB5, 0x1A, 0x42, 0xFB, 0x81, 0xEF, 0x4D, 0xF7, 0xC5, 0xB8};
	unsigned char std_pubKey[64] = {
		0x09, 0xF9, 0xDF, 0x31, 0x1E, 0x54, 0x21, 0xA1, 0x50, 0xDD, 0x7D, 0x16, 0x1E, 0x4B, 0xC5, 0xC6,
		0x72, 0x17, 0x9F, 0xAD, 0x18, 0x33, 0xFC, 0x07, 0x6B, 0xB0, 0x8F, 0xF3, 0x56, 0xF3, 0x50, 0x20,
		0xCC, 0xEA, 0x49, 0x0C, 0xE2, 0x67, 0x75, 0xA5, 0x2D, 0xC6, 0xEA, 0x71, 0x8C, 0xC1, 0xAA, 0x60,
		0x0A, 0xED, 0x05, 0xFB, 0xF3, 0x5E, 0x08, 0x4A, 0x66, 0x32, 0xF6, 0x07, 0x2D, 0xA9, 0xAD, 0x13};
	unsigned char std_rand[32] = {
		0x59, 0x27, 0x6E, 0x27, 0xD5, 0x06, 0x86, 0x1A, 0x16, 0x68, 0x0F, 0x3A, 0xD9, 0xC0, 0x2D, 0xCC,
		0xEF, 0x3C, 0xC1, 0xFA, 0x3C, 0xDB, 0xE4, 0xCE, 0x6D, 0x54, 0xB8, 0x0D, 0xEA, 0xC1, 0xBC, 0x21};
	unsigned char std_Message[19] = {
		0x65, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x73, 0x74, 0x61, 0x6E, 0x64, 
		0x61, 0x72, 0x64};
	unsigned char std_Cipher[115] = {
		0x04, 0xEB, 0xFC, 0x71, 0x8E, 0x8D, 0x17, 0x98, 0x62, 0x04, 0x32, 0x26, 0x8E, 0x77, 0xFE, 0xB6,
		0x41, 0x5E, 0x2E, 0xDE, 0x0E, 0x07, 0x3C, 0x0F, 0x4F, 0x64, 0x0E, 0xCD, 0x2E, 0x14, 0x9A, 0x73,
		0xE8, 0x58, 0xF9, 0xD8, 0x1E, 0x54, 0x30, 0xA5, 0x7B, 0x36, 0xDA, 0xAB, 0x8F, 0x95, 0x0A, 0x3C,
		0x64, 0xE6, 0xEE, 0x6A, 0x63, 0x09, 0x4D, 0x99, 0x28, 0x3A, 0xFF, 0x76, 0x7E, 0x12, 0x4D, 0xF0,
		0x59, 0x98, 0x3C, 0x18, 0xF8, 0x09, 0xE2, 0x62, 0x92, 0x3C, 0x53, 0xAE, 0xC2, 0x95, 0xD3, 0x03,
		0x83, 0xB5, 0x4E, 0x39, 0xD6, 0x09, 0xD1, 0x60, 0xAF, 0xCB, 0x19, 0x08, 0xD0, 0xBD, 0x87, 0x66,
		0x21, 0x88, 0x6C, 0xA9, 0x89, 0xCA, 0x9C, 0x7D, 0x58, 0x08, 0x73, 0x07, 0xCA, 0x93, 0x09, 0x2D, 
		0x65, 0x1E, 0xFA};
	
	mip= mirsys(1000, 16);
	mip->IOBASE = 16;
	x = mirvar(0);
	y = mirvar(0);
	ks = mirvar(0);
	kG = epoint_init();
	bytes_to_big(32, std_priKey, ks);	//ks is the standard private key
	
	//initiate SM2 curve
	SM2_standard_init();
	
	//generate key pair
	if(0 != (tmp = SM2_keygeneration_1(ks, kG)))
	{
		printf("[ERROR]%s %s: SM2_keygeneration_1() test error\n", __FILE__, __LINE__);
		return tmp;
	}
	
	epoint_get(kG, x, y);
	big_to_bytes(SM2_NUMWORD, x, kGxy, 1);
	big_to_bytes(SM2_NUMWORD, y, kGxy + SM2_NUMWORD, 1);
	if (memcmp(kGxy, std_pubKey, SM2_NUMWORD * 2) != 0)
	{
		printf("[ERROR]%s %s: SM2_keygeneration_1() test error\n", __FILE__, __LINE__);
		return ERR_SELFTEST_KG;
	}

	//encrypt data and compare the result with the standard data
	if(0 != (tmp = SM2_standard_encrypt(std_rand, kG, std_Message, 19, Cipher)))
	{
		printf("[ERROR]%s %s: SM2_standard_encrypt() test error\n", __FILE__, __LINE__);
		return tmp;
	}
		
	if (memcmp(Cipher, std_Cipher, 19 + SM2_NUMWORD * 3) != 0)
	{
		printf("[ERROR]%s %s: SM2_standard_encrypt() test error\n", __FILE__, __LINE__);
		return ERR_SELFTEST_ENC;
	}
	
	//decrypt cipher and compare the result with the standard data
	if(0 != (tmp = SM2_standard_decrypt(ks, Cipher, 115, M)))
	{
		printf("[ERROR]%s %s: SM2_standard_decrypt() test error\n", __FILE__, __LINE__);
		return tmp;
	}
		
	if (memcmp(M, std_Message, 19) != 0)
	{
		printf("[ERROR]%s %s: SM2_standard_decrypt() test error\n", __FILE__, __LINE__);
		return ERR_SELFTEST_DEC;
	}

	printf("SM2_enc_selftest pass\n");

	return 0;
}


/*
	功能：由私钥d生成公钥点G(x,y)
	输入：PriKey私钥d
	输出：Px公钥Gx、Py公钥Gy
	返回：0成功 !0失败
*/
int SM2_keygeneration_2(unsigned char PriKey[], unsigned char Px[], unsigned char Py[])
{
	int i = 0;
	big d, PAx, PAy;
	epoint *PA;

	SM2_standard_init();
	PA = epoint_init();

	d = mirvar(0);
	PAx = mirvar(0);
	PAy = mirvar(0);

	bytes_to_big(SM2_NUMWORD, PriKey, d);

	ecurve_mult(d, G, PA);
	epoint_get(PA, PAx, PAy);

	big_to_bytes(SM2_NUMWORD, PAx, Px, TRUE);
	big_to_bytes(SM2_NUMWORD, PAy, Py, TRUE);

	if(0 != (i = Test_PubKey(PA))) return i;
	
	return 0;
}