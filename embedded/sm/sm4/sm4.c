//#include "sm4.h"


const unsigned char Sbox[256] = {
	0Xd6, 0X90, 0Xe9, 0Xfe, 0Xcc, 0Xe1, 0X3d, 0Xb7, 0X16, 0Xb6, 0X14, 0Xc2, 0X28, 0Xfb, 0X2c, 0X05,
	0X2b, 0X67, 0X9a, 0X76, 0X2a, 0Xbe, 0X04, 0Xc3, 0Xaa, 0X44, 0X13, 0X26, 0X49, 0X86, 0X06, 0X99,
	0X9c, 0X42, 0X50, 0Xf4, 0X91, 0Xef, 0X98, 0X7a, 0X33, 0X54, 0X0b, 0X43, 0Xed, 0Xcf, 0Xac, 0X62,
	0Xe4, 0Xb3, 0X1c, 0Xa9, 0Xc9, 0X08, 0Xe8, 0X95, 0X80, 0Xdf, 0X94, 0Xfa, 0X75, 0X8f, 0X3f, 0Xa6,
	0X47, 0X07, 0Xa7, 0Xfc, 0Xf3, 0X73, 0X17, 0Xba, 0X83, 0X59, 0X3c, 0X19, 0Xe6, 0X85, 0X4f, 0Xa8,
	0X68, 0X6b, 0X81, 0Xb2, 0X71, 0X64, 0Xda, 0X8b, 0Xf8, 0Xeb, 0X0f, 0X4b, 0X70, 0X56, 0X9d, 0X35,
	0X1e, 0X24, 0X0e, 0X5e, 0X63, 0X58, 0Xd1, 0Xa2, 0X25, 0X22, 0X7c, 0X3b, 0X01, 0X21, 0X78, 0X87,
	0Xd4, 0X00, 0X46, 0X57, 0X9f, 0Xd3, 0X27, 0X52, 0X4c, 0X36, 0X02, 0Xe7, 0Xa0, 0Xc4, 0Xc8, 0X9e,
	0Xea, 0Xbf, 0X8a, 0Xd2, 0X40, 0Xc7, 0X38, 0Xb5, 0Xa3, 0Xf7, 0Xf2, 0Xce, 0Xf9, 0X61, 0X15, 0Xa1,
	0Xe0, 0Xae, 0X5d, 0Xa4, 0X9b, 0X34, 0X1a, 0X55, 0Xad, 0X93, 0X32, 0X30, 0Xf5, 0X8c, 0Xb1, 0Xe3,
	0X1d, 0Xf6, 0Xe2, 0X2e, 0X82, 0X66, 0Xca, 0X60, 0Xc0, 0X29, 0X23, 0Xab, 0X0d, 0X53, 0X4e, 0X6f,
	0Xd5, 0Xdb, 0X37, 0X45, 0Xde, 0Xfd, 0X8e, 0X2f, 0X03, 0Xff, 0X6a, 0X72, 0X6d, 0X6c, 0X5b, 0X51,
	0X8d, 0X1b, 0Xaf, 0X92, 0Xbb, 0Xdd, 0Xbc, 0X7f, 0X11, 0Xd9, 0X5c, 0X41, 0X1f, 0X10, 0X5a, 0Xd8,
	0X0a, 0Xc1, 0X31, 0X88, 0Xa5, 0Xcd, 0X7b, 0Xbd, 0X2d, 0X74, 0Xd0, 0X12, 0Xb8, 0Xe5, 0Xb4, 0Xb0,
	0X89, 0X69, 0X97, 0X4a, 0X0c, 0X96, 0X77, 0X7e, 0X65, 0Xb9, 0Xf1, 0X09, 0Xc5, 0X6e, 0Xc6, 0X84,
	0X18, 0Xf0, 0X7d, 0Xec, 0X3a, 0Xdc, 0X4d, 0X20, 0X79, 0Xee, 0X5f, 0X3e, 0Xd7, 0Xcb, 0X39, 0X48
};

const unsigned int CK[32] = {
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};


const unsigned int FK[4] = { 0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc };

unsigned int KeyTrans(unsigned int K)
{
	unsigned int resK;
	
	resK = ( (Sbox[K&0xff]) ) ^ ( (Sbox[(K>>8)&0xff])  << 8) ^ ( (Sbox[(K>>16)&0xff]) << 16 ) ^ ( (Sbox[(K>>24)&0xff]) << 24 ) ;

	resK = ((resK << 23) ^ (resK >> 9)) ^ (resK)^ ((resK << 13) ^ (resK >> 19));

	return resK;
}

unsigned int EncTrans(unsigned int T)
{
	unsigned int resT;
	
	resT = ( (Sbox[T&0xff]) ) ^ ( (Sbox[(T>>8)&0xff])  << 8) ^ ( (Sbox[(T>>16)&0xff]) << 16 ) ^ ( (Sbox[(T>>24)&0xff]) << 24 ) ;
	
	resT = (resT) ^ ( (resT<<2) ^ (resT>>30) ) ^ ( (resT<<10) ^ (resT>>22) ) ^ ( (resT<<18) ^ (resT>>14) )  ^ ( (resT<<24) ^ (resT>>8) );
	
	return resT;
}

unsigned int DecTrans(unsigned int T)
{
	unsigned int resT;

	resT = ((Sbox[T & 0xff])) ^ ((Sbox[(T >> 8) & 0xff]) << 8) ^ ((Sbox[(T >> 16) & 0xff]) << 16) ^ ((Sbox[(T >> 24) & 0xff]) << 24);

	resT = (resT) ^ ((resT << 2) ^ (resT >> 30)) ^ ((resT << 10) ^ (resT >> 22)) ^ ((resT << 18) ^ (resT >> 14)) ^ ((resT << 24) ^ (resT >> 8));

	return resT;
}

void KeyGen(unsigned int roundkey[32], unsigned int MK[4])
{
	int i;
	
	unsigned int K[50];
	
	for(i=0; i<4; i++)
	{
		K[i] = MK[i] ^ FK[i];
		//printf("%08x", K[i]);
	}
	//printf("\n\n", K[i]);


	for(i=0; i<32; i++)
	{
		unsigned int tmpK;

		tmpK = K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i];
		
		



		tmpK = KeyTrans(tmpK);
		
		roundkey[i] = tmpK ^ K[i];

		K[i+4] = roundkey[i];
	}
	
}


void SM4_KeyGen(unsigned char rk[4*32], unsigned char mkey[4*4])
{
	int i;
	unsigned int roundkey[32];
	unsigned int K[50];
	unsigned int MK[4];

	for (i = 0; i < 4; i++)
	{
		MK[i] = mkey[4*i];
		MK[i] = (MK[i] << 8) | mkey[4 * i + 1];
		MK[i] = (MK[i] << 8) | mkey[4 * i + 2];
		MK[i] = (MK[i] << 8) | mkey[4 * i + 3];
	}


	for (i = 0; i < 4; i++)
	{
		K[i] = MK[i] ^ FK[i];
	}

	for (i = 0; i < 32; i++)
	{
		unsigned int tmpK;

		tmpK = K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i];

		tmpK = KeyTrans(tmpK);

		roundkey[i] = tmpK ^ K[i];

		K[i + 4] = roundkey[i];
	}

	for (i = 0; i < 32; i++)
	{
		rk[4 * i] = roundkey[i] >> 24;
		rk[4 * i + 1] = (roundkey[i] >> 16) & 0xff;
		rk[4 * i + 2] = (roundkey[i] >> 8) & 0xff;
		rk[4 * i + 3] = (roundkey[i]) & 0xff;
	}


}


void Enc(unsigned int ct[4], unsigned int msg[4], unsigned int roundkey[32])
{
	int i;
	
	unsigned int TX[50];
	unsigned int tmp;
	
	for(i=0; i<4; i++)
	{
		TX[i] = msg[i];
	}
	
	for(i=0; i<32; i++)
	{
		tmp = TX[i+1] ^ TX[i+2] ^ TX[i+3] ^ roundkey[i];
		
		tmp = EncTrans(tmp);
		
		TX[i+4] = tmp ^ TX[i];
	}
	
	ct[0] = TX[35];
	ct[1] = TX[34];
	ct[2] = TX[33];
	ct[3] = TX[32];
}


void SM4_Enc(unsigned char  ctxt[16], unsigned char msg[16], unsigned char rk[32*4])
{
	int i;

	unsigned int TX[50];
	unsigned int roundkey[32], ct[4];

	unsigned int tmp;

	for (i = 0; i < 4; i++)
	{
		TX[i] = msg[i*4];

		TX[i] = (TX[i] << 8) | msg[4 * i + 1];
		TX[i] = (TX[i] << 8) | msg[4 * i + 2];
		TX[i] = (TX[i] << 8) | msg[4 * i + 3];
	}

	for (i = 0; i < 32; i++)
	{
		roundkey[i] = rk[i * 4];
		roundkey[i] = (roundkey[i] << 8) | rk[4 * i + 1];
		roundkey[i] = (roundkey[i] << 8) | rk[4 * i + 2];
		roundkey[i] = (roundkey[i] << 8) | rk[4 * i + 3];
	}


	for (i = 0; i < 32; i++)
	{
		tmp = TX[i + 1] ^ TX[i + 2] ^ TX[i + 3] ^ roundkey[i];

		tmp = EncTrans(tmp);

		TX[i + 4] = tmp ^ TX[i];
	}

	ct[0] = TX[35];
	ct[1] = TX[34];
	ct[2] = TX[33];
	ct[3] = TX[32];

	for (i = 0; i < 4; i++)
	{
		ctxt[4 * i] = ct[i]>>24;
		ctxt[4 * i + 1] = (ct[i] >> 16) & 0xff;
		ctxt[4 * i + 2] = (ct[i] >> 8) & 0xff;
		ctxt[4 * i + 3] = (ct[i]) & 0xff;
	}

}


void Dec(unsigned int msg[4], unsigned int ct[4], unsigned int roundkey[32])
{
	int i;

	unsigned int TX[50];
	unsigned int tmp;

	for (i = 0; i < 4; i++)
	{
		TX[i] = ct[i];
	}


	for (i = 0; i < 32; i++)
	{
		tmp = TX[i + 1] ^ TX[i + 2] ^ TX[i + 3] ^ roundkey[31-i];

		tmp = DecTrans(tmp);

		TX[i + 4] = tmp ^ TX[i];
	}

	msg[0] = TX[35];
	msg[1] = TX[34];
	msg[2] = TX[33];
	msg[3] = TX[32];
}


void SM4_Dec(unsigned char pt[16], unsigned char ctxt[16], unsigned char rk[128])
{
	int i;

	unsigned int TX[50];
	unsigned int tmp;
	unsigned int msg[4];
	unsigned int ct[4];
	unsigned int roundkey[32];

	for (i = 0; i < 4; i++)
	{
		TX[i] = ct[i];
	}


	for (i = 0; i < 4; i++)
	{
		TX[i] = ctxt[i * 4];

		TX[i] = (TX[i] << 8) | ctxt[4 * i + 1];
		TX[i] = (TX[i] << 8) | ctxt[4 * i + 2];
		TX[i] = (TX[i] << 8) | ctxt[4 * i + 3];
	}

	for (i = 0; i < 32; i++)
	{
		roundkey[i] = rk[i * 4];
		roundkey[i] = (roundkey[i] << 8) | rk[4 * i + 1];
		roundkey[i] = (roundkey[i] << 8) | rk[4 * i + 2];
		roundkey[i] = (roundkey[i] << 8) | rk[4 * i + 3];
	}

	for (i = 0; i < 32; i++)
	{
		tmp = TX[i + 1] ^ TX[i + 2] ^ TX[i + 3] ^ roundkey[31 - i];

		tmp = DecTrans(tmp);

		TX[i + 4] = tmp ^ TX[i];
	}

	msg[0] = TX[35];
	msg[1] = TX[34];
	msg[2] = TX[33];
	msg[3] = TX[32];

	for (i = 0; i < 4; i++)
	{
		pt[4 * i] = msg[i] >> 24;
		pt[4 * i + 1] = (msg[i] >> 16) & 0xff;
		pt[4 * i + 2] = (msg[i] >> 8) & 0xff;
		pt[4 * i + 3] = (msg[i]) & 0xff;
	}
}














