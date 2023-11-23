#ifndef _sm4_H
#define _sm4_H

#ifdef __cplusplus 
extern "C" { 
#endif 

void keygen(unsigned char* master_key,unsigned char* round_key);

void enc(unsigned char* pt, unsigned char* roundkey, unsigned char* ct);

void dec(unsigned char* ct, unsigned char* roundkey, unsigned char* pt);

	
void new_enc(unsigned char* pt, unsigned char* roundkey, unsigned char* ct);

void new_dec(unsigned char* ct, unsigned char* roundkey, unsigned char* pt);

	
	
//The Following APIs are for testing the efficiency of C-implemented routines;

void KeyGen(unsigned int roundkey[32], unsigned int MK[4]);
void Enc(unsigned int ct[4], unsigned int msg[4], unsigned int roundkey[32]);
void Dec(unsigned int msg[4], unsigned int ct[4], unsigned int roundkey[32]);

void SM4_KeyGen(unsigned char rk[4*32], unsigned char mkey[4*4]);
void SM4_Enc(unsigned char  ctxt[16], unsigned char msg[16], unsigned char rk[32*4]);
void SM4_Dec(unsigned char pt[16], unsigned char ctxt[16], unsigned char rk[128]);


#ifdef __cplusplus 
} 
#endif 


#endif

