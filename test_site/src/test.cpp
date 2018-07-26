
#include <stdlib.h>
#include <memory.h>

#include <iostream>
#include <sstream>
#include <iomanip>
using namespace std;

#include <openssl/rand.h>
#include <openssl/evp.h>

#include "encrypt.h"
#include "aes_prg.h"
#include "util.h"

static const u_int8_t key[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
static const u_int8_t iv[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };

void trace_buffer(const char * label, const u_int8_t * buffer, const size_t size);
void trace_block(const char * label, const u_int64_t * block, const int extended);
int test1();
int test2();
int test4();
int test5();

int generate_input_p1(u_int64_t P1[BLONG_SIZE], aes_prg & prg, const u_int64_t init_block[4][5]);
int generate_input_p2(u_int64_t P1[BLONG_SIZE], u_int64_t P2[BLONG_SIZE]);
int generate_inputs(u_int64_t P1[BLONG_SIZE], u_int64_t P2[BLONG_SIZE], aes_prg & prg, const size_t id, const u_int64_t init_block[4][5]);

int main() {
	cout << "!!!Hello World!!!" << endl; // prints !!!Hello World!!!

	test5();

	return 0;
}

void trace_buffer(const char * label, const u_int8_t * buffer, const size_t size)
{
	std::stringstream srs;
	srs << std::hex << std::setfill('0');
	for(size_t i = 0; i < size; ++i)
		srs << std::setw(2) << static_cast<unsigned>(buffer[i]);
	cout << label << "=[" << srs.str() << "]" << endl;
}

void trace_block(const char * label, const u_int64_t * block, const int extended)
{
	char buffer[64];
	size_t rows = 4, cols = (extended)? 5: 4;
	cout << label << ":" << endl;
	for(size_t i = 0; i < rows; ++i)
	{
		for(size_t j = 0; j < cols; ++j)
		{
			snprintf(buffer, 64, "0x%016lX ", RC2I(block, i, j));
			cout << buffer;
		}
		cout << endl;
	}
}

int test1()
{
	u_int8_t C1[2*128+16];
	memset(C1, 0, 2*128+16);
	unsigned long long clen1 = 2*128+16;

	u_int8_t C2[2*128+16];
	memset(C2, 0, 2*128+16);
	unsigned long long clen2 = 2*128+16;

	u_int8_t P1[2*128];
	RAND_bytes(P1, 2*128);

	u_int8_t P2[2*128];
	memcpy(P2, P1, 2*128);

	P2[64] ^= 0x1;
	P2[8] ^= 0x1;
	P2[40] ^= 0x1;
	P2[72] ^= 0x1;
	P2[104] ^= 0x1;
	P2[48] ^= 0x1;
	P2[112] ^= 0x1;
	P2[24] ^= 0x1;
	P2[88] ^= 0x1;

	if(0 == memcmp(P1, P2, 2*128))
	{
		cout << "P1 & P2 equal." << endl;
		return -1;
	}

	u_int64_t x_state_1[20], x_state_2[20];
	memset(x_state_1, 0, 20*sizeof(u_int64_t));
	memset(x_state_2, 0, 20*sizeof(u_int64_t));

	crypto_aead_encrypt_hack((unsigned char *)C1, &clen1, (const unsigned char *)P1, 2*128, NULL, 0, NULL,iv, key, (u_int64_t (*)[5])x_state_1);
	crypto_aead_encrypt_hack((unsigned char *)C2, &clen2, (const unsigned char *)P2, 2*128, NULL, 0, NULL,iv, key, (u_int64_t (*)[5])x_state_2);

	if(0 == memcmp(x_state_1, x_state_2, 20*8))
	{
		cout << "x_state_1 & x_state_2 are equal." << endl;
		trace_buffer("x_state_1", (const u_int8_t*)x_state_1, 20*8);
		trace_buffer("x_state_2", (const u_int8_t*)x_state_2, 20*8);
		return -1;
	}
	return 0;
}

int test4()
{
	u_int8_t C[128+16];
	memset(C, 0, 128+16);
	unsigned long long clen = 128+16;

	u_int8_t P[128];
	RAND_bytes(P, 128);

	u_int64_t is[4][5];
	for(size_t i = 0; i < 4; ++i)
		for(size_t j = 0; j < 5; ++j)
			is[i][j] = 0;

	crypto_aead_encrypt_i((unsigned char *)C, &clen, (const unsigned char *)P, 128, NULL, 0, NULL, iv, key, is);

	//trace_block("P", (u_int64_t*)P, 0);
	//trace_block("C", (u_int64_t*)C, 0);

	char buffer[64];
	const u_int64_t * u64P = (const u_int64_t *)P;
	const u_int64_t * u64C = (const u_int64_t *)C;

	for(size_t i = 0; i < 4; ++i)
	{
		for(size_t j = 0; j < 4; ++j)
		{
			snprintf(buffer, 64, "0x%016lX ", RC2I(u64P, i, j) ^ RC2I(u64C, i, j));
			cout << "P^C[" << i << "][" << j << "]=" << buffer << endl;
		}
	}
	cout << endl;
	for(size_t i = 0; i < 4; ++i)
	{
		for(size_t j = 0; j < 4; ++j)
		{
			snprintf(buffer, 64, "0x%016lX ", is[i][j]);
			cout << "is[" << i << "][" << j << "]=" << buffer << endl;
		}
	}
	for(size_t i = 0; i < 4; ++i)
	{
		snprintf(buffer, 64, "0x%016lX ", is[i][4]);
		cout << "is[" << i << "][" << 4 << "]=" << buffer << endl;
	}
	return 0;
}

int test2()
{
	u_int8_t C[256+16];
	memset(C, 0, 256+16);
	unsigned long long clen = 256+16;

	u_int8_t P[256];
	memset(P, 0, 256);
	RAND_bytes(P, 128);

	u_int64_t xs[4][5];
	for(size_t i = 0; i < 4; ++i)
		for(size_t j = 0; j < 5; ++j)
			xs[i][j] = 0;

	crypto_aead_encrypt_hack((unsigned char *)C, &clen, (const unsigned char *)P, 256, NULL, 0, NULL, iv, key, xs);

	char buffer[64];
	for(size_t i = 0; i < 4; ++i)
	{
		for(size_t j = 0; j < 5; ++j)
		{
			snprintf(buffer, 64, "0x%016lX ", xs[i][j]);
			cout << "xs[" << i << "][" << j << "]=" << buffer << endl;
		}
	}
	return 0;
}

int test5()
{
	/**/
	static const char label[] = "column-order";
	static const u_int64_t C[20] = { 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x1, 0x1, 0x1, 0x1, 0x1, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0,0x0, 0x0 };

	/*
	static const char label[] = "row-order";
	static const u_int64_t C[20] = { 0x0, 0x0, 0x1, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x1, 0x1, 0x1, 0x1, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0 };
	*/

	cout << label << endl;

	u_int64_t C_[20];
	memset(C_, 0, 20*sizeof(u_int64_t));

	char buffer[32];

	cout << "C:" << endl;
	for(int i = 0; i < 4; i++)
	{
		for(int j = 0; j < 5; j++)
		{
			snprintf(buffer, 32, "[%02d]%016lX ", i+4*j, RC2I(C,i,j));
			cout << buffer;
		}
		cout << endl;
	}

	pi_rho_mu((const u_int8_t *)C, (u_int8_t *)C_);

	cout << "C_:" << endl;
	for(int i = 0; i < 4; i++)
	{
		for(int j = 0; j < 5; j++)
		{
			snprintf(buffer, 32, "[%02d]%016lX ", i+4*j, RC2I(C_,i,j));
			cout << buffer;
		}
		cout << endl;
	}
	return 0;
}

int generate_inputs(u_int64_t P1[BLONG_SIZE], u_int64_t P2[BLONG_SIZE], aes_prg & prg, const size_t id, const u_int64_t init_block[4][5])
{
	generate_input_p1(P1, prg, init_block);
	generate_input_p2(P1, P2);

	//shift the input in accordance with the thread id
	for(size_t i = 0; i < BLONG_SIZE; ++i)
	{
		P1[i] = left_rotate(P1[i], id);
		P2[i] = left_rotate(P2[i], id);
	}
	return 0;
}

int generate_input_p1(u_int64_t P1[BLONG_SIZE], aes_prg & prg, const u_int64_t init_block[4][5])
{
	//Generation of random bytes in P1
	prg.gen_rand_bytes((u_int8_t *)P1, BLOCK_SIZE);

	//XOR of P1 with the icepole init block into P1_ib_xor
	u_int64_t P1_ib_xor[BLONG_SIZE];
	for(size_t i = 0; i < 4; ++i)
		for(size_t j = 0; j < 4; ++j)
			RC2I(P1_ib_xor,i,j) = RC2I(P1,i,j) ^ init_block[i][j];

	{	/* set 1st constraint
		const u_int64_t u03_P1_1st_constraint[16] =
		{
			0x0000000000000000, 0x0000000000000010, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
			0x0000000000000010, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
			0x0000000000000000, 0x0000000000000010, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
			0x0000000000000010, 0x0000000000000000, 0x0000000000000010, 0x0000000000000000, //0x0000000000000000,
		}; */
		u_int64_t mask = 0x0000000000000010;
		if (0 == (	(RC2I(P1_ib_xor,0,1) & mask) ^
					(RC2I(P1_ib_xor,1,0) & mask) ^
					(RC2I(P1_ib_xor,2,1) & mask) ^
					(RC2I(P1_ib_xor,3,0) & mask) ^
					(RC2I(P1_ib_xor,3,2) & mask)))
		RC2I(P1,3,2) ^= mask;
	}

	{	/* set 2nd constraint
		const u_int64_t u03_P1_2nd_constraint[16] =
		{
			0x0000000000000000, 0x0000000800000000, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
			0x0000000800000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
			0x0000000000000000, 0x0000000800000000, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
			0x0000000800000000, 0x0000000000000000, 0x0000000800000000, 0x0000000000000000, //0x0000000000000000,
		}; */
		u_int64_t mask = 0x0000000800000000;
		if(0 == (	(RC2I(P1_ib_xor,0,1) & mask) ^
					(RC2I(P1_ib_xor,1,0) & mask) ^
					(RC2I(P1_ib_xor,2,1) & mask) ^
					(RC2I(P1_ib_xor,3,0) & mask) ^
					(RC2I(P1_ib_xor,3,2) & mask)))
			RC2I(P1,3,2) ^= mask;
	}

	{	/* set 3rd constraint
		const u_int64_t u03_P1_3rd_constraint[16] =
		{
			0x0000000000000000, 0x0000000000000000, 0x0000000200000000, 0x0000000000000000, //0x0000000000000000,
			0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000200000000, //0x0000000000000000,
			0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000200000000, //0x0000000000000000,
			0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000200000000, //0x0000000000000000,
		}; */
		u_int64_t mask = 0x0000000200000000;
		if(mask == (
					(RC2I(P1_ib_xor,0,2) & mask) ^
					(RC2I(P1_ib_xor,1,3) & mask) ^
					(RC2I(P1_ib_xor,2,3) & mask) ^
					(RC2I(P1_ib_xor,3,3) & mask)))
			RC2I(P1,3,3) ^= mask;
	}

	{	/* set 4th constraint
		const u_int64_t u03_P1_4th_constraint[16] =
		{
			0x0000000000000000, 0x0000000000000000, 0x0000000000000001, 0x0000000000000000, //0x0000000000000000,
			0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000001, //0x0000000000000000,
			0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000001, //0x0000000000000000,
			0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000001, //0x0000000000000000,
		}; */
		u_int64_t mask = 0x0000000000000001;
		if(mask == (
					(RC2I(P1_ib_xor,0,2) & mask) ^
					(RC2I(P1_ib_xor,1,3) & mask) ^
					(RC2I(P1_ib_xor,2,3) & mask) ^
					(RC2I(P1_ib_xor,3,3) & mask)))
			RC2I(P1,3,3) ^= mask;
	}

	//set the 2nd block of P1 to zeroes
	memset((u_int8_t *)P1 + BLOCK_SIZE, 0, BLOCK_SIZE);
	return 0;
}

int generate_input_p2(u_int64_t P1[BLONG_SIZE], u_int64_t P2[BLONG_SIZE])
{
	/*
	const u_int64_t u03_P1_P2_conversion[16] =
	{
		0x0, 0x0, 0x1, 0x0, //0x0,
		0x1, 0x1, 0x1, 0x1, //0x0,
		0x0, 0x1, 0x0, 0x1, //0x0,
		0x1, 0x0, 0x1, 0x0, //0x0,
	}; */

	//copy P1 onto P2 and modify the bits by the conversion mask
	memcpy(P2, P1, 2 * BLOCK_SIZE);
	RC2I(P2,0,2) ^= 0x1;
	RC2I(P2,1,0) ^= 0x1;
	RC2I(P2,1,1) ^= 0x1;
	RC2I(P2,1,2) ^= 0x1;
	RC2I(P2,1,3) ^= 0x1;
	RC2I(P2,2,1) ^= 0x1;
	RC2I(P2,2,3) ^= 0x1;
	RC2I(P2,3,0) ^= 0x1;
	RC2I(P2,3,2) ^= 0x1;
	return 0;
}
