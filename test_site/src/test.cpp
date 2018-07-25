
#include <stdlib.h>
#include <memory.h>

#include <iostream>
#include <sstream>
#include <iomanip>
using namespace std;

#include <openssl/rand.h>
#include <openssl/evp.h>

#include "encrypt.h"

#define RC2I(arr,x,y) arr[x + 4*y]

static const u_int8_t key[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
static const u_int8_t iv[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };

void trace_buffer(const char * label, const u_int8_t * buffer, const size_t size);
void trace_block(const char * label, const u_int64_t * block, const int extended);
int test1();
int test2();
int test4();
int test5();

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
	static const u_int64_t C[4][5] =
	{
		{ 0x0, 0x0, 0x1, 0x0, 0x0 },
		{ 0x1, 0x0, 0x1, 0x0, 0x0 },
		{ 0x1, 0x1, 0x1, 0x1, 0x0 },
		{ 0x0, 0x1, 0x0, 0x0, 0x0 }
	};

	char buffer[32];

	cout << "C:" << endl;
	for(int i = 0; i < 4; i++)
	{
		for(int j = 0; j < 4; j++)
		{
			snprintf(buffer, 32, "%016lX ", C[i][j]);
			cout << buffer;
		}
		cout << endl;
	}

	u_int64_t C_[4][5];
	memset(C_, 0, 20*sizeof(u_int64_t));

	pi_rho_mu((const u_int8_t *)C, (u_int8_t *)C_);

	cout << "C_:" << endl;
	for(int i = 0; i < 4; i++)
	{
		for(int j = 0; j < 4; j++)
		{
			snprintf(buffer, 32, "%016lX ", C_[i][j]);
			cout << buffer;
		}
		cout << endl;
	}
	return 0;
}
