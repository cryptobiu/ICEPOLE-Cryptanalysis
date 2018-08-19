
#include <stdlib.h>
#include <memory.h>
#include <math.h>

#include <iostream>
#include <sstream>
#include <iomanip>
using namespace std;

#include <openssl/rand.h>
#include <openssl/evp.h>

#include "encrypt.h"
#include "aes_prg.h"

void test();

int main() {
	cout << "!!!Hello World!!!" << endl; // prints !!!Hello World!!!

	test();

	return 0;
}

#define BLOCK_SIZE 128
#define BLONG_SIZE 16
#define RC2I(arr,x,y) arr[x + 4*y]

void log_block(const char * label, const u_int64_t * block)
{
	std::string str;
	char buffer[64];
	for(int i = 0; i < 4; ++i)
	{
		for(int j = 0; j < 4; ++j)
		{
			snprintf(buffer, 64, "%016lX ", RC2I(block, i, j));
			str += buffer;
		}
		str += '\n';
	}
	cout << label << ":" << endl << str << endl;
}

void log_state(const char * label, const u_int64_t state[4][5])
{
	std::string str;
	char buffer[64];
	for(int i = 0; i < 4; ++i)
	{
		for(int j = 0; j < 5; ++j)
		{
			snprintf(buffer, 64, "%016lX ", state[i][j]);
			str += buffer;
		}
		str += '\n';
	}
	cout << label << ":" << endl << str << endl;
}

#define PxIS(x,y)		(RC2I(P1,x,y)^IS[x][y])

int gen(u_int64_t P1[2*BLONG_SIZE], aes_prg & prg, const u_int64_t IS[4][5])
{
	//Generation of random bytes in P1
	prg.gen_rand_bytes((u_int8_t *)P1, BLOCK_SIZE);

	/* 4th constraint: xor of the bits of this mask should be equal to 0
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000100L
	0x0000000000000100L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000100L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000100L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	[0,4]=U0 , [1,0] , [2,0] , [3,0]																[3,0]*/
	RC2I(P1,3,0) ^= (IS[0][4] ^ PxIS(1,0) ^ PxIS(2,0) ^ PxIS(3,0));

	/*	1st constraint: xor of the bits of this mask should be equal to 1
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000008000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000008000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000008000000L,0x0000000000000000L,0x0000000000000000L
	[0,3] , [1,3] , [3,2]		 																	[3,2]*/
	RC2I(P1,3,2) ^= ~(PxIS(0,3) ^ PxIS(1,3) ^ PxIS(3,2));

	/* 2nd constraint: xor of the bits of this mask should be equal to 1
	0x0000000000000000L,0x0000000000020000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000020000L,0x0000000000000000L,0x0000000000020000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000020000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000020000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	[0,1] , [1,0] , [1,2] , [2,0] , [3,1]	 														[1,2]*/
	RC2I(P1,1,2) ^= ~(PxIS(0,1) ^ PxIS(1,0) ^ PxIS(1,2) ^ PxIS(2,0) ^ PxIS(3,1));

	/* 3rd constraint: xor of the bits of this mask should be equal to 1
	0x0000000000000000L,0x0400000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0400000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0400000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0400000000000000L,0x0000000000000000L,0x0400000000000000L,0x0000000000000000L,0x0000000000000000L
	[0,1] , [1,0] , [2,1] , [3,0] , [3,2]	 														[2,1]*/
	RC2I(P1,2,1) ^= ~(PxIS(0,1) ^ PxIS(1,0) ^ PxIS(2,1) ^ PxIS(3,0) ^ PxIS(3,2));

	/* 5th constraint: xor of the bits of this mask should be equal to 0
	0x0000000000000000L,0x0000000000000000L,0x0000000000800000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000800000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000800000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000800000L,0x0000000000000000L
	[0,2] , [1,3] , [2,3] , [3,3]																	[3,3]*/
	RC2I(P1,3,3) ^= (PxIS(0,2) ^ PxIS(1,3) ^ PxIS(2,3) ^ PxIS(3,3));

	//set the 2nd block of P1 to zeroes
	memset((u_int8_t *)P1 + BLOCK_SIZE, 0, BLOCK_SIZE);
	return 0;
}
#undef PxIS

void test()
{
	char buffer[64];
	aes_prg prg;
	if(0 != prg.init(128))
	{
		cout << __FUNCTION__ << ": prg.init() failure" << endl;
		return;
	}

	u_int64_t P1[2*BLONG_SIZE], IS[4][5];
	prg.gen_rand_bytes((u_int8_t *)IS, 4*5*sizeof(u_int64_t));
	gen(P1, prg, IS);

	{//[0,4]=U0 , [1,0] , [2,0] , [3,0]
		u_int64_t _4th_v = IS[0][4] ^ PxIS(1,0) ^ PxIS(2,0) ^ PxIS(3,0);
		snprintf(buffer, 64, "%016lX", _4th_v);
		std::cout << "_4th_v = " << buffer << std::endl;
		if(0 != _4th_v)
			std::cout << "4th constraint failure." << std::endl;
	}

	{//[0,3] , [1,3] , [3,2]
		u_int64_t _1st_v = (PxIS(0,3) ^ PxIS(1,3) ^ PxIS(3,2));
		snprintf(buffer, 64, "%016lX", _1st_v);
		std::cout << "_1st_v = " << buffer << std::endl;
		if(0 != ~_1st_v)
			std::cout << "1st constraint failure." << std::endl;
	}

	{//[0,1] , [1,0] , [1,2] , [2,0] , [3,1]
		u_int64_t _2nd_v = (PxIS(0,1) ^ PxIS(1,0) ^ PxIS(1,2) ^ PxIS(2,0) ^ PxIS(3,1));
		snprintf(buffer, 64, "%016lX", _2nd_v);
		std::cout << "_2nd_v = " << buffer << std::endl;
		if(0 != ~_2nd_v)
			std::cout << "2nd constraint failure." << std::endl;
	}

	{//[0,1] , [1,0] , [2,1] , [3,0] , [3,2]
		u_int64_t _3rd_v = (PxIS(0,1) ^ PxIS(1,0) ^ PxIS(2,1) ^ PxIS(3,0) ^ PxIS(3,2));
		snprintf(buffer, 64, "%016lX", _3rd_v);
		std::cout << "_3rd_v = " << buffer << std::endl;
		if(0 != ~_3rd_v)
			std::cout << "3rd constraint failure." << std::endl;
	}

	{//[0,2] , [1,3] , [2,3] , [3,3]
		u_int64_t _5th_v = (PxIS(0,2) ^ PxIS(1,3) ^ PxIS(2,3) ^ PxIS(3,3));
		snprintf(buffer, 64, "%016lX", _5th_v);
		std::cout << "_5th_v = " << buffer << std::endl;
		if(0 != _5th_v)
			std::cout << "5th constraint failure." << std::endl;
	}
}

