
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
#include "util.h"

void test();

int main() {
	cout << "!!!Hello World!!!" << endl; // prints !!!Hello World!!!

	test();

	return 0;
}

void test()
{
	u_int64_t v[5];

	aes_prg prg;
	if(0 != prg.init(BLOCK_SIZE))
	{
		cout << "prg.init() failure" << endl;
		return;
	}

	prg.gen_rand_bytes((u_int8_t *)v, 5*sizeof(u_int64_t));
	for(u_int64_t mask = 1; mask != 0; mask <<= 1)
	{
		u_int64_t A = 0, B = 0;
		for(int i = 0; i < 5; ++i)
		{
			A ^= (v[i] & mask);
			B ^= v[i];
		}
		B &= mask;

		if(A != B)
		{
			cout << "test failure." << endl;
			exit(-1);
		}
	}
	cout << "test success." << endl;
}
