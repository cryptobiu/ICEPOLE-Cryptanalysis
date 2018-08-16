
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

void test()
{
	aes_prg prg;
	if(0 != prg.init(128))
	{
		cout << __FUNCTION__ << ": prg.init() failure" << endl;
		return;
	}

	u_int64_t v[5];
	prg.gen_rand_bytes((u_int8_t *)v, 5 * sizeof(u_int64_t));

	u_int64_t xm = v[0] ^ v[1] ^ v[2] ^ v[3] ^ v[4];

	cout << __FUNCTION__ << ": this should be zero = " << (unsigned long long)(xm ^ xm) << endl;
	cout << __FUNCTION__ << ": this should be FF's = " << (unsigned long long)(xm ^ ~xm) << endl;

}

