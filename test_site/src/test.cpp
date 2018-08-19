
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
	u_int64_t C[16];

	cout << "sizeof(C)=" << sizeof(C) << endl;
	cout << "sizeof(C)*sizeof(u_int64_t)=" << sizeof(C)*sizeof(u_int64_t) << endl;
	cout << "sizeof(C)/sizeof(u_int64_t)=" << sizeof(C)/sizeof(u_int64_t) << endl;
}
