
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

u_int8_t get_block_bit(const u_int64_t * P, const size_t x, const size_t y, const size_t z)
{
	return (0 != (P[x + 4 * y] & (0x1UL << (z%64))))? 1: 0;
}

u_int8_t get_block_row_bits(const u_int64_t * P, const size_t x, const size_t z)
{
	return (
			(get_block_bit(P, x, 0, z)	 )	|
			(get_block_bit(P, x, 1, z) << 1)	|
			(get_block_bit(P, x, 2, z) << 2)	|
			(get_block_bit(P, x, 3, z) << 3)
			);
}
/*
0:0
29F64B45908E60B4 CC28AAEA3AA5090E EC6F0EB9A8C11E5C 724A2EF3C62BB792

1:0
C71D94409F4E7ED6 1FAD9025B81300E1 9E39F75C2FE7AA5F E289D09D6C99ADC8

2:0
F86CE2853C699CDE 2B214F4D9B058D32 B8DF45D63DEACBA8 8A4C027ACD6A5231

3:0
4300E9F7CEB9510D 8F06FDD161EC9FEA 18769F8D401D215B CB466BAD655637C5
*/
static const u_int64_t perm[] =
{
	0x29F64B45908E60B4, 0xC71D94409F4E7ED6, 0xF86CE2853C699CDE, 0x4300E9F7CEB9510D,
	0xCC28AAEA3AA5090E, 0x1FAD9025B81300E1, 0x2B214F4D9B058D32, 0x8F06FDD161EC9FEA,
	0xEC6F0EB9A8C11E5C, 0x9E39F75C2FE7AA5F, 0xB8DF45D63DEACBA8, 0x18769F8D401D215B,
	0x724A2EF3C62BB792, 0xE289D09D6C99ADC8, 0x8A4C027ACD6A5231, 0xCB466BAD655637C5
};

void test()
{
	u_int8_t res = get_block_row_bits(perm, 0, 33);

	cout << "row bits: ";
	for(u_int8_t i = 1; i != 0; i = i << 1)
	{
		cout << ((res & i)? "1": "0") << " ";
	}
	cout << endl;
}

