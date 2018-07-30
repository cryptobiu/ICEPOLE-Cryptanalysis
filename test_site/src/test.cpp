
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

void test();

int main() {
	cout << "!!!Hello World!!!" << endl; // prints !!!Hello World!!!

	test();

	return 0;
}

u_int8_t get_bit(const u_int64_t * P, const size_t x, const size_t y, const size_t z)
{
	//size_t _z = z%64;
	return (0 != (P[x + 4 * y] & (0x1UL << (z%64))))? 1: 0;
	/*
	{
		char buffer[32];

		u_int64_t v = P[x + 4 * y];
		snprintf(buffer, 32, "%016lX", v);
		cout << "v[" << x << "][" << y << "][" << z << "] = " << buffer << endl;

		u_int64_t mask = 1;
		mask = mask << _z;
		snprintf(buffer, 32, "%016lX", mask);
		cout << "mask = " << buffer << endl;

		v = v & mask;
		snprintf(buffer, 32, "%016lX", v);
		cout << "v[" << x << "][" << y << "][" << z << "] & mask = " << buffer << endl;
	}
	if(P[x + 4 * y] & (0x1 << _z))
		return 1;
	return 0;
	*/
}

u_int8_t get_row_bits(const u_int64_t * P, const size_t x, const size_t z)
{
	u_int8_t res = 0;
	res |= get_bit(P, x, 3, z);
	res = res << 1;
	res |= get_bit(P, x, 2, z);
	res = res << 1;
	res |= get_bit(P, x, 1, z);
	res = res << 1;
	res |= get_bit(P, x, 0, z);
	return res;
}

bool lookup_Sbox_input_bit(const u_int8_t output_row_bits, const size_t input_bit_index, u_int8_t & input_bit)
{
	switch(output_row_bits)
	{
	case 0x0://in doc
		switch(input_bit_index)
		{
		case 0: input_bit = 1; return true;
		case 2: input_bit = 1; return true;
		case 4: input_bit = 1; return true;
		default: return false;
		}
		break;
	case 0x1://1000
		return false;
	case 0x2://0100
		switch(input_bit_index)
		{
		case 0: input_bit = 0; return true;
		case 1: input_bit = 1; return true;
		case 3: input_bit = 0; return true;
		default: return false;
		}
		break;
	case 0x3://1100
		switch(input_bit_index)
		{
		case 0: input_bit = 1; return true;
		default: return false;
		}
		break;
	case 0x4://0010
		switch(input_bit_index)
		{
		case 1: input_bit = 0; return true;
		default: return false;
		}
		break;
	case 0x5://1010
		switch(input_bit_index)
		{
		case 1: input_bit = 0; return true;
		case 3: input_bit = 0; return true;
		default: return false;
		}
		break;
	case 0x6://0110
		switch(input_bit_index)
		{
		case 0: input_bit = 0; return true;
		case 1: input_bit = 1; return true;
		case 3: input_bit = 0; return true;
		default: return false;
		}
		break;
	case 0x7://1110
		switch(input_bit_index)
		{
		case 0: input_bit = 1; return true;
		case 1: input_bit = 1; return true;
		default: return false;
		}
		break;
	case 0x8://0001
		switch(input_bit_index)
		{
		case 0: input_bit = 0; return true;
		case 1: input_bit = 1; return true;
		case 2: input_bit = 0; return true;
		case 3: input_bit = 1; return true;
		default: return false;
		}
		break;
	case 0x9://1001
		switch(input_bit_index)
		{
		case 0: input_bit = 1; return true;
		case 2: input_bit = 0; return true;
		default: return false;
		}
		break;
	case 0xA://0101
		switch(input_bit_index)
		{
		case 0: input_bit = 0; return true;
		case 1: input_bit = 0; return true;
		case 2: input_bit = 0; return true;
		case 3: input_bit = 1; return true;
		default: return false;
		}
		break;
	case 0xB://1101
		switch(input_bit_index)
		{
		case 0: input_bit = 1; return true;
		case 2: input_bit = 0; return true;
		default: return false;
		}
		break;
	case 0xC://0011
		switch(input_bit_index)
		{
		case 0: input_bit = 1; return true;
		case 1: input_bit = 0; return true;
		case 2: input_bit = 1; return true;
		default: return false;
		}
		break;
	case 0xD://1011
		switch(input_bit_index)
		{
		case 0: input_bit = 0; return true;
		case 1: input_bit = 0; return true;
		case 2: input_bit = 1; return true;
		case 3: input_bit = 1; return true;
		default: return false;
		}
		break;
	case 0xE://0111
		switch(input_bit_index)
		{
		case 0: input_bit = 0; return true;
		case 1: input_bit = 1; return true;
		case 2: input_bit = 1; return true;
		case 3: input_bit = 1; return true;
		default: return false;
		}
		break;
	case 0xF://1111
		switch(input_bit_index)
		{
		case 3: input_bit = 0; return true;
		case 4: input_bit = 0; return true;
		default: return false;
		}
		break;
	default: return false;
	}
	return false;
}

bool last_Sbox_lookup_filter(const u_int64_t * P_perm_output, const size_t id, u_int8_t & F_xor_res, const char * logcat)
{
	/* This is the Omega mask for thread with id=0; for all others shift by id must be applied to z
	const u_int64_t omega_mask[16] =
	{
		0x0008000000000000, 0x0000000200000000, 0x0000000000000000, 0x0000000000001000, //0x0000000000000000,
		0x0000000000000000, 0x0000000800000000, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
		0x0000000000000000, 0x0040000000000000, 0x0000000040000000, 0x0000000000000000, //0x0000000000000000,
		0x0000000000000000, 0x0000000000000000, 0x0000000000000400, 0x0000000002000000, //0x0000000000000000,
	};
	[0][0][51]
	[0][1][33]
	[0][3][12]
	[1][1][35]
	[2][1][54]
	[2][2][30]
	[3][2][10]
	[3][3][25]
	 */

	static const struct __row_t { size_t x; size_t y; size_t z; } rows[8] = { 	{0, 0, 51}, {0, 1, 33}, {0, 3, 12}, {1, 1, 35},
																				{2, 1, 54}, {2, 2, 30}, {3, 2, 10}, {3, 3, 25} };

	u_int8_t row_bits, input_bit;
	F_xor_res = 0;

	for(size_t i = 0; i < 8; ++i)
	{
		struct __row_t current_row = rows[i];
		current_row.z = (current_row.z + id)%64;

		row_bits = get_row_bits(P_perm_output, current_row.x, current_row.z);
		cout << "row-bits for [" << current_row.x << "][" << current_row.y << "][" << current_row.z << "] = " << (int)row_bits << endl;
		input_bit = 0;

		if(lookup_Sbox_input_bit(row_bits, current_row.y, input_bit))
			F_xor_res ^= input_bit;
		else
			return false;
	}

	return true;
}

void test()
{
	const u_int64_t P2_perm_kappa[] =
	{
		0x034B7C0BD4F0A429, 0x25C86D6C21825913, 0xFEEF2FE8AF27CD98, 0xD53894CFFBDE732F,
		0x33AD9B377433E916, 0x66CA6FB59058D553, 0x78618DDA1EE62C0B, 0xE588B2FACA4BA02C,
		0xE6E3DC93319BFFAB, 0x451064EA5DF5281A, 0xA4886A179F62692D, 0xA04A97796CF300D3,
		0xE44D58C66566CA1B, 0x9D5522999A8B5238, 0x1A3B8E7E70C5DAD2, 0xB553923EB642813A,
	};

	u_int8_t F_xor_res;

	last_Sbox_lookup_filter(P2_perm_kappa, 0, F_xor_res, "");
}
