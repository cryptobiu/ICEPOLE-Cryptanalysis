
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

//***************************************************************************************************//

typedef struct
{
	size_t x, y, z;
}block_bit_t;

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

bool last_Sbox_lookup_filter(const u_int64_t * P_perm_output, const size_t bit_offset,
							 const block_bit_t * bits, const size_t bit_count,
							 u_int8_t & F_xor_res)
{
	u_int8_t row_bits, input_bit;
	F_xor_res = 0;

	for(size_t i = 0; i < bit_count; ++i)
	{
		block_bit_t current_bit = bits[i];
		current_bit.z = (current_bit.z + bit_offset)%64;

		row_bits = get_block_row_bits(P_perm_output, current_bit.x, current_bit.z);
		input_bit = 0;

		if(lookup_Sbox_input_bit(row_bits, current_bit.y, input_bit))
			F_xor_res ^= input_bit;
		else
			return false;
	}
	return true;
}

u_int64_t left_rotate(u_int64_t v, size_t r);

u_int8_t xor_state_bits(const u_int64_t state[4][5], const size_t bit_offset, const block_bit_t * bits, const size_t bit_count)
{
	u_int8_t result = 0;
	for(size_t i = 0; i < bit_count; ++i)
	{
		u_int64_t integer = state[bits[i].x][bits[i].y];
		u_int64_t mask = left_rotate(0x1, bits[i].z + bit_offset);
		result ^= ((integer & mask)? 1: 0);
	}
	return result;
}

static const block_bit_t u3_omega_bits[8] = { 	{0, 0, 51}, {0, 1, 33}, {0, 3, 12}, {1, 1, 35},
												{2, 1, 54}, {2, 2, 30}, {3, 2, 10}, {3, 3, 25} };

void test()
{
	static const u_int64_t C1_1[] =
	{
		0x9A2361DDF707736D, 0xE86FD41ED92942F8, 0x231D3B6C8E5E6A74, 0x6920459BF729B603,
		0x388E4D0C72AC0190, 0x0BCD2B48BC39BE4D, 0x0AF54B1E56A0C501, 0x2A35DFE648685AE4,
		0x85C895D6A1F00CE4, 0x7625D4EB579FCCE3, 0xE1E4D91B7911A7C8, 0x424C6F3E9471CF68,
		0xE4B311340BCA2FFB, 0xAC04FCC7A1F23822, 0x509A943104A44D65, 0xEA857B14D3393EED,
	};

	static const u_int64_t x_state[4][5] =
	{
		{0x9FB7CDC80FB3F55E, 0xBC6F900DA988C2F9, 0xA59EB108869A6B6C, 0x74144513F6BBC245, 0x8683CF76BEED8319},
		{0xECBE041B33AE4192, 0x6BC7B2A8957DA439, 0xDF75621F5122E40A, 0x623BD2FE79445A74, 0xF7B1E0270782714F},
		{0x8C9A9CC689E03FB8, 0x743FF6CB534F8C93, 0x6D5759DB3807B71E, 0x425E7B381CC1E038, 0xCCFF8AD04147D0BE},
		{0xA54B012C0BCAA3AE, 0x064186C378E1802A, 0x45F8845820608477, 0xEACD6A14D933B44D, 0xF7E7427D35E4E15E},
	};

	u_int8_t F1 = 0;
	bool b = last_Sbox_lookup_filter(C1_1, 45, u3_omega_bits, 8, F1);
	if(b)
	{
		u_int8_t F1_chk = xor_state_bits(x_state, 6, u3_omega_bits, 8);

		if(F1 == F1_chk)
			cout << "OK" << endl;
		else
			cout << "KO" << endl;
	}
}
