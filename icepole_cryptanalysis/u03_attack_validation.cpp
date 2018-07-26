
#include <stdlib.h>
#include <sstream>
#include <iomanip>

#include <log4cpp/Category.hh>

#include "icepole128av2/ref/encrypt.h"

#include "util.h"

void log_buffer(const char * label, const u_int8_t * buffer, const size_t size, const char * logcat, const int level)
{
	std::stringstream srs;
	srs << std::hex << std::setfill('0');
	for(size_t i = 0; i < size; ++i)
		srs << std::setw(2) << static_cast<unsigned>(buffer[i]);
	log4cpp::Category::getInstance(logcat).log(level, "%s: [%s]", label, srs.str().c_str());
}

void log_block(const char * label, const u_int64_t * block, const char * logcat, const int level)
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
	log4cpp::Category::getInstance(logcat).log(level, "%s:\n%s", label, str.c_str());
}

void log_state(const char * label, const u_int64_t state[4][5], const char * logcat, const int level)
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
	log4cpp::Category::getInstance(logcat).log(level, "%s:\n%s", label, str.c_str());
}

void validate_init_state(const u_int64_t * P, const u_int64_t * C, const u_int64_t init_block[4][5], const char * logcat)
{
	for(int i = 0; i < 4; ++i)
	{
		for(int j = 0; j < 4; ++j)
		{
			if( ( RC2I(P,i,j) ^ RC2I(C,i,j) ) != init_block[i][j])
			{
				log4cpp::Category::getInstance(logcat).fatal("%s: P^C[%d:%d] = %016lX; IB[i][i] = %016lX; mismatch.",
						__FUNCTION__, i, j, ( RC2I(P,i,j) ^ RC2I(C,i,j) ), init_block[i][j]);
				log_block("P", P, logcat, 0);
				log_state("IS", init_block, logcat, 0);
				exit(-1);
			}
		}
	}
}

int validate_generated_input_1st_constraint(const size_t thd_id, const u_int64_t * PxorIS, const u_int64_t init_state[4][5], const char * logcat)
{
	/*
	// 1st constraint - XOR of all the masked bits below should equal 1
	const u_int64_t u03_P1_1st_constraint[16] =
	{
		0x0000000000000000, 0x0000000000000010, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
		0x0000000000000010, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
		0x0000000000000000, 0x0000000000000010, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
		0x0000000000000010, 0x0000000000000000, 0x0000000000000010, 0x0000000000000000, //0x0000000000000000,
	};
	(0,1) , (1,0) , (2,1) , (3,0) , (3,2)
	*/

	u_int64_t mask = left_rotate(0x0000000000000010, thd_id);
	if(0 == (mask & (RC2I(PxorIS,0,1) ^ RC2I(PxorIS,1,0) ^ RC2I(PxorIS,2,1) ^ RC2I(PxorIS,3,0) ^ RC2I(PxorIS,3,2))))
		return -1;
	return 0;
}

int validate_generated_input_2nd_constraint(const size_t thd_id, const u_int64_t * PxorIS, const u_int64_t init_state[4][5], const char * logcat)
{
	/*
	// 2nd constraint - XOR of all the masked bits below should equal 1
	const u_int64_t u03_P1_2nd_constraint[16] =
	{
		0x0000000000000000, 0x0000000800000000, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
		0x0000000800000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
		0x0000000000000000, 0x0000000800000000, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
		0x0000000800000000, 0x0000000000000000, 0x0000000800000000, 0x0000000000000000, //0x0000000000000000,
	};
	(0,1) , (1,0) , (2,1) , (3,0) , (3,2)
	*/
	u_int64_t mask = left_rotate(0x0000000800000000, thd_id);
	if(0 == (mask & (RC2I(PxorIS,0,1) ^ RC2I(PxorIS,1,0) ^ RC2I(PxorIS,2,1) ^ RC2I(PxorIS,3,0) ^ RC2I(PxorIS,3,2))))
		return -1;
	return 0;
}

int validate_generated_input_3rd_constraint(const u_int64_t * PxorIS, const u_int64_t init_state[4][5], const char * logcat)
{
	/*
	// 3rd constraint - XOR of all the masked bits below should equal 0
	const u_int64_t u03_P1_3rd_constraint[16] =
	{
		0x0000000000000000, 0x0000000000000000, 0x0000000200000000, 0x0000000000000000, //0x0000000000000000,
		0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000200000000, //0x0000000000000000,
		0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000200000000, //0x0000000000000000,
		0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000200000000, //0x0000000000000000,
	};
	(0,2) , (1,3) , (2,3) , (3,3)
	*/
	if(0 != (0x0000000200000000 & (RC2I(PxorIS,0,2) ^ RC2I(PxorIS,1,3) ^ RC2I(PxorIS,2,3) ^ RC2I(PxorIS,3,3))))
		return -1;
	return 0;
}

int validate_generated_input_4th_constraint(const u_int64_t * PxorIS, const u_int64_t init_state[4][5], const char * logcat)
{
	/*
	// 4th constraint - XOR of all the masked bits below should equal 0
	const u_int64_t u03_P1_4th_constraint[16] =
	{
		0x0000000000000000, 0x0000000000000000, 0x0000000000000001, 0x0000000000000000, //0x0000000000000000,
		0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000001, //0x0000000000000000,
		0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000001, //0x0000000000000000,
		0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000001, //0x0000000000000000,
	};
	(0,2) , (1,3) , (2,3) , (3,3)
	*/
	if(0 != (0x0000000000000001 & (RC2I(PxorIS,0,2) ^ RC2I(PxorIS,1,3) ^ RC2I(PxorIS,2,3) ^ RC2I(PxorIS,3,3))))
		return -1;
	return 0;
}

void validate_generated_input_1(const u_int64_t * P, const u_int64_t init_state[4][5], const char * logcat)
{
	u_int64_t PxorIS[4*4];
	for(int i = 0; i < 4; ++i)
	{
		for(int j = 0; j < 4; ++j)
		{
			RC2I(PxorIS, i, j) = RC2I(P, i, j) ^ init_state[i][j];
		}
	}

	if(0 != validate_generated_input_1st_constraint(0, PxorIS, init_state, logcat))
	{
		log4cpp::Category::getInstance(logcat).fatal("%s: generated input 1st constraint violation.", __FUNCTION__);
		log_block("P", P, logcat, 0);
		log_state("IS", init_state, logcat, 0);
		exit(-1);
	}

	if(0 != validate_generated_input_2nd_constraint(0, PxorIS, init_state, logcat))
	{
		log4cpp::Category::getInstance(logcat).fatal("%s: generated input 2nd constraint violation.", __FUNCTION__);
		log_block("P", P, logcat, 0);
		log_state("IS", init_state, logcat, 0);
		exit(-1);
	}

	if(0 != validate_generated_input_3rd_constraint(PxorIS, init_state, logcat))
	{
		log4cpp::Category::getInstance(logcat).fatal("%s: generated input 3rd constraint violation.", __FUNCTION__);
		log_block("P", P, logcat, 0);
		log_state("IS", init_state, logcat, 0);
		exit(-1);
	}

	if(0 != validate_generated_input_4th_constraint(PxorIS, init_state, logcat))
	{
		log4cpp::Category::getInstance(logcat).fatal("%s: generated input 4th constraint violation.", __FUNCTION__);
		log_block("P", P, logcat, 0);
		log_state("IS", init_state, logcat, 0);
		exit(-1);
	}
	log4cpp::Category::getInstance(logcat).info("%s: generated input 4 constraints check out.", __FUNCTION__);
}

int validate_inputs_diff(int i, int j, const u_int64_t P1v, const u_int64_t P2v, const char * logcat)
{
	/*
	const u_int64_t u03_P1_P2_conversion[16] =
	{
		0x0, 0x0, 0x1, 0x0, //0x0,
		0x1, 0x1, 0x1, 0x1, //0x0,
		0x0, 0x1, 0x0, 0x1, //0x0,
		0x1, 0x0, 0x1, 0x0, //0x0,
	};
	RC2I(P2,0,2) ^= 0x1;
	RC2I(P2,1,0) ^= 0x1;
	RC2I(P2,1,1) ^= 0x1;
	RC2I(P2,1,2) ^= 0x1;
	RC2I(P2,1,3) ^= 0x1;
	RC2I(P2,2,1) ^= 0x1;
	RC2I(P2,2,3) ^= 0x1;
	RC2I(P2,3,0) ^= 0x1;
	RC2I(P2,3,2) ^= 0x1;
	*/
	switch(i)
	{
	case 0:
		if(j == 2 && (P1v^P2v) != 1)
			return -1;
		break;
	case 1:
		if((P1v^P2v) != 1)
			return -1;
		break;
	case 2:
		if((j == 1 || j == 3) && (P1v^P2v) != 1)
			return -1;
		break;
	case 3:
		if((j == 0 || j == 2) && (P1v^P2v) != 1)
			return -1;
		break;
	default:
		break;
	}
	return 0;
}

void validate_generated_input_2(const u_int64_t * P1, const u_int64_t * P2, const char * logcat)
{
	for(int i = 0; i < 4; ++i)
	{
		for(int j = 0; j < 4; ++j)
		{
			if(0 != validate_inputs_diff(i, j, RC2I(P1,i,j), RC2I(P2,i,j), logcat))
			{
				log4cpp::Category::getInstance(logcat).fatal("%s: generated inputs diff violation @[%d:%d].", __FUNCTION__, i, j);
				log_block("P1", P1, logcat, 0);
				log_block("P2", P2, logcat, 0);
				exit(-1);
			}
		}
	}
	log4cpp::Category::getInstance(logcat).info("%s: generated inputs XOR diff check out.", __FUNCTION__);
}

void validate_state_bits(const u_int64_t x_state[4][5], const u_int8_t F, const char * logcat)
{
	static const u_int64_t state_xor_bitmask[4][5] =
	{
		{ 0x0008000000000000, 0x0000000200000000, 0x0000000000000000, 0x0000000000001000, 0x0000000000000000 },
		{ 0x0000000000000000, 0x0000000800000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 },
		{ 0x0000000000000000, 0x0040000000000000, 0x0000000040000000, 0x0000000000000000, 0x0000000000000000 },
		{ 0x0000000000000000, 0x0000000000000000, 0x0000000000000400, 0x0000000002000000, 0x0000000000000000 }
	};

	u_int8_t control = 0;
	for(int i = 0; i < 4; ++i)
	{
		for(int j = 0; j < 5; ++j)
		{
			if(0 != (x_state[i][j] & state_xor_bitmask[i][j]))
				control ^= 1;
		}
	}

	if(F != control)
	{
		log4cpp::Category::getInstance(logcat).fatal("%s: state XOR bits mismatch; F=%hhu.", __FUNCTION__, F);
		log_state("x_state", x_state, logcat, 0);
		exit(-1);
	}
	log4cpp::Category::getInstance(logcat).info("%s: x-state XOR bits check out.", __FUNCTION__);
}

void validate_counter_bits(const u_int64_t * C, const size_t n, const char * logcat)
{
	u_int64_t LC[16];

	pi_rho_mu((const unsigned char *)C, (unsigned char *)LC);

	u_int64_t bit_3_1_41 = (0 == (RC2I(LC,3,1) & (0x1UL << 41)))? 0: 1;
	u_int64_t bit_3_3_41 = (0 == (RC2I(LC,3,3) & (0x1UL << 41)))? 0: 1;

	if(n != ((bit_3_1_41 << 1) | bit_3_3_41))
	{
		log4cpp::Category::getInstance(logcat).fatal("%s: counter bits mismatch; n = %lu; bit_3_1_41 = %lu; bit_3_3_41 = %lu;",
				__FUNCTION__, n, bit_3_1_41, bit_3_3_41);
		log_block("C", C, logcat, 0);
		log_block("LC", LC, logcat, 0);
		exit(-1);
	}
	/**/
	else
	{
		//log_block("C", C, logcat, 700);
		log_block("LC", LC, logcat, 700);

		log4cpp::Category::getInstance(logcat).debug("%s: LC[3][1] = 0x%016lX; LC[3][3] = 0x%016lX; ",
				__FUNCTION__, RC2I(LC,3,1), RC2I(LC,3,3));
		log4cpp::Category::getInstance(logcat).debug("%s: LC[3][1][41] = 0x%016lX & 0x%016lX = 0x%016lX",
				__FUNCTION__, RC2I(LC,3,1), (0x1UL << 41), (RC2I(LC,3,1) & (0x1UL << 41)));
		log4cpp::Category::getInstance(logcat).debug("%s: LC[3][3][41] = 0x%016lX & 0x%016lX = 0x%016lX",
				__FUNCTION__, RC2I(LC,3,3), (0x1UL << 41), (RC2I(LC,3,3) & (0x1UL << 41)));

		log4cpp::Category::getInstance(logcat).debug("%s: counter bits match; n = %lu; bit_3_1_41 = %lu; bit_3_3_41 = %lu;",
				__FUNCTION__, n, bit_3_1_41, bit_3_3_41);
	}

	log4cpp::Category::getInstance(logcat).info("%s: counter bits check out.", __FUNCTION__);
}

