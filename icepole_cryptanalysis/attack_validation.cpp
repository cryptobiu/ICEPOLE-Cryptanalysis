
#include <stdlib.h>
#include <semaphore.h>

#include <event2/event.h>
#include <log4cpp/Category.hh>

#include "icepole128av2/ref/encrypt.h"

#include "util.h"

namespace U03
{
/*
void validate_init_state(const u_int64_t * P, const u_int64_t * C, const u_int64_t init_state[4][5], const char * logcat)
{
	for(int i = 0; i < 4; ++i)
	{
		for(int j = 0; j < 4; ++j)
		{
			if( ( RC2I(P,i,j) ^ RC2I(C,i,j) ) != init_state[i][j])
			{
				log4cpp::Category::getInstance(logcat).fatal("%s: P^C[%d:%d] = %016lX; IB[i][i] = %016lX; mismatch.",
						__FUNCTION__, i, j, ( RC2I(P,i,j) ^ RC2I(C,i,j) ), init_state[i][j]);
				log_block("P", P, logcat, 0);
				log_state("IS", init_state, logcat, 0);
				exit(-1);
			}
		}
	}
}*/

int validate_generated_input_1st_constraint(const size_t bit_offset, const u_int64_t * PxorIS, const u_int64_t init_state[4][5], const char * logcat)
{
	/* 1st constraint - XOR of all the masked bits below should equal 1
	const u_int64_t u03_P1_1st_constraint[16] =
	{
		0x0000000000000000, 0x0000000000000010, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
		0x0000000000000010, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
		0x0000000000000000, 0x0000000000000010, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
		0x0000000000000010, 0x0000000000000000, 0x0000000000000010, 0x0000000000000000, //0x0000000000000000,
	};
	(0,1) , (1,0) , (2,1) , (3,0) , (3,2) */

	u_int64_t mask = left_rotate(0x0000000000000010, bit_offset);
	if(0 == (mask & (RC2I(PxorIS,0,1) ^ RC2I(PxorIS,1,0) ^ RC2I(PxorIS,2,1) ^ RC2I(PxorIS,3,0) ^ RC2I(PxorIS,3,2))))
		return -1;
	return 0;
}

int validate_generated_input_2nd_constraint(const size_t bit_offset, const u_int64_t * PxorIS, const u_int64_t init_state[4][5], const char * logcat)
{
	/* 2nd constraint - XOR of all the masked bits below should equal 1
	const u_int64_t u03_P1_2nd_constraint[16] =
	{
		0x0000000000000000, 0x0000000800000000, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
		0x0000000800000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
		0x0000000000000000, 0x0000000800000000, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
		0x0000000800000000, 0x0000000000000000, 0x0000000800000000, 0x0000000000000000, //0x0000000000000000,
	};
	(0,1) , (1,0) , (2,1) , (3,0) , (3,2) */

	u_int64_t mask = left_rotate(0x0000000800000000, bit_offset);
	if(0 == (mask & (RC2I(PxorIS,0,1) ^ RC2I(PxorIS,1,0) ^ RC2I(PxorIS,2,1) ^ RC2I(PxorIS,3,0) ^ RC2I(PxorIS,3,2))))
		return -1;
	return 0;
}

int validate_generated_input_3rd_constraint(const size_t bit_offset, const u_int64_t * PxorIS, const u_int64_t init_state[4][5], const char * logcat)
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
	u_int64_t mask = left_rotate(0x0000000200000000, bit_offset);
	if(0 != (mask & (RC2I(PxorIS,0,2) ^ RC2I(PxorIS,1,3) ^ RC2I(PxorIS,2,3) ^ RC2I(PxorIS,3,3))))
		return -1;
	return 0;
}

int validate_generated_input_4th_constraint(const size_t bit_offset, const u_int64_t * PxorIS, const u_int64_t init_state[4][5], const char * logcat)
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
	u_int64_t mask = left_rotate(0x0000000000000001, bit_offset);
	if(0 != (mask & (RC2I(PxorIS,0,2) ^ RC2I(PxorIS,1,3) ^ RC2I(PxorIS,2,3) ^ RC2I(PxorIS,3,3))))
		return -1;
	return 0;
}

void validate_generated_input_1(const size_t bit_offset, const u_int64_t * P, const u_int64_t init_state[4][5], const char * logcat)
{
	u_int64_t PxorIS[4*4];
	for(int i = 0; i < 4; ++i)
	{
		for(int j = 0; j < 4; ++j)
		{
			RC2I(PxorIS, i, j) = RC2I(P, i, j) ^ init_state[i][j];
		}
	}

	if(0 != validate_generated_input_1st_constraint(bit_offset, PxorIS, init_state, logcat))
	{
		log4cpp::Category::getInstance(logcat).fatal("%s: generated input 1st constraint violation; id=%lu.", __FUNCTION__, bit_offset);
		log_block("P", P, logcat, 0);
		log_state("IS", init_state, logcat, 0);
		exit(-1);
	}

	if(0 != validate_generated_input_2nd_constraint(bit_offset, PxorIS, init_state, logcat))
	{
		log4cpp::Category::getInstance(logcat).fatal("%s: generated input 2nd constraint violation; id=%lu.", __FUNCTION__, bit_offset);
		log_block("P", P, logcat, 0);
		log_state("IS", init_state, logcat, 0);
		exit(-1);
	}

	if(0 != validate_generated_input_3rd_constraint(bit_offset, PxorIS, init_state, logcat))
	{
		log4cpp::Category::getInstance(logcat).fatal("%s: generated input 3rd constraint violation; id=%lu.", __FUNCTION__, bit_offset);
		log_block("P", P, logcat, 0);
		log_state("IS", init_state, logcat, 0);
		exit(-1);
	}

	if(0 != validate_generated_input_4th_constraint(bit_offset, PxorIS, init_state, logcat))
	{
		log4cpp::Category::getInstance(logcat).fatal("%s: generated input 4th constraint violation; id=%lu.", __FUNCTION__, bit_offset);
		log_block("P", P, logcat, 0);
		log_state("IS", init_state, logcat, 0);
		exit(-1);
	}
	log4cpp::Category::getInstance(logcat).info("%s: generated input 4 constraints check out.", __FUNCTION__);
}

int validate_inputs_diff(const size_t bit_offset, int i, int j, const u_int64_t P1v, const u_int64_t P2v, const char * logcat)
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
	u_int64_t mask = left_rotate(1, bit_offset);
	switch(i)
	{
	case 0:
		if(j == 2 && ((P1v^P2v) & mask) != mask)
			return -1;
		break;
	case 1:
		if(((P1v^P2v) & mask) != mask)
			return -1;
		break;
	case 2:
		if((j == 1 || j == 3) && ((P1v^P2v) & mask) != mask)
			return -1;
		break;
	case 3:
		if((j == 0 || j == 2) && ((P1v^P2v) & mask) != mask)
			return -1;
		break;
	default:
		break;
	}
	return 0;
}

void validate_generated_input_2(const size_t bit_offset, const u_int64_t * P1, const u_int64_t * P2, const char * logcat)
{
	for(int i = 0; i < 4; ++i)
	{
		for(int j = 0; j < 4; ++j)
		{
			if(0 != validate_inputs_diff(bit_offset, i, j, RC2I(P1,i,j), RC2I(P2,i,j), logcat))
			{
				log4cpp::Category::getInstance(logcat).fatal("%s: generated inputs diff violation @[%d:%d]; id=%lu.", __FUNCTION__, i, j, bit_offset);
				log_block("P1", P1, logcat, 0);
				log_block("P2", P2, logcat, 0);
				exit(-1);
			}
		}
	}
	log4cpp::Category::getInstance(logcat).info("%s: generated inputs XOR diff check out.", __FUNCTION__);
}

void validate_state_bits(const size_t bit_offset, const u_int64_t x_state[4][5], const u_int8_t F, const char * logcat)
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
			if(0 != (x_state[i][j] & left_rotate(state_xor_bitmask[i][j], bit_offset)))
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

void validate_counter_bits(const size_t bit_offset, const u_int64_t * C, const size_t n, const char * logcat)
{
	u_int64_t LC[16];

	pi_rho_mu((const unsigned char *)C, (unsigned char *)LC);

	u_int64_t mask_41_id = left_rotate(0x1, (41 + bit_offset));

	u_int64_t bit_3_1_41_id = (0 == (RC2I(LC,3,1) & mask_41_id))? 0: 1;
	u_int64_t bit_3_3_41_id = (0 == (RC2I(LC,3,3) & mask_41_id))? 0: 1;

	if(n != ((bit_3_1_41_id << 1) | bit_3_3_41_id))
	{
		log4cpp::Category::getInstance(logcat).fatal("%s: counter bits mismatch; n = %lu; bit_3_1_%lu = %lu; bit_3_3_%lu = %lu;",
				__FUNCTION__, n, (41 + bit_offset), bit_3_1_41_id, (41 + bit_offset), bit_3_3_41_id);
		log_block("C", C, logcat, 0);
		log_block("LC", LC, logcat, 0);
		exit(-1);
	}
	else
	{
		//log_block("C", C, logcat, 700);
		log_block("LC", LC, logcat, 700);

		log4cpp::Category::getInstance(logcat).debug("%s: LC[3][1] = 0x%016lX; LC[3][3] = 0x%016lX; ",
				__FUNCTION__, RC2I(LC,3,1), RC2I(LC,3,3));
		log4cpp::Category::getInstance(logcat).debug("%s: LC[3][1][%lu] = 0x%016lX & 0x%016lX = 0x%016lX",
				__FUNCTION__, (41 + bit_offset), RC2I(LC,3,1), mask_41_id, (RC2I(LC,3,1) & mask_41_id));
		log4cpp::Category::getInstance(logcat).debug("%s: LC[3][3][%lu] = 0x%016lX & 0x%016lX = 0x%016lX",
				__FUNCTION__, (41 + bit_offset), RC2I(LC,3,3), mask_41_id, (RC2I(LC,3,3) & mask_41_id));

		log4cpp::Category::getInstance(logcat).debug("%s: counter bits match; n = %lu; bit_3_1_41_id = %lu; bit_3_3_41_id = %lu;",
				__FUNCTION__, n, bit_3_1_41_id, bit_3_3_41_id);
	}

	log4cpp::Category::getInstance(logcat).info("%s: counter bits check out.", __FUNCTION__);
}

}//namespace U03

namespace U2
{

int validate_generated_input_1st_constraint(const size_t bit_offset, const u_int64_t * PxorIS, const u_int64_t init_state[4][5], const char * logcat)
{
	/*	1st constraint: xor of the bits of this mask should be equal to 1
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000008000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000008000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000008000000L,0x0000000000000000L,0x0000000000000000L
	[0,3] , [1,3] , [3,2]		 */
	u_int64_t mask = left_rotate(0x0000000008000000, bit_offset);
	if(0 == ( mask & ( RC2I(PxorIS,0,3) ^ RC2I(PxorIS,1,3) ^ RC2I(PxorIS,3,2) ) ) )
		return -1;
	return 0;
}

int validate_generated_input_2nd_constraint(const size_t bit_offset, const u_int64_t * PxorIS, const u_int64_t init_state[4][5], const char * logcat)
{
	/* 2nd constraint: xor of the bits of this mask should be equal to 1
	0x0000000000000000L,0x0000000000020000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000020000L,0x0000000000000000L,0x0000000000020000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000020000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000020000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	[0,1] , [1,0] , [1,2] , [2,0] , [3,1]	 */
	u_int64_t mask = left_rotate(0x0000000000020000, bit_offset);
	if (0 == ( mask & ( RC2I(PxorIS,0,1) ^ RC2I(PxorIS,1,0) ^ RC2I(PxorIS,1,2) ^ RC2I(PxorIS,2,0) ^ RC2I(PxorIS,3,1) ) ) )
		return -1;
	return 0;
}

int validate_generated_input_3rd_constraint(const size_t bit_offset, const u_int64_t * PxorIS, const u_int64_t init_state[4][5], const char * logcat)
{
	/* 3rd constraint: xor of the bits of this mask should be equal to 1
	0x0000000000000000L,0x0400000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0400000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0400000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0400000000000000L,0x0000000000000000L,0x0400000000000000L,0x0000000000000000L,0x0000000000000000L
	[0,1] , [1,0] , [2,1] , [3,0] , [3,2]	 */
	u_int64_t mask = left_rotate(0x0400000000000000, bit_offset);
	if (0 == ( mask & ( RC2I(PxorIS,0,1) ^ RC2I(PxorIS,1,0) ^ RC2I(PxorIS,2,1) ^ RC2I(PxorIS,3,0) ^ RC2I(PxorIS,3,2) ) ) )
		return -1;
	return 0;
}

int validate_generated_input_4th_constraint(const size_t bit_offset, const u_int64_t * PxorIS, const u_int64_t init_state[4][5], const char * logcat)
{
	/* 4th constraint: xor of the bits of this mask should be equal to 0
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000100L
	0x0000000000000100L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000100L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000100L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	[0,4]=U0 , [1,0] , [2,0] , [3,0]	*/
	u_int64_t mask = left_rotate(0x0000000000000100, bit_offset);
	if (0 != ( mask & ( init_state[0][4] ^ RC2I(PxorIS,1,0) ^ RC2I(PxorIS,2,0) ^ RC2I(PxorIS,3,0) ) ) )
		return -1;
	return 0;
}

int validate_generated_input_5th_constraint(const size_t bit_offset, const u_int64_t * PxorIS, const u_int64_t init_state[4][5], const char * logcat)
{
	/* 5th constraint: xor of the bits of this mask should be equal to 0
	0x0000000000000000L,0x0000000000000000L,0x0000000000800000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000800000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000800000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000800000L,0x0000000000000000L
	[0,2] , [1,3] , [2,3] , [3,3]	*/
	u_int64_t mask = left_rotate(0x0000000000800000, bit_offset);
	if (0 != ( mask & ( RC2I(PxorIS,0,2) ^ RC2I(PxorIS,1,3) ^ RC2I(PxorIS,2,3) ^ RC2I(PxorIS,3,3) ) ) )
		return -1;
	return 0;
}

void validate_generated_input_1(const size_t bit_offset, const u_int64_t * P, const u_int64_t init_state[4][5], const char * logcat)
{
	u_int64_t PxorIS[4*4];
	for(int i = 0; i < 4; ++i)
	{
		for(int j = 0; j < 4; ++j)
		{
			RC2I(PxorIS, i, j) = RC2I(P, i, j) ^ init_state[i][j];
		}
	}

	if(0 != validate_generated_input_1st_constraint(bit_offset, PxorIS, init_state, logcat))
	{
		log4cpp::Category::getInstance(logcat).fatal("%s: generated input 1st constraint violation; id=%lu.", __FUNCTION__, bit_offset);
		log_block("P", P, logcat, 0);
		log_state("IS", init_state, logcat, 0);
		exit(-1);
	}

	if(0 != validate_generated_input_2nd_constraint(bit_offset, PxorIS, init_state, logcat))
	{
		log4cpp::Category::getInstance(logcat).fatal("%s: generated input 2nd constraint violation; id=%lu.", __FUNCTION__, bit_offset);
		log_block("P", P, logcat, 0);
		log_state("IS", init_state, logcat, 0);
		exit(-1);
	}

	if(0 != validate_generated_input_3rd_constraint(bit_offset, PxorIS, init_state, logcat))
	{
		log4cpp::Category::getInstance(logcat).fatal("%s: generated input 3rd constraint violation; id=%lu.", __FUNCTION__, bit_offset);
		log_block("P", P, logcat, 0);
		log_state("IS", init_state, logcat, 0);
		exit(-1);
	}

	if(0 != validate_generated_input_4th_constraint(bit_offset, PxorIS, init_state, logcat))
	{
		log4cpp::Category::getInstance(logcat).fatal("%s: generated input 4th constraint violation; id=%lu.", __FUNCTION__, bit_offset);
		log_block("P", P, logcat, 0);
		log_state("IS", init_state, logcat, 0);
		exit(-1);
	}

	if(0 != validate_generated_input_5th_constraint(bit_offset, PxorIS, init_state, logcat))
	{
		log4cpp::Category::getInstance(logcat).fatal("%s: generated input 4th constraint violation; id=%lu.", __FUNCTION__, bit_offset);
		log_block("P", P, logcat, 0);
		log_state("IS", init_state, logcat, 0);
		exit(-1);
	}
	log4cpp::Category::getInstance(logcat).info("%s: generated input 4 constraints check out.", __FUNCTION__);
}

}//namespace U2

namespace U1
{
int validate_generated_input_1st_constraint(const size_t bit_offset, const u_int64_t * PxorIS, const u_int64_t init_state[4][5], const char * logcat)
{
//	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000001L
//	0x0000000000000001L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
//	0x0000000000000001L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
//	0x0000000000000001L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
//	[0,4] , [1,0] , [2,0] , [3,0]
	u_int64_t mask = left_rotate(0x1, bit_offset);
	if(0 != (mask & (init_state[0][4] ^ RC2I(PxorIS,1,0) ^ RC2I(PxorIS,2,0) ^ RC2I(PxorIS,3,0))))
		return 0;
	return -1;
}

int validate_generated_input_2nd_constraint(const size_t bit_offset, const u_int64_t * PxorIS, const u_int64_t init_state[4][5], const char * logcat)
{
//	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000080000L,0x0000000000000000L
//	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000080000L,0x0000000000000000L
//	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000080000L
//	0x0000000000000000L,0x0000000000000000L,0x0000000000080000L,0x0000000000000000L,0x0000000000000000L
//	[0,3] , [1,3] , [2,4] , [3,2]
	u_int64_t mask = left_rotate(0x80000, bit_offset);
	if(0 != (mask & (RC2I(PxorIS,0,3) ^ RC2I(PxorIS,1,3) ^ init_state[2][4] ^ RC2I(PxorIS,3,2))))
		return 0;
	return -1;
}

int validate_generated_input_3rd_constraint(const size_t bit_offset, const u_int64_t * PxorIS, const u_int64_t init_state[4][5], const char * logcat)
{
//	0x0000000000000000L,0x0000000000000000L,0x0000000001000000L,0x0000000000000000L,0x0000000000000000L
//	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000001000000L,0x0000000000000000L
//	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000001000000L,0x0000000000000000L
//	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000001000000L,0x0000000000000000L
//	[0,2] , [1,3] , [2,3] , [3,3]
	u_int64_t mask = left_rotate(0x1000000, bit_offset);
	if(0 != (mask & (RC2I(PxorIS,0,2) ^ RC2I(PxorIS,1,3) ^ RC2I(PxorIS,2,3) ^ RC2I(PxorIS,3,3))))
		return 0;
	return -1;
}

int validate_generated_input_4th_constraint(const size_t bit_offset, const u_int64_t * PxorIS, const u_int64_t init_state[4][5], const char * logcat)
{
//	0x0000000000000000L,0x0000000000000000L,0x0000000000200000L,0x0000000000000000L,0x0000000000000000L
//	0x0000000000000000L,0x0000000000200000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
//	0x0000000000000000L,0x0000000000000000L,0x0000000000200000L,0x0000000000000000L,0x0000000000000000L
//	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000200000L,0x0000000000000000L
//	[0,2] , [1,1] , [2,2] , [3,3]
	u_int64_t mask = left_rotate(0x200000, bit_offset);
	if(0 == (mask & (RC2I(PxorIS,0,2) ^ RC2I(PxorIS,1,1) ^ RC2I(PxorIS,2,2) ^ RC2I(PxorIS,3,3))))
		return 0;
	return -1;
}

int validate_generated_input_5th_constraint(const size_t bit_offset, const u_int64_t * PxorIS, const u_int64_t init_state[4][5], const char * logcat)
{
//	0x0000000000000000L,0x0000000000000000L,0x0080000000000000L,0x0000000000000000L,0x0000000000000000L
//	0x0000000000000000L,0x0000000000000000L,0x0080000000000000L,0x0000000000000000L,0x0000000000000000L
//	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0080000000000000L,0x0000000000000000L
//	0x0000000000000000L,0x0080000000000000L,0x0000000000000000L,0x0000000000000000L,0x0080000000000000L
//	[0,2] , [1,2] , [2,3] , [3,1] , [3,4]
	u_int64_t mask = left_rotate(0x80000000000000, bit_offset);
	if(0 == (mask & (RC2I(PxorIS,0,2) ^ RC2I(PxorIS,1,2) ^ RC2I(PxorIS,2,3) ^ RC2I(PxorIS,3,1) ^ init_state[3][4])))
		return 0;
	return -1;
}

int validate_generated_input_6th_constraint(const size_t bit_offset, const u_int64_t * PxorIS, const u_int64_t init_state[4][5], const char * logcat)
{
//	0x0000002000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
//	0x0000000000000000L,0x0000002000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
//	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000002000000000L
//	0x0000002000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
//	[0,0] , [1,1] , [2,4] , [3,0]
	u_int64_t mask = left_rotate(0x2000000000, bit_offset);
	if(0 == (mask & (RC2I(PxorIS,0,0) ^ RC2I(PxorIS,1,1) ^ init_state[2][4] ^ RC2I(PxorIS,3,0))))
		return 0;
	return -1;
}

void validate_generated_input_1(const size_t bit_offset, const u_int64_t * P, const u_int64_t init_state[4][5], const char * logcat)
{
	u_int64_t PxorIS[4*4];
	for(int i = 0; i < 4; ++i)
	{
		for(int j = 0; j < 4; ++j)
		{
			RC2I(PxorIS, i, j) = RC2I(P, i, j) ^ init_state[i][j];
		}
	}

	if(0 != validate_generated_input_1st_constraint(bit_offset, PxorIS, init_state, logcat))
	{
		log4cpp::Category::getInstance(logcat).fatal("%s: generated input 1st constraint violation; id=%lu.", __FUNCTION__, bit_offset);
		log_block("P", P, logcat, 0);
		log_state("IS", init_state, logcat, 0);
		exit(-1);
	}

	if(0 != validate_generated_input_2nd_constraint(bit_offset, PxorIS, init_state, logcat))
	{
		log4cpp::Category::getInstance(logcat).fatal("%s: generated input 2nd constraint violation; id=%lu.", __FUNCTION__, bit_offset);
		log_block("P", P, logcat, 0);
		log_state("IS", init_state, logcat, 0);
		exit(-1);
	}

	if(0 != validate_generated_input_3rd_constraint(bit_offset, PxorIS, init_state, logcat))
	{
		log4cpp::Category::getInstance(logcat).fatal("%s: generated input 3rd constraint violation; id=%lu.", __FUNCTION__, bit_offset);
		log_block("P", P, logcat, 0);
		log_state("IS", init_state, logcat, 0);
		exit(-1);
	}

	if(0 != validate_generated_input_4th_constraint(bit_offset, PxorIS, init_state, logcat))
	{
		log4cpp::Category::getInstance(logcat).fatal("%s: generated input 4th constraint violation; id=%lu.", __FUNCTION__, bit_offset);
		log_block("P", P, logcat, 0);
		log_state("IS", init_state, logcat, 0);
		exit(-1);
	}

	if(0 != validate_generated_input_5th_constraint(bit_offset, PxorIS, init_state, logcat))
	{
		log4cpp::Category::getInstance(logcat).fatal("%s: generated input 5th constraint violation; id=%lu.", __FUNCTION__, bit_offset);
		log_block("P", P, logcat, 0);
		log_state("IS", init_state, logcat, 0);
		exit(-1);
	}

	if(0 != validate_generated_input_6th_constraint(bit_offset, PxorIS, init_state, logcat))
	{
		log4cpp::Category::getInstance(logcat).fatal("%s: generated input 6th constraint violation; id=%lu.", __FUNCTION__, bit_offset);
		log_block("P", P, logcat, 0);
		log_state("IS", init_state, logcat, 0);
		exit(-1);
	}
	log4cpp::Category::getInstance(logcat).info("%s: generated input 6 constraints check out.", __FUNCTION__);
}

int validate_inputs_diff(const size_t bit_offset, int i, int j, const u_int64_t P1v, const u_int64_t P2v, const char * logcat)
{
	/*
	0x0000000000000200L,0x0000000000000200L,0x0000000000000200L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000200L,0x0000000000000200L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000200L,0x0000000000000000L,0x0000000000000200L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000200L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	[0,0] , [0,1] , [0,2] , [1,1] , [1,2] , [2,1] , [2,3] , [3,1]
	*/
	u_int64_t positive = left_rotate(0x200, bit_offset);
	switch(j)
	{
	case 0:
		if(i == 0 && (P1v^P2v) != positive)
			return -1;
		break;
	case 1:
		if((P1v^P2v) != positive)
			return -1;
		break;
	case 2:
		if((i < 2) && (P1v^P2v) != positive)
			return -1;
		break;
	case 3:
		if((i == 2) && (P1v^P2v) != positive)
			return -1;
		break;
	default:
		break;
	}
	return 0;
}

void validate_generated_input_2(const size_t bit_offset, const u_int64_t * P1, const u_int64_t * P2, const char * logcat)
{
	for(int i = 0; i < 4; ++i)
	{
		for(int j = 0; j < 4; ++j)
		{
			if(0 != validate_inputs_diff(bit_offset, i, j, RC2I(P1,i,j), RC2I(P2,i,j), logcat))
			{
				log4cpp::Category::getInstance(logcat).fatal("%s: generated inputs diff violation @[%d:%d]; id=%lu.", __FUNCTION__, i, j, bit_offset);
				log_block("P1", P1, logcat, 0);
				log_block("P2", P2, logcat, 0);
				exit(-1);
			}
		}
	}
	log4cpp::Category::getInstance(logcat).info("%s: generated inputs XOR diff check out.", __FUNCTION__);
}

}//namespace U1
