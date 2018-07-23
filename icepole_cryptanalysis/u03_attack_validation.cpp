
#include <stdlib.h>
#include <sstream>
#include <iomanip>

#include <log4cpp/Category.hh>

#define RC2I(arr,x,y) arr[x + 4*y]

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
				log4cpp::Category::getInstance(logcat).fatal("%s: P^C[%d:%d] = %016lX; IB[i][i] = %016lX; mismatch.", __FUNCTION__, i, j, ( RC2I(P,i,j) ^ RC2I(C,i,j) ), init_block[i][j]);
				exit(-1);
			}
		}
	}
}

int validate_generated_input_1st_constraint(const u_int64_t * PxorIS, const u_int64_t init_state[4][5], const char * logcat)
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

	if(0 == (0x0000000000000010 & (RC2I(PxorIS,0,1) ^ RC2I(PxorIS,1,0) ^ RC2I(PxorIS,2,1) ^ RC2I(PxorIS,3,0) ^ RC2I(PxorIS,3,2))))
		return -1;
	return 0;
}

int validate_generated_input_2nd_constraint(const u_int64_t * PxorIS, const u_int64_t init_state[4][5], const char * logcat)
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
	if(0 == (0x0000000800000000 & (RC2I(PxorIS,0,1) ^ RC2I(PxorIS,1,0) ^ RC2I(PxorIS,2,1) ^ RC2I(PxorIS,3,0) ^ RC2I(PxorIS,3,2))))
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

	if(0 != validate_generated_input_1st_constraint(PxorIS, init_state, logcat))
	{
		log4cpp::Category::getInstance(logcat).fatal("%s: generated input 1st constraint violation.", __FUNCTION__);
		log_block("P", P, logcat, 0);
		log_state("IS", init_state, logcat, 0);
		exit(-1);
	}

	if(0 != validate_generated_input_2nd_constraint(PxorIS, init_state, logcat))
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
	log4cpp::Category::getInstance(logcat).info("%s: generated input 4 constraints check.", __FUNCTION__);
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
}
