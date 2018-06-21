
#include <stdlib.h>
#include <unistd.h>
#include <semaphore.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <openssl/rand.h>

#include <iostream>
#include <sstream>
#include <iomanip>

#include <log4cpp/Category.hh>
#include <log4cpp/FileAppender.hh>
#include <log4cpp/SimpleLayout.hh>
#include <log4cpp/RollingFileAppender.hh>
#include <log4cpp/SimpleLayout.hh>
#include <log4cpp/BasicLayout.hh>
#include <log4cpp/PatternLayout.hh>

#include "aes_prg.h"

#include "icepole128av2/ref/encrypt.h"

#define KEYSIZE		16
#define BLOCKSIZE	128

void get_options(int argc, char *argv[], int * log_level);
void show_usage(const char * prog);
void init_log(const char * a_log_file, const char * a_log_dir, const int log_level, const char * logcat);
u_int64_t left_rotate(u_int64_t v, size_t r);
void cryptanalysis();
int attack_u03(const char * logcat, const u_int8_t * key, const u_int8_t * iv, u_int64_t & U0, u_int64_t & U3);
int attack_u2(const u_int8_t * key, const u_int8_t * iv, u_int64_t & U2);
int attack_u1(const u_int8_t * key, const u_int8_t * iv, u_int64_t & U1);


void cryptanalyser_round(const char * locat, const char * recat, aes_prg & prg);
int generate_inputs(u_int8_t * P1, u_int8_t * P2, aes_prg & prg);
int trace_inputs(const u_int8_t * P1, const u_int8_t * P2, const char * locat);

static const char * logcat = "ca4ip.log";

int main(int argc, char *argv[])
{
	int log_level = 500; //notice
	get_options(argc, argv, &log_level);

	mkdir("./logs", S_IRWXU | S_IRWXG | S_IRWXO);
	init_log("icepole_cryptanalysis.log", "./logs", log_level, logcat);

	cryptanalysis();

	return 0;
}

void get_options(int argc, char *argv[], int * log_level)
{
	int opt;
	while ((opt = getopt(argc, argv, "hl:")) != -1)
	{
		switch (opt)
		{
		case 'h':
			show_usage(argv[0]);
			exit(0);
		case 'l':
			*log_level = (int)strtol(optarg, NULL, 10);
			break;
		default:
			std::cerr << "Invalid program arguments." << std::endl;
			show_usage(argv[0]);
			exit(__LINE__);
		}
	}
}

void show_usage(const char * prog)
{
	std::cout << "Usage:" << std::endl;
	std::cout << prog << "   [ OPTIONS ]" << std::endl;
	std::cout << "-l   log level (notice)" << std::endl;
}

void init_log(const char * a_log_file, const char * a_log_dir, const int log_level, const char * logcat)
{
	static const char the_layout[] = "%d{%y-%m-%d %H:%M:%S.%l}| %-6p | %-15c | %m%n";

	std::string log_file = a_log_file;
	log_file.insert(0, "/");
	log_file.insert(0, a_log_dir);

    log4cpp::Layout * log_layout = NULL;
    log4cpp::Appender * appender = new log4cpp::RollingFileAppender("rlf.appender", log_file.c_str(), 10*1024*1024, 5);

    bool pattern_layout = false;
    try
    {
        log_layout = new log4cpp::PatternLayout();
        ((log4cpp::PatternLayout *)log_layout)->setConversionPattern(the_layout);
        appender->setLayout(log_layout);
        pattern_layout = true;
    }
    catch(...)
    {
        pattern_layout = false;
    }

    if(!pattern_layout)
    {
        log_layout = new log4cpp::BasicLayout();
        appender->setLayout(log_layout);
    }

    log4cpp::Category::getInstance(logcat).addAppender(appender);
    log4cpp::Category::getInstance(logcat).setPriority((log4cpp::Priority::PriorityLevel)log_level);
    log4cpp::Category::getInstance(logcat).notice("log start");
}

u_int64_t left_rotate(u_int64_t v, size_t r)
{
	r = r % 64;
	return (v << r) | (v >> (64-r));
}

void cryptanalysis()
{
	static const u_int8_t key[KEYSIZE] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
	static const u_int8_t iv[KEYSIZE] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };

	u_int64_t U[4];
	memset(U, 0, 4 * sizeof(u_int64_t));

	if(0 != attack_u03(logcat, key, iv, U[0], U[3]))
	{
		log4cpp::Category::getInstance(logcat).error("%s: attack_u03() failure.", __FUNCTION__);
		return;
	}

	/*
	if(0 != attack_u2(key, iv, U[2]))
	{
		log4cpp::Category::getInstance(logcat).error("%s: attack_u2() failure.", __FUNCTION__);
		return;
	}*/

	/*
	if(0 != attack_u1(key, iv, U[1]))
	{
		log4cpp::Category::getInstance(logcat).error("%s: attack_u1() failure.", __FUNCTION__);
		return;
	}*/

	log4cpp::Category::getInstance(logcat).notice("%s: attack done; U0=0x%016lX; U1=0x%016lX; U2=0x%016lX; U3=0x%016lX;",
													__FUNCTION__, U[0], U[1], U[2], U[3]);
}

















/*
void * cryptanalyser(void * arg)
{
	char locat[32], recat[32];
	snprintf(locat, 32, "%s.%ld", logcat, (int64_t)arg);
	snprintf(recat, 32, "%s.%ld", rescat, (int64_t)arg);

	aes_prg prg;
	if(0 != prg.init(BLOCKSIZE))
	{
		log4cpp::Category::getInstance(locat).error("%s: prg.init() failure", __FUNCTION__);
		exit(__LINE__);
	}

	int run_flag_value;
	if(0 != sem_getvalue(&run_flag, &run_flag_value))
	{
		int errcode = errno;
		char errmsg[256];
		log4cpp::Category::getInstance(locat).error("%s: sem_getvalue() failed with error %d : [%s]",
				__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
		exit(__LINE__);
	}

	while(0 < run_flag_value)
	{
		cryptanalyser_round(locat, recat, prg);
		if(0 != sem_getvalue(&run_flag, &run_flag_value))
		{
			int errcode = errno;
			char errmsg[256];
			log4cpp::Category::getInstance(locat).error("%s: sem_getvalue() failed with error %d : [%s]",
					__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
			exit(__LINE__);
		}
	}

	prg.term();

	return NULL;
}
*/

/*
void cryptanalyser_round(const char * locat, const char * recat, aes_prg & prg)
{
	//generate P1 & P2
	u_int8_t P1[2 * BLOCKSIZE], P2[2 * BLOCKSIZE];
	generate_inputs(P1, P2, prg);
	if(log4cpp::Category::getInstance(locat).isPriorityEnabled(700))
		trace_inputs(P1, P2, locat);

}

int generate_inputs(u_int8_t * P1, u_int8_t * P2, aes_prg & prg)
{
	prg.gen_rand_bytes(P1, BLOCKSIZE);
	u_int64_t * p1u64 = (u_int64_t *)P1;

	{//set 1st constraint
		u_int64_t mask = 0x0000000000000010;
		if(0 == ((p1u64[1] & mask) ^ (p1u64[4] & mask) ^ (p1u64[9] & mask) ^ (p1u64[12] & mask) ^ (p1u64[14] & mask)))
			p1u64[14] ^= mask;
	}

	{//set 2nd constraint
		u_int64_t mask = 0x0000000800000000;
		if(0 == ((p1u64[1] & mask) ^ (p1u64[4] & mask) ^ (p1u64[9] & mask) ^ (p1u64[12] & mask) ^ (p1u64[14] & mask)))
			p1u64[14] ^= mask;
	}

	{//set 3rd constraint
		u_int64_t mask = 0x0000000200000000;
		if(1 == ((p1u64[2] & mask) ^ (p1u64[7] & mask) ^ (p1u64[11] & mask) ^ (p1u64[15] & mask)))
			p1u64[15] ^= mask;
	}

	{//set 3rd constraint
		u_int64_t mask = 0x0000000000000001;
		if(1 == ((p1u64[2] & mask) ^ (p1u64[7] & mask) ^ (p1u64[11] & mask) ^ (p1u64[15] & mask)))
			p1u64[15] ^= mask;
	}

	memset(P1 + BLOCKSIZE, 0, BLOCKSIZE);

	memcpy(P2, P1, BLOCKSIZE);
	u_int64_t * p2u64 = (u_int64_t *)P2;
	p2u64[2] = p1u64[2] ^ 0x1;
	p2u64[4] = p1u64[4] ^ 0x1;
	p2u64[5] = p1u64[5] ^ 0x1;
	p2u64[6] = p1u64[6] ^ 0x1;
	p2u64[7] = p1u64[7] ^ 0x1;
	p2u64[9] = p1u64[9] ^ 0x1;
	p2u64[11] = p1u64[11] ^ 0x1;
	p2u64[12] = p1u64[12] ^ 0x1;
	p2u64[14] = p1u64[14] ^ 0x1;

	memset(P2 + BLOCKSIZE, 0, BLOCKSIZE);
}

int trace_inputs(const u_int8_t * P1, const u_int8_t * P2, const char * locat)
{
	u_int64_t * p1u64 = (u_int64_t *)P1;
	u_int64_t * p2u64 = (u_int64_t *)P2;
	char buffer[32];

	std::string str = "inputs:\n";

	str += "P1=\n";
	for(size_t i = 0; i < 4; i++)
	{
		for(size_t j = 0; j < 4; j++)
		{
			snprintf(buffer, 32, "0x%016lX, ", p1u64[4*i+j]);
			str += buffer;
		}
		str += "0x0000000000000000\n";
	}

	str += "P2=\n";
	for(size_t i = 0; i < 4; i++)
	{
		for(size_t j = 0; j < 4; j++)
		{
			snprintf(buffer, 32, "0x%016lX, ", p2u64[4*i+j]);
			str += buffer;
		}
		str += "0x0000000000000000\n";
	}

	log4cpp::Category::getInstance(locat).debug(str.c_str());
}
*/
