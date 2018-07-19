
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

int attack_u03_bit0_test0(const char * logcat);
int attack_u03_bit0_test1(const char * logcat);

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
    log4cpp::Appender * appender = new log4cpp::RollingFileAppender("rlf.appender", log_file.c_str(), 50*1024*1024, 20);

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

void cryptanalysis()
{
	static const u_int8_t key[KEYSIZE] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
	static const u_int8_t iv[KEYSIZE] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };

	u_int64_t U[4];
	memset(U, 0, 4 * sizeof(u_int64_t));

	if(0 != attack_u03_bit0_test0(logcat))
	{
		log4cpp::Category::getInstance(logcat).error("%s: attack_u03_bit0_test() failure.", __FUNCTION__);
		return;
	}

	/*
	if(0 != attack_u03(logcat, key, iv, U[0], U[3]))
	{
		log4cpp::Category::getInstance(logcat).error("%s: attack_u03() failure.", __FUNCTION__);
		return;
	}*/

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

