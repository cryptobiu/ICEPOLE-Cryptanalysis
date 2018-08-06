
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

#include <event2/event.h>
#include <log4cpp/Category.hh>
#include <log4cpp/FileAppender.hh>
#include <log4cpp/SimpleLayout.hh>
#include <log4cpp/RollingFileAppender.hh>
#include <log4cpp/SimpleLayout.hh>
#include <log4cpp/BasicLayout.hh>
#include <log4cpp/PatternLayout.hh>

#include "aes_prg.h"
#include "util.h"

#include "icepole128av2/ref/encrypt.h"

#include "u03_attack.h"
#include "u2_attack.h"
#include "u1_attack.h"

void get_options(int argc, char *argv[], int * log_level);
void show_usage(const char * prog);
void init_log(const char * a_log_file, const char * a_log_dir, const int log_level, const char * logcat);
void cryptanalysis();

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
	u_int8_t key[KEY_SIZE], iv[KEY_SIZE];

	aes_prg prg;
	if(0 != prg.init(BLOCK_SIZE))
	{
		log4cpp::Category::getInstance(logcat).error("%s: prg.init() failure", __FUNCTION__);
		return;
	}

	prg.gen_rand_bytes(key, KEY_SIZE);
	log_buffer("Selected key", key, KEY_SIZE, logcat, 700);
	prg.gen_rand_bytes(iv, KEY_SIZE);
	log_buffer("Selected iv ", iv, KEY_SIZE, logcat, 700);

	u_int64_t U[4];
	memset(U, 0, 4 * sizeof(u_int64_t));

	/*
	if(0 != ATTACK_U03::attack_u03(logcat, key, iv, U[0], U[3]))
	{
		log4cpp::Category::getInstance(logcat).error("%s: attack_u03() failure.", __FUNCTION__);
		return;
	}
	*/

	/*
	//provide U0 and U3 instead of the above U03 attack
	u_int64_t init_state[4][5];
	get_init_block(init_state, key, iv, logcat);

	if(0 != ATTACK_U2::attack_u2(logcat, key, iv, U[2], init_state[0][4], init_state[3][4]))
	{
		log4cpp::Category::getInstance(logcat).error("%s: attack_u2() failure.", __FUNCTION__);
		return;
	}
	*/

	/**/
	//provide U0, U2 and U3 instead of the above U03 and U2 attacks
	u_int64_t init_state[4][5];
	get_init_block(init_state, key, iv, logcat);//U0 must be XORed with 3 to revert the 2 padding bits
	//if(0 != ATTACK_U1::attack_u1(logcat, key, iv, U[1], init_state[0][4] ^ 3, init_state[2][4], init_state[3][4]))
	if(0 != ATTACK_U1::attack_u1_gen_test(logcat, key, iv, prg))
	{
		//log4cpp::Category::getInstance(logcat).error("%s: attack_u1() failure.", __FUNCTION__);
		log4cpp::Category::getInstance(logcat).error("%s: attack_u1_gen_test() failure.", __FUNCTION__);
		return;
	}

	/*
	log4cpp::Category::getInstance(logcat).notice("%s: attack done; U0=0x%016lX; U1=0x%016lX; U2=0x%016lX; U3=0x%016lX;",
													__FUNCTION__, U[0], U[1], U[2], U[3]);*/

}

