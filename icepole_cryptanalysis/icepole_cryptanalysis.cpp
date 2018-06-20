
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

#include <event2/event.h>

#include "aes_prg.h"

#include "icepole128av2/ref/encrypt.h"

void get_options(int argc, char *argv[], int * log_level, size_t * thread_count, unsigned int * required_tests, unsigned int * required_results);
void show_usage(const char * prog);
void init_log(const char * a_log_file, const char * a_log_dir, const int log_level, const char * logcat);
void cryptanalysis(size_t thread_count);
void cryptanalyser_round(const char * locat, const char * recat, aes_prg & prg);

static const char * logcat = "ca4ip.log";
static const char * rescat = "ca4ip.res";
unsigned int tests = 0, results = 0, required_tests = UINT_MAX, required_results = UINT_MAX;
sem_t run_flag;

#define BLOCKSIZE	128

int generate_inputs(u_int8_t * P1, u_int8_t * P2, aes_prg & prg);
int trace_inputs(const u_int8_t * P1, const u_int8_t * P2, const char * locat);

/*
int suitable_msg(u_int8_t * buffer, size_t size);
int pair_msg(const u_int8_t * m1, u_int8_t * m2, size_t size);
int enc_(void * token, const u_int8_t * m, const size_t m_size, u_int8_t * c, size_t * c_size);
int test(const u_int8_t * c1, const size_t c1_size, const u_int8_t * c2, const size_t c2_size);
void log_result(const u_int8_t * m1, const u_int8_t * m2, const size_t m_size,
			    const u_int8_t * c1, const size_t c1_size,
				const u_int8_t * c2, const size_t c2_size, const char * recat);
				*/

int main(int argc, char *argv[])
{
	int log_level = 500; //notice
	size_t thread_count = 1;
	get_options(argc, argv, &log_level, &thread_count, &required_tests, &required_results);

	srand(time(NULL)%1000);

	mkdir("./logs", S_IRWXU | S_IRWXG | S_IRWXO);
	init_log("icepole_cryptanalysis.log", "./logs", log_level, logcat);
	mkdir("./results", S_IRWXU | S_IRWXG | S_IRWXO);
	init_log("icepole_cryptanalysis.txt", "./results", 500, rescat);

	if(0 != sem_init(&run_flag, 0, 1))
	{
		int errcode = errno;
		char errmsg[256];
		log4cpp::Category::getInstance(logcat).error("%s: sem_init() failed with error %d : [%s]",
				__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
		exit(__LINE__);
	}

	cryptanalysis(thread_count);

	if(0 != sem_destroy(&run_flag))
	{
		int errcode = errno;
		char errmsg[256];
		log4cpp::Category::getInstance(logcat).error("%s: sem_destroy() failed with error %d : [%s]",
				__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
		exit(__LINE__);
	}

	return 0;
}

void get_options(int argc, char *argv[], int * log_level, size_t * thread_count, unsigned int * required_tests, unsigned int * required_results)
{
	int opt;
	while ((opt = getopt(argc, argv, "hl:t:s:r:")) != -1)
	{
		switch (opt)
		{
		case 'h':
			show_usage(argv[0]);
			exit(0);
		case 'l':
			*log_level = (int)strtol(optarg, NULL, 10);
			break;
		case 't':
			*thread_count = (size_t)strtol(optarg, NULL, 10);
			break;
		case 's':
			*required_tests = (unsigned int)strtol(optarg, NULL, 10);
			break;
		case 'r':
			*required_results = (unsigned int)strtol(optarg, NULL, 10);
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
	std::cout << "-t   threads count (1)" << std::endl;
	std::cout << "-s   test count (unlimited)" << std::endl;
	std::cout << "-r   result count (unlimited)" << std::endl;
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

void sigint_cb(evutil_socket_t, short, void *);
void timer_cb(evutil_socket_t, short, void *);
void * cryptanalyser(void *);

void cryptanalysis(size_t thread_count)
{
	struct event_base * the_base = event_base_new();
	if(NULL != the_base)
	{
		log4cpp::Category::getInstance(logcat).debug("%s: the event base was created.", __FUNCTION__);

		struct event * sigint_evt = evsignal_new(the_base, 2/*=SIGINT*/, sigint_cb, the_base);
		if(NULL != sigint_evt)
		{
			log4cpp::Category::getInstance(logcat).debug("%s: the SIGINT event was created.", __FUNCTION__);

			if(0 == event_add(sigint_evt, NULL))
			{
				log4cpp::Category::getInstance(logcat).debug("%s: the SIGINT event was added.", __FUNCTION__);

				struct event * timer_evt = event_new(the_base, -1, EV_TIMEOUT|EV_PERSIST, timer_cb, the_base);
				if(NULL != timer_evt)
				{
					log4cpp::Category::getInstance(logcat).debug("%s: the timer event was created.", __FUNCTION__);

					struct timeval asec = {1,0};
					if(0 == event_add(timer_evt, &asec))
					{
						log4cpp::Category::getInstance(logcat).debug("%s: the timer event was added.", __FUNCTION__);

						int errcode;
						std::vector<pthread_t> analysers(thread_count);
						for(size_t i = 0; i < thread_count; ++i)
						{
							if(0 != (errcode = pthread_create(analysers.data() + i, NULL, cryptanalyser, (void *)i)))
							{
								char errmsg[256];
								log4cpp::Category::getInstance(logcat).error("%s: pthread_create() failed with error %d : [%s]",
										__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
								exit(__LINE__);
							}
							else
								log4cpp::Category::getInstance(logcat).debug("%s: analyser thread %lu started.", __FUNCTION__, i);
						}
						log4cpp::Category::getInstance(logcat).notice("%s: all analyser threads are run.", __FUNCTION__);

						log4cpp::Category::getInstance(logcat).notice("%s: event loop started.", __FUNCTION__);
						event_base_dispatch(the_base);
						log4cpp::Category::getInstance(logcat).notice("%s: event loop stopped.", __FUNCTION__);

						if(0 != sem_wait(&run_flag))
						{
							int errcode = errno;
							char errmsg[256];
							log4cpp::Category::getInstance(logcat).error("%s: sem_wait() failed with error %d : [%s]",
									__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
							exit(__LINE__);
						}
						else
							log4cpp::Category::getInstance(logcat).notice("%s: analyser thread run signal is down.", __FUNCTION__);

						for(size_t i = 0; i < thread_count; ++i)
						{
							void * retval = NULL;
							if(0 != (errcode = pthread_join(analysers[i], &retval)))
							{
								char errmsg[256];
								log4cpp::Category::getInstance(logcat).error("%s: pthread_join() failed with error %d : [%s]",
										__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
								exit(__LINE__);
							}
							else
								log4cpp::Category::getInstance(logcat).debug("%s: analyser thread %lu joined.", __FUNCTION__, i);
						}
						log4cpp::Category::getInstance(logcat).notice("%s: all analyser threads are joined.", __FUNCTION__);

						event_del(timer_evt);
						log4cpp::Category::getInstance(logcat).debug("%s: the timer event was removed.", __FUNCTION__);
					}
					else
						log4cpp::Category::getInstance(logcat).error("%s: event_add(timer) failed.", __FUNCTION__);

					event_free(timer_evt);
					log4cpp::Category::getInstance(logcat).debug("%s: the timer event was freed.", __FUNCTION__);
				}
				else
					log4cpp::Category::getInstance(logcat).error("%s: event_new() failed.", __FUNCTION__);

				event_del(sigint_evt);
				log4cpp::Category::getInstance(logcat).debug("%s: the SIGINT event was removed.", __FUNCTION__);
			}
			else
				log4cpp::Category::getInstance(logcat).error("%s: event_add(sigint) failed.", __FUNCTION__);

			event_free(sigint_evt);
			log4cpp::Category::getInstance(logcat).debug("%s: the SIGINT event was freed.", __FUNCTION__);
		}
		else
			log4cpp::Category::getInstance(logcat).error("%s: evsignal_new() failed.", __FUNCTION__);

		event_base_free(the_base);
		log4cpp::Category::getInstance(logcat).debug("%s: the event base was destroyed.", __FUNCTION__);
	}
	else
		log4cpp::Category::getInstance(logcat).error("%s: event_base_new() failed.", __FUNCTION__);
}

void sigint_cb(evutil_socket_t, short, void * arg)
{
	log4cpp::Category::getInstance(logcat).notice("%s: SIGINT caught; breaking event loop.", __FUNCTION__);
	event_base_loopbreak((struct event_base *)arg);
}

void timer_cb(evutil_socket_t, short, void * arg)
{
	unsigned int current_result_count = __sync_add_and_fetch(&results, 0);
	if(current_result_count >= required_results)
	{
		log4cpp::Category::getInstance(logcat).notice("%s: %u results reached; breaking event loop.", __FUNCTION__, current_result_count);
		event_base_loopbreak((struct event_base *)arg);
		return;
	}

	unsigned int current_test_count = __sync_add_and_fetch(&tests, 0);
	if(current_test_count >= required_tests)
	{
		log4cpp::Category::getInstance(logcat).notice("%s: %u tests reached; breaking event loop.", __FUNCTION__, current_test_count);
		event_base_loopbreak((struct event_base *)arg);
		return;
	}

	log4cpp::Category::getInstance(logcat).notice("%s: %u tests performed; %u results collected.",
			__FUNCTION__, current_test_count, current_result_count);
}

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

void cryptanalyser_round(const char * locat, const char * recat, aes_prg & prg)
{
	//*******************************************************************//
	//generate P1 & P2
	u_int8_t P1[2 * BLOCKSIZE], P2[2 * BLOCKSIZE];
	generate_inputs(P1, P2, prg);
	//if(log4cpp::Category::getInstance(locat).isPriorityEnabled(700))
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

/*
void cryptanalyser_round(const char * locat, const char * recat, aes_prg & prg, void * token)
{
	u_int8_t rand_chunk[RAND_CHUNK_SIZE];
	if(0 == prg.gen_rand_bytes(rand_chunk, RAND_CHUNK_SIZE))
	{
		for(size_t i = 0; i < MSGS_IN_CHUNK; i++)
		{
			u_int8_t * m1 = rand_chunk + i * MSG_SIZE;
			if(0 == suitable_msg(m1, MSG_SIZE))
			{
				log4cpp::Category::getInstance(locat).debug("%s: suitable_msg() success.", __FUNCTION__);
				u_int8_t m2[MSG_SIZE];
				if(0 == pair_msg(m1, m2, MSG_SIZE))
				{
					log4cpp::Category::getInstance(locat).debug("%s: pair_msg() success.", __FUNCTION__);
					u_int8_t c1[MSG_SIZE];
					size_t c1_size = 0;
					if(0 == enc_(token, m1, MSG_SIZE, c1, &c1_size))
					{
						log4cpp::Category::getInstance(locat).debug("%s: enc_(m1) success.", __FUNCTION__);
						u_int8_t c2[MSG_SIZE];
						size_t c2_size = 0;
						if(0 == enc_(token, m2, MSG_SIZE, c2, &c2_size))
						{
							log4cpp::Category::getInstance(locat).debug("%s: enc_(m2) success.", __FUNCTION__);
							if(0 == test(c1, c1_size, c2, c2_size))
							{
								log_result(m1, m2, MSG_SIZE, c1, c1_size, c2, c2_size, recat);
								__sync_fetch_and_add(&results, 1);
							}
							else
								log4cpp::Category::getInstance(locat).debug("%s: test() failure.", __FUNCTION__);

						}
						else
							log4cpp::Category::getInstance(locat).error("%s: enc_(m2) failure.", __FUNCTION__);
					}
					else
						log4cpp::Category::getInstance(locat).error("%s: enc_(m1) failure.", __FUNCTION__);
				}
				else
					log4cpp::Category::getInstance(locat).error("%s: pair_msg() failure.", __FUNCTION__);
			}
			else
				log4cpp::Category::getInstance(locat).debug("%s: suitable_msg() failure.", __FUNCTION__);

		}
		__sync_add_and_fetch(&tests, MSGS_IN_CHUNK);
	}
	else
		log4cpp::Category::getInstance(locat).error("%s: prg.gen_rand_bytes() failure.", __FUNCTION__);

}

void log_result(const u_int8_t * m1, const u_int8_t * m2, const size_t m_size,
	    		const u_int8_t * c1, const size_t c1_size,
				const u_int8_t * c2, const size_t c2_size, const char * recat)
{
	std::string result_log_line = "result:";
	std::stringstream srs;

	result_log_line += "\nm1=[";
	srs << std::setfill('0') << std::hex;
	for(size_t i = 0; i < m_size; ++i) srs << std::setw(2) << (int)m1[i];
	result_log_line += srs.str();
	result_log_line += "];\nc1=[";

	srs.str("");
	srs << std::setfill('0') << std::hex;
	for(size_t i = 0; i < c1_size; ++i) srs << std::setw(2) << (int)c1[i];
	result_log_line += srs.str();
	result_log_line += "];\nm2=[";

	srs.str("");
	srs << std::setfill('0') << std::hex;
	for(size_t i = 0; i < m_size; ++i) srs << std::setw(2) << (int)m2[i];
	result_log_line += srs.str();
	result_log_line += "];\nc2=[";

	srs.str("");
	srs << std::setfill('0') << std::hex;
	for(size_t i = 0; i < c2_size; ++i) srs << std::setw(2) << (int)c2[i];
	result_log_line += srs.str();
	result_log_line += "];";

	log4cpp::Category::getInstance(recat).notice(result_log_line);
}

int suitable_msg(u_int8_t * buffer, size_t size)
{
	return -1;
}

int pair_msg(const u_int8_t * m1, u_int8_t * m2, size_t size)
{
	memcpy(m2, m1, size);
	m2[0] ^= 0x80;
	return 0;
}

int enc_(void * token, const u_int8_t * m, const size_t m_size, u_int8_t * c, size_t * c_size)
{
	unsigned long long ct_size = 0;
	if(0 == crypto_aead_encrypt_s(token, c, &ct_size, m, m_size, NULL, 0))
	{
		*c_size = ct_size;
		return 0;
	}
	return -1;
}

int test(const u_int8_t * c1, const size_t c1_size, const u_int8_t * c2, const size_t c2_size)
{
	return -1;
}
*/
