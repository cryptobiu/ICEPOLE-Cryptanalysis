
#include <stdlib.h>
#include <memory.h>
#include <semaphore.h>
#include <math.h>

#include <sstream>
#include <iomanip>

#include <openssl/evp.h>
#include <event2/event.h>
#include <log4cpp/Category.hh>

#include "util.h"
#include "aes_prg.h"
#include "icepole128av2/ref/encrypt.h"

void log_buffer(const char * label, const u_int8_t * buffer, const size_t size, const char * logcat, const int level)
{
	if(log4cpp::Category::getInstance(logcat).isPriorityEnabled(level))
	{
		std::stringstream srs;
		srs << std::hex << std::setfill('0');
		for(size_t i = 0; i < size; ++i)
			srs << std::setw(2) << static_cast<unsigned>(buffer[i]);
		log4cpp::Category::getInstance(logcat).log(level, "%s: [%s]", label, srs.str().c_str());
	}
}

void log_block(const char * label, const u_int64_t * block, const char * logcat, const int level)
{
	if(log4cpp::Category::getInstance(logcat).isPriorityEnabled(level))
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
}

void log_state(const char * label, const u_int64_t state[4][5], const char * logcat, const int level)
{
	if(log4cpp::Category::getInstance(logcat).isPriorityEnabled(level))
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
}

void sigint_cb(evutil_socket_t, short, void * arg)
{
	event_param_t * eprm = (event_param_t *)arg;
	log4cpp::Category::getInstance(eprm->locat).notice("%s: SIGINT caught; breaking event loop.", __FUNCTION__);
	event_base_loopbreak(eprm->the_base);
}

void timer_cb(evutil_socket_t, short, void * arg)
{
	event_param_t * eprm = (event_param_t *)arg;

	bool all_attacks_done = true;
	size_t samples_done, attacks_done;
	for(size_t i = 0; i < thread_count; ++i)
	{
		all_attacks_done = all_attacks_done && ((*eprm->atckr_prms)[i].attacks_done >= (*eprm->atckr_prms)[i].required_attacks);
		samples_done = (*eprm->atckr_prms)[i].ctr_1[0] +
					   (*eprm->atckr_prms)[i].ctr_1[1] +
					   (*eprm->atckr_prms)[i].ctr_1[2] +
					   (*eprm->atckr_prms)[i].ctr_1[3];
		attacks_done = (*eprm->atckr_prms)[i].attacks_done;
		log4cpp::Category::getInstance(eprm->locat).notice("%s: thread %lu collected %lu samples in %lu attacks.",
				__FUNCTION__, i, samples_done, attacks_done);
	}

	if(all_attacks_done)
	{
		log4cpp::Category::getInstance(eprm->locat).notice("%s: all samples are done for all threads; breaking event loop.", __FUNCTION__);
		event_base_loopbreak(eprm->the_base);
		return;
	}

	time_t now = time(NULL);
	if(now > (eprm->start_time + allotted_time))
	{
		log4cpp::Category::getInstance(eprm->locat).info("%s: start=%lu; allotted=%lu; now=%lu;", __FUNCTION__, eprm->start_time, allotted_time, now);
		log4cpp::Category::getInstance(eprm->locat).notice("%s: allotted time of %lu seconds is up; breaking event loop.", __FUNCTION__, allotted_time);
		event_base_loopbreak(eprm->the_base);
		return;
	}
}

u_int64_t left_rotate(u_int64_t v, size_t r)
{
	r = r % 64;
	return (v << r) | (v >> (64-r));
}

void get_init_block(u_int64_t ib[4][5], const u_int8_t * key, const u_int8_t * iv)
{
	u_int8_t C[128+16];
	memset(C, 0, 128+16);
	unsigned long long clen = 128+16;

	u_int8_t P[128] = { 0 };

	u_int64_t is[4][5];
	memset(is, 0, 20*sizeof(u_int64_t));

	crypto_aead_encrypt_i((unsigned char *)C, &clen, (const unsigned char *)P, 128, NULL, 0, NULL, iv, key, ib);
}

void * attacker(void * arg)
{
	attacker_t * prm = (attacker_t *)arg;

	char atckr_locat[32];
	snprintf(atckr_locat, 32, "%s.%lu", prm->logcat.c_str(), prm->id);
	prm->logcat = atckr_locat;

	aes_prg prg;
	if(0 != prg.init(BLOCK_SIZE))
	{
		log4cpp::Category::getInstance(prm->logcat).error("%s: prg.init() failure", __FUNCTION__);
		return NULL;
	}

	int run_flag_value;
	if(0 != sem_getvalue(prm->run_flag, &run_flag_value))
	{
		int errcode = errno;
		char errmsg[256];
		log4cpp::Category::getInstance(prm->logcat).error("%s: sem_getvalue() failed with error %d : [%s]",
				__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
		exit(__LINE__);
	}

	while(0 != run_flag_value && prm->required_attacks > prm->attacks_done++)
	{
		(*prm->bit_attack)(prm->id, prm->logcat.c_str(), prm->key, prm->iv, prm->init_state, prg, prm->ctr_1, prm->ctr_2);

		if(0 != sem_getvalue(prm->run_flag, &run_flag_value))
		{
			int errcode = errno;
			char errmsg[256];
			log4cpp::Category::getInstance(prm->logcat).error("%s: sem_getvalue() failed with error %d : [%s]",
					__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
			exit(__LINE__);
		}
	}
	log4cpp::Category::getInstance(prm->logcat).debug("%s: exit.", __FUNCTION__);
	return NULL;
}

