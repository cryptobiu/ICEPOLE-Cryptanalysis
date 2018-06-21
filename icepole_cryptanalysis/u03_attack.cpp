
#include <stdlib.h>
#include <unistd.h>
#include <semaphore.h>
#include <memory.h>

#include <string>

#include <openssl/evp.h>
#include <event2/event.h>
#include <log4cpp/Category.hh>

#include "aes_prg.h"

void sigint_cb(evutil_socket_t, short, void *);
void timer_cb(evutil_socket_t, short, void *);
void * u03_attacker(void *);
int generate_inputs(u_int64_t * P1, u_int64_t * P2, aes_prg & prg, const size_t id);
int trace_inputs(const u_int64_t * P1, const u_int64_t * P2, const char * locat);

#define KEYSIZE		16
#define BLOCKSIZE	128
#define BLONGSIZE	16

const size_t u03_thread_count = 64;

const u_int64_t u03_ceiling_pow_2_33p9 = 10;//16029384739;

typedef struct
{
	size_t id;
	std::string locat;
	sem_t * run_flag;
	u_int64_t * U0, * U3;
	u_int64_t * samples_done;
}u03_attacker_t;

typedef struct
{
	struct event_base * the_base;
	std::string locat;
	u_int64_t * samples_done;
}event_param_t;

int attack_u03(const char * logcat, const u_int8_t * key, const u_int8_t * iv, u_int64_t & U0, u_int64_t & U3)
{
	int result = -1;

	char locat[32];
	snprintf(locat, 32, "%s.u03", logcat);

	u_int64_t * samples_done = new u_int64_t[u03_thread_count];
	memset(samples_done, 0, u03_thread_count * sizeof(u_int64_t));

	sem_t run_flag;
	if(0 == sem_init(&run_flag, 0, 1))
	{
		struct event_base * the_base = event_base_new();
		if(NULL != the_base)
		{
			log4cpp::Category::getInstance(locat).debug("%s: the event base was created.", __FUNCTION__);

			event_param_t eprm;
			eprm.the_base = the_base;
			eprm.locat = locat;
			eprm.samples_done = samples_done;

			struct event * sigint_evt = evsignal_new(the_base, 2/*=SIGINT*/, sigint_cb, &eprm);
			if(NULL != sigint_evt)
			{
				log4cpp::Category::getInstance(locat).debug("%s: the SIGINT event was created.", __FUNCTION__);

				if(0 == event_add(sigint_evt, NULL))
				{
					log4cpp::Category::getInstance(locat).debug("%s: the SIGINT event was added.", __FUNCTION__);

					struct event * timer_evt = event_new(the_base, -1, EV_TIMEOUT|EV_PERSIST, timer_cb, &eprm);
					if(NULL != timer_evt)
					{
						log4cpp::Category::getInstance(locat).debug("%s: the timer event was created.", __FUNCTION__);

						struct timeval twosec = {2,0};
						if(0 == event_add(timer_evt, &twosec))
						{
							log4cpp::Category::getInstance(locat).debug("%s: the timer event was added.", __FUNCTION__);

							int errcode;
							std::vector<pthread_t> atckr_thds(u03_thread_count);
							std::vector<u03_attacker_t> atckr_prms(u03_thread_count);
							for(size_t i = 0; i < u03_thread_count; ++i)
							{
								atckr_prms[i].id = i;
								atckr_prms[i].locat = locat;
								atckr_prms[i].run_flag = &run_flag;
								atckr_prms[i].U0 = &U0;
								atckr_prms[i].U3 = &U3;
								atckr_prms[i].samples_done = samples_done + i;
								if(0 != (errcode = pthread_create(atckr_thds.data() + i, NULL, u03_attacker, (void *)(atckr_prms.data() + i))))
								{
									char errmsg[256];
									log4cpp::Category::getInstance(locat).error("%s: pthread_create() failed with error %d : [%s]",
											__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
									exit(__LINE__);
								}
								log4cpp::Category::getInstance(locat).debug("%s: u03 attacker thread %lu started.", __FUNCTION__, i);
							}
							log4cpp::Category::getInstance(locat).notice("%s: all u03 attacker threads are run.", __FUNCTION__);

							log4cpp::Category::getInstance(locat).notice("%s: event loop started.", __FUNCTION__);
							event_base_dispatch(the_base);
							log4cpp::Category::getInstance(locat).notice("%s: event loop stopped.", __FUNCTION__);

							if(0 != sem_wait(&run_flag))
							{
								int errcode = errno;
								char errmsg[256];
								log4cpp::Category::getInstance(locat).error("%s: sem_wait() failed with error %d : [%s]",
										__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
								exit(__LINE__);
							}
							log4cpp::Category::getInstance(locat).notice("%s: u03 attacker thread run signal is down.", __FUNCTION__);

							for(size_t i = 0; i < u03_thread_count; ++i)
							{
								void * retval = NULL;
								if(0 != (errcode = pthread_join(atckr_thds[i], &retval)))
								{
									char errmsg[256];
									log4cpp::Category::getInstance(locat).error("%s: pthread_join() failed with error %d : [%s]",
											__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
									exit(__LINE__);
								}
								log4cpp::Category::getInstance(locat).debug("%s: u03 attacker thread %lu joined.", __FUNCTION__, i);
							}
							log4cpp::Category::getInstance(locat).notice("%s: all u03 attacker threads are joined.", __FUNCTION__);

							event_del(timer_evt);
							log4cpp::Category::getInstance(locat).debug("%s: the timer event was removed.", __FUNCTION__);
						}
						else
							log4cpp::Category::getInstance(locat).error("%s: event_add(timer) failed.", __FUNCTION__);

						event_free(timer_evt);
						log4cpp::Category::getInstance(locat).debug("%s: the timer event was freed.", __FUNCTION__);
					}
					else
						log4cpp::Category::getInstance(locat).error("%s: event_new() failed.", __FUNCTION__);

					event_del(sigint_evt);
					log4cpp::Category::getInstance(locat).debug("%s: the SIGINT event was removed.", __FUNCTION__);
				}
				else
					log4cpp::Category::getInstance(locat).error("%s: event_add(sigint) failed.", __FUNCTION__);

				event_free(sigint_evt);
				log4cpp::Category::getInstance(locat).debug("%s: the SIGINT event was freed.", __FUNCTION__);
			}
			else
				log4cpp::Category::getInstance(locat).error("%s: evsignal_new() failed.", __FUNCTION__);

			event_base_free(the_base);
			log4cpp::Category::getInstance(locat).debug("%s: the event base was destroyed.", __FUNCTION__);
		}
		else
			log4cpp::Category::getInstance(locat).error("%s: event_base_new() failed.", __FUNCTION__);

		if(0 != sem_destroy(&run_flag))
		{
			int errcode = errno;
			char errmsg[256];
			log4cpp::Category::getInstance(locat).error("%s: sem_destroy() failed with error %d : [%s]",
					__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
		}
	}
	else
	{
		int errcode = errno;
		char errmsg[256];
		log4cpp::Category::getInstance(locat).error("%s: sem_init() failed with error %d : [%s]",
				__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
	}
	delete []samples_done;
	return result;
}

void sigint_cb(evutil_socket_t, short, void * arg)
{
	event_param_t * eprm = (event_param_t *)arg;
	log4cpp::Category::getInstance(eprm->locat).notice("%s: SIGINT caught; breaking event loop.", __FUNCTION__);
	event_base_loopbreak(eprm->the_base);
}

void timer_cb(evutil_socket_t, short, void * arg)
{
	bool all_samples_done = true;
	event_param_t * eprm = (event_param_t *)arg;
	for(size_t i = 0; i < u03_thread_count; ++i)
	{
		u_int64_t samples_done = __sync_add_and_fetch(eprm->samples_done + i, 0);
		log4cpp::Category::getInstance(eprm->locat).notice("%s: thread %lu smaples done = %lu.", __FUNCTION__, i, samples_done);

		all_samples_done = all_samples_done && (samples_done >= u03_ceiling_pow_2_33p9);
	}

	if(all_samples_done)
	{
		log4cpp::Category::getInstance(eprm->locat).notice("%s: all samples are done for all threads; breaking event loop.", __FUNCTION__);
		event_base_loopbreak(eprm->the_base);
	}
}

void * u03_attacker(void * arg)
{
	u03_attacker_t * prm = (u03_attacker_t *)arg;

	char atckr_locat[32];
	snprintf(atckr_locat, 32, "%s.%lu", prm->locat.c_str(), prm->id);
	prm->locat = atckr_locat;

	aes_prg prg;
	if(0 != prg.init(BLOCKSIZE))
	{
		log4cpp::Category::getInstance(prm->locat).error("%s: prg.init() failure", __FUNCTION__);
		return NULL;
	}

	int run_flag_value;
	if(0 != sem_getvalue(prm->run_flag, &run_flag_value))
	{
		int errcode = errno;
		char errmsg[256];
		log4cpp::Category::getInstance(prm->locat).error("%s: sem_getvalue() failed with error %d : [%s]",
				__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
		exit(__LINE__);
	}

	size_t samples_done = __sync_add_and_fetch(prm->samples_done, 0);
	while(0 != run_flag_value && samples_done < u03_ceiling_pow_2_33p9)
	{
		u_int64_t P1[2 * BLONGSIZE], P2[2 * BLONGSIZE];
		generate_inputs(P1, P2, prg, prm->id);
		if(log4cpp::Category::getInstance(prm->locat).isPriorityEnabled(700))
			trace_inputs(P1, P2, prm->locat.c_str());

		samples_done = __sync_add_and_fetch(prm->samples_done, 1);

		if(0 != sem_getvalue(prm->run_flag, &run_flag_value))
		{
			int errcode = errno;
			char errmsg[256];
			log4cpp::Category::getInstance(prm->locat).error("%s: sem_getvalue() failed with error %d : [%s]",
					__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
			exit(__LINE__);
		}
	}
	return NULL;
}

/*
const u_int64_t u03_P1_1st_constraint_base[16] =
{
	0x0000000000000000, 0x0000000000000010, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
	0x0000000000000010, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
	0x0000000000000000, 0x0000000000000010, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
	0x0000000000000010, 0x0000000000000000, 0x0000000000000010, 0x0000000000000000, //0x0000000000000000,
};

const u_int64_t u03_P1_2nd_constraint_base[16] =
{
	0x0000000000000000, 0x0000000800000000, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
	0x0000000800000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
	0x0000000000000000, 0x0000000800000000, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
	0x0000000800000000, 0x0000000000000000, 0x0000000800000000, 0x0000000000000000, //0x0000000000000000,
};

const u_int64_t u03_P1_3rd_constraint_base[16] =
{
	0x0000000000000000, 0x0000000000000000, 0x0000000200000000, 0x0000000000000000, //0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000200000000, //0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000200000000, //0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000200000000, //0x0000000000000000,
};

const u_int64_t u03_P1_4th_constraint_base[16] =
{
	0x0000000000000000, 0x0000000000000000, 0x0000000000000001, 0x0000000000000000, //0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000001, //0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000001, //0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000001, //0x0000000000000000,
};
*/

int generate_inputs(u_int64_t * P1, u_int64_t * P2, aes_prg & prg, const size_t id)
{
	prg.gen_rand_bytes((u_int8_t *)P1, BLOCKSIZE);

	{//set 1st constraint
		u_int64_t mask = 0x0000000000000010;
		if(0 == ((P1[1] & mask) ^ (P1[4] & mask) ^ (P1[9] & mask) ^ (P1[12] & mask) ^ (P1[14] & mask)))
			P1[14] ^= mask;
	}

	{//set 2nd constraint
		u_int64_t mask = 0x0000000800000000;
		if(0 == ((P1[1] & mask) ^ (P1[4] & mask) ^ (P1[9] & mask) ^ (P1[12] & mask) ^ (P1[14] & mask)))
			P1[14] ^= mask;
	}

	{//set 3rd constraint
		u_int64_t mask = 0x0000000200000000;
		if(1 == ((P1[2] & mask) ^ (P1[7] & mask) ^ (P1[11] & mask) ^ (P1[15] & mask)))
			P1[15] ^= mask;
	}

	{//set 3rd constraint
		u_int64_t mask = 0x0000000000000001;
		if(1 == ((P1[2] & mask) ^ (P1[7] & mask) ^ (P1[11] & mask) ^ (P1[15] & mask)))
			P1[15] ^= mask;
	}

	memset((u_int8_t *)P1 + BLOCKSIZE, 0, BLOCKSIZE);

	memcpy(P2, P1, BLOCKSIZE);
	P2[2]  = P1[2]  ^ 0x1;
	P2[4]  = P1[4]  ^ 0x1;
	P2[5]  = P1[5]  ^ 0x1;
	P2[6]  = P1[6]  ^ 0x1;
	P2[7]  = P1[7]  ^ 0x1;
	P2[9]  = P1[9]  ^ 0x1;
	P2[11] = P1[11] ^ 0x1;
	P2[12] = P1[12] ^ 0x1;
	P2[14] = P1[14] ^ 0x1;

	memset((u_int8_t *)P2 + BLOCKSIZE, 0, BLOCKSIZE);
}

int trace_inputs(const u_int64_t * P1, const u_int64_t * P2, const char * locat)
{
	char buffer[32];

	std::string str = "inputs:\n";

	str += "P1=\n";
	for(size_t i = 0; i < 4; i++)
	{
		for(size_t j = 0; j < 4; j++)
		{
			snprintf(buffer, 32, "0x%016lX, ", P1[4*i+j]);
			str += buffer;
		}
		str += "0x0000000000000000\n";
	}

	str += "P2=\n";
	for(size_t i = 0; i < 4; i++)
	{
		for(size_t j = 0; j < 4; j++)
		{
			snprintf(buffer, 32, "0x%016lX, ", P2[4*i+j]);
			str += buffer;
		}
		str += "0x0000000000000000\n";
	}

	log4cpp::Category::getInstance(locat).debug(str.c_str());
}
