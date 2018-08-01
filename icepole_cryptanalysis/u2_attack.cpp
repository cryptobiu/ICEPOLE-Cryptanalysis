
#include <stdlib.h>
#include <unistd.h>
#include <semaphore.h>
#include <memory.h>
#include <errno.h>
#include <math.h>

#include <string>
#include <sstream>
#include <iomanip>

#include <openssl/evp.h>
#include <event2/event.h>
#include <log4cpp/Category.hh>

#include "aes_prg.h"
#include "icepole128av2/ref/encrypt.h"

#include "util.h"

namespace ATTACK_U2
{
static const size_t thread_count = 64;
static const time_t allotted_time = 28/*days*/ * 24/*hrs*/ * 60/*mins*/ * 60/*secs*/;
static const struct timeval _3sec = {3,0};

typedef struct
{
	size_t id;
	std::string logcat;
	sem_t * run_flag;
	bool attack_done;
	u_int8_t * key, * iv;
	u_int64_t init_state[4][5];
	u_int64_t ctr_1[4], ctr_2[4];
}attacker_t;

typedef struct
{
	struct event_base * the_base;
	std::string locat;
	std::vector<attacker_t> * atckr_prms;
	time_t start_time;
}event_param_t;

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
	size_t samples_done;
	for(size_t i = 0; i < thread_count; ++i)
	{
		all_attacks_done = all_attacks_done && (*eprm->atckr_prms)[i].attack_done;
		samples_done = (*eprm->atckr_prms)[i].ctr_1[0] +
					   (*eprm->atckr_prms)[i].ctr_1[1] +
					   (*eprm->atckr_prms)[i].ctr_1[2] +
					   (*eprm->atckr_prms)[i].ctr_1[3];
		log4cpp::Category::getInstance(eprm->locat).notice("%s: thread %lu collected %lu samples.", __FUNCTION__, i, samples_done);
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

void * attacker(void * arg);
void guess_work(const std::vector<attacker_t> & atckr_prms, u_int64_t & U2, const char * logcat);

int attack_u2(const char * logcat, const u_int8_t * key, const u_int8_t * iv, u_int64_t & U2, const u_int64_t & U0, const u_int64_t & U3)
{
	int result = -1;

	char locat[32];
	snprintf(locat, 32, "%s.u2", logcat);

	u_int64_t init_state[4][5];
	get_init_block(init_state, key, iv);

	std::vector<attacker_t> atckr_prms(thread_count);

	log4cpp::Category::getInstance(logcat).notice("%s: Provided: U0=0x%016lX; U3=0x%016lX;", __FUNCTION__, U0, U3);
	log4cpp::Category::getInstance(logcat).notice("%s: Real: U0=0x%016lX; U2=0x%016lX; U3=0x%016lX;",
			__FUNCTION__, init_state[0][4], init_state[2][4], init_state[3][4]);

	sem_t run_flag;
	if(0 == sem_init(&run_flag, 0, 1))
	{
		struct event_base * the_base = event_base_new();
		if(NULL != the_base)
		{
			log4cpp::Category::getInstance(logcat).debug("%s: the event base was created.", __FUNCTION__);

			event_param_t eprm;
			eprm.the_base = the_base;
			eprm.locat = locat;
			eprm.atckr_prms = &atckr_prms;
			eprm.start_time = time(NULL);

			struct event * sigint_evt = evsignal_new(the_base, 2/*=SIGINT*/, sigint_cb, &eprm);
			if(NULL != sigint_evt)
			{
				log4cpp::Category::getInstance(logcat).debug("%s: the SIGINT event was created.", __FUNCTION__);

				if(0 == event_add(sigint_evt, NULL))
				{
					log4cpp::Category::getInstance(logcat).debug("%s: the SIGINT event was added.", __FUNCTION__);

					struct event * timer_evt = event_new(the_base, -1, EV_TIMEOUT|EV_PERSIST, timer_cb, &eprm);
					if(NULL != timer_evt)
					{
						log4cpp::Category::getInstance(logcat).debug("%s: the timer event was created.", __FUNCTION__);

						if(0 == event_add(timer_evt, &_3sec))
						{
							log4cpp::Category::getInstance(logcat).debug("%s: the timer event was added.", __FUNCTION__);

							/////////////////////////////////////////////////////////////////////////////////////////////////
							int errcode;
							std::vector<pthread_t> atckr_thds(thread_count);

							for(size_t i = 0; i < thread_count; ++i)
							{
								atckr_prms[i].id = i;
								atckr_prms[i].logcat = locat;
								atckr_prms[i].run_flag = &run_flag;
								atckr_prms[i].attack_done = false;
								atckr_prms[i].key = (u_int8_t *)key;
								atckr_prms[i].iv = (u_int8_t *)iv;
								memcpy(atckr_prms[i].init_state, init_state, 4*5*sizeof(u_int64_t));
								memset(atckr_prms[i].ctr_1, 0, 4 * sizeof(u_int64_t));
								memset(atckr_prms[i].ctr_2, 0, 4 * sizeof(u_int64_t));
								if(0 != (errcode = pthread_create(atckr_thds.data() + i, NULL, attacker, (void *)(atckr_prms.data() + i))))
								{
									char errmsg[256];
									log4cpp::Category::getInstance(locat).error("%s: pthread_create() failed with error %d : [%s]",
											__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
									exit(__LINE__);
								}
								log4cpp::Category::getInstance(locat).debug("%s: attacker thread %lu started.", __FUNCTION__, i);
							}
							log4cpp::Category::getInstance(locat).notice("%s: all attacker threads are run.", __FUNCTION__);

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
							log4cpp::Category::getInstance(locat).notice("%s: attacker thread run signal is down.", __FUNCTION__);

							for(size_t i = 0; i < thread_count; ++i)
							{
								void * retval = NULL;
								if(0 != (errcode = pthread_join(atckr_thds[i], &retval)))
								{
									char errmsg[256];
									log4cpp::Category::getInstance(locat).error("%s: pthread_join() failed with error %d : [%s]",
											__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
									exit(__LINE__);
								}
								log4cpp::Category::getInstance(locat).debug("%s: attacker thread %lu joined.", __FUNCTION__, i);
							}
							log4cpp::Category::getInstance(locat).notice("%s: all attacker threads are joined.", __FUNCTION__);

							guess_work(atckr_prms, U2, locat);

							log4cpp::Category::getInstance(logcat).notice("%s: actual U2 = 0x%016lX.", __FUNCTION__, init_state[2][4]);

							{
								u_int64_t u2cmp = ~(U2 ^ init_state[2][4]);
								size_t eq_bit_cnt = 0;
								for(u_int64_t m = 0x1; m != 0; m <<= 1)
									if(m & u2cmp) eq_bit_cnt++;
								log4cpp::Category::getInstance(locat).notice("%s: correct guessed U2 bits count = %lu.", __FUNCTION__, eq_bit_cnt);
							}

							result = 0;

							/////////////////////////////////////////////////////////////////////////////////////////////////

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

		if(0 != sem_destroy(&run_flag))
		{
			int errcode = errno;
			char errmsg[256];
			log4cpp::Category::getInstance(logcat).error("%s: sem_destroy() failed with error %d : [%s]",
					__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
		}
	}
	else
	{
		int errcode = errno;
		char errmsg[256];
		log4cpp::Category::getInstance(logcat).error("%s: sem_init() failed with error %d : [%s]",
				__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
	}
	return result;
}

}
