
#include <stdlib.h>
#include <unistd.h>
#include <semaphore.h>
#include <memory.h>

#include <string>

#include <openssl/evp.h>
#include <event2/event.h>
#include <log4cpp/Category.hh>

#include "aes_prg.h"
#include "icepole128av2/ref/encrypt.h"

#define RC2I(arr,x,y) arr[x + 4*y]

typedef struct
{
	size_t id;
	std::string locat;
	sem_t * run_flag;
	u_int64_t * U0, * U3;
	u_int64_t * samples_done;
	u_int8_t * key, * iv;
}u03_attacker_t;

void sigint_cb(evutil_socket_t, short, void *);
void timer_cb(evutil_socket_t, short, void *);
void * u03_attacker(void *);
int generate_inputs(u_int64_t * P1, u_int64_t * P2, aes_prg & prg, const size_t id);
int trace_inputs(const u_int64_t * P1, const u_int64_t * P2, const char * locat);
u_int64_t left_rotate(u_int64_t v, size_t r);
int encrypt_input(const u_int64_t * P, u_int64_t * C, u03_attacker_t * prm);
int get_perm_output(const u_int64_t * P, const u_int64_t * C, u_int64_t * P_perm_output);

#define KEY_SIZE			16
#define BLOCK_SIZE			128
#define BLONG_SIZE			16
#define ICEPOLE_TAG_SIZE	16

const size_t u03_thread_count = 64;

const u_int64_t u03_ceiling_pow_2_33p9 = 10;//16029384739;

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
								atckr_prms[i].key = (u_int8_t *)key;
								atckr_prms[i].iv = (u_int8_t *)iv;
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
	if(0 != prg.init(BLOCK_SIZE))
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
		u_int64_t P1[2 * BLONG_SIZE], P2[2 * BLONG_SIZE];
		generate_inputs(P1, P2, prg, prm->id);

		u_int64_t C1[2 * BLONG_SIZE], C2[2 * BLONG_SIZE];
		encrypt_input(P1, C1, prm);
		encrypt_input(P2, C2, prm);

		//XOR the 2nd P block with the 2nd C block to get the output of [P6] permutation.
		u_int64_t P1_perm_output[BLONG_SIZE], P2_perm_output[BLONG_SIZE];
		get_perm_output(P1, C1, P1_perm_output);
		get_perm_output(P2, C2, P2_perm_output);

		//XOR with the Kappa constant to undo the Kappa last step in [P6]
		static const u_int8_t k_constant_r5_bytes[] = { 0x00, 0x04, 0x8D, 0x15, 0xFE, 0x26, 0xAF, 0x37 };
		u_int64_t * k_constant_r5 = (u_int64_t *)k_constant_r5_bytes;
		P1_perm_output[0] ^= *k_constant_r5;
		P2_perm_output[0] ^= *k_constant_r5;

		/* For each P:
		 *
		 * 			XOR the 2nd block of P with the 2nd C block to get the output of [P6] permutation.
		 *
		 * 			XOR with the Kappa constant to undo the Kappa last step in [P6]
		 *
		 * 			For each bit in the mask in section 3, we need to get the the respective values
		 * 			of all bits in the same row in the last-S output, and lookup using the table on p.2.
		 * 			If we don't get the value for the target bit before the last-S the filter fails (move on).
		 *
		 * 			If we get the value of all target bits, calculate their XOR call it F1/F2.
		 *
		 * 	Apply pi & rho & mu on 1st block of C1 and get bits[3][1][41] & [3][3][41]
		 *
		 * 	Increment counter-1 [ [3][1][41] , [3][3][41] ].
		 *
		 * 	If the calculated XOR F1/F2 is equal for P1/P2 increment counter-2 [ [3][1][41] , [3][3][41] ].
		 *
		 * 	!!! For all of the above: apply shift-left by ID for everything !!!
		 *
		 * 	Once this is done for 2^33.9 samples, check for which counter pair the deviation from 0.5 is greatest:
		 * 	divide counter-2[v0,v1] by counter-1[v0,v1] and abs ( sub 0.5 ). get the (v0,v1) of the counter with max result.
		 *
		 * 	Collect the ID, v0 and v1 for all thread and rejoin.
		 *
		 * 	Now it is possible to execute step 4 of the guesswork to calculate all bits of U0 and U3
		 *
		 */

		//if(log4cpp::Category::getInstance(prm->locat).isDebugEnabled())
			//log4cpp::Category::getInstance(prm->locat).debug("%s: plaintext size = %lu; cyphertext size = %lu;", __FUNCTION__, 2*BLOCK_SIZE, clen);

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

int generate_inputs(u_int64_t * P1, u_int64_t * P2, aes_prg & prg, const size_t id)
{
	prg.gen_rand_bytes((u_int8_t *)P1, BLOCK_SIZE);

	{	//set 1st constraint
		/*
		const u_int64_t u03_P1_1st_constraint[16] =
		{
			0x0000000000000000, 0x0000000000000010, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
			0x0000000000000010, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
			0x0000000000000000, 0x0000000000000010, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
			0x0000000000000010, 0x0000000000000000, 0x0000000000000010, 0x0000000000000000, //0x0000000000000000,
		};
		*/
		u_int64_t mask = 0x0000000000000010;
		if (0 == (
					(RC2I(P1,0,1) & mask) ^
					(RC2I(P1,1,0) & mask) ^
					(RC2I(P1,2,1) & mask) ^
					(RC2I(P1,3,0) & mask) ^
					(RC2I(P1,3,2) & mask)))
		RC2I(P1,3,2) ^= mask;
	}

	{	//set 2nd constraint
		/*
		const u_int64_t u03_P1_2nd_constraint[16] =
		{
			0x0000000000000000, 0x0000000800000000, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
			0x0000000800000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
			0x0000000000000000, 0x0000000800000000, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
			0x0000000800000000, 0x0000000000000000, 0x0000000800000000, 0x0000000000000000, //0x0000000000000000,
		};
		*/
		u_int64_t mask = 0x0000000800000000;
		if(0 == (
					(RC2I(P1,0,1) & mask) ^
					(RC2I(P1,1,0) & mask) ^
					(RC2I(P1,2,1) & mask) ^
					(RC2I(P1,3,0) & mask) ^
					(RC2I(P1,3,2) & mask)))
			RC2I(P1,3,2) ^= mask;
	}

	{	//set 3rd constraint
		/*
		const u_int64_t u03_P1_3rd_constraint[16] =
		{
			0x0000000000000000, 0x0000000000000000, 0x0000000200000000, 0x0000000000000000, //0x0000000000000000,
			0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000200000000, //0x0000000000000000,
			0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000200000000, //0x0000000000000000,
			0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000200000000, //0x0000000000000000,
		};
		*/
		u_int64_t mask = 0x0000000200000000;
		if(1 == (
					(RC2I(P1,0,2) & mask) ^
					(RC2I(P1,1,3) & mask) ^
					(RC2I(P1,2,3) & mask) ^
					(RC2I(P1,3,3) & mask)))
			RC2I(P1,3,3) ^= mask;
	}

	{	//set 3rd constraint
		/*
		const u_int64_t u03_P1_4th_constraint[16] =
		{
			0x0000000000000000, 0x0000000000000000, 0x0000000000000001, 0x0000000000000000, //0x0000000000000000,
			0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000001, //0x0000000000000000,
			0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000001, //0x0000000000000000,
			0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000001, //0x0000000000000000,
		};
		 */
		u_int64_t mask = 0x0000000000000001;
		if(1 == (
					(RC2I(P1,0,2) & mask) ^
					(RC2I(P1,1,3) & mask) ^
					(RC2I(P1,2,3) & mask) ^
					(RC2I(P1,3,3) & mask)))
			RC2I(P1,3,3) ^= mask;
	}

	memset((u_int8_t *)P1 + BLOCK_SIZE, 0, BLOCK_SIZE);

	/*
	const u_int64_t u03_P1_P2_conversion[16] =
	{
		0x0, 0x0, 0x1, 0x0, //0x0,
		0x1, 0x1, 0x1, 0x1, //0x0,
		0x0, 0x1, 0x0, 0x1, //0x0,
		0x1, 0x0, 0x1, 0x0, //0x0,
	};
	*/
	memcpy(P2, P1, BLOCK_SIZE);
	RC2I(P2,0,2) ^= 0x1;
	RC2I(P2,1,0) ^= 0x1;
	RC2I(P2,1,1) ^= 0x1;
	RC2I(P2,1,2) ^= 0x1;
	RC2I(P2,1,3) ^= 0x1;
	RC2I(P2,2,1) ^= 0x1;
	RC2I(P2,2,3) ^= 0x1;
	RC2I(P2,3,0) ^= 0x1;
	RC2I(P2,3,2) ^= 0x1;

	memset((u_int8_t *)P2 + BLOCK_SIZE, 0, BLOCK_SIZE);

	for(size_t i = 0; i < BLONG_SIZE; ++i)
	{
		P1[i] = left_rotate(P1[i], id);
		P2[i] = left_rotate(P2[i], id);
	}
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

u_int64_t left_rotate(u_int64_t v, size_t r)
{
	r = r % 64;
	return (v << r) | (v >> (64-r));
}

int encrypt_input(const u_int64_t * P, u_int64_t * C, u03_attacker_t * prm)
{
	u_int8_t cenc[2*BLOCK_SIZE + ICEPOLE_TAG_SIZE];
	unsigned long long clen;

	crypto_aead_encrypt(cenc, &clen, (const unsigned char *)P, 2*BLOCK_SIZE, NULL, 0, NULL, prm->iv, prm->key);
	memcpy(C, cenc, 2*BLOCK_SIZE);

	return 0;
}

int get_perm_output(const u_int64_t * P, const u_int64_t * C, u_int64_t * P_perm_output)
{
	const u_int64_t * P_2nd_block = (P+BLONG_SIZE), * C_2nd_block = (C+BLONG_SIZE);
	for(int x = 0; x < 4; ++x)
	{
		for(int y = 0; y < 4; ++y)
		{
			RC2I(P_perm_output,x,y) = RC2I(P_2nd_block,x,y) ^ RC2I(C_2nd_block,x,y);
		}
	}
	return 0;
}
