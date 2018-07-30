
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
#include "u03_attack_validation.h"

typedef struct
{
	size_t id;
	std::string locat;
	sem_t * run_flag;
	u_int64_t * samples_done;
	u_int8_t * key, * iv;
	u_int64_t init_block[4][5];
	u_int64_t ctr_1[4], ctr_2[4];
}u03_attacker_t;

void sigint_cb(evutil_socket_t, short, void *);
void timer_cb(evutil_socket_t, short, void *);
void * u03_attacker(void *);

int generate_input_p1(const size_t thd_id, u_int64_t P1[BLONG_SIZE], aes_prg & prg, const u_int64_t init_state[4][5], const char * logcat);
int generate_input_p2(const size_t thd_id, u_int64_t P1[BLONG_SIZE], u_int64_t P2[BLONG_SIZE], const char * logcat);
int generate_inputs(const size_t thd_id, u_int64_t P1[BLONG_SIZE], u_int64_t P2[BLONG_SIZE], aes_prg & prg, const u_int64_t init_block[4][5], const char * logcat);

int get_permutation_output(const u_int64_t * P, const u_int64_t * C, u_int64_t * P_perm_output);
bool last_Sbox_lookup_filter(const u_int64_t * P_perm_output, const size_t id, u_int8_t & F_xor_res, const char * logcat);
u_int8_t get_row_bits(const u_int64_t * P, const size_t x, const size_t z);
bool lookup_Sbox_input_bit(const u_int8_t output_row_bits, const size_t input_bit_index, u_int8_t & input_bit);
size_t lookup_counter_bits(const size_t thd_id, const u_int64_t * C);
void guess_work(const std::vector<u03_attacker_t> & atckr_prms, u_int64_t & U0, u_int64_t & U3, const char * logcat);
void * u03_attacker_hack(void * arg);
u_int8_t xor_state_bits(const u_int64_t state[4][5], const size_t id);
void get_init_block(u_int64_t ib[4][5], const u_int8_t * key, const u_int8_t * iv);

const size_t u03_thread_count = 64;

const u_int64_t u03_ceiling_pow_2_33p9 = pow(2, 22);//16029384739;

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

	u_int64_t init_block[4][5];
	get_init_block(init_block, key, iv);

	log4cpp::Category::getInstance(logcat).notice("%s: Real: U0=0x%016lX; U3=0x%016lX;", __FUNCTION__, init_block[0][4], init_block[3][4]);

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
								atckr_prms[i].samples_done = samples_done + i;
								atckr_prms[i].key = (u_int8_t *)key;
								atckr_prms[i].iv = (u_int8_t *)iv;
								memcpy(atckr_prms[i].init_block, init_block, 4*5*sizeof(u_int64_t));
								memset(atckr_prms[i].ctr_1, 0, 4 * sizeof(u_int64_t));
								memset(atckr_prms[i].ctr_2, 0, 4 * sizeof(u_int64_t));
								if(0 != (errcode = pthread_create(atckr_thds.data() + i, NULL, u03_attacker_hack, (void *)(atckr_prms.data() + i))))
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

							guess_work(atckr_prms, U0, U3, locat);

							//Check U0 & U3 against the init block.
							//u_int64_t * U_column = (u_int64_t *)init_block + BLONG_SIZE;

							log4cpp::Category::getInstance(logcat).notice("%s: actual U0 = 0x%016lX.", __FUNCTION__, init_block[0][4]);
							log4cpp::Category::getInstance(logcat).notice("%s: actual U3 = 0x%016lX.", __FUNCTION__, init_block[3][4]);

							{
								u_int64_t u3cmp = ~(U3 ^ init_block[3][4]);
								size_t eq_bit_cnt = 0;
								for(u_int64_t m = 0x1; m != 0; m <<= 1)
									if(m & u3cmp) eq_bit_cnt++;
								log4cpp::Category::getInstance(locat).notice("%s: correct guessed U3 bits count = %lu.", __FUNCTION__, eq_bit_cnt);
							}

							{
								u_int64_t u0cmp = ~(U0 ^ init_block[0][4]);
								size_t eq_bit_cnt = 0;
								for(u_int64_t m = 0x1; m != 0; m <<= 1)
									if(m & u0cmp) eq_bit_cnt++;
								log4cpp::Category::getInstance(locat).notice("%s: correct guessed U0 bits count = %lu.", __FUNCTION__, eq_bit_cnt);
							}

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

	u_int64_t P1[2 * BLONG_SIZE], P2[2 * BLONG_SIZE];
	u_int64_t C1[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE], C2[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE];
	unsigned long long clen;

	size_t samples_done = __sync_add_and_fetch(prm->samples_done, 0);
	while(0 != run_flag_value && samples_done < u03_ceiling_pow_2_33p9)
	{
		generate_inputs(prm->id, P1, P2, prg, prm->init_block, prm->locat.c_str());

		//each generated input counts for the 'u03_ceiling_pow_2_33p9'
		samples_done = __sync_add_and_fetch(prm->samples_done, 1);

		clen = 2 * BLONG_SIZE + ICEPOLE_TAG_SIZE;
		crypto_aead_encrypt((unsigned char *)C1, &clen, (const unsigned char *)P1, 2*BLOCK_SIZE, NULL, 0, NULL, prm->iv, prm->key);

		clen = 2 * BLONG_SIZE + ICEPOLE_TAG_SIZE;
		crypto_aead_encrypt((unsigned char *)C2, &clen, (const unsigned char *)P2, 2*BLOCK_SIZE, NULL, 0, NULL, prm->iv, prm->key);

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
		 */

		//XOR the 2nd P block with the 2nd C block to get the output of [P6] permutation.
		u_int64_t P1_perm_output[BLONG_SIZE], P2_perm_output[BLONG_SIZE];
		get_permutation_output(P1, C1, P1_perm_output);
		get_permutation_output(P2, C2, P2_perm_output);

		//XOR with the Kappa constant to undo the Kappa last step in [P6]
		kappa5((unsigned char *)P1_perm_output);
		kappa5((unsigned char *)P2_perm_output);

		u_int8_t F1 = 0;
		if(last_Sbox_lookup_filter(P1_perm_output, prm->id, F1, prm->locat.c_str()))
		{
			u_int8_t F2 = 0;
			if(last_Sbox_lookup_filter(P2_perm_output, prm->id, F2, prm->locat.c_str()))
			{
				/* 	Apply pi & rho & mu on 1st block of C1 and get bits[3][1][41] & [3][3][41]
				 */
				size_t n = lookup_counter_bits(prm->id, C1);

				/* 	Increment counter-1 [ [3][1][41] , [3][3][41] ].
				 */
				prm->ctr_1[n]++;

				/*
				 * 	If the calculated XOR F1/F2 is equal for P1/P2 increment counter-2 [ [3][1][41] , [3][3][41] ].
				 */
				if(F1 == F2)
					prm->ctr_2[n]++;

				/*
				 * 	!!! For all of the above: apply shift-left by ID for everything !!!
				 */
			}
		}

		if(0 != sem_getvalue(prm->run_flag, &run_flag_value))
		{
			int errcode = errno;
			char errmsg[256];
			log4cpp::Category::getInstance(prm->locat).error("%s: sem_getvalue() failed with error %d : [%s]",
					__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
			exit(__LINE__);
		}
	}

	/*
	 * 	Once the above is done for 2^33.9 samples, check for which counter pair the deviation from 0.5 is greatest:
	 * 	divide counter-2[v0,v1] by counter-1[v0,v1] and abs ( sub 0.5 ). get the (v0,v1) of the counter with max result.
	 *
	 * 	Collect the ID, v0 and v1 for all thread and rejoin.
	 *
	 * 	Now it is possible to execute step 4 of the guesswork to calculate all bits of U0 and U3
	 *
	 * 	-------------> The above is done for all threads together post-join.
	 *
	 */

	log4cpp::Category::getInstance(prm->locat).debug("%s: exit.", __FUNCTION__);

	return NULL;
}

int generate_inputs(const size_t thd_id, u_int64_t P1[BLONG_SIZE], u_int64_t P2[BLONG_SIZE], aes_prg & prg, const u_int64_t init_state[4][5], const char * logcat)
{
	generate_input_p1(thd_id, P1, prg, init_state, logcat);
	generate_input_p2(thd_id, P1, P2, logcat);

	log_block("P1shft", P1, logcat, 700);
	log_block("P2shft", P2, logcat, 700);
	return 0;
}

int generate_input_p1(const size_t thd_id, u_int64_t P1[BLONG_SIZE], aes_prg & prg, const u_int64_t init_state[4][5], const char * logcat)
{
	//Generation of random bytes in P1
	prg.gen_rand_bytes((u_int8_t *)P1, BLOCK_SIZE);

	log_block("P1rnd", P1, logcat, 700);

	//XOR of P1 with the icepole init state into P1xIS
	u_int64_t P1xIS[BLONG_SIZE];
	for(size_t i = 0; i < 4; ++i)
		for(size_t j = 0; j < 4; ++j)
			RC2I(P1xIS,i,j) = RC2I(P1,i,j) ^ init_state[i][j], thd_id;

	log_block("P1xIS", P1xIS, logcat, 700);

	{	/* set 1st constraint
		const u_int64_t u03_P1_1st_constraint[16] =
		{
			0x0000000000000000, 0x0000000000000010, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
			0x0000000000000010, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
			0x0000000000000000, 0x0000000000000010, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
			0x0000000000000010, 0x0000000000000000, 0x0000000000000010, 0x0000000000000000, //0x0000000000000000,
		}; */
		u_int64_t mask = left_rotate(0x0000000000000010, thd_id);
		if (0 == (	(RC2I(P1xIS,0,1) & mask) ^
					(RC2I(P1xIS,1,0) & mask) ^
					(RC2I(P1xIS,2,1) & mask) ^
					(RC2I(P1xIS,3,0) & mask) ^
					(RC2I(P1xIS,3,2) & mask)))
		{
			log4cpp::Category::getInstance(logcat).debug("%s: PxIS 1st constraint fixed.", __FUNCTION__);
			RC2I(P1,3,2) ^= mask;
		}
	}

	{	/* set 2nd constraint
		const u_int64_t u03_P1_2nd_constraint[16] =
		{
			0x0000000000000000, 0x0000000800000000, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
			0x0000000800000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
			0x0000000000000000, 0x0000000800000000, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
			0x0000000800000000, 0x0000000000000000, 0x0000000800000000, 0x0000000000000000, //0x0000000000000000,
		}; */
		u_int64_t mask = left_rotate(0x0000000800000000, thd_id);
		if(0 == (	(RC2I(P1xIS,0,1) & mask) ^
					(RC2I(P1xIS,1,0) & mask) ^
					(RC2I(P1xIS,2,1) & mask) ^
					(RC2I(P1xIS,3,0) & mask) ^
					(RC2I(P1xIS,3,2) & mask)))
		{
			log4cpp::Category::getInstance(logcat).debug("%s: PxIS 2nd constraint fixed.", __FUNCTION__);
			RC2I(P1,3,2) ^= mask;
		}
	}

	{	/* set 3rd constraint
		const u_int64_t u03_P1_3rd_constraint[16] =
		{
			0x0000000000000000, 0x0000000000000000, 0x0000000200000000, 0x0000000000000000, //0x0000000000000000,
			0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000200000000, //0x0000000000000000,
			0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000200000000, //0x0000000000000000,
			0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000200000000, //0x0000000000000000,
		}; */
		u_int64_t mask = left_rotate(0x0000000200000000, thd_id);
		if(mask == (	(RC2I(P1xIS,0,2) & mask) ^
						(RC2I(P1xIS,1,3) & mask) ^
						(RC2I(P1xIS,2,3) & mask) ^
						(RC2I(P1xIS,3,3) & mask)))
		{
			log4cpp::Category::getInstance(logcat).debug("%s: PxIS 3rd constraint fixed.", __FUNCTION__);
			RC2I(P1,3,3) ^= mask;
		}
	}

	{	/* set 4th constraint
		const u_int64_t u03_P1_4th_constraint[16] =
		{
			0x0000000000000000, 0x0000000000000000, 0x0000000000000001, 0x0000000000000000, //0x0000000000000000,
			0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000001, //0x0000000000000000,
			0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000001, //0x0000000000000000,
			0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000001, //0x0000000000000000,
		}; */
		u_int64_t mask = left_rotate(0x0000000000000001, thd_id);
		if(mask == (	(RC2I(P1xIS,0,2) & mask) ^
						(RC2I(P1xIS,1,3) & mask) ^
						(RC2I(P1xIS,2,3) & mask) ^
						(RC2I(P1xIS,3,3) & mask)))
		{
			log4cpp::Category::getInstance(logcat).debug("%s: PxIS 4th constraint fixed.", __FUNCTION__);
			RC2I(P1,3,3) ^= mask;
		}
	}

	log_block("P1fix", P1, logcat, 700);

	//set the 2nd block of P1 to zeroes
	memset((u_int8_t *)P1 + BLOCK_SIZE, 0, BLOCK_SIZE);
	return 0;
}

int generate_input_p2(const size_t thd_id, u_int64_t P1[BLONG_SIZE], u_int64_t P2[BLONG_SIZE], const char * logcat)
{
	/*
	const u_int64_t u03_P1_P2_conversion[16] =
	{
		0x0, 0x0, 0x1, 0x0, //0x0,
		0x1, 0x1, 0x1, 0x1, //0x0,
		0x0, 0x1, 0x0, 0x1, //0x0,
		0x1, 0x0, 0x1, 0x0, //0x0,
	}; */

	//copy P1 onto P2 and modify the bits by the conversion mask
	memcpy(P2, P1, 2 * BLOCK_SIZE);
	RC2I(P2,0,2) ^= left_rotate(0x1, thd_id);
	RC2I(P2,1,0) ^= left_rotate(0x1, thd_id);
	RC2I(P2,1,1) ^= left_rotate(0x1, thd_id);
	RC2I(P2,1,2) ^= left_rotate(0x1, thd_id);
	RC2I(P2,1,3) ^= left_rotate(0x1, thd_id);
	RC2I(P2,2,1) ^= left_rotate(0x1, thd_id);
	RC2I(P2,2,3) ^= left_rotate(0x1, thd_id);
	RC2I(P2,3,0) ^= left_rotate(0x1, thd_id);
	RC2I(P2,3,2) ^= left_rotate(0x1, thd_id);
	log_block("P2fix", P2, logcat, 700);
	return 0;
}

int get_permutation_output(const u_int64_t * P, const u_int64_t * C, u_int64_t * P_perm_output)
{
	const u_int64_t * P_2nd_block = (P+BLONG_SIZE), * C_2nd_block = (C+BLONG_SIZE);

	/* Actual implementation
	for(int x = 0; x < 4; ++x)
	{
		for(int y = 0; y < 4; ++y)
		{
			RC2I(P_perm_output,x,y) = RC2I(P_2nd_block,x,y) ^ RC2I(C_2nd_block,x,y);
		}
	}
	*/

	//P_2nd_block is all zeros hence P_2nd_block ^ C_2nd_block = C_2nd_block!!
	memcpy(P_perm_output, C_2nd_block, BLOCK_SIZE);

	return 0;
}

bool last_Sbox_lookup_filter(const u_int64_t * P_perm_output, const size_t id, u_int8_t & F_xor_res, const char * logcat)
{
	/* This is the Omega mask for thread with id=0; for all others shift by id must be applied to z
	const u_int64_t omega_mask[16] =
	{
		0x0008000000000000, 0x0000000200000000, 0x0000000000000000, 0x0000000000001000, //0x0000000000000000,
		0x0000000000000000, 0x0000000800000000, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
		0x0000000000000000, 0x0040000000000000, 0x0000000040000000, 0x0000000000000000, //0x0000000000000000,
		0x0000000000000000, 0x0000000000000000, 0x0000000000000400, 0x0000000002000000, //0x0000000000000000,
	};
	[0][0][51]
	[0][1][33]
	[0][3][12]
	[1][1][35]
	[2][1][54]
	[2][2][30]
	[3][2][10]
	[3][3][25]
	 */

	static const struct __row_t { size_t x; size_t y; size_t z; } rows[8] = { 	{0, 0, 51}, {0, 1, 33}, {0, 3, 12}, {1, 1, 35},
																				{2, 1, 54}, {2, 2, 30}, {3, 2, 10}, {3, 3, 25} };

	u_int8_t row_bits, input_bit;
	F_xor_res = 0;

	for(size_t i = 0; i < 8; ++i)
	{
		struct __row_t current_row = rows[i];
		current_row.z = (current_row.z + id)%64;

		row_bits = get_row_bits(P_perm_output, current_row.x, current_row.z);
		input_bit = 0;

		if(lookup_Sbox_input_bit(row_bits, current_row.y, input_bit))
			F_xor_res ^= input_bit;
		else
			return false;
	}

	return true;
}

u_int8_t get_bit(const u_int64_t * P, const size_t x, const size_t y, const size_t z)
{
	return (0 != (P[x + 4 * y] & (0x1UL << (z%64))))? 1: 0;
}

u_int8_t get_row_bits(const u_int64_t * P, const size_t x, const size_t z)
{
	return (
			(get_bit(P, x, 0, z)	 )	|
			(get_bit(P, x, 1, z) << 1)	|
			(get_bit(P, x, 2, z) << 2)	|
			(get_bit(P, x, 3, z) << 3)
			);
}

bool lookup_Sbox_input_bit(const u_int8_t output_row_bits, const size_t input_bit_index, u_int8_t & input_bit)
{
	switch(output_row_bits)
	{
	case 0x0://in doc
		switch(input_bit_index)
		{
		case 0: input_bit = 1; return true;
		case 2: input_bit = 1; return true;
		case 4: input_bit = 1; return true;
		default: return false;
		}
		break;
	case 0x1://1000
		return false;
	case 0x2://0100
		switch(input_bit_index)
		{
		case 0: input_bit = 0; return true;
		case 1: input_bit = 1; return true;
		case 3: input_bit = 0; return true;
		default: return false;
		}
		break;
	case 0x3://1100
		switch(input_bit_index)
		{
		case 0: input_bit = 1; return true;
		default: return false;
		}
		break;
	case 0x4://0010
		switch(input_bit_index)
		{
		case 1: input_bit = 0; return true;
		default: return false;
		}
		break;
	case 0x5://1010
		switch(input_bit_index)
		{
		case 1: input_bit = 0; return true;
		case 3: input_bit = 0; return true;
		default: return false;
		}
		break;
	case 0x6://0110
		switch(input_bit_index)
		{
		case 0: input_bit = 0; return true;
		case 1: input_bit = 1; return true;
		case 3: input_bit = 0; return true;
		default: return false;
		}
		break;
	case 0x7://1110
		switch(input_bit_index)
		{
		case 0: input_bit = 1; return true;
		case 1: input_bit = 1; return true;
		default: return false;
		}
		break;
	case 0x8://0001
		switch(input_bit_index)
		{
		case 0: input_bit = 0; return true;
		case 1: input_bit = 1; return true;
		case 2: input_bit = 0; return true;
		case 3: input_bit = 1; return true;
		default: return false;
		}
		break;
	case 0x9://1001
		switch(input_bit_index)
		{
		case 0: input_bit = 1; return true;
		case 2: input_bit = 0; return true;
		default: return false;
		}
		break;
	case 0xA://0101
		switch(input_bit_index)
		{
		case 0: input_bit = 0; return true;
		case 1: input_bit = 0; return true;
		case 2: input_bit = 0; return true;
		case 3: input_bit = 1; return true;
		default: return false;
		}
		break;
	case 0xB://1101
		switch(input_bit_index)
		{
		case 0: input_bit = 1; return true;
		case 2: input_bit = 0; return true;
		default: return false;
		}
		break;
	case 0xC://0011
		switch(input_bit_index)
		{
		case 0: input_bit = 1; return true;
		case 1: input_bit = 0; return true;
		case 2: input_bit = 1; return true;
		default: return false;
		}
		break;
	case 0xD://1011
		switch(input_bit_index)
		{
		case 0: input_bit = 0; return true;
		case 1: input_bit = 0; return true;
		case 2: input_bit = 1; return true;
		case 3: input_bit = 1; return true;
		default: return false;
		}
		break;
	case 0xE://0111
		switch(input_bit_index)
		{
		case 0: input_bit = 0; return true;
		case 1: input_bit = 1; return true;
		case 2: input_bit = 1; return true;
		case 3: input_bit = 1; return true;
		default: return false;
		}
		break;
	case 0xF://1111
		switch(input_bit_index)
		{
		case 3: input_bit = 0; return true;
		case 4: input_bit = 0; return true;
		default: return false;
		}
		break;
	default: return false;
	}
	return false;
}

size_t lookup_counter_bits(const size_t thd_id, const u_int64_t * C)
{
	u_int64_t LC[BLONG_SIZE];
	pi_rho_mu((const unsigned char *)C, (unsigned char *)LC);

	u_int8_t bit_3_1_41 = 0;
	if(RC2I(LC,3,1) & left_rotate(1, 41 + thd_id))
	{
		bit_3_1_41 = 1;
	}

	u_int8_t bit_3_3_41 = 0;
	if(RC2I(LC,3,3) & left_rotate(1, 41 + thd_id))
	{
		bit_3_3_41 = 1;
	}

	return (bit_3_1_41 << 1) | bit_3_3_41;
}

void guess_work(const std::vector<u03_attacker_t> & atckr_prms, u_int64_t & U0, u_int64_t & U3, const char * logcat)
{
	//counter-1 [ [3][1][41] , [3][3][41] ] ==> counter-1 [ v0 , v1 ]

	U3 = 0;
	U0 = 0;

	u_int64_t v[64][2];
	memset(v, 0, 64 * 2 * sizeof(u_int64_t));

	for(std::vector<u03_attacker_t>::const_iterator j = atckr_prms.begin(); j != atckr_prms.end(); ++j)
	{
		size_t max_dev_counter_index = 4;
		double max_dev = 0.0, dev;
		for(size_t i = 0; i < 4; ++i)
		{
			dev = (0 != j->ctr_1[i])? fabs( ( double(j->ctr_2[i]) / double(j->ctr_1[i]) ) - 0.5 ): 0.0;

			log4cpp::Category::getInstance(j->locat).notice("%s: ctr1[%lu]=%lu; ctr2[%lu]=%lu; dev=%.08f;",
					__FUNCTION__, i, j->ctr_1[i], i, j->ctr_2[i], dev);

			if(max_dev < dev)
			{
				max_dev = dev;
				max_dev_counter_index = i;
			}
		}
		log4cpp::Category::getInstance(j->locat).debug("%s: selected ctr = %lu.",
				__FUNCTION__, max_dev_counter_index);

		v[j->id][0] = (max_dev_counter_index & 0x2)? 1: 0;
		v[j->id][1] = (max_dev_counter_index & 0x1)? 1: 0;

		log4cpp::Category::getInstance(j->locat).notice("%s: selected ctr-idx = %lu; v0 = %lu; v1 = %lu.",
				__FUNCTION__, max_dev_counter_index, v[j->id][0], v[j->id][1]);

		U3 |= left_rotate((v[j->id][0] ^ 1), 31 + j->id);
	}

	for(std::vector<u03_attacker_t>::const_iterator j = atckr_prms.begin(); j != atckr_prms.end(); ++j)
	{
		U0 |= ( U3 & left_rotate(1, 49 + j->id) ) ^ left_rotate(v[j->id][1], 49 + j->id);
	}
	log4cpp::Category::getInstance(logcat).notice("%s: guessed U0 = 0x%016lX.", __FUNCTION__, U0);
	log4cpp::Category::getInstance(logcat).notice("%s: guessed U3 = 0x%016lX.", __FUNCTION__, U3);
}


/*
 * 3. Implement an encrypt version that saves the icepole state from inside P6, from round4 + Mu, Rho & Pi.
 * (that's P6 minus the last Kappa and Psi).
 *
 * 4. The saved state from 3 is the original 'looked up' state. So now F1 and F2 can be calculated
 * directly. Use the __row_t for mask, and calculate F1 and F2 without filtering.
 *
 * 5. last_Sbox_lookup_filter is not needed. Update the counters accordingly.
 *
 * 6. Perform 2^22 tests and compare.
 *
 */

void * u03_attacker_hack(void * arg)
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

	u_int64_t P1[2 * BLONG_SIZE], P2[2 * BLONG_SIZE];
	u_int64_t C[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE];
	unsigned long long clen;
	u_int64_t x_state[4][5];
	u_int8_t F1 = 0, F2 = 0;

	size_t samples_done = __sync_add_and_fetch(prm->samples_done, 0);
	while(0 != run_flag_value && samples_done < u03_ceiling_pow_2_33p9)
	{
		generate_inputs(prm->id, P1, P2, prg, prm->init_block, prm->locat.c_str());

		//each generated input counts for the 'u03_ceiling_pow_2_33p9'
		samples_done = __sync_add_and_fetch(prm->samples_done, 1);

		clen = 2 * BLONG_SIZE + ICEPOLE_TAG_SIZE;
		crypto_aead_encrypt_hack((unsigned char *)C, &clen, (const unsigned char *)P1, 2*BLOCK_SIZE, NULL, 0, NULL, prm->iv, prm->key, x_state);
		F1 = xor_state_bits(x_state, prm->id);

		size_t n = lookup_counter_bits(prm->id, C);

		clen = 2 * BLONG_SIZE + ICEPOLE_TAG_SIZE;
		crypto_aead_encrypt_hack((unsigned char *)C, &clen, (const unsigned char *)P2, 2*BLOCK_SIZE, NULL, 0, NULL, prm->iv, prm->key, x_state);
		F2 = xor_state_bits(x_state, prm->id);

		/* 	Increment counter-1 [ [3][1][41] , [3][3][41] ]. */
		prm->ctr_1[n]++;

		/* If the calculated XOR F1/F2 is equal for P1/P2 increment counter-2 [ [3][1][41] , [3][3][41] ]. */
		if(F1 == F2)
			prm->ctr_2[n]++;

		if(0 != sem_getvalue(prm->run_flag, &run_flag_value))
		{
			int errcode = errno;
			char errmsg[256];
			log4cpp::Category::getInstance(prm->locat).error("%s: sem_getvalue() failed with error %d : [%s]",
					__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
			exit(__LINE__);
		}
	}

	log4cpp::Category::getInstance(prm->locat).debug("%s: exit.", __FUNCTION__);

	return NULL;
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

u_int8_t xor_state_bits(const u_int64_t state[4][5], const size_t id)
{
	static const struct __bit_t { size_t x; size_t y; size_t z; } bits[8] = { {0, 0, 51}, {0, 1, 33}, {0, 3, 12}, {1, 1, 35},
																			  {2, 1, 54}, {2, 2, 30}, {3, 2, 10}, {3, 3, 25} };
	u_int8_t result = 0;
	for(size_t i = 0; i < 8; ++i)
	{
		u_int64_t integer = state[bits[i].x][bits[i].y];
		u_int64_t mask = left_rotate(0x1, bits[i].z + id);
		result ^= ((integer & mask)? 1: 0);
	}
	return result;
}

void attack_key(const char * logcat, const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE],
				const u_int64_t init_state[4][5], aes_prg & prg, size_t ctr_1[4], size_t ctr_2[4],
				const size_t thd_id)
{
	u_int64_t P1[2 * BLONG_SIZE], P2[2 * BLONG_SIZE];
	u_int64_t C1[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE], C2[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE];
	unsigned long long clen;

	u_int64_t x_state[4][5];
	u_int8_t F1 = 0, F2 = 0;

	generate_inputs(thd_id, P1, P2, prg, init_state, logcat);

	validate_generated_input_1(thd_id, P1, init_state, logcat);
	validate_generated_input_2(thd_id, P1, P2, logcat);

	/**/
	log_block("P1-0", P1, logcat, 700);
	log_block("P1-1", P1+BLONG_SIZE, logcat, 700);
	log_block("P2-0", P2, logcat, 700);
	log_block("P2-1", P2+BLONG_SIZE, logcat, 700);


	clen = 2 * BLONG_SIZE + ICEPOLE_TAG_SIZE;
	crypto_aead_encrypt_hack((unsigned char *)C1, &clen, (const unsigned char *)P1, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key, x_state);

	validate_init_state(P1, C1, init_state, logcat);

	/**/
	log_block("C1-0", C1, logcat, 700);
	log_block("C1-1", C1+BLONG_SIZE, logcat, 700);
	log_state("x-state-1", x_state, logcat, 700);


	F1 = xor_state_bits(x_state, thd_id);
	log4cpp::Category::getInstance(logcat).debug("%s: x-state-1 XOR of designated bits = %hhu.", __FUNCTION__, F1);
	validate_state_bits(thd_id, x_state, F1, logcat);

	clen = 2 * BLONG_SIZE + ICEPOLE_TAG_SIZE;
	crypto_aead_encrypt_hack((unsigned char *)C2, &clen, (const unsigned char *)P2, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key, x_state);

	validate_init_state(P2, C2, init_state, logcat);

	/**/
	log_block("C2-0", C2, logcat, 700);
	log_block("C2-1", C2+BLONG_SIZE, logcat, 700);
	log_state("x-state-2", x_state, logcat, 700);


	F2 = xor_state_bits(x_state, thd_id);
	log4cpp::Category::getInstance(logcat).debug("%s: x-state-2 XOR of designated bits = %hhu.", __FUNCTION__, F2);
	validate_state_bits(thd_id, x_state, F2, logcat);

	size_t n = lookup_counter_bits(thd_id, C1);
	validate_counter_bits(thd_id, C1, n, logcat);

	/**/
	log4cpp::Category::getInstance(logcat).debug("%s: counter bit [3][1][%lu] = %hhu.", __FUNCTION__, 41 + thd_id, ((n & 0x2)? 1: 0));
	log4cpp::Category::getInstance(logcat).debug("%s: counter bit [3][3][%lu] = %hhu.", __FUNCTION__, 41 + thd_id, ((n & 0x1)? 1: 0));
	log4cpp::Category::getInstance(logcat).debug("%s: selected counter = %lu.", __FUNCTION__, n);


	/* 	Increment counter-1 [ [3][1][41] , [3][3][41] ].
	 */
	ctr_1[n]++;

	/*
	 * 	If the calculated XOR F1/F2 is equal for P1/P2 increment counter-2 [ [3][1][41] , [3][3][41] ].
	 */
	if(F1 == F2)
		ctr_2[n]++;
}

void guess(const char * logcat, const size_t ctr_1[4], const size_t ctr_2[4], const u_int64_t U0, const u_int64_t U3, const size_t thd_id)
{
	log4cpp::Category::getInstance(logcat).notice("%s: U0=0x%016lX; U3=0x%016lX;", __FUNCTION__, U0, U3);

	u_int64_t v[2];

	size_t max_dev_counter_index = 4;
	double max_dev = 0.0, dev;
	for(size_t i = 0; i < 4; ++i)
	{
		dev = (0 != ctr_1[i])? fabs( ( double(ctr_2[i]) / double(ctr_1[i]) ) - 0.5 ): 0.0;

		log4cpp::Category::getInstance(logcat).notice("%s: ctr1[%lu]=%lu; ctr2[%lu]=%lu; dev=%.08f;",
				__FUNCTION__, i, ctr_1[i], i, ctr_2[i], dev);

		if(max_dev < dev)
		{
			max_dev = dev;
			max_dev_counter_index = i;
		}
	}
	log4cpp::Category::getInstance(logcat).debug("%s: selected ctr = %lu.",
			__FUNCTION__, max_dev_counter_index);

	v[0] = (max_dev_counter_index & 0x2)? 1: 0;
	v[1] = (max_dev_counter_index & 0x1)? 1: 0;

	log4cpp::Category::getInstance(logcat).notice("%s: selected ctr-idx = %lu; v0 = %lu; v1 = %lu.",
			__FUNCTION__, max_dev_counter_index, v[0], v[1]);

	size_t guessed_bit_offset = 31 + thd_id;
	u_int64_t guessed_bit = v[0]^1, actual_bit = (U3 & left_rotate(0x1, guessed_bit_offset))? 1: 0;

	log4cpp::Category::getInstance(logcat).notice("%s: guessed U3 bit %lu = %lu; actual U3 bit %lu = %lu; U3 %s.",
				__FUNCTION__, guessed_bit_offset, guessed_bit, guessed_bit_offset, actual_bit, ((guessed_bit == actual_bit)? "success": "failure"));

	guessed_bit_offset = 49 + thd_id;
	u_int64_t U0_b49_id = (U0 & left_rotate(0x1, guessed_bit_offset))? 1: 0;
	u_int64_t U3_b49_id = (U3 & left_rotate(0x1, guessed_bit_offset))? 1: 0;

	log4cpp::Category::getInstance(logcat).notice("%s: U0 bit %lu = %lu; U3 bit %lu = %lu; v[1] = %lu.",
			__FUNCTION__, guessed_bit_offset, U0_b49_id, guessed_bit_offset, U3_b49_id, v[1]);

	if((U0_b49_id ^ U3_b49_id) == v[1])
		log4cpp::Category::getInstance(logcat).notice("%s: (U0 bit %lu ^ U3 bit %lu) == v[1]; U0 success.", __FUNCTION__, guessed_bit_offset, guessed_bit_offset);
	else
		log4cpp::Category::getInstance(logcat).notice("%s: (U0 bit %lu ^ U3 bit %lu) != v[1]; U0 failure.", __FUNCTION__, guessed_bit_offset, guessed_bit_offset);
}

void attack_check(const char * logcat, const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE],
				  const u_int64_t init_state[4][5], aes_prg & prg, const size_t thd_id)
{
	u_int64_t P1[2 * BLONG_SIZE], P2[2 * BLONG_SIZE];
	u_int64_t C1[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE], C2[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE];
	unsigned long long clen;
	u_int64_t P1_perm_output[BLONG_SIZE], P2_perm_output[BLONG_SIZE];

	u_int64_t x_state[4][5];
	u_int8_t hF1 = 0, hF2 = 0, tF1 = 0, tF2 = 0, nCount = 0;

	generate_inputs(thd_id, P1, P2, prg, init_state, logcat);

	validate_generated_input_1(thd_id, P1, init_state, logcat);
	validate_generated_input_2(thd_id, P1, P2, logcat);

	log_block("P1-0", P1, logcat, 700);
	log_block("P1-1", P1+BLONG_SIZE, logcat, 700);
	log_block("P2-0", P2, logcat, 700);
	log_block("P2-1", P2+BLONG_SIZE, logcat, 700);

	clen = 2 * BLONG_SIZE + ICEPOLE_TAG_SIZE;
	crypto_aead_encrypt_hack((unsigned char *)C1, &clen, (const unsigned char *)P1, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key, x_state);

	validate_init_state(P1, C1, init_state, logcat);

	log_block("C1-0", C1, logcat, 700);
	log_block("C1-1", C1+BLONG_SIZE, logcat, 700);
	log_state("x-state-1", x_state, logcat, 700);

	hF1 = xor_state_bits(x_state, thd_id);
	validate_state_bits(thd_id, x_state, hF1, logcat);
	log4cpp::Category::getInstance(logcat).debug("%s: x-state-1 XOR of designated bits = %hhu.", __FUNCTION__, hF1);

	get_permutation_output(P1, C1, P1_perm_output);
	kappa5((unsigned char *)P1_perm_output);

	if(last_Sbox_lookup_filter(P1_perm_output, thd_id, tF1, logcat))
	{
		log4cpp::Category::getInstance(logcat).log(((hF1 == tF1)? 500: 300), "%s: tF1 = %hhu %s= %hhu = hF1.",
				__FUNCTION__, tF1, ((hF1 == tF1)? "": "!"), hF1);
		if(hF1 != tF1)
		{
			log_block("P1-0", P1, logcat, 300);
			log_block("P1-1", P1+BLONG_SIZE, logcat, 300);
			log_block("C1-0", C1, logcat, 300);
			log_block("C1-1", C1+BLONG_SIZE, logcat, 300);
			log_state("x-state-1", x_state, logcat, 300);
			log_block("P1_perm-kappa", P1_perm_output, logcat, 300);
		}
		else
			nCount++;
	}
	else
	{
		log4cpp::Category::getInstance(logcat).warn("%s: last_Sbox_lookup_filter() for P1 failed.", __FUNCTION__);
	}

	clen = 2 * BLONG_SIZE + ICEPOLE_TAG_SIZE;
	crypto_aead_encrypt_hack((unsigned char *)C2, &clen, (const unsigned char *)P2, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key, x_state);

	validate_init_state(P2, C2, init_state, logcat);

	log_block("C2-0", C2, logcat, 700);
	log_block("C2-1", C2+BLONG_SIZE, logcat, 700);
	log_state("x-state-2", x_state, logcat, 700);

	hF2 = xor_state_bits(x_state, thd_id);
	validate_state_bits(thd_id, x_state, hF2, logcat);
	log4cpp::Category::getInstance(logcat).debug("%s: x-state-2 XOR of designated bits = %hhu.", __FUNCTION__, hF2);

	get_permutation_output(P2, C2, P2_perm_output);
	kappa5((unsigned char *)P2_perm_output);

	if(last_Sbox_lookup_filter(P2_perm_output, thd_id, tF2, logcat))
	{
		log4cpp::Category::getInstance(logcat).log(((hF2 == tF2)? 500: 300), "%s: tF2 = %hhu %s= %hhu = hF2.",
				__FUNCTION__, tF2, ((hF2 == tF2)? "": "!"), hF2);
		if(hF2 != tF2)
		{
			log_block("P2-0", P2, logcat, 300);
			log_block("P2-1", P2+BLONG_SIZE, logcat, 300);
			log_block("C2-0", C2, logcat, 300);
			log_block("C2-1", C2+BLONG_SIZE, logcat, 300);
			log_state("x-state-2", x_state, logcat, 300);
			log_block("P2_perm-kappa", P2_perm_output, logcat, 300);
		}
		else
			nCount++;
	}
	else
	{
		log4cpp::Category::getInstance(logcat).warn("%s: last_Sbox_lookup_filter() for P1 failed.", __FUNCTION__);
	}

	if(nCount == 2 && (hF1 == tF1) && (hF2 == tF2))
	{
		log4cpp::Category::getInstance(logcat).notice("%s: bingo!!!.", __FUNCTION__);
	}
}

static const size_t keys = 1, attacks = 10000; //pow(2,22);

int attack_u03_test20(const char * logcat)
{
	aes_prg prg;
	if(0 != prg.init(BLOCK_SIZE))
	{
		log4cpp::Category::getInstance(logcat).error("%s: prg.init() failure", __FUNCTION__);
		return -1;
	}

	u_int8_t key[KEY_SIZE], iv[KEY_SIZE];

	log4cpp::Category::getInstance(logcat).notice("%s: testing %lu keys against %lu attack checks:", __FUNCTION__, keys, attacks);

	for(int i = 0; i < keys; ++i)
	{
		log4cpp::Category::getInstance(logcat).notice("%s: checking key %d.\n====================================================================================================================================================\n", __FUNCTION__, i);
		prg.gen_rand_bytes(key, KEY_SIZE);
		log_buffer("key", key, KEY_SIZE, logcat, 700);
		prg.gen_rand_bytes(iv, KEY_SIZE);
		log_buffer("iv ", iv, KEY_SIZE, logcat, 700);

		u_int64_t init_state[4][5];
		get_init_block(init_state, key, iv);
		log_state("init_state", init_state, logcat, 700);

		for(size_t id = 0; id < 1; ++id)
		{
			log4cpp::Category::getInstance(logcat).notice("%s: attack on bit at offset %lu.\n****************************************************************************************************************************************************\n", __FUNCTION__, id);
			size_t ctr_1[4], ctr_2[4];
			memset(ctr_1, 0, 4 * sizeof(size_t));
			memset(ctr_2, 0, 4 * sizeof(size_t));

			for(size_t j = 0; j < attacks; ++j)
			{
				log4cpp::Category::getInstance(logcat).debug("%s: running attack check %lu.\n----------------------------------------------------------------------------------------------------------------------------------------------------\n", __FUNCTION__, j);
				attack_check(logcat, key, iv, init_state, prg, id);
				log4cpp::Category::getInstance(logcat).debug("\n----------------------------------------------------------------------------------------------------------------------------------------------------\n", __FUNCTION__, j);
			}
		}

	}
}

