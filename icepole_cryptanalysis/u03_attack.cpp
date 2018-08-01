
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

namespace ATTACK_U03
{

int generate_input_p1(const size_t thd_id, u_int64_t P1[BLONG_SIZE], aes_prg & prg, const u_int64_t init_state[4][5], const char * logcat);
int generate_input_p2(const size_t thd_id, u_int64_t P1[BLONG_SIZE], u_int64_t P2[BLONG_SIZE], const char * logcat);
int get_permutation_output(const u_int64_t * P, const u_int64_t * C, u_int64_t * Perm_output);
bool last_Sbox_lookup_filter(const u_int64_t * P_perm_output, const size_t id, u_int8_t & F_xor_res, const char * logcat);
u_int8_t get_row_bits(const u_int64_t * P, const size_t x, const size_t z);
bool lookup_Sbox_input_bit(const u_int8_t output_row_bits, const size_t input_bit_index, u_int8_t & input_bit);
size_t lookup_counter_bits(const size_t thd_id, const u_int64_t * C);
int bit_attack(const size_t bit_offset,
			   const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE], const u_int64_t init_state[4][5],
			   aes_prg & prg, const char * logcat, size_t ctr_1[4], size_t ctr_2[4]);
int u03_bit_attack_check(const size_t bit_offset,
				   	     const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE], const u_int64_t init_state[4][5],
						 aes_prg & prg, const char * logcat, size_t ctr_1[4], size_t ctr_2[4]);
void * attacker(void *);
void guess_work(const std::vector<attacker_t> & atckr_prms, u_int64_t & U0, u_int64_t & U3, const char * logcat);
u_int8_t xor_state_bits(const u_int64_t state[4][5], const size_t bit_offset);

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

int attack_u03(const char * logcat, const u_int8_t * key, const u_int8_t * iv, u_int64_t & U0, u_int64_t & U3)
{
	int result = -1;

	char locat[32];
	snprintf(locat, 32, "%s.u03", logcat);

	u_int64_t init_state[4][5];
	get_init_block(init_state, key, iv);

	std::vector<attacker_t> atckr_prms(thread_count);

	log4cpp::Category::getInstance(logcat).notice("%s: Real: U0=0x%016lX; U3=0x%016lX;", __FUNCTION__, init_state[0][4], init_state[3][4]);

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
			eprm.atckr_prms = &atckr_prms;
			eprm.start_time = time(NULL);

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

						if(0 == event_add(timer_evt, &_3sec))
						{
							log4cpp::Category::getInstance(locat).debug("%s: the timer event was added.", __FUNCTION__);

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

							guess_work(atckr_prms, U0, U3, locat);

							log4cpp::Category::getInstance(logcat).notice("%s: guessed U0 = 0x%016lX.", __FUNCTION__, U0);
							log4cpp::Category::getInstance(logcat).notice("%s: actual  U0 = 0x%016lX.", __FUNCTION__, init_state[0][4]);
							log4cpp::Category::getInstance(logcat).notice("%s: guessed U3 = 0x%016lX.", __FUNCTION__, U3);
							log4cpp::Category::getInstance(logcat).notice("%s: actual  U3 = 0x%016lX.", __FUNCTION__, init_state[3][4]);

							{
								u_int64_t u3cmp = ~(U3 ^ init_state[3][4]);
								size_t eq_bit_cnt = 0;
								for(u_int64_t m = 0x1; m != 0; m <<= 1)
									if(m & u3cmp) eq_bit_cnt++;
								log4cpp::Category::getInstance(locat).notice("%s: correct guessed U3 bits count = %lu.", __FUNCTION__, eq_bit_cnt);
							}

							{
								u_int64_t u0cmp = ~(U0 ^ init_state[0][4]);
								size_t eq_bit_cnt = 0;
								for(u_int64_t m = 0x1; m != 0; m <<= 1)
									if(m & u0cmp) eq_bit_cnt++;
								log4cpp::Category::getInstance(locat).notice("%s: correct guessed U0 bits count = %lu.", __FUNCTION__, eq_bit_cnt);
							}

							result = 0;

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
	return result;
}

int bit_attack(const size_t bit_offset,
				   const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE], const u_int64_t init_state[4][5],
				   aes_prg & prg, const char * logcat, size_t ctr_1[4], size_t ctr_2[4])
{
	u_int64_t P1[2 * BLONG_SIZE], P2[2 * BLONG_SIZE], C[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE];
	unsigned long long clen;
	u_int8_t F1 = 0, F2 = 0;
	u_int64_t x_state[4][5];

	generate_input_p1(bit_offset, P1, prg, init_state, logcat);
	clen = 2 * BLONG_SIZE + ICEPOLE_TAG_SIZE;
	crypto_aead_encrypt((unsigned char *)C, &clen, (const unsigned char *)P1, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key);
	kappa5((unsigned char *)(C+BLONG_SIZE));

	if(last_Sbox_lookup_filter((C+BLONG_SIZE), bit_offset, F1, logcat))
	{
		size_t n = lookup_counter_bits(bit_offset, C);
		generate_input_p2(bit_offset, P1, P2, logcat);
		clen = 2 * BLONG_SIZE + ICEPOLE_TAG_SIZE;
		crypto_aead_encrypt((unsigned char *)C, &clen, (const unsigned char *)P2, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key);
		kappa5((unsigned char *)(C+BLONG_SIZE));
		if(last_Sbox_lookup_filter((C+BLONG_SIZE), bit_offset, F2, logcat))
		{
			ctr_1[n]++;
			if(F1 == F2)
				ctr_2[n]++;
		}
	}
	return 0;
}

int u03_bit_attack_check(const size_t bit_offset,
				   	     const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE], const u_int64_t init_state[4][5],
						 aes_prg & prg, const char * logcat, size_t ctr_1[4], size_t ctr_2[4])
{
	u_int64_t P1[2 * BLONG_SIZE], P2[2 * BLONG_SIZE], C[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE];
	unsigned long long clen;
	u_int8_t F1 = 0, F2 = 0;
	u_int64_t x_state[4][5];

	generate_input_p1(bit_offset, P1, prg, init_state, logcat);
	clen = 2 * BLONG_SIZE + ICEPOLE_TAG_SIZE;
	crypto_aead_encrypt((unsigned char *)C, &clen, (const unsigned char *)P1, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key);
	kappa5((unsigned char *)(C+BLONG_SIZE));

	if(last_Sbox_lookup_filter((C+BLONG_SIZE), bit_offset, F1, logcat))
	{
		size_t n = lookup_counter_bits(bit_offset, C);
		generate_input_p2(bit_offset, P1, P2, logcat);
		clen = 2 * BLONG_SIZE + ICEPOLE_TAG_SIZE;
		crypto_aead_encrypt((unsigned char *)C, &clen, (const unsigned char *)P2, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key);
		kappa5((unsigned char *)(C+BLONG_SIZE));
		if(last_Sbox_lookup_filter((C+BLONG_SIZE), bit_offset, F2, logcat))
		{
			ctr_1[n]++;
			if(F1 == F2)
				ctr_2[n]++;

			clen = 2 * BLONG_SIZE + ICEPOLE_TAG_SIZE;
			crypto_aead_encrypt_hack((unsigned char *)C, &clen, (const unsigned char *)P1, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key, x_state);
			u_int8_t hF1 = xor_state_bits(x_state, bit_offset);

			if(hF1 != F1)
			{
				log4cpp::Category::getInstance(logcat).fatal("%s: hF1 = %hhu != %hhu = F1!", __FUNCTION__, hF1, F1);
				log_buffer("key", key, KEY_SIZE, logcat, 0);
				log_buffer("iv ", iv, KEY_SIZE, logcat, 0);
				log_state("x_state", x_state, logcat, 0);
				log_block("P1", P1, logcat, 0);
				exit(-1);
			}

			clen = 2 * BLONG_SIZE + ICEPOLE_TAG_SIZE;
			crypto_aead_encrypt_hack((unsigned char *)C, &clen, (const unsigned char *)P2, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key, x_state);
			u_int8_t hF2 = xor_state_bits(x_state, bit_offset);

			if(hF2 != F2)
			{
				log4cpp::Category::getInstance(logcat).fatal("%s: hF2 = %hhu != %hhu = F2!", __FUNCTION__, hF2, F2);
				log_buffer("key", key, KEY_SIZE, logcat, 0);
				log_buffer("iv ", iv, KEY_SIZE, logcat, 0);
				log_state("x_state", x_state, logcat, 0);
				log_block("P1", P1, logcat, 0);
				log_block("P2", P1, logcat, 0);
				exit(-1);
			}
		}
	}
	return 0;
}

int generate_input_p1(const size_t thd_id, u_int64_t P1[BLONG_SIZE], aes_prg & prg, const u_int64_t init_state[4][5], const char * logcat)
{
	//Generation of random bytes in P1
	prg.gen_rand_bytes((u_int8_t *)P1, BLOCK_SIZE);

	//XOR of P1 with the icepole init state into P1xIS
	u_int64_t P1xIS[BLONG_SIZE];
	for(size_t i = 0; i < 4; ++i)
		for(size_t j = 0; j < 4; ++j)
			RC2I(P1xIS,i,j) = RC2I(P1,i,j) ^ init_state[i][j], thd_id;

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
			RC2I(P1,3,3) ^= mask;
		}
	}

	//set the 2nd block of P1 to zeroes
	memset((u_int8_t *)P1 + BLOCK_SIZE, 0, BLOCK_SIZE);
	return 0;
}

int get_permutation_output(const u_int64_t * P, const u_int64_t * C, u_int64_t * Perm_output)
{
	const u_int64_t * P_2nd_block = (P+BLONG_SIZE), * C_2nd_block = (C+BLONG_SIZE);

	/* Actual implementation
	for(int x = 0; x < 4; ++x)
	{
		for(int y = 0; y < 4; ++y)
		{
			RC2I(Perm_output,x,y) = RC2I(P_2nd_block,x,y) ^ RC2I(C_2nd_block,x,y);
		}
	}
	*/

	//P_2nd_block is all zeros hence P_2nd_block ^ C_2nd_block = C_2nd_block!!
	memcpy(Perm_output, C_2nd_block, BLOCK_SIZE);

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
	return 0;
}

void guess_work(const std::vector<attacker_t> & atckr_prms, u_int64_t & U0, u_int64_t & U3, const char * logcat)
{
	//counter-1 [ [3][1][41] , [3][3][41] ] ==> counter-1 [ v0 , v1 ]

	U3 = 0;
	U0 = 0;

	u_int64_t v[64][2];
	memset(v, 0, 64 * 2 * sizeof(u_int64_t));

	for(std::vector<attacker_t>::const_iterator j = atckr_prms.begin(); j != atckr_prms.end(); ++j)
	{
		size_t max_dev_counter_index = 4;
		double max_dev = 0.0, dev;
		for(size_t i = 0; i < 4; ++i)
		{
			dev = (0 != j->ctr_1[i])? fabs( ( double(j->ctr_2[i]) / double(j->ctr_1[i]) ) - 0.5 ): 0.0;

			log4cpp::Category::getInstance(j->logcat).debug("%s: ctr1[%lu]=%lu; ctr2[%lu]=%lu; dev=%.08f;",
					__FUNCTION__, i, j->ctr_1[i], i, j->ctr_2[i], dev);

			if(max_dev < dev)
			{
				max_dev = dev;
				max_dev_counter_index = i;
			}
		}

		v[j->id][0] = (max_dev_counter_index & 0x2)? 1: 0;
		v[j->id][1] = (max_dev_counter_index & 0x1)? 1: 0;

		log4cpp::Category::getInstance(j->logcat).debug("%s: selected ctr-idx = %lu; v0 = %lu; v1 = %lu.",
				__FUNCTION__, max_dev_counter_index, v[j->id][0], v[j->id][1]);

		U3 |= left_rotate((v[j->id][0] ^ 1), 31 + j->id);
	}

	for(std::vector<attacker_t>::const_iterator j = atckr_prms.begin(); j != atckr_prms.end(); ++j)
	{
		U0 |= ( U3 & left_rotate(1, 49 + j->id) ) ^ left_rotate(v[j->id][1], 49 + j->id);
	}
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

	size_t required_samples = (size_t)pow(2, 22), samples_done = 0;
	while(0 != run_flag_value && samples_done < required_samples)
	{
		bit_attack(prm->id, prm->key, prm->iv, prm->init_state, prg, prm->logcat.c_str(), prm->ctr_1, prm->ctr_2);

		if(0 != sem_getvalue(prm->run_flag, &run_flag_value))
		{
			int errcode = errno;
			char errmsg[256];
			log4cpp::Category::getInstance(prm->logcat).error("%s: sem_getvalue() failed with error %d : [%s]",
					__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
			exit(__LINE__);
		}
	}

	prm->attack_done = true;
	log4cpp::Category::getInstance(prm->logcat).debug("%s: exit.", __FUNCTION__);
	return NULL;
}

u_int8_t xor_state_bits(const u_int64_t state[4][5], const size_t bit_offset)
{
	static const struct __bit_t { size_t x; size_t y; size_t z; } bits[8] = { {0, 0, 51}, {0, 1, 33}, {0, 3, 12}, {1, 1, 35},
																			  {2, 1, 54}, {2, 2, 30}, {3, 2, 10}, {3, 3, 25} };
	u_int8_t result = 0;
	for(size_t i = 0; i < 8; ++i)
	{
		u_int64_t integer = state[bits[i].x][bits[i].y];
		u_int64_t mask = left_rotate(0x1, bits[i].z + bit_offset);
		result ^= ((integer & mask)? 1: 0);
	}
	return result;
}

}//namespace ATTACK_U03
