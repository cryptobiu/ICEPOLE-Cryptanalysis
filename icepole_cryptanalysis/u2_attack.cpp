
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

void guess_work(const std::vector<attacker_t> & atckr_prms, u_int64_t & U2, const char * logcat);
int bit_attack(const size_t bit_offset, const char * logcat,
				   const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE], const u_int64_t init_state[4][5],
				   aes_prg & prg, size_t ctr_1[4], size_t ctr_2[4]);
int bit_attack_check(const size_t bit_offset, const char * logcat,
				   	 const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE], const u_int64_t init_state[4][5],
					 aes_prg & prg, size_t ctr_1[4], size_t ctr_2[4]);
int generate_input_p1(const size_t bit_offset, u_int64_t P1[BLONG_SIZE], aes_prg & prg, const u_int64_t init_state[4][5], const char * logcat);
int generate_input_p2(const size_t bit_offset, const u_int64_t P1[BLONG_SIZE], u_int64_t P2[BLONG_SIZE], const char * logcat);
bool last_Sbox_lookup_filter(const u_int64_t * P_perm_output, const size_t id, u_int8_t & F_xor_res, const char * logcat);

int attack_u2(const char * logcat, const u_int8_t * key, const u_int8_t * iv, u_int64_t & U2, const u_int64_t & U0, const u_int64_t & U3)
{
	int result = -1;

	char locat[32];
	snprintf(locat, 32, "%s.u2", logcat);

	u_int64_t init_state[4][5];
	get_init_block(init_state, key, iv, logcat);
	init_state[0][4] = U0;
	init_state[3][4] = U3;

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
								atckr_prms[i].key = (u_int8_t *)key;
								atckr_prms[i].iv = (u_int8_t *)iv;
								memcpy(atckr_prms[i].init_state, init_state, 4*5*sizeof(u_int64_t));
								memset(atckr_prms[i].ctr_1, 0, 4 * sizeof(u_int64_t));
								memset(atckr_prms[i].ctr_2, 0, 4 * sizeof(u_int64_t));
								atckr_prms[i].attacks_done = 0;
								atckr_prms[i].required_attacks = pow(2, 30);
								atckr_prms[i].bit_attack = bit_attack;
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

							log4cpp::Category::getInstance(logcat).notice("%s: guessed U2 = 0x%016lX.", __FUNCTION__, U2);
							log4cpp::Category::getInstance(logcat).notice("%s: actual  U2 = 0x%016lX.", __FUNCTION__, init_state[2][4]);

							{
								u_int64_t u2cmp = ~(U2 ^ init_state[2][4]);
								size_t eq_bit_cnt = 0;
								for(u_int64_t m = 0x1; m != 0; m <<= 1)
									if(m & u2cmp) eq_bit_cnt++;
								log4cpp::Category::getInstance(locat).notice("%s: correct guessed U2 bits count = %lu.", __FUNCTION__, eq_bit_cnt);
							}

							result = 0;

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

void guess_work(const std::vector<attacker_t> & atckr_prms, u_int64_t & U2, const char * logcat)
{
	U2 = 0;
	for(size_t j = 0; j < thread_count; ++j)
	{
		const attacker_t & aj(atckr_prms[j]);
		double dev = (aj.ctr_1[0] != 0)? fabs( ( double(aj.ctr_2[0]) / double(aj.ctr_1[0]) ) - 0.5): 0.0;
		if(pow(2.0, -9.83) >= dev)
		{
			U2 |= left_rotate(0x1, 27 + j);
		}
	}
}

int bit_attack(const size_t bit_offset, const char * logcat,
			   const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE], const u_int64_t init_state[4][5],
			   aes_prg & prg, size_t ctr_1[4], size_t ctr_2[4])
{
	/**/
	u_int64_t P1[2 * BLONG_SIZE], P2[2 * BLONG_SIZE], C[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE];
	unsigned long long clen;
	u_int8_t F1 = 0, F2 = 0;
	u_int64_t x_state[4][5];

	generate_input_p1(bit_offset, P1, prg, init_state, logcat);
	clen = 2 * BLONG_SIZE + ICEPOLE_TAG_SIZE;
	crypto_aead_encrypt((unsigned char *)C, &clen, (const unsigned char *)P1, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key);
	kappa5((unsigned char *)(C+BLONG_SIZE));

	/*
	if(last_Sbox_lookup_filter((C+BLONG_SIZE), bit_offset, F1, logcat))
	{
		generate_input_p2(bit_offset, P1, P2, logcat);
		clen = 2 * BLONG_SIZE + ICEPOLE_TAG_SIZE;
		crypto_aead_encrypt((unsigned char *)C, &clen, (const unsigned char *)P2, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key);
		kappa5((unsigned char *)(C+BLONG_SIZE));
		if(last_Sbox_lookup_filter((C+BLONG_SIZE), bit_offset, F2, logcat))
		{
			ctr_1[0]++;
			if(F1 == F2)
				ctr_2[0]++;
		}
	}*/
	return 0;
}

int generate_input_p1(const size_t bit_offset, u_int64_t P1[BLONG_SIZE], aes_prg & prg, const u_int64_t init_state[4][5], const char * logcat)
{
	//Generation of random bytes in P1
	prg.gen_rand_bytes((u_int8_t *)P1, BLOCK_SIZE);

	//XOR of P1 with the icepole init state into P1xIS
	u_int64_t P1xIS[BLONG_SIZE];
	for(size_t i = 0; i < 4; ++i)
		for(size_t j = 0; j < 4; ++j)
			RC2I(P1xIS,i,j) = RC2I(P1,i,j) ^ init_state[i][j];

	/*	1st constraint: xor of the bits of this mask should be equal to 1
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000008000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000008000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000008000000L,0x0000000000000000L,0x0000000000000000L
	[0,3] , [1,3] , [3,2]		 */
	u_int64_t mask1 = left_rotate(0x0000000008000000, bit_offset);
	if (0 == ( mask1 & ( RC2I(P1xIS,0,3) ^ RC2I(P1xIS,1,3) ^ RC2I(P1xIS,3,2) ) ) )
	{
		RC2I(P1,3,2) ^= mask1;
	}

	/* 2nd constraint: xor of the bits of this mask should be equal to 1
	0x0000000000000000L,0x0000000000020000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000020000L,0x0000000000000000L,0x0000000000020000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000020000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000020000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	[0,1] , [1,0] , [1,2] , [2,0] , [3,1]	 */
	u_int64_t mask2 = left_rotate(0x0000000000020000, bit_offset);
	if (0 == ( mask2 & ( RC2I(P1xIS,0,1) ^ RC2I(P1xIS,1,0) ^ RC2I(P1xIS,1,2) ^ RC2I(P1xIS,2,0) ^ RC2I(P1xIS,3,1) ) ) )
	{
		RC2I(P1,3,1) ^= mask2;
	}

	/* 3rd constraint: xor of the bits of this mask should be equal to 1
	0x0000000000000000L,0x0400000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0400000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0400000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0400000000000000L,0x0000000000000000L,0x0400000000000000L,0x0000000000000000L,0x0000000000000000L
	[0,1] , [1,0] , [2,1] , [3,0] , [3,2]	 */
	u_int64_t mask3 = left_rotate(0x0400000000000000, bit_offset);
	if (0 == ( mask3 & ( RC2I(P1xIS,0,1) ^ RC2I(P1xIS,1,0) ^ RC2I(P1xIS,2,1) ^ RC2I(P1xIS,3,0) ^ RC2I(P1xIS,3,2) ) ) )
	{
		RC2I(P1,3,2) ^= mask3;
	}

	/* 4th constraint: xor of the bits of this mask should be equal to 0
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000100L
	0x0000000000000100L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000100L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000100L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	[0,4]=U0 , [1,0] , [2,0] , [3,0]
	*/
	u_int64_t mask4 = left_rotate(0x0000000000000100, bit_offset);
	if (mask4 == ( mask4 & ( init_state[0][4] ^ RC2I(P1xIS,1,0) ^ RC2I(P1xIS,2,0) ^ RC2I(P1xIS,3,0) ) ) )
	{
		RC2I(P1,3,0) ^= mask4;
	}

	/* 5th constraint: xor of the bits of this mask should be equal to 0
	0x0000000000000000L,0x0000000000000000L,0x0000000000800000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000800000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000800000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000800000L,0x0000000000000000L
	[0,2] , [1,4] , [2,4] , [3,4]
	*/
	u_int64_t mask5 = left_rotate(0x0000000000800000, bit_offset);
	if (mask5 == ( mask5 & ( RC2I(P1xIS,0,2) ^ RC2I(P1xIS,1,4) ^ RC2I(P1xIS,2,4) ^ RC2I(P1xIS,3,4) ) ) )
	{
		RC2I(P1,3,4) ^= mask5;
	}

	//set the 2nd block of P1 to zeroes
	memset((u_int8_t *)P1 + BLOCK_SIZE, 0, BLOCK_SIZE);
	return 0;
}

int generate_input_p2(const size_t bit_offset, const u_int64_t P1[BLONG_SIZE], u_int64_t P2[BLONG_SIZE], const char * logcat)
{
	/* Diff: P1 ^ P2 = the following map -
	0x0000000000000000L,0x0040000000000000L,0x0000000000000000L,0x0040000000000000L,0x0000000000000000L
	0x0040000000000000L,0x0040000000000000L,0x0000000000000000L,0x0040000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0040000000000000L,0x0040000000000000L,0x0040000000000000L,0x0000000000000000L
	0x0040000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	*/

	u_int64_t mask = left_rotate(0x0040000000000000, bit_offset);

	//copy P1 onto P2 and modify the bits by the conversion mask
	memcpy(P2, P1, 2 * BLOCK_SIZE);
	RC2I(P2,0,1) ^= mask;
	RC2I(P2,0,3) ^= mask;
	RC2I(P2,1,0) ^= mask;
	RC2I(P2,1,1) ^= mask;
	RC2I(P2,1,3) ^= mask;
	RC2I(P2,2,1) ^= mask;
	RC2I(P2,2,2) ^= mask;
	RC2I(P2,2,3) ^= mask;
	RC2I(P2,3,0) ^= mask;
	return 0;
}

int attack_u2_gen_test(const char * logcat, const u_int8_t * key, const u_int8_t * iv, aes_prg & prg)
{
	int result = -1;

	char locat[32];
	snprintf(locat, 32, "%s.u2", logcat);

	u_int64_t init_state[4][5];
	get_init_block(init_state, key, iv, logcat);

	log4cpp::Category::getInstance(logcat).notice("%s: Real: U0=0x%016lX; U1=0x%016lX; U2=0x%016lX; U3=0x%016lX;",
			__FUNCTION__, init_state[0][4],  init_state[1][4], init_state[2][4], init_state[3][4]);

	u_int64_t P1[2*BLONG_SIZE], P2[2*BLONG_SIZE];
	for(size_t bit_offset = 0; bit_offset < 64; ++bit_offset)
	{
		log4cpp::Category::getInstance(logcat).notice("%s: bit_offset = %lu.", __FUNCTION__, bit_offset);

		generate_input_p1(bit_offset, P1, prg, init_state, logcat);
		log_block("P1", P1, logcat, 500);

		generate_input_p2(bit_offset, P1, P2, logcat);
		log_block("P2", P2, logcat, 500);
	}
}


}//namespace ATTACK_U2

