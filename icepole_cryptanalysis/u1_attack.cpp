
#include <stdlib.h>
#include <stdio.h>
#include <semaphore.h>
#include <memory.h>
#include <errno.h>
#include <math.h>

#include <string>
#include <vector>

#include <openssl/evp.h>
#include <event2/event.h>
#include <log4cpp/Category.hh>

#include "icepole128av2/ref/encrypt.h"
#include "aes_prg.h"
#include "util.h"
#include "attack_validation.h"

namespace ATTACK_U1
{
void guess_work(const std::vector<attacker_t> & atckr_prms, u_int64_t & U1, const char * logcat);
int bit_attack(const size_t bit_offset, const char * logcat,
				   const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE], const u_int64_t init_state[4][5],
				   aes_prg & prg, size_t ctr_1[4], size_t ctr_2[4]);
int bit_attack_check(const size_t bit_offset, const char * logcat,
				   	 const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE], const u_int64_t init_state[4][5],
					 aes_prg & prg, size_t ctr_1[4], size_t ctr_2[4]);
int bit_attack_hack(const size_t bit_offset, const char * logcat,
				   	     const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE], const u_int64_t init_state[4][5],
						 aes_prg & prg, size_t ctr_1[4], size_t ctr_2[4]);
int generate_input_p1(const size_t bit_offset, u_int64_t P1[BLONG_SIZE], aes_prg & prg, const u_int64_t init_state[4][5], const char * logcat);
int generate_input_p2(const size_t bit_offset, const u_int64_t P1[BLONG_SIZE], u_int64_t P2[BLONG_SIZE], const char * logcat);

/* This is the U1 Omega mask for thread with bit_offset=0; for all others shift by bit_offset must be applied to z
omega_mask:
0x2000000000000000L,0x0000080000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
0x0000000000000000L,0x0000200000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
0x0000000000000000L,0x0000000000000000L,0x0000010000000000L,0x0000000000000000L,0x0000000000000000L
0x0000000000000000L,0x0000000000000000L,0x0000000000100000L,0x0000000800000000L,0x0000000000000000L
[0][0][61]
[0][1][43]
[1][1][45]
[2][2][40]
[3][2][20]
[3][3][35]
*/
static const block_bit_t u1_omega_bits[6] = { {0,0,61}, {0,1,43}, {1,1,45}, {2,2,40}, {3,2,20}, {3,3,35} };

int attack_u1(const char * logcat, const u_int8_t * key, const u_int8_t * iv,
			  u_int64_t & U1, const u_int64_t & U0, const u_int64_t & U2, const u_int64_t & U3)
{
	int result = -1;

	char locat[32];
	snprintf(locat, 32, "%s.u1", logcat);

	u_int64_t init_state[4][5];
	get_init_block(init_state, key, iv, logcat);
	init_state[0][4] = U0;
	init_state[2][4] = U2;
	init_state[3][4] = U3;

	std::vector<attacker_t> atckr_prms(thread_count);

	log4cpp::Category::getInstance(logcat).notice("%s: Provided: U0=0x%016lX; U2=0x%016lX; U3=0x%016lX;", __FUNCTION__, U0, U2, U3);

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
								atckr_prms[i].required_attacks = pow(2, 20);//pow(2, 32.7)+1;
								//atckr_prms[i].bit_attack = bit_attack;
								atckr_prms[i].bit_attack = bit_attack_check;
								//atckr_prms[i].bit_attack = bit_attack_hack;
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

							guess_work(atckr_prms, U1, locat);

							log4cpp::Category::getInstance(logcat).notice("%s: guessed U1 = 0x%016lX.", __FUNCTION__, U1);
							log4cpp::Category::getInstance(logcat).notice("%s: actual  U1 = 0x%016lX.", __FUNCTION__, init_state[1][4]);

							{
								u_int64_t u2cmp = ~(U1 ^ init_state[1][4]);
								size_t eq_bit_cnt = 0;
								for(u_int64_t m = 0x1; m != 0; m <<= 1)
									if(m & u2cmp) eq_bit_cnt++;
								log4cpp::Category::getInstance(locat).notice("%s: correct guessed U1 bits count = %lu.", __FUNCTION__, eq_bit_cnt);
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

void guess_work(const std::vector<attacker_t> & atckr_prms, u_int64_t & U1, const char * logcat)
{
	U1 = 0;
	for(size_t j = 0; j < thread_count; ++j)
	{
		const attacker_t & aj(atckr_prms[j]);
		double dev = (aj.ctr_1[0] != 0)? fabs( ( double(aj.ctr_2[0]) / double(aj.ctr_1[0]) ) - 0.5): 0.0;
		log4cpp::Category::getInstance(logcat).debug("%s: thread %lu; ctr_1=%lu; ctr_2=%lu; dev=%.05f;",
				__FUNCTION__, aj.ctr_1[0], aj.ctr_2[0], dev);
		if(pow(2.0, -10.78) >= dev)
		{
			log4cpp::Category::getInstance(logcat).debug("%s: U1 bit %lu = 1", __FUNCTION__, 21 + j);
			U1 |= left_rotate(0x1, 21 + j);
		}
		else
		{
			log4cpp::Category::getInstance(logcat).debug("%s: U1 bit %lu = 0", __FUNCTION__, 21 + j);
		}
	}
}

int bit_attack(const size_t bit_offset, const char * logcat,
			   const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE], const u_int64_t init_state[4][5],
			   aes_prg & prg, size_t ctr_1[4], size_t ctr_2[4])
{
	u_int64_t P1[2 * BLONG_SIZE], P2[2 * BLONG_SIZE], C[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE];
	unsigned long long clen;
	u_int8_t F1 = 0, F2 = 0;
	u_int64_t x_state[4][5];

	generate_input_p1(bit_offset, P1, prg, init_state, logcat);
	clen = 2 * BLONG_SIZE + ICEPOLE_TAG_SIZE;
	crypto_aead_encrypt((unsigned char *)C, &clen, (const unsigned char *)P1, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key);
	kappa5((unsigned char *)(C+BLONG_SIZE));

	if(last_Sbox_lookup_filter((C+BLONG_SIZE), bit_offset, u1_omega_bits, 6, F1, logcat))
	{
		generate_input_p2(bit_offset, P1, P2, logcat);
		clen = 2 * BLONG_SIZE + ICEPOLE_TAG_SIZE;
		crypto_aead_encrypt((unsigned char *)C, &clen, (const unsigned char *)P2, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key);
		kappa5((unsigned char *)(C+BLONG_SIZE));
		if(last_Sbox_lookup_filter((C+BLONG_SIZE), bit_offset, u1_omega_bits, 6, F2, logcat))
		{
			ctr_1[0]++;
			if(F1 == F2)
				ctr_2[0]++;
		}
	}
	return 0;
}

int bit_attack_check(const size_t bit_offset, const char * logcat,
				   	     const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE], const u_int64_t init_state[4][5],
						 aes_prg & prg, size_t ctr_1[4], size_t ctr_2[4])
{
	u_int64_t P1[2 * BLONG_SIZE], P2[2 * BLONG_SIZE], C[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE];
	unsigned long long clen;
	u_int8_t F1 = 0, F2 = 0;
	u_int64_t x_state[4][5];

	generate_input_p1(bit_offset, P1, prg, init_state, logcat);
	clen = 2 * BLONG_SIZE + ICEPOLE_TAG_SIZE;
	crypto_aead_encrypt((unsigned char *)C, &clen, (const unsigned char *)P1, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key);
	kappa5((unsigned char *)(C+BLONG_SIZE));

	if(last_Sbox_lookup_filter((C+BLONG_SIZE), bit_offset, u1_omega_bits, 6, F1, logcat))
	{
		generate_input_p2(bit_offset, P1, P2, logcat);
		clen = 2 * BLONG_SIZE + ICEPOLE_TAG_SIZE;
		crypto_aead_encrypt((unsigned char *)C, &clen, (const unsigned char *)P2, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key);
		kappa5((unsigned char *)(C+BLONG_SIZE));
		if(last_Sbox_lookup_filter((C+BLONG_SIZE), bit_offset, u1_omega_bits, 6, F2, logcat))
		{
			ctr_1[0]++;
			if(F1 == F2)
				ctr_2[0]++;

			clen = 2 * BLONG_SIZE + ICEPOLE_TAG_SIZE;
			crypto_aead_encrypt_hack((unsigned char *)C, &clen, (const unsigned char *)P1, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key, x_state);
			u_int8_t hF1 = xor_state_bits(x_state, bit_offset, u1_omega_bits, 6);

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
			u_int8_t hF2 = xor_state_bits(x_state, bit_offset, u1_omega_bits, 6);

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

int bit_attack_hack(const size_t bit_offset, const char * logcat,
				   	     const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE], const u_int64_t init_state[4][5],
						 aes_prg & prg, size_t ctr_1[4], size_t ctr_2[4])
{
	u_int64_t P1[2 * BLONG_SIZE], P2[2 * BLONG_SIZE], C[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE];
	unsigned long long clen;
	u_int8_t F1 = 0, F2 = 0;
	u_int64_t x_state[4][5];

	generate_input_p1(bit_offset, P1, prg, init_state, logcat);
	clen = 2 * BLONG_SIZE + ICEPOLE_TAG_SIZE;
	crypto_aead_encrypt_hack((unsigned char *)C, &clen, (const unsigned char *)P1, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key, x_state);
	F1 = xor_state_bits(x_state, bit_offset, u1_omega_bits, 6);

	generate_input_p2(bit_offset, P1, P2, logcat);
	clen = 2 * BLONG_SIZE + ICEPOLE_TAG_SIZE;
	crypto_aead_encrypt_hack((unsigned char *)C, &clen, (const unsigned char *)P2, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key, x_state);
	F2 = xor_state_bits(x_state, bit_offset, u1_omega_bits, 6);

	ctr_1[0]++;
	if(F1 == F2)
		ctr_2[0]++;

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

	//=================================================================================================
	/* 1st constraint: xor of the bits of this mask should be equal to 1
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000001L
	0x0000000000000001L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000001L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000001L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	[0,4] , [1,0] , [2,0] , [3,0]																[1,0]
	*/
	u_int64_t mask1 = left_rotate(0x1, bit_offset);
	if (0 == ( mask1 & ( init_state[0][4] ^ RC2I(P1xIS,1,0) ^ RC2I(P1xIS,2,0) ^ RC2I(P1xIS,3,0) ) ) )
	{
		RC2I(P1,1,0) ^= mask1;
	}
	//=================================================================================================
	/* 2nd constraint: xor of the bits of this mask should be equal to 1
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000080000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000080000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000080000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000080000L,0x0000000000000000L,0x0000000000000000L
	[0,3] , [1,3] , [2,4] , [3,2]																[0,3]
	*/
	u_int64_t mask2 = left_rotate(0x80000, bit_offset);
	if (0 == ( mask2 & ( RC2I(P1xIS,0,3) ^ RC2I(P1xIS,1,3) ^ init_state[2][4] ^ RC2I(P1xIS,3,2) ) ) )
	{
		RC2I(P1,0,3) ^= mask2;
	}
	//=================================================================================================
	/* 3rd constraint: xor of the bits of this mask should be equal to 1
	0x0000000000000000L,0x0000000000000000L,0x0000000001000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000001000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000001000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000001000000L,0x0000000000000000L
	[0,2] , [1,3] , [2,3] , [3,3]																[0,2]
	*/
	u_int64_t mask3 = left_rotate(0x1000000, bit_offset);
	if (0 == ( mask3 & ( RC2I(P1xIS,0,2) ^ RC2I(P1xIS,1,3) ^ RC2I(P1xIS,2,3) ^ RC2I(P1xIS,3,3) ) ) )
	{
		RC2I(P1,0,2) ^= mask3;
	}
	//=================================================================================================
	/* 4th constraint: xor of the bits of this mask should be equal to 0
	0x0000000000000000L,0x0000000000000000L,0x0000000000200000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000200000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000200000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000200000L,0x0000000000000000L
	[0,2] , [1,1] , [2,2] , [3,3]																[1,1]
	*/
	u_int64_t mask4 = left_rotate(0x200000, bit_offset);
	if (0 != ( mask4 & ( RC2I(P1xIS,0,2) ^ RC2I(P1xIS,1,1) ^ RC2I(P1xIS,2,2) ^ RC2I(P1xIS,3,3) ) ) )
	{
		RC2I(P1,1,1) ^= mask4;
	}
	//=================================================================================================
	/* 5th constraint: xor of the bits of this mask should be equal to 0
	0x0000000000000000L,0x0000000000000000L,0x0080000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0080000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0080000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0080000000000000L,0x0000000000000000L,0x0000000000000000L,0x0080000000000000L
	[0,2] , [1,2] , [2,3] , [3,1] , [3,4]														[1,2]
	*/
	u_int64_t mask5 = left_rotate(0x80000000000000, bit_offset);
	if (0 != ( mask5 & ( RC2I(P1xIS,0,2) ^ RC2I(P1xIS,1,2) ^ RC2I(P1xIS,2,3) ^ RC2I(P1xIS,3,1) ^ init_state[3][4] ) ) )
	{
		RC2I(P1,1,2) ^= mask5;
	}
	//=================================================================================================
	/* 6th constraint: xor of the bits of this mask should be equal to 0
	0x0000002000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0000002000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000002000000000L
	0x0000002000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	[0,0] , [1,1] , [2,4] , [3,0]																[0,0]
	*/
	u_int64_t mask6 = left_rotate(0x2000000000, bit_offset);
	if (0 != ( mask6 & ( RC2I(P1xIS,0,0) ^ RC2I(P1xIS,1,1) ^ init_state[2][4] ^ RC2I(P1xIS,3,0) ) ) )
	{
		RC2I(P1,0,0) ^= mask6;
	}
	//=================================================================================================

	//set the 2nd block of P1 to zeroes
	memset((u_int8_t *)P1 + BLOCK_SIZE, 0, BLOCK_SIZE);
	return 0;
}

int generate_input_p2(const size_t bit_offset, const u_int64_t P1[BLONG_SIZE], u_int64_t P2[BLONG_SIZE], const char * logcat)
{
	/* Diff: P1 ^ P2 = the following map -
	0x0000000000000200L,0x0000000000000200L,0x0000000000000200L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000200L,0x0000000000000200L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000200L,0x0000000000000000L,0x0000000000000200L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000200L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	[0,0] , [0,1] , [0,2] , [1,1] , [1,2] , [2,1] , [2,3] , [3,1]		 */

	u_int64_t mask = left_rotate(0x200, bit_offset);

	//copy P1 onto P2 and modify the bits by the conversion mask
	memcpy(P2, P1, 2 * BLOCK_SIZE);
	RC2I(P2,0,0) ^= mask;
	RC2I(P2,0,1) ^= mask;
	RC2I(P2,0,2) ^= mask;
	RC2I(P2,1,1) ^= mask;
	RC2I(P2,1,2) ^= mask;
	RC2I(P2,2,1) ^= mask;
	RC2I(P2,2,3) ^= mask;
	RC2I(P2,3,1) ^= mask;
	return 0;
}

int attack_u1_gen_test(const char * logcat, const u_int8_t * key, const u_int8_t * iv, aes_prg & prg)
{
	int result = -1;

	char locat[32];
	snprintf(locat, 32, "%s.u1", logcat);

	u_int64_t init_state[4][5];
	get_init_block(init_state, key, iv, logcat);

	log_state("init_state", init_state, logcat, 500);

	u_int64_t P1[2*BLONG_SIZE], P2[2*BLONG_SIZE];
	for(size_t bit_offset = 0; bit_offset < 64; ++bit_offset)
	{
		log4cpp::Category::getInstance(logcat).notice("%s: bit_offset = %lu.", __FUNCTION__, bit_offset);

		generate_input_p1(bit_offset, P1, prg, init_state, logcat);
		log_block("P1", P1, logcat, 500);
		U1::validate_generated_input_1(bit_offset, P1, init_state, logcat);

		generate_input_p2(bit_offset, P1, P2, logcat);
		log_block("P2", P2, logcat, 500);
		U1::validate_generated_input_2(bit_offset, P1, P2, logcat);
	}
}

}//namespace ATTACK_U1
