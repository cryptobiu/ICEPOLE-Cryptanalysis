
#include <stdlib.h>
#include <stdio.h>
#include <semaphore.h>
#include <memory.h>
#include <errno.h>
#include <math.h>

#include <string>
#include <sstream>
#include <iomanip>
#include <vector>

#include <openssl/evp.h>
#include <event2/event.h>
#include <log4cpp/Category.hh>

#include "icepole128av2/ref/encrypt.h"
#include "aes_prg.h"
#include "attack_validation.h"
#include "util.h"

namespace ATTACK_U1
{

static const block_bit_t u1_omega_bits[6] = { {0,0,61}, {0,1,43}, {1,1,45}, {2,2,40}, {3,2,20}, {3,3,35} };

int the_attack(const char * logcat, const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE],
			   const u_int64_t init_state[4][5], aes_prg & prg, bit_ctrs_t ctrs[64]);
int the_attack_check(const char * logcat, const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE],
			   	     const u_int64_t init_state[4][5], aes_prg & prg, bit_ctrs_t ctrs[64]);
int the_attack_hack(const char * logcat, const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE],
			   	    const u_int64_t init_state[4][5], aes_prg & prg, bit_ctrs_t ctrs[64]);
void guess_work(const std::vector<attacker_t> & atckr_prms, u_int64_t & U1, const char * logcat);
int generate_input_p1(u_int64_t P1[2*BLONG_SIZE], aes_prg & prg, const u_int64_t init_state[4][5], const char * logcat);
int generate_input_p2(const size_t bit_offset, const u_int64_t P1[2*BLONG_SIZE], u_int64_t P2[2*BLONG_SIZE], const char * logcat);

int attack_u1(const char * logcat, const u_int8_t * key, const u_int8_t * iv,
			  u_int64_t & U1, const u_int64_t & U0, const u_int64_t & U2, const u_int64_t & U3)
{
	int result = -1;

	char locat[32];
	snprintf(locat, 32, "%s.u1", logcat);

	u_int64_t init_state[4][5];
	get_honest_init_state(init_state, key, iv, logcat);
	init_state[0][4] = U0;
	init_state[2][4] = U2;
	init_state[3][4] = U3;

	std::vector<attacker_t> atckr_prms(thread_count);

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
								memset(atckr_prms[i].ctrs, 0, 64 * sizeof(bit_ctrs_t));
								atckr_prms[i].attacks_done = 0;
								atckr_prms[i].required_attacks = (pow(2, 22)/thread_count)+1;//(pow(2, 32.4)/thread_count)+1;
								//atckr_prms[i].attack = the_attack;
								//atckr_prms[i].attack = the_attack_check;
								atckr_prms[i].attack = the_attack_hack;
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

int the_attack(const char * logcat, const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE],
			   const u_int64_t init_state[4][5], aes_prg & prg, bit_ctrs_t ctrs[64])
{
	u_int64_t P1[2 * BLONG_SIZE], C1[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE/sizeof(u_int64_t)];
	unsigned long long clen1 = sizeof(C1);

	generate_input_p1(P1, prg, init_state, logcat);
	crypto_aead_encrypt((unsigned char *)C1, &clen1, (const unsigned char *)P1, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key);
	kappa5((unsigned char *)(C1+BLONG_SIZE));

	for(size_t bit = 0; bit < 64; ++bit)
	{
		u_int8_t F1, F2;
		if(last_Sbox_lookup_filter((C1+BLONG_SIZE), bit, u1_omega_bits, 6, F1, logcat))
		{
			u_int64_t P2[2 * BLONG_SIZE], C2[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE/sizeof(u_int64_t)];
			unsigned long long clen2 = sizeof(C2);

			generate_input_p2(bit, P1, P2, logcat);
			crypto_aead_encrypt((unsigned char *)C2, &clen2, (const unsigned char *)P2, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key);
			kappa5((unsigned char *)(C2+BLONG_SIZE));
			if(last_Sbox_lookup_filter((C2+BLONG_SIZE), bit, u1_omega_bits, 6, F2, logcat))
			{
				ctrs[bit].ctr_1[0]++;
				if(F1 == F2)
					ctrs[bit].ctr_2[0]++;
			}
		}
	}
	return 0;
}

int the_attack_check(const char * logcat, const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE],
					 const u_int64_t init_state[4][5], aes_prg & prg, bit_ctrs_t ctrs[64])
{
	u_int64_t P1[2 * BLONG_SIZE];
	generate_input_p1(P1, prg, init_state, logcat);
	for(size_t bit = 0; bit < 64; ++bit)
		U1::validate_generated_input_1(bit, P1, init_state, logcat);

	u_int64_t C1[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE/sizeof(u_int64_t)];
	unsigned long long clen1 = sizeof(C1);
	crypto_aead_encrypt((unsigned char *)C1, &clen1, (const unsigned char *)P1, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key);
	kappa5((unsigned char *)(C1+BLONG_SIZE));

	u_int64_t C1_check[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE/sizeof(u_int64_t)];
	unsigned long long clen1_check = sizeof(C1_check);
	u_int64_t p1_x_state_check[4][5];
	crypto_aead_encrypt_hack((unsigned char *)C1_check, &clen1_check, (const unsigned char *)P1, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key, p1_x_state_check);

	for(size_t bit = 0; bit < 64; ++bit)
	{
		u_int8_t F1;
		if(last_Sbox_lookup_filter((C1+BLONG_SIZE), bit, u1_omega_bits, 6, F1, logcat))
		{
			u_int8_t F1_check = xor_state_bits(p1_x_state_check, bit, u1_omega_bits, 6);
			if(F1_check != F1)
			{
				log4cpp::Category::getInstance(logcat).fatal("%s: bit %lu - F1_check = %hhu != %hhu = F1.", __FUNCTION__, bit, F1_check, F1);
				log_buffer("key", key, KEY_SIZE, logcat, 0);
				log_buffer("iv ", iv, KEY_SIZE, logcat, 0);
				log_block("P1-0", P1, logcat, 0);
				log_block("P1-1", P1+BLONG_SIZE, logcat, 0);
				log_state("p1_x_state", p1_x_state_check, logcat, 0);
				exit(-1);
			}

			u_int64_t P2[2 * BLONG_SIZE];
			generate_input_p2(bit, P1, P2, logcat);
			U1::validate_generated_input_2(bit, P1, P2, logcat);

			u_int64_t C2[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE/sizeof(u_int64_t)];
			unsigned long long clen2 = sizeof(C2);
			crypto_aead_encrypt((unsigned char *)C2, &clen2, (const unsigned char *)P2, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key);
			kappa5((unsigned char *)(C2+BLONG_SIZE));

			u_int8_t F2;
			if(last_Sbox_lookup_filter((C2+BLONG_SIZE), bit, u1_omega_bits, 6, F2, logcat))
			{
				u_int64_t C2_check[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE/sizeof(u_int64_t)];
				unsigned long long clen2_check = sizeof(C2_check);
				u_int64_t p2_x_state_check[4][5];
				crypto_aead_encrypt_hack((unsigned char *)C2_check, &clen2_check, (const unsigned char *)P2, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key, p2_x_state_check);

				u_int8_t F2_check = xor_state_bits(p2_x_state_check, bit, u1_omega_bits, 6);
				if(F2_check != F2)
				{
					log4cpp::Category::getInstance(logcat).fatal("%s: bit %lu - F2_check = %hhu != %hhu = F2.", __FUNCTION__, bit, F2_check, F2);
					log_buffer("key", key, KEY_SIZE, logcat, 0);
					log_buffer("iv ", iv, KEY_SIZE, logcat, 0);
					log_block("P1-0", P1, logcat, 0);
					log_block("P1-1", P1+BLONG_SIZE, logcat, 0);
					log_block("P2-0", P2, logcat, 0);
					log_block("P2-1", P2+BLONG_SIZE, logcat, 0);
					log_state("p2_x_state", p2_x_state_check, logcat, 0);
					exit(-1);
				}
			}
		}
	}
	return 0;
}

int the_attack_hack(const char * logcat, const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE],
					const u_int64_t init_state[4][5], aes_prg & prg, bit_ctrs_t ctrs[64])
{
	u_int64_t P1[2 * BLONG_SIZE], P2[2 * BLONG_SIZE], C[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE/sizeof(u_int64_t)];
	unsigned long long clen = 2 * BLOCK_SIZE + ICEPOLE_TAG_SIZE;
	u_int64_t p1_x_state[4][5], p2_x_state[4][5];

	generate_input_p1(P1, prg, init_state, logcat);
	crypto_aead_encrypt_hack((unsigned char *)C, &clen, (const unsigned char *)P1, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key, p1_x_state);

	for(size_t bit = 0; bit < 64; ++bit)
	{
		u_int8_t F1, F2;
		F1 = xor_state_bits(p1_x_state, bit, u1_omega_bits, 6);

		generate_input_p2(bit, P1, P2, logcat);
		crypto_aead_encrypt_hack((unsigned char *)C, &clen, (const unsigned char *)P2, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key, p2_x_state);
		F2 = xor_state_bits(p2_x_state, bit, u1_omega_bits, 6);

		ctrs[bit].ctr_1[0]++;
		if(F1 == F2)
			ctrs[bit].ctr_2[0]++;
	}
	return 0;
}

int generate_input_p1(u_int64_t P1[2*BLONG_SIZE], aes_prg & prg, const u_int64_t init_state[4][5], const char * logcat)
{
	//Generation of random bytes in P1
	prg.gen_rand_bytes((u_int8_t *)P1, BLOCK_SIZE);

#define PxIS(x,y)		(RC2I(P1,x,y)^init_state[x][y])
	//=================================================================================================
	/* 3rd constraint: xor of the bits of this mask should be equal to 1
	0x0000000000000000L,0x0000000000000000L,0x0000000001000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000001000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000001000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000001000000L,0x0000000000000000L
	[0,2] , [1,3] , [2,3] , [3,3]																	[0,2]
	*/
	RC2I(P1,0,2) ^= ~(PxIS(0,2) ^ PxIS(1,3) ^ PxIS(2,3) ^ PxIS(3,3));

	//=================================================================================================
	/* 6th constraint: xor of the bits of this mask should be equal to 0
	0x0000002000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0000002000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000002000000000L
	0x0000002000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	[0,0] , [1,1] , [2,4] , [3,0]																	[0,0]
	*/
	RC2I(P1,0,0) ^= (PxIS(0,0) ^ PxIS(1,1) ^ PxIS(2,4) ^ PxIS(3,0));

	//=================================================================================================
	/* 5th constraint: xor of the bits of this mask should be equal to 0
	0x0000000000000000L,0x0000000000000000L,0x0080000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0080000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0080000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0080000000000000L,0x0000000000000000L,0x0000000000000000L,0x0080000000000000L
	[0,2] , [1,2] , [2,3] , [3,1] , [3,4]															[3,1]
	*/
	RC2I(P1,3,1) ^= (PxIS(0,2) ^ PxIS(1,2) ^ PxIS(2,3) ^ PxIS(3,1) ^ init_state[3][4]);

	//=================================================================================================
	/* 4th constraint: xor of the bits of this mask should be equal to 0
	0x0000000000000000L,0x0000000000000000L,0x0000000000200000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000200000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000200000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000200000L,0x0000000000000000L
	[0,2] , [1,1] , [2,2] , [3,3]																	[2,2]
	*/
	RC2I(P1,2,2) ^= (PxIS(0,2) ^ PxIS(1,1) ^ PxIS(2,2) ^ PxIS(3,3));

	//=================================================================================================
	/* 2nd constraint: xor of the bits of this mask should be equal to 1
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000080000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000080000L,0x0000000000000000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000080000L
	0x0000000000000000L,0x0000000000000000L,0x0000000000080000L,0x0000000000000000L,0x0000000000000000L
	[0,3] , [1,3] , [2,4] , [3,2]																	[0,3]
	*/
	RC2I(P1,0,3) ^= ~(PxIS(0,3) ^ PxIS(1,3) ^ init_state[2][4] ^ PxIS(3,2));

	//=================================================================================================
	/* 1st constraint: xor of the bits of this mask should be equal to 1
	0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000001L
	0x0000000000000001L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000001L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	0x0000000000000001L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
	[0,4] , [1,0] , [2,0] , [3,0]																	[2,0]
	*/
	RC2I(P1,2,0) ^= ~(init_state[0][4] ^ PxIS(1,0) ^ PxIS(2,0) ^ PxIS(3,0));

	//=================================================================================================
#undef PxIS

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

void guess_work(const std::vector<attacker_t> & atckr_prms, u_int64_t & U1, const char * logcat)
{
	u_int64_t bit_ctrs[64][2];
	memset(bit_ctrs, 0, 64*2*sizeof(u_int64_t));
	for(std::vector<attacker_t>::const_iterator atckr = atckr_prms.begin(); atckr != atckr_prms.end(); ++atckr)
	{
		for(size_t bit = 0; bit < 64; ++bit)
		{
			bit_ctrs[bit][0] += atckr->ctrs[bit].ctr_1[0];
			bit_ctrs[bit][1] += atckr->ctrs[bit].ctr_2[0];
		}
	}

	U1 = 0;
	double limit = pow(2.0, -10.39);
	log4cpp::Category::getInstance(logcat).debug("%s: limit=%.05f;", __FUNCTION__, limit);
	for(size_t bit = 0; bit < 64; ++bit)
	{
		double dev = (bit_ctrs[bit][0] != 0)? fabs( ( double(bit_ctrs[bit][1]) / double(bit_ctrs[bit][0]) ) - 0.5): 0.0;
		log4cpp::Category::getInstance(logcat).debug("%s: bit %lu; ctr_1=%lu; ctr_2=%lu; dev=%.05f;",
				__FUNCTION__, bit,bit_ctrs[bit][0], bit_ctrs[bit][1], dev);
		if(limit >= dev)
		{
			log4cpp::Category::getInstance(logcat).debug("%s: U1 bit %lu = 1", __FUNCTION__, (21 + bit)%64);
			U1 |= left_rotate(0x1, 21 + bit);
		}
		else
		{
			log4cpp::Category::getInstance(logcat).debug("%s: U1 bit %lu = 0", __FUNCTION__, (21 + bit)%64);
		}
	}
}


}//namespace ATTACK_U1

