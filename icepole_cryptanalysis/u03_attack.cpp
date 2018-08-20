
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
#include "attack_validation.h"
#include "icepole128av2/ref/encrypt.h"
#include "util.h"

namespace ATTACK_U03
{

static const block_bit_t u3_omega_bits[8] = { 	{0, 0, 51}, {0, 1, 33}, {0, 3, 12}, {1, 1, 35},
												{2, 1, 54}, {2, 2, 30}, {3, 2, 10}, {3, 3, 25} };

int the_attack(const char * logcat, const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE],
			   const u_int64_t init_state[4][5], aes_prg & prg, bit_ctrs_t ctrs[64]);
int the_attack_check(const char * logcat, const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE],
			   	     const u_int64_t init_state[4][5], aes_prg & prg, bit_ctrs_t ctrs[64]);
int the_attack_hack(const char * logcat, const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE],
			   	    const u_int64_t init_state[4][5], aes_prg & prg, bit_ctrs_t ctrs[64]);
void guess_work(const std::vector<attacker_t> & atckr_prms, u_int64_t & U0, u_int64_t & U3, const char * logcat);
void v_extract(const std::vector<attacker_t> & atckr_prms, u_int8_t v[64][2], const char * logcat);
int generate_input_p1(u_int64_t P1[BLONG_SIZE], aes_prg & prg, const u_int64_t init_state[4][5], const char * logcat);
int generate_input_p2(const size_t thd_id, const u_int64_t P1[BLONG_SIZE], u_int64_t P2[BLONG_SIZE], const char * logcat);
void lookup_counter_bits(const u_int64_t * C, u_int8_t ctr_idx[64]);

int attack_u03(const char * logcat, const u_int8_t * key, const u_int8_t * iv, u_int64_t & U0, u_int64_t & U3)
{
	int result = -1;

	char locat[32];
	snprintf(locat, 32, "%s.u03", logcat);

	u_int64_t init_state[4][5];
	get_honest_init_state(init_state, key, iv, logcat);

	std::vector<attacker_t> atckr_prms(thread_count);

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
								atckr_prms[i].key = (u_int8_t *)key;
								atckr_prms[i].iv = (u_int8_t *)iv;
								memcpy(atckr_prms[i].init_state, init_state, 4*5*sizeof(u_int64_t));
								memset(atckr_prms[i].ctrs, 0, 64 * sizeof(bit_ctrs_t));
								atckr_prms[i].attacks_done = 0;
								atckr_prms[i].required_attacks = (pow(2, 32.7)/thread_count)+1;
								atckr_prms[i].attack = the_attack;
								//atckr_prms[i].attack = the_attack_check;
								//atckr_prms[i].attack = the_attack_hack;
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

int the_attack(const char * logcat, const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE],
			   const u_int64_t init_state[4][5], aes_prg & prg, bit_ctrs_t ctrs[64])
{
	u_int64_t P1[2 * BLONG_SIZE], C1[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE/sizeof(u_int64_t)];
	unsigned long long clen1 = sizeof(C1);
	u_int8_t counter_bits[64];

	generate_input_p1(P1, prg, init_state, logcat);
	crypto_aead_encrypt((unsigned char *)C1, &clen1, (const unsigned char *)P1, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key);
	kappa5((unsigned char *)(C1+BLONG_SIZE));
	lookup_counter_bits(C1, counter_bits);

	for(size_t bit = 0; bit < 64; ++bit)
	{
		u_int8_t F1, F2;
		if(last_Sbox_lookup_filter((C1+BLONG_SIZE), bit, u3_omega_bits, 8, F1, logcat))
		{
			u_int64_t P2[2 * BLONG_SIZE], C2[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE/sizeof(u_int64_t)];
			unsigned long long clen2 = sizeof(C2);

			generate_input_p2(bit, P1, P2, logcat);
			crypto_aead_encrypt((unsigned char *)C2, &clen2, (const unsigned char *)P2, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key);
			kappa5((unsigned char *)(C2+BLONG_SIZE));
			if(last_Sbox_lookup_filter((C2+BLONG_SIZE), bit, u3_omega_bits, 8, F2, logcat))
			{
				ctrs[bit].ctr_1[counter_bits[bit]]++;
				if(F1 == F2)
					ctrs[bit].ctr_2[counter_bits[bit]]++;
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
	for(size_t bit = 0; bit < 63; ++bit)
		U03::validate_generated_input_1(bit, P1, init_state, logcat);

	u_int8_t F1, counter_bits[64];
	u_int64_t C1[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE/sizeof(u_int64_t)];
	unsigned long long clen1 = 2 * BLOCK_SIZE + ICEPOLE_TAG_SIZE;
	crypto_aead_encrypt((unsigned char *)C1, &clen1, (const unsigned char *)P1, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key);
	kappa5((unsigned char *)(C1+BLONG_SIZE));
	lookup_counter_bits(C1, counter_bits);

	unsigned long long clen1_check = 2 * BLOCK_SIZE + ICEPOLE_TAG_SIZE;
	u_int64_t C1_check[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE/sizeof(u_int64_t)];
	u_int64_t p1_x_state_check[4][5];
	u_int8_t F1_check;

	clen1_check = 2 * BLOCK_SIZE + ICEPOLE_TAG_SIZE/sizeof(u_int64_t);
	crypto_aead_encrypt_hack((unsigned char *)C1_check, &clen1_check, (const unsigned char *)P1, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key, p1_x_state_check);

	for(size_t bit = 0; bit < 64; ++bit)
	{
		if(last_Sbox_lookup_filter((C1+BLONG_SIZE), bit, u3_omega_bits, 8, F1, logcat))
		{
			F1_check = xor_state_bits(p1_x_state_check, bit, u3_omega_bits, 8);
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
			U03::validate_generated_input_2(bit, P1, P2, logcat);

			u_int64_t C2[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE/sizeof(u_int64_t)];
			unsigned long long clen2 = 2 * BLOCK_SIZE + ICEPOLE_TAG_SIZE/sizeof(u_int64_t);
			crypto_aead_encrypt((unsigned char *)C2, &clen2, (const unsigned char *)P2, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key);
			kappa5((unsigned char *)(C2+BLONG_SIZE));

			u_int8_t F2;
			if(last_Sbox_lookup_filter((C2+BLONG_SIZE), bit, u3_omega_bits, 8, F2, logcat))
			{
				unsigned long long clen2_check = 2 * BLOCK_SIZE + ICEPOLE_TAG_SIZE/sizeof(u_int64_t);
				u_int64_t C2_check[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE/sizeof(u_int64_t)];
				u_int64_t p2_x_state_check[4][5];
				u_int8_t F2_check;

				crypto_aead_encrypt_hack((unsigned char *)C2_check, &clen2_check, (const unsigned char *)P2, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key, p2_x_state_check);
				F2_check = xor_state_bits(p2_x_state_check, bit, u3_omega_bits, 8);
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
	u_int64_t P1[2 * BLONG_SIZE], C1[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE/sizeof(u_int64_t)];
	unsigned long long clen1 = 2 * BLOCK_SIZE + ICEPOLE_TAG_SIZE/sizeof(u_int64_t);
	u_int8_t counter_bits[64];
	u_int64_t p1_x_state_check[4][5];

	generate_input_p1(P1, prg, init_state, logcat);
	crypto_aead_encrypt_hack((unsigned char *)C1, &clen1, (const unsigned char *)P1, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key, p1_x_state_check);
	lookup_counter_bits(C1, counter_bits);

	for(size_t bit = 0; bit < 64; ++bit)
	{
		u_int8_t F1, F2;
		F1 = xor_state_bits(p1_x_state_check, bit, u3_omega_bits, 8);

		u_int64_t P2[2 * BLONG_SIZE], C2[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE/sizeof(u_int64_t)];
		unsigned long long clen2 = 2 * BLOCK_SIZE + ICEPOLE_TAG_SIZE/sizeof(u_int64_t);
		u_int64_t p2_x_state_check[4][5];

		generate_input_p2(bit, P1, P2, logcat);
		crypto_aead_encrypt_hack((unsigned char *)C2, &clen2, (const unsigned char *)P2, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key, p2_x_state_check);
		F2 = xor_state_bits(p2_x_state_check, bit, u3_omega_bits, 8);

		ctrs[bit].ctr_1[counter_bits[bit]]++;
		if(F1 == F2)
			ctrs[bit].ctr_2[counter_bits[bit]]++;
	}

	return 0;
}

void guess_work(const std::vector<attacker_t> & atckr_prms, u_int64_t & U0, u_int64_t & U3, const char * logcat)
{
	u_int8_t v[64][2];
	memset(v, 0, 64 * 2 * sizeof(u_int8_t));

	v_extract(atckr_prms, v, logcat);

	for(size_t bit = 0; bit < 64; ++bit)
		U3 |= left_rotate(((u_int64_t)v[bit][0] ^ 1), 31 + bit);

	for(size_t bit = 0; bit < 64; ++bit)
		U0 |= ( U3 & left_rotate(1, 49 + bit) ) ^ left_rotate(v[bit][1], 49 + bit);
}

void v_extract(const std::vector<attacker_t> & atckr_prms, u_int8_t v[64][2], const char * logcat)
{
	bit_ctrs_t bit_ctrs[64];
	memset(bit_ctrs, 0, 64*sizeof(bit_ctrs_t));
	for(std::vector<attacker_t>::const_iterator atckr = atckr_prms.begin(); atckr != atckr_prms.end(); ++atckr)
	{
		for(size_t bit = 0; bit < 64; ++bit)
		{
			for(size_t idx = 0; idx < 4; ++idx)
			{
				bit_ctrs[bit].ctr_1[idx] += atckr->ctrs[bit].ctr_1[idx];
				bit_ctrs[bit].ctr_2[idx] += atckr->ctrs[bit].ctr_2[idx];
			}
		}
	}

	for(size_t bit = 0; bit < 64; ++bit)
	{
		size_t max_dev_counter_index = 4;
		double max_dev = 0.0, dev;
		for(size_t idx = 0; idx < 4; ++idx)
		{
			dev = (0 != bit_ctrs[bit].ctr_1[idx])? fabs( ( double(bit_ctrs[bit].ctr_2[idx]) / double(bit_ctrs[bit].ctr_1[idx]) ) - 0.5 ): 0.0;

			log4cpp::Category::getInstance(logcat).debug("%s: bit %lu; ctr1[%lu]=%lu; ctr2[%lu]=%lu; dev=%.08f;",
					__FUNCTION__, bit, idx, bit_ctrs[bit].ctr_1[idx], idx, bit_ctrs[bit].ctr_2[idx], dev);

			if(max_dev < dev)
			{
				max_dev = dev;
				max_dev_counter_index = idx;
			}
		}

		v[bit][0] = (max_dev_counter_index & 0x2)? 1: 0;
		v[bit][1] = (max_dev_counter_index & 0x1)? 1: 0;

		log4cpp::Category::getInstance(logcat).debug("%s: bit %lu selected ctr-idx = %lu; v0 = %lu; v1 = %lu.",
				__FUNCTION__, bit, max_dev_counter_index, v[bit][0], v[bit][1]);
	}
}

void lookup_counter_bits(const u_int64_t * C, u_int8_t ctr_idx[64])
{
	u_int64_t LC[BLONG_SIZE];
	pi_rho_mu((const unsigned char *)C, (unsigned char *)LC);

	for(size_t bit = 0; bit < 64; ++bit)
	{
		ctr_idx[bit] = ( (u_int8_t)((RC2I(LC,3,1) & left_rotate(0x1, 41 + bit))? 1: 0) << 1	) | ( (u_int8_t)((RC2I(LC,3,3) & left_rotate(1, 41 + bit))? 1: 0) );
	}
}

int generate_input_p1(u_int64_t P1[BLONG_SIZE], aes_prg & prg, const u_int64_t init_state[4][5], const char * logcat)
{
	//Generation of random bytes in P1
	prg.gen_rand_bytes((u_int8_t *)P1, BLOCK_SIZE);

#define PxIS(x,y)		(RC2I(P1,x,y)^init_state[x][y])
	//=================================================================================================
	/* 1st & 2ns constraints: xor of the bits of this mask should be equal to 1
	0x0000000000000000, 0x0000000000000010, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000010, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000010, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000010, 0x0000000000000000, 0x0000000000000010, 0x0000000000000000, 0x0000000000000000,
	[0,1] , [1,0] , [2,1] , [3,0] , [3,2]															*/
	RC2I(P1,3,2) ^= ~(PxIS(0,1) ^ PxIS(1,0) ^  PxIS(2,1) ^ PxIS(3,0) ^ PxIS(3,2));

	//=================================================================================================
	/* 3rd & 4th constraints: xor of the bits of this mask should be equal to 0
	0x0000000000000000, 0x0000000000000000, 0x0000000200000000, 0x0000000000000000, //0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000200000000, //0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000200000000, //0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000200000000, //0x0000000000000000,
	[0,2] , [1,3] , [2,3] , [3,3]																	*/
	RC2I(P1,0,2) ^= (PxIS(0,2) ^ PxIS(1,3) ^  PxIS(2,3) ^ PxIS(3,3));

	return 0;
}

int generate_input_p2(const size_t thd_id, const u_int64_t P1[BLONG_SIZE], u_int64_t P2[BLONG_SIZE], const char * logcat)
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
	u_int64_t mask = left_rotate(0x1, thd_id);
	memcpy(P2, P1, 2 * BLOCK_SIZE);
	RC2I(P2,0,2) ^= mask;
	RC2I(P2,1,0) ^= mask;
	RC2I(P2,1,1) ^= mask;
	RC2I(P2,1,2) ^= mask;
	RC2I(P2,1,3) ^= mask;
	RC2I(P2,2,1) ^= mask;
	RC2I(P2,2,3) ^= mask;
	RC2I(P2,3,0) ^= mask;
	RC2I(P2,3,2) ^= mask;
	return 0;
}

}
