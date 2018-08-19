
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
void get_init_state(u_int64_t is[4][5], const u_int8_t * key, const u_int8_t * iv, const char * logcat);
void log_buffer(const char * label, const u_int8_t * buffer, const size_t size, const char * logcat, const int level);
void log_block(const char * label, const u_int64_t * block, const char * logcat, const int level);
void log_state(const char * label, const u_int64_t state[4][5], const char * logcat, const int level);
void sigint_cb(evutil_socket_t, short, void * arg);
void timer_cb(evutil_socket_t, short, void * arg);
bool last_Sbox_lookup_filter(const u_int64_t * P_perm_output, const size_t bit_offset,
							 const block_bit_t * bits, const size_t bit_count,
							 u_int8_t & F_xor_res, const char * logcat);
u_int8_t get_block_bit(const u_int64_t * P, const size_t x, const size_t y, const size_t z);
u_int8_t get_block_row_bits(const u_int64_t * P, const size_t x, const size_t z);
bool lookup_Sbox_input_bit(const u_int8_t output_row_bits, const size_t input_bit_index, u_int8_t & input_bit);
int generate_input_p1(u_int64_t P1[2*BLONG_SIZE], aes_prg & prg, const u_int64_t init_state[4][5], const char * logcat);
int generate_input_p2(const size_t bit_offset, const u_int64_t P1[2*BLONG_SIZE], u_int64_t P2[2*BLONG_SIZE], const char * logcat);

int attack_u1(const char * logcat, const u_int8_t * key, const u_int8_t * iv,
			  u_int64_t & U1, const u_int64_t & U0, const u_int64_t & U2, const u_int64_t & U3)
{
	int result = -1;

	char locat[32];
	snprintf(locat, 32, "%s.u1", logcat);

	u_int64_t init_state[4][5];
	get_init_state(init_state, key, iv, logcat);
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

void get_init_state(u_int64_t is[4][5], const u_int8_t * key, const u_int8_t * iv, const char * logcat)
{
	u_int8_t C[128+16];
	memset(C, 0, 128+16);
	unsigned long long clen = 128+16;

	u_int8_t P[128] = { 0 };

	crypto_aead_encrypt_i((unsigned char *)C, &clen, (const unsigned char *)P, 128, NULL, 0, NULL, iv, key, is);

	{
		/*
		The code below proves that the hacked init state's first four columns are identical
		to the XOR of a single block with its encryption result P^C (In the specific example here P=0 so C=P^C).
		Later, when we no longer need crutches, the crypto_aead_encrypt_i(...) will be replaced with
		a regular crypto_aead_encrypt(...) call and C will be placed inside the first four columns of
		is and the fifth column will be zeroed out.
		*/
		const u_int64_t * pC = (const u_int64_t *)C;
		for(int i = 0; i < 4; ++i)
		{
			for(int j = 0; j < 4; ++j)
			{
				if(RC2I(pC,i,j) != is[i][j])
				{
					log4cpp::Category::getInstance(logcat).fatal("%s: init state validation failure.", __FUNCTION__);
					log_state("is", is, logcat, 0);
					log_block("P", (const u_int64_t *)P, logcat, 0);
					log_block("C", (const u_int64_t *)C, logcat, 0);
					exit(-1);
				}
			}
		}
	}
}

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
		log4cpp::Category::getInstance(eprm->locat).notice("%s: thread %lu launched %lu attacks out of prescribed %lu.",
				__FUNCTION__, i, (*eprm->atckr_prms)[i].attacks_done, (*eprm->atckr_prms)[i].required_attacks);
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

bool last_Sbox_lookup_filter(const u_int64_t * P_perm_output, const size_t bit_offset,
							 const block_bit_t * bits, const size_t bit_count,
							 u_int8_t & F_xor_res, const char * logcat)
{
	u_int8_t row_bits, input_bit;
	F_xor_res = 0;

	for(size_t i = 0; i < bit_count; ++i)
	{
		block_bit_t current_bit = bits[i];
		current_bit.z = (current_bit.z + bit_offset)%64;

		row_bits = get_block_row_bits(P_perm_output, current_bit.x, current_bit.z);
		input_bit = 0;

		if(lookup_Sbox_input_bit(row_bits, current_bit.y, input_bit))
			F_xor_res ^= input_bit;
		else
			return false;
	}
	return true;
}

u_int8_t get_block_bit(const u_int64_t * P, const size_t x, const size_t y, const size_t z)
{
	return (0 != (P[x + 4 * y] & (0x1UL << (z%64))))? 1: 0;
}

u_int8_t get_block_row_bits(const u_int64_t * P, const size_t x, const size_t z)
{
	return (
			(get_block_bit(P, x, 0, z)	 )	|
			(get_block_bit(P, x, 1, z) << 1)	|
			(get_block_bit(P, x, 2, z) << 2)	|
			(get_block_bit(P, x, 3, z) << 3)
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

