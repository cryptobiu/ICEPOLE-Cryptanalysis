
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

namespace ATTACK_U03
{
#define KEY_SIZE			16
#define BLOCK_SIZE			128
#define BLONG_SIZE			16
#define ICEPOLE_TAG_SIZE	16
#define RC2I(arr,x,y) arr[x + 4*y]

typedef struct
{
	u_int64_t ctr_1[4], ctr_2[4];
}bit_ctrs_t;

typedef struct
{
	size_t id;
	std::string logcat;
	sem_t * run_flag;
	u_int8_t * key, * iv;
	u_int64_t init_state[4][5];
	bit_ctrs_t ctrs[64];
	size_t required_attacks, attacks_done;

	int (*attack)(const char * logcat, const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE],
				  const u_int64_t init_state[4][5], aes_prg & prg, bit_ctrs_t ctrs[64]);
}attacker_t;

typedef struct
{
	struct event_base * the_base;
	std::string locat;
	std::vector<attacker_t> * atckr_prms;
	time_t start_time;
}event_param_t;

typedef struct
{
	size_t x, y, z;
}block_bit_t;

static const size_t thread_count = 64;
static const time_t allotted_time = 21600/*secs*/; //6hrs
static const struct timeval _3sec = {3,0};
static const block_bit_t u3_omega_bits[8] = { 	{0, 0, 51}, {0, 1, 33}, {0, 3, 12}, {1, 1, 35},
												{2, 1, 54}, {2, 2, 30}, {3, 2, 10}, {3, 3, 25} };

void * attacker(void * arg);
int the_attack(const char * logcat, const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE],
			   const u_int64_t init_state[4][5], aes_prg & prg, bit_ctrs_t ctrs[64]);
int the_attack_check(const char * logcat, const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE],
			   	     const u_int64_t init_state[4][5], aes_prg & prg, bit_ctrs_t ctrs[64]);
int the_attack_hack(const char * logcat, const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE],
			   	    const u_int64_t init_state[4][5], aes_prg & prg, bit_ctrs_t ctrs[64]);
void guess_work(const std::vector<attacker_t> & atckr_prms, u_int64_t & U0, u_int64_t & U3, const char * logcat);
void v_extract(const std::vector<attacker_t> & atckr_prms, u_int8_t v[64][2], const char * logcat);
/*
void guess_u3(const std::vector<attacker_t> & atckr_prms, u_int64_t & U3, const char * logcat);
void guess_u0(const std::vector<attacker_t> & atckr_prms, const u_int64_t & U3, u_int64_t & U0, const char * logcat);
void guess_u3_bit(const size_t bit, const std::vector<attacker_t> & atckr_prms, u_int64_t & U3, const char * logcat);
*/
void get_init_block(u_int64_t is[4][5], const u_int8_t * key, const u_int8_t * iv, const char * logcat);
u_int64_t left_rotate(u_int64_t v, size_t r);
void log_buffer(const char * label, const u_int8_t * buffer, const size_t size, const char * logcat, const int level);
void log_block(const char * label, const u_int64_t * block, const char * logcat, const int level);
void log_state(const char * label, const u_int64_t state[4][5], const char * logcat, const int level);
void sigint_cb(evutil_socket_t, short, void * arg);
void timer_cb(evutil_socket_t, short, void * arg);
int generate_input_p1(u_int64_t P1[BLONG_SIZE], aes_prg & prg, const u_int64_t init_state[4][5], const char * logcat);
int generate_input_p2(const u_int64_t P1[BLONG_SIZE], u_int64_t P2[BLONG_SIZE], const char * logcat);
bool last_Sbox_lookup_filter(const u_int64_t * P_perm_output, const size_t bit_offset,
							 const block_bit_t * bits, const size_t bit_count,
							 u_int8_t & F_xor_res, const char * logcat);
u_int8_t get_block_bit(const u_int64_t * P, const size_t x, const size_t y, const size_t z);
u_int8_t get_block_row_bits(const u_int64_t * P, const size_t x, const size_t z);
bool lookup_Sbox_input_bit(const u_int8_t output_row_bits, const size_t input_bit_index, u_int8_t & input_bit);
void lookup_counter_bits(const u_int64_t * C, u_int8_t ctr_idx[64]);
u_int8_t xor_state_bits(const u_int64_t state[4][5], const size_t bit_offset, const block_bit_t * bits, const size_t bit_count);

int attack_u03(const char * logcat, const u_int8_t * key, const u_int8_t * iv, u_int64_t & U0, u_int64_t & U3)
{
	int result = -1;

	char locat[32];
	snprintf(locat, 32, "%s.u03", logcat);

	u_int64_t init_state[4][5];
	get_init_block(init_state, key, iv, logcat);
	log4cpp::Category::getInstance(logcat).notice("%s: Real: U0=0x%016lX; U3=0x%016lX;", __FUNCTION__, init_state[0][4], init_state[3][4] ^ 3);

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
								atckr_prms[i].required_attacks = (pow(2, 33.7)/thread_count)+1;
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

							guess_work(atckr_prms, U0, U3, locat);

							log4cpp::Category::getInstance(logcat).notice("%s: guessed U0 = 0x%016lX.", __FUNCTION__, U0);
							log4cpp::Category::getInstance(logcat).notice("%s: actual  U0 = 0x%016lX.", __FUNCTION__, init_state[0][4] ^ 3);
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
								u_int64_t u0cmp = ~(U0 ^ (init_state[0][4] ^ 3));
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

	while(0 != run_flag_value && prm->attacks_done < prm->required_attacks)
	{
		(*prm->attack)(prm->logcat.c_str(), prm->key, prm->iv, prm->init_state, prg, prm->ctrs);
		prm->attacks_done++;

		if(0 != sem_getvalue(prm->run_flag, &run_flag_value))
		{
			int errcode = errno;
			char errmsg[256];
			log4cpp::Category::getInstance(prm->logcat).error("%s: sem_getvalue() failed with error %d : [%s]",
					__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
			exit(__LINE__);
		}
	}
	for(size_t bit = 0; bit < 64; ++bit)
	{
		for(size_t idx = 0; idx < 4; ++idx)
			log4cpp::Category::getInstance(prm->logcat).debug("%s: bit %lu - ctr_1[%lu]=%lu; ctr_2[%lu]=%lu;",
					__FUNCTION__, bit, idx, prm->ctrs[bit].ctr_1[idx], idx, prm->ctrs[bit].ctr_2[idx]);
	}
	log4cpp::Category::getInstance(prm->logcat).debug("%s: exit.", __FUNCTION__);
	return NULL;
}

int the_attack(const char * logcat, const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE],
			   const u_int64_t init_state[4][5], aes_prg & prg, bit_ctrs_t ctrs[64])
{
	u_int64_t P1[2 * BLONG_SIZE], P2[2 * BLONG_SIZE], C[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE/sizeof(u_int64_t)];
	unsigned long long clen = 2 * BLOCK_SIZE + ICEPOLE_TAG_SIZE/sizeof(u_int64_t);
	u_int8_t F1[64], F2[64], counter_bits[64];

	generate_input_p1(P1, prg, init_state, logcat);
	generate_input_p2(P1, P2, logcat);

	crypto_aead_encrypt((unsigned char *)C, &clen, (const unsigned char *)P1, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key);
	kappa5((unsigned char *)(C+BLONG_SIZE));

	lookup_counter_bits(C, counter_bits);

	std::set<size_t> fit_bits;
	for(size_t bit = 0; bit < 64; ++bit)
	{
		if(last_Sbox_lookup_filter((C+BLONG_SIZE), bit, u3_omega_bits, 8, F1[bit], logcat))
		{
			fit_bits.insert(bit);
		}
	}

	if(!fit_bits.empty())
	{
		clen = 2 * BLOCK_SIZE + ICEPOLE_TAG_SIZE/sizeof(u_int64_t);
		crypto_aead_encrypt((unsigned char *)C, &clen, (const unsigned char *)P2, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key);
		kappa5((unsigned char *)(C+BLONG_SIZE));

		for(std::set<size_t>::const_iterator bit = fit_bits.begin(); bit != fit_bits.end(); ++bit)
		{
			if(last_Sbox_lookup_filter((C+BLONG_SIZE), *bit, u3_omega_bits, 8, F2[*bit], logcat))
			{
				ctrs[*bit].ctr_1[counter_bits[*bit]]++;
				if(F1[*bit] == F2[*bit])
					ctrs[*bit].ctr_2[counter_bits[*bit]]++;
			}
		}
	}

	return 0;
}

int the_attack_check(const char * logcat, const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE],
					 const u_int64_t init_state[4][5], aes_prg & prg, bit_ctrs_t ctrs[64])
{
	u_int64_t P1[2 * BLONG_SIZE], P2[2 * BLONG_SIZE], C[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE/sizeof(u_int64_t)];
	unsigned long long clen = 2 * BLOCK_SIZE + ICEPOLE_TAG_SIZE/sizeof(u_int64_t);
	u_int8_t F1[64], F2[64], counter_bits[64];

	//attack_check
	unsigned long long clen_h = 2 * BLOCK_SIZE + ICEPOLE_TAG_SIZE/sizeof(u_int64_t);
	u_int64_t C_h[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE/sizeof(u_int64_t)];
	u_int64_t XS[4][5];

	generate_input_p1(P1, prg, init_state, logcat);

	for(size_t bit = 0; bit < 64; ++bit) U03::validate_generated_input_1(bit, P1, init_state, logcat);

	generate_input_p2(P1, P2, logcat);

	for(size_t bit = 0; bit < 64; ++bit) U03::validate_generated_input_2(bit, P1, P2, logcat);

	crypto_aead_encrypt((unsigned char *)C, &clen, (const unsigned char *)P1, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key);
	kappa5((unsigned char *)(C+BLONG_SIZE));

	lookup_counter_bits(C, counter_bits);

	//attack_check
	crypto_aead_encrypt_hack((unsigned char *)C_h, &clen_h, (const unsigned char *)P1, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key, XS);

	std::set<size_t> fit_bits;
	for(size_t bit = 0; bit < 64; ++bit)
	{
		if(last_Sbox_lookup_filter((C+BLONG_SIZE), bit, u3_omega_bits, 8, F1[bit], logcat))
		{
			fit_bits.insert(bit);

			//attack_check
			u_int8_t F1_h = xor_state_bits(XS, bit, u3_omega_bits, 8);
			if(F1_h != F1[bit])
			{
				log4cpp::Category::getInstance(logcat).fatal("%s: bit %lu - F1_h = %hhu != %hhu = F1!", __FUNCTION__, bit, F1_h, F1[bit]);
				log_buffer("key", key, KEY_SIZE, logcat, 0);
				log_buffer("iv ", iv, KEY_SIZE, logcat, 0);
				log_block("P1-0", P1, logcat, 0);
				log_block("P1-1", P1+BLONG_SIZE, logcat, 0);
				log_block("P_perm_output", (C+BLONG_SIZE), logcat, 0);
				log_state("x_state", XS, logcat, 0);
				exit(-1);
			}
		}
	}

	if(!fit_bits.empty())
	{
		clen = 2 * BLOCK_SIZE + ICEPOLE_TAG_SIZE/sizeof(u_int64_t);
		crypto_aead_encrypt((unsigned char *)C, &clen, (const unsigned char *)P2, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key);
		kappa5((unsigned char *)(C+BLONG_SIZE));

		//attack_check
		crypto_aead_encrypt_hack((unsigned char *)C_h, &clen_h, (const unsigned char *)P2, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key, XS);

		for(std::set<size_t>::const_iterator bit = fit_bits.begin(); bit != fit_bits.end(); ++bit)
		{
			if(last_Sbox_lookup_filter((C+BLONG_SIZE), *bit, u3_omega_bits, 8, F2[*bit], logcat))
			{
				//attack_check
				u_int8_t F2_h = xor_state_bits(XS, *bit, u3_omega_bits, 8);
				if(F2_h != F2[*bit])
				{
					log4cpp::Category::getInstance(logcat).fatal("%s: bit %lu - F2_h = %hhu != %hhu = F2!", __FUNCTION__, *bit, F2_h, F2[*bit]);
					log_buffer("key", key, KEY_SIZE, logcat, 0);
					log_buffer("iv ", iv, KEY_SIZE, logcat, 0);
					log_state("x_state", XS, logcat, 0);
					log_block("P1", P1, logcat, 0);
					log_block("P2", P2, logcat, 0);
					exit(-1);
				}

				ctrs[*bit].ctr_1[counter_bits[*bit]]++;
				if(F1[*bit] == F2[*bit])
					ctrs[*bit].ctr_2[counter_bits[*bit]]++;
			}
		}
	}

	return 0;
}

int the_attack_hack(const char * logcat, const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE],
					const u_int64_t init_state[4][5], aes_prg & prg, bit_ctrs_t ctrs[64])
{
	u_int64_t P1[2 * BLONG_SIZE], P2[2 * BLONG_SIZE], C[2 * BLONG_SIZE + ICEPOLE_TAG_SIZE/sizeof(u_int64_t)];
	unsigned long long clen = 2 * BLOCK_SIZE + ICEPOLE_TAG_SIZE/sizeof(u_int64_t);
	u_int8_t F1[64], F2[64], counter_bits[64];
	u_int64_t XS[4][5];

	generate_input_p1(P1, prg, init_state, logcat);
	generate_input_p2(P1, P2, logcat);

	crypto_aead_encrypt_hack((unsigned char *)C, &clen, (const unsigned char *)P1, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key, XS);

	lookup_counter_bits(C, counter_bits);

	std::set<size_t> fit_bits;
	for(size_t bit = 0; bit < 64; ++bit)
	{
		F1[bit] = xor_state_bits(XS, bit, u3_omega_bits, 8);
		fit_bits.insert(bit);
	}

	if(!fit_bits.empty())
	{
		clen = 2 * BLOCK_SIZE + ICEPOLE_TAG_SIZE/sizeof(u_int64_t);
		crypto_aead_encrypt_hack((unsigned char *)C, &clen, (const unsigned char *)P2, 2*BLOCK_SIZE, NULL, 0, NULL, iv, key, XS);

		for(std::set<size_t>::const_iterator bit = fit_bits.begin(); bit != fit_bits.end(); ++bit)
		{
			F2[*bit] = xor_state_bits(XS, *bit, u3_omega_bits, 8);
			ctrs[*bit].ctr_1[counter_bits[*bit]]++;
			if(F1[*bit] == F2[*bit])
				ctrs[*bit].ctr_2[counter_bits[*bit]]++;
		}
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

void get_init_block(u_int64_t is[4][5], const u_int8_t * key, const u_int8_t * iv, const char * logcat)
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

u_int64_t left_rotate(u_int64_t v, size_t r)
{
	r = r % 64;
	return (v << r) | (v >> (64-r));
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
	memset(P1+BLONG_SIZE, 0, BLOCK_SIZE);

	//XOR of P1 with the icepole init state into P1xIS
	u_int64_t P1xIS[BLONG_SIZE];
	for(size_t i = 0; i < 4; ++i)
		for(size_t j = 0; j < 4; ++j)
			RC2I(P1xIS,i,j) = RC2I(P1,i,j) ^ init_state[i][j];

	for(size_t bit = 0; bit < 64; ++bit)
	{	/* set 1st constraint
		const u_int64_t u03_P1_1st_constraint[16] =
		{
			0x0000000000000000, 0x0000000000000010, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
			0x0000000000000010, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
			0x0000000000000000, 0x0000000000000010, 0x0000000000000000, 0x0000000000000000, //0x0000000000000000,
			0x0000000000000010, 0x0000000000000000, 0x0000000000000010, 0x0000000000000000, //0x0000000000000000,
		}; */
		u_int64_t mask = left_rotate(0x0000000000000010, bit);
		if (0 == (	(RC2I(P1xIS,0,1) & mask) ^
					(RC2I(P1xIS,1,0) & mask) ^
					(RC2I(P1xIS,2,1) & mask) ^
					(RC2I(P1xIS,3,0) & mask) ^
					(RC2I(P1xIS,3,2) & mask)))
		{
			RC2I(P1,3,2) ^= mask;
		}
	}

	for(size_t bit = 0; bit < 64; ++bit)
	{	/* set 3rd constraint
		const u_int64_t u03_P1_3rd_constraint[16] =
		{
			0x0000000000000000, 0x0000000000000000, 0x0000000200000000, 0x0000000000000000, //0x0000000000000000,
			0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000200000000, //0x0000000000000000,
			0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000200000000, //0x0000000000000000,
			0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000200000000, //0x0000000000000000,
		}; */
		u_int64_t mask = left_rotate(0x0000000200000000, bit);
		if(mask == (	(RC2I(P1xIS,0,2) & mask) ^
						(RC2I(P1xIS,1,3) & mask) ^
						(RC2I(P1xIS,2,3) & mask) ^
						(RC2I(P1xIS,3,3) & mask)))
		{
			RC2I(P1,3,3) ^= mask;
		}
	}

	return 0;
}

int generate_input_p2(const u_int64_t P1[BLONG_SIZE], u_int64_t P2[BLONG_SIZE], const char * logcat)
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
	u_int64_t mask = ~(0x0);
	RC2I(P2,0,2) ^= mask;
	RC2I(P2,1,0) ^= mask;
	RC2I(P2,1,1) ^= mask;
	RC2I(P2,1,2) ^= mask;
	RC2I(P2,1,3) ^= mask;
	RC2I(P2,2,1) ^= mask;
	RC2I(P2,2,3) ^= mask;
	RC2I(P2,3,0) ^= mask;
	RC2I(P2,3,2) ^= mask;

	/*
	for(std::set<size_t>::const_iterator i = fit_bits.begin(); i != fit_bits.end(); ++i)
	{
		u_int64_t mask = left_rotate(0x1, *i);
		RC2I(P2,0,2) ^= mask;
		RC2I(P2,1,0) ^= mask;
		RC2I(P2,1,1) ^= mask;
		RC2I(P2,1,2) ^= mask;
		RC2I(P2,1,3) ^= mask;
		RC2I(P2,2,1) ^= mask;
		RC2I(P2,2,3) ^= mask;
		RC2I(P2,3,0) ^= mask;
		RC2I(P2,3,2) ^= mask;
	}
	*/
}

u_int8_t xor_state_bits(const u_int64_t state[4][5], const size_t bit_offset, const block_bit_t * bits, const size_t bit_count)
{
	u_int8_t result = 0;
	for(size_t i = 0; i < bit_count; ++i)
	{
		u_int64_t integer = state[bits[i].x][bits[i].y];
		u_int64_t mask = left_rotate(0x1, bits[i].z + bit_offset);
		result ^= ((integer & mask)? 1: 0);
	}
	return result;
}

}
