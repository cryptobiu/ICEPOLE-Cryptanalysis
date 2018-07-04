
#include <stdlib.h>
#include <unistd.h>
#include <semaphore.h>
#include <memory.h>
#include <errno.h>

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
	u_int64_t * samples_done;
	u_int8_t * key, * iv;
	u_int64_t ctr_1[4], ctr_2[4];
}u03_attacker_t;

void sigint_cb(evutil_socket_t, short, void *);
void timer_cb(evutil_socket_t, short, void *);
void * u03_attacker(void *);
int generate_inputs(u_int64_t * P1, u_int64_t * P2, aes_prg & prg, const size_t id);
u_int64_t left_rotate(u_int64_t v, size_t r);
int get_permutation_output(const u_int64_t * P, const u_int64_t * C, u_int64_t * P_perm_output);
bool last_Sbox_lookup_filter(const u_int64_t * P_perm_output, const size_t id, u_int8_t & F_xor_res, const char * logcat);
u_int8_t get_bit(const u_int64_t * P, const size_t x, const size_t y, const size_t z);
u_int8_t get_row_bits(const u_int64_t * P, const size_t x, const size_t z);
bool lookup_Sbox_input_bit(const u_int8_t output_row_bits, const size_t input_bit_index, u_int8_t & input_bit);
size_t lookup_counter_bits(const u_int64_t * C, const size_t id);
void guess_work(const std::vector<u03_attacker_t> & atckr_prms, u_int64_t & U0, u_int64_t & U3, const char * logcat);
std::string block2text(const u_int64_t * B);

#define KEY_SIZE			16
#define BLOCK_SIZE			128
#define BLONG_SIZE			16
#define ICEPOLE_TAG_SIZE	16

const size_t u03_thread_count = 64;

const u_int64_t u03_ceiling_pow_2_33p9 = 500000;//16029384739;

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
								atckr_prms[i].samples_done = samples_done + i;
								atckr_prms[i].key = (u_int8_t *)key;
								atckr_prms[i].iv = (u_int8_t *)iv;
								memset(atckr_prms[i].ctr_1, 0, 4 * sizeof(u_int64_t));
								memset(atckr_prms[i].ctr_2, 0, 4 * sizeof(u_int64_t));
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

							guess_work(atckr_prms, U0, U3, locat);

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
		generate_inputs(P1, P2, prg, prm->id);

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
				size_t n = lookup_counter_bits(C1, prm->id);

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
	memcpy(P2, P1, 2 * BLOCK_SIZE);
	RC2I(P2,0,2) ^= 0x1;
	RC2I(P2,1,0) ^= 0x1;
	RC2I(P2,1,1) ^= 0x1;
	RC2I(P2,1,2) ^= 0x1;
	RC2I(P2,1,3) ^= 0x1;
	RC2I(P2,2,1) ^= 0x1;
	RC2I(P2,2,3) ^= 0x1;
	RC2I(P2,3,0) ^= 0x1;
	RC2I(P2,3,2) ^= 0x1;

	for(size_t i = 0; i < BLONG_SIZE; ++i)
	{
		P1[i] = left_rotate(P1[i], id);
		P2[i] = left_rotate(P2[i], id);
	}
}

u_int64_t left_rotate(u_int64_t v, size_t r)
{
	r = r % 64;
	return (v << r) | (v >> (64-r));
}

int get_permutation_output(const u_int64_t * P, const u_int64_t * C, u_int64_t * P_perm_output)
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
/*
#define CHECKBIT(X,Z,rb,ib,xr) \
{ rb = get_row_bits(P_perm_output, X, Z); ib = 0; \
if(lookup_Sbox_input_bit(rb, 0, ib))  xr ^= ib; \
else return false; }
*/

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
		//CHECKBIT(current_row.x, current_row.z, row_bits, input_bit, F_xor_res)

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
	size_t _z = z%64;
	if(P[x + 4 * y] & (0x1 << _z)) return 1;
	return 0;
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
		case 0: input_bit = 0; return true;
		default: return false;
		}
		break;
	case 0x5://1010
		switch(input_bit_index)
		{
		case 0: input_bit = 0; return true;
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

size_t lookup_counter_bits(const u_int64_t * C, const size_t id)
{
	u_int64_t LC[BLONG_SIZE];
	pi_rho_mu((const unsigned char *)C, (unsigned char *)LC);

	u_int64_t x = 3, y_hi = 1, y_lo = 3, z = 41;

	return (get_bit(LC, x, y_hi, left_rotate(z, id)) << 1) | (get_bit(LC, x, y_lo, left_rotate(z, id)));

}

void guess_work(const std::vector<u03_attacker_t> & atckr_prms, u_int64_t & U0, u_int64_t & U3, const char * logcat)
{
	U3 = 0;
	for(std::vector<u03_attacker_t>::const_iterator j = atckr_prms.begin(); j != atckr_prms.end(); ++j)
	{
		size_t max_dev_counter_index = 4;
		double max_dev = 0.0, dev;
		for(size_t i = 0; i < 4; ++i)
		{
			dev = (0 != j->ctr_1[i])? abs( (double(j->ctr_2[i]) / double(j->ctr_1[i])) - 0.5 ): 0.5;
			if(max_dev <= dev)
			{
				max_dev = dev;
				max_dev_counter_index = i;
			}
			log4cpp::Category::getInstance(j->locat).notice("%s: id=%u; ctr1[%lu]=%lu; ctr2[%lu]=%lu.",
					__FUNCTION__, j->id, i, j->ctr_1[i], i, j->ctr_2[i]);
		}

		u_int64_t v[2];
		v[0] = (max_dev_counter_index & 0x10)? 1: 0;
		v[1] = (max_dev_counter_index & 0x01)? 1: 0;
		log4cpp::Category::getInstance(j->locat).notice("%s: selected ctr-idx = %lu; v0 = %lu; v1 = %lu.",
				__FUNCTION__, max_dev_counter_index, v[0], v[1]);

		U3 |= left_rotate((v[0] ^ 1), 31 + j->id);
	}
	log4cpp::Category::getInstance(logcat).notice("%s: guessed U3 = 0x%016lX.", __FUNCTION__, U3);

}

std::string block2text(const u_int64_t * B)
{
	std::string str;
	char buffer[64];
	str += "block=\n";
	for(size_t x = 0; x < 4; ++x)
	{
		for(size_t y = 0; y < 4; ++y)
		{
			snprintf(buffer, 64, "B[%lu][%lu]=0x%016lX, ", x, y, RC2I(B,x,y));
			str += buffer;
		}
		str += "\n";
	}
	return str;
}
