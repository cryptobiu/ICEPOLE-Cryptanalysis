#pragma once

#define KEY_SIZE			16
#define BLOCK_SIZE			128
#define BLONG_SIZE			16
#define ICEPOLE_TAG_SIZE	16

#define RC2I(arr,x,y) arr[x + 4*y]

void log_buffer(const char * label, const u_int8_t * buffer, const size_t size, const char * logcat, const int level);
void log_block(const char * label, const u_int64_t * block, const char * logcat, const int level);
void log_state(const char * label, const u_int64_t state[4][5], const char * logcat, const int level);

void sigint_cb(evutil_socket_t, short, void * arg);
void timer_cb(evutil_socket_t, short, void * arg);

u_int64_t left_rotate(u_int64_t v, size_t r);
void get_honest_init_state(u_int64_t is[4][5], const u_int8_t * key, const u_int8_t * iv, const char * logcat);
void get_hacked_init_state(u_int64_t is[4][5], const u_int8_t * key, const u_int8_t * iv, const char * logcat);

class aes_prg;

typedef struct
{
	size_t id;
	std::string logcat;
	sem_t * run_flag;
	u_int8_t * key, * iv;
	u_int64_t init_state[4][5];
	u_int64_t ctr_1[4], ctr_2[4];
	size_t required_attacks, attacks_done;

	int (*bit_attack)(const size_t bit_offset, const char * logcat,
				   	  const u_int8_t key[KEY_SIZE], const u_int8_t iv[KEY_SIZE], const u_int64_t init_state[4][5],
					  aes_prg & prg, size_t ctr_1[4], size_t ctr_2[4]);

}attacker_t;

void * attacker(void * arg);

typedef struct
{
	struct event_base * the_base;
	std::string locat;
	std::vector<attacker_t> * atckr_prms;
	time_t start_time;
}event_param_t;

static const size_t thread_count = 64;
static const struct timeval _3sec = {3,0};
static const time_t allotted_time = 28/*days*/ * 24/*hrs*/ * 60/*mins*/ * 60/*secs*/;

u_int8_t get_block_bit(const u_int64_t * P, const size_t x, const size_t y, const size_t z);
u_int8_t get_block_row_bits(const u_int64_t * P, const size_t x, const size_t z);
bool lookup_Sbox_input_bit(const u_int8_t output_row_bits, const size_t input_bit_index, u_int8_t & input_bit);

typedef struct
{
	size_t x, y, z;
}block_bit_t;

bool last_Sbox_lookup_filter(const u_int64_t * P_perm_output, const size_t bit_offset,
							 const block_bit_t * bits, const size_t bit_count,
							 u_int8_t & F_xor_res, const char * logcat);
u_int8_t xor_state_bits(const u_int64_t state[4][5], const size_t bit_offset, const block_bit_t * bits, const size_t bit_count);
