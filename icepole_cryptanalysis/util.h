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
void get_init_block(u_int64_t ib[4][5], const u_int8_t * key, const u_int8_t * iv, const char * logcat);

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
//u_int8_t u12_xor_state_bits(const u_int64_t state[4][5], const size_t bit_offset);
//bool u12_last_Sbox_lookup_filter(const u_int64_t * P_perm_output, const size_t bit_offset, u_int8_t & F_xor_res, const char * logcat);
/* This is the Omega mask for thread with bit_offset=0; for all others shift by bit_offset must be applied to z
omega_mask:
0x0000000000000008L,0x0002000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
0x0000000000000000L,0x0008000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
0x0000000000000000L,0x0000000000000000L,0x0000400000000000L,0x0000000000000000L,0x0000000000000000L
0x0000000000000000L,0x0000000000000000L,0x0000000004000000L,0x0000020000000000L,0x0000000000000000L
[0][0][3]
[0][1][49]
[1][1][51]
[2][2][46]
[3][2][26]
[3][3][41]
*/
static const block_bit_t u12_omega_bits[6] = { {0,0,3}, {0,1,49}, {1,1,51}, {2,2,46}, {3,2,26}, {3,3,41} };

