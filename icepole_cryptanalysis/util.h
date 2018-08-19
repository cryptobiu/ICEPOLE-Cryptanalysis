#pragma once

#define RC2I(arr,x,y) arr[x + 4*y]
#define KEY_SIZE			16
#define BLOCK_SIZE			128
#define BLONG_SIZE			16
#define ICEPOLE_TAG_SIZE	16

typedef struct
{
	size_t x, y, z;
}block_bit_t;

u_int64_t left_rotate(u_int64_t v, size_t r);
void log_buffer(const char * label, const u_int8_t * buffer, const size_t size, const char * logcat, const int level);
void log_block(const char * label, const u_int64_t * block, const char * logcat, const int level);
void log_state(const char * label, const u_int64_t state[4][5], const char * logcat, const int level);
u_int8_t xor_state_bits(const u_int64_t state[4][5], const size_t bit_offset, const block_bit_t * bits, const size_t bit_count);
