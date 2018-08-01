#pragma once

#define KEY_SIZE			16
#define BLOCK_SIZE			128
#define BLONG_SIZE			16
#define ICEPOLE_TAG_SIZE	16

#define RC2I(arr,x,y) arr[x + 4*y]

void log_buffer(const char * label, const u_int8_t * buffer, const size_t size, const char * logcat, const int level);
void log_block(const char * label, const u_int64_t * block, const char * logcat, const int level);
void log_state(const char * label, const u_int64_t state[4][5], const char * logcat, const int level);

u_int64_t left_rotate(u_int64_t v, size_t r);
void get_init_block(u_int64_t ib[4][5], const u_int8_t * key, const u_int8_t * iv);
