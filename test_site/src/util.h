#pragma once

#define KEY_SIZE			16
#define BLOCK_SIZE			128
#define BLONG_SIZE			16
#define ICEPOLE_TAG_SIZE	16

#define RC2I(arr,x,y) arr[x + 4*y]

u_int64_t left_rotate(u_int64_t v, size_t r);
