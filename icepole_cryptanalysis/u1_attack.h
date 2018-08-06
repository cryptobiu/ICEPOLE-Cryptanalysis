
#pragma once

namespace ATTACK_U1
{
int attack_u1(const char * logcat, const u_int8_t * key, const u_int8_t * iv,
			  u_int64_t & U1, const u_int64_t & U0, const u_int64_t & U2, const u_int64_t & U3);
int attack_u1_gen_test(const char * logcat, const u_int8_t * key, const u_int8_t * iv, aes_prg & prg);
}
