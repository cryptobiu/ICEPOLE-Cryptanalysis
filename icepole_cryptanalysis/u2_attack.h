
#pragma once

namespace ATTACK_U2
{
int attack_u2(const char * logcat, const u_int8_t * key, const u_int8_t * iv, u_int64_t & U2, const u_int64_t & U0, const u_int64_t & U3);
int attack_u2_gen_test(const char * logcat, const u_int8_t * key, const u_int8_t * iv, aes_prg & prg);
}
