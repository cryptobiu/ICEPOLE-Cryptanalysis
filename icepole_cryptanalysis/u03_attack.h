
#pragma once

namespace ATTACK_U03
{
int attack_u03(const char * logcat, const u_int8_t * key, const u_int8_t * iv, u_int64_t init_state[4][5], u_int64_t & U0, u_int64_t & U3);
}
