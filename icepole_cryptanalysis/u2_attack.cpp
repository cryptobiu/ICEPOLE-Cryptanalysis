
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
#include "icepole128av2/ref/encrypt.h"

#include "util.h"

namespace ATTACK_U2
{
const size_t u2_thread_count = 64;

typedef struct
{
	size_t id;
	std::string logcat;
	sem_t * run_flag;
	bool attack_done;
	u_int8_t * key, * iv;
	u_int64_t init_state[4][5];
	u_int64_t ctr_1[4], ctr_2[4];
}u2_attacker_t;


int attack_u2(const char * logcat, const u_int8_t * key, const u_int8_t * iv, u_int64_t & U2, const u_int64_t & U0, const u_int64_t & U3)
{
	int result = -1;

	char locat[32];
	snprintf(locat, 32, "%s.u2", logcat);

	u_int64_t init_state[4][5];
	get_init_block(init_state, key, iv);

	std::vector<u2_attacker_t> atckr_prms(u2_thread_count);

	log4cpp::Category::getInstance(logcat).notice("%s: Provided: U0=0x%016lX; U3=0x%016lX;", __FUNCTION__, U0, U3);
	log4cpp::Category::getInstance(logcat).notice("%s: Real: U0=0x%016lX; U2=0x%016lX; U3=0x%016lX;",
			__FUNCTION__, init_state[0][4], init_state[2][4], init_state[3][4]);

	return result;
}

}
