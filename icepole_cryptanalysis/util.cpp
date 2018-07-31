
#include <stdlib.h>
#include <sstream>
#include <iomanip>

#include <log4cpp/Category.hh>

#include "util.h"

void log_buffer(const char * label, const u_int8_t * buffer, const size_t size, const char * logcat, const int level)
{
	if(log4cpp::Category::getInstance(logcat).isPriorityEnabled(level))
	{
		std::stringstream srs;
		srs << std::hex << std::setfill('0');
		for(size_t i = 0; i < size; ++i)
			srs << std::setw(2) << static_cast<unsigned>(buffer[i]);
		log4cpp::Category::getInstance(logcat).log(level, "%s: [%s]", label, srs.str().c_str());
	}
}

void log_block(const char * label, const u_int64_t * block, const char * logcat, const int level)
{
	if(log4cpp::Category::getInstance(logcat).isPriorityEnabled(level))
	{
		std::string str;
		char buffer[64];
		for(int i = 0; i < 4; ++i)
		{
			for(int j = 0; j < 4; ++j)
			{
				snprintf(buffer, 64, "%016lX ", RC2I(block, i, j));
				str += buffer;
			}
			str += '\n';
		}
		log4cpp::Category::getInstance(logcat).log(level, "%s:\n%s", label, str.c_str());
	}
}

void log_state(const char * label, const u_int64_t state[4][5], const char * logcat, const int level)
{
	if(log4cpp::Category::getInstance(logcat).isPriorityEnabled(level))
	{
		std::string str;
		char buffer[64];
		for(int i = 0; i < 4; ++i)
		{
			for(int j = 0; j < 5; ++j)
			{
				snprintf(buffer, 64, "%016lX ", state[i][j]);
				str += buffer;
			}
			str += '\n';
		}
		log4cpp::Category::getInstance(logcat).log(level, "%s:\n%s", label, str.c_str());
	}
}

u_int64_t left_rotate(u_int64_t v, size_t r)
{
	r = r % 64;
	return (v << r) | (v >> (64-r));
}

