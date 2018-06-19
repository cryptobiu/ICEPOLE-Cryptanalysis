
#include <stdlib.h>
#include <assert.h>
#include <memory.h>

#include <openssl/rand.h>
#include <openssl/evp.h>

#include "aes_prg.h"

aes_prg::aes_prg()
: m_ctx(NULL), m_chunk_size(0), m_ctr_buffer(NULL), m_ctr(0)
{
}

aes_prg::~aes_prg()
{
	term();
}

int aes_prg::init(const size_t chunk_size, const u_int8_t * key, const u_int8_t * iv)
{
	if(0 != chunk_size%KSIZE)
		return -1;
	m_ctr_buffer = new u_int8_t[m_chunk_size = chunk_size];
	m_ctr = 1;

	if(NULL != key)
		memcpy(m_key, key, KSIZE);
	else
		RAND_bytes(m_key, KSIZE);

	if(NULL != iv)
		memcpy(m_iv, iv, KSIZE);
	else
		RAND_bytes(m_iv, KSIZE);

	m_ctx = new EVP_CIPHER_CTX();
	EVP_CIPHER_CTX_init(m_ctx);
	if(1 != EVP_EncryptInit(m_ctx, EVP_aes_128_ecb(), m_key, m_iv))
	{
		EVP_CIPHER_CTX_cleanup(m_ctx);
		delete m_ctx;
		m_ctx = NULL;
		return -1;
	}

	return 0;
}

int aes_prg::gen_rand_bytes(u_int8_t * buffer, size_t size)
{
	size_t runner = 0;
	while(runner < size)
	{
		size_t todo = m_chunk_size;
		if(todo > (size - runner))
			todo = (size - runner);

		u_int64_t * p = (u_int64_t *)m_ctr_buffer;
		for(size_t i = 0; i < (todo+KSIZE-1)/KSIZE; ++i)
			p[2*i] = m_ctr++;

		int outlen = 0;
		if(1 != EVP_EncryptUpdate(m_ctx, buffer + runner, &outlen, m_ctr_buffer, todo))
			return -1;

		runner += todo;
	}
	return 0;
}

void aes_prg::term()
{
	if(NULL != m_ctx)
	{
		EVP_CIPHER_CTX_cleanup(m_ctx);
		delete m_ctx;
		m_ctx = NULL;
	}

	if(NULL != m_ctr_buffer)
	{
		delete m_ctr_buffer;
		m_ctr_buffer = NULL;
	}
}
