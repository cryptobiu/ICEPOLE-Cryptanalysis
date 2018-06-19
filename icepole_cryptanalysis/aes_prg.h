
#pragma once

#define KSIZE 16
#define DCHUNK 80*KSIZE

class aes_prg
{
	 EVP_CIPHER_CTX * m_ctx;
	 u_int8_t m_key[KSIZE], m_iv[KSIZE];

	 size_t m_chunk_size;
	 u_int8_t * m_ctr_buffer;
	 u_int64_t m_ctr;
public:
	aes_prg();
	~aes_prg();

	int init(const size_t chunk_size = DCHUNK, const u_int8_t * key = NULL, const u_int8_t * iv = NULL);
	int gen_rand_bytes(u_int8_t * buffer, size_t size);
	void term();
};
