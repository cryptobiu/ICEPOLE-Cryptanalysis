
#pragma once

extern "C"
{
	int init_token(void ** token, const unsigned char * key, const unsigned char * iv);

	int crypto_aead_encrypt_s(
		void * token,
		unsigned char *c,unsigned long long *clen,
		const unsigned char *m,unsigned long long mlen,
		const unsigned char *ad,unsigned long long adlen );

	int crypto_aead_encrypt(
		unsigned char *c,unsigned long long *clen,
		const unsigned char *m,unsigned long long mlen,
		const unsigned char *ad,unsigned long long adlen,
		const unsigned char *nsec,
		const unsigned char *npub,
		const unsigned char *k );

	int crypto_aead_decrypt(
		unsigned char *m,unsigned long long *mlen,
		unsigned char *nsec,
		const unsigned char *c,unsigned long long clen,
		const unsigned char *ad,unsigned long long adlen,
		const unsigned char *npub,
		const unsigned char *k);

	int pi_rho_mu(const unsigned char * c, unsigned char * c_);
};
