#include <string.h>
#include <stdlib.h>
//#include "crypto_aead.h"
#include "icepole.h"

int init_token(void * init_state, const unsigned char * key, const unsigned char * iv)
{
	initState128a(*((ICESTATE*)(init_state)), key, iv);
	return 0;
}

int crypto_aead_encrypt(
	unsigned char *c,unsigned long long *clen,
	const unsigned char *m,unsigned long long mlen,
	const unsigned char *ad,unsigned long long adlen,
	const unsigned char *nsec,
	const unsigned char *npub,
	const unsigned char *k )
{
    ICESTATE S;
    unsigned int frameBit;
    
    /* initialize the state with secret key and nonce */
    initState128a(S, k, npub);

    /* ciphertext length is plaintext len + size of tag and nsec */
    *clen = mlen + ICEPOLETAGLEN; 
    
    /* secret message number is of zero length */
    processDataBlock(S, NULL, NULL, 0, 0);
    
    /* process auth-only associated data blocks */
    do {
        unsigned long long blocklen = ICEPOLEDATABLOCKLEN;
        frameBit = (adlen <= blocklen ? 1 : 0); /* is it the last block? */
        if (adlen < blocklen) {
            blocklen = adlen;
        }
        /* apply the permutation to the state */
        P6(S,S);
        /* absorb a data block */
        processDataBlock(S, ad, NULL, blocklen, frameBit);
        ad += blocklen;
        adlen -= blocklen;
    } while (adlen > 0);

    /* process plaintext blocks to get the ciphertext */
    do {
        unsigned long long blocklen = ICEPOLEDATABLOCKLEN;
        frameBit = (mlen <=blocklen ? 0 : 1);
        if (mlen < blocklen) {
            blocklen = mlen;
        }
        /* apply the permutation to the state */
        P6(S,S);
        /* absorb a data block and produce a ciphertext block */
        processDataBlock(S, m, &c, blocklen, frameBit);
        m += blocklen;
        mlen -= blocklen;    
    } while (mlen > 0);

    /* store authentication tag at the end of the ciphertext */
    generateTag(S, c);
    return 0;
}

int crypto_aead_decrypt(
	unsigned char *m,unsigned long long *mlen,
	unsigned char *nsec,
	const unsigned char *c,unsigned long long clen,
	const unsigned char *ad,unsigned long long adlen,
	const unsigned char *npub,
	const unsigned char *k
)
{
    ICESTATE S;
    unsigned char Tcomp[ICEPOLETAGLEN]; /* computed authentication tag */
    unsigned int frameBit;
    
    /* ciphertext cannot be shorter than the tag length */
    if (clen < ICEPOLETAGLEN) {
        return -1;
    }
    
    initState128a(S, k, npub);

    /* process 128-bit secret message number */
    frameBit = 0;
    processDataBlockRev(S, NULL, NULL, 0, frameBit);
   
    /* process associated data blocks */
    do {
        unsigned long long blocklen = ICEPOLEDATABLOCKLEN;
        frameBit = (adlen <= blocklen ? 1 : 0);
        if (adlen < blocklen) {
            blocklen = adlen;
        }
        /* apply the permutation to the state */
        P6(S,S);
        /* absorb a data block */
        processDataBlock(S, ad, NULL, blocklen, frameBit);
        ad += blocklen;
        adlen -= blocklen;
    } while (adlen > 0);
    
    /* process ciphertext blocks to get auth tag */
    *mlen = 0;
    clen -= ICEPOLETAGLEN; /* need to stop before auth tag*/
    do {
        unsigned long long blocklen = ICEPOLEDATABLOCKLEN;
        frameBit = (clen <= blocklen ? 0 : 1);
        if (clen < blocklen) {
            blocklen = clen;
        }
        /* apply the permutation to the state */
        P6(S,S);
        /* absorb a ciphertext block and produce a plaintext block */
        processDataBlockRev(S, c, &m, blocklen, frameBit);
        c += blocklen;
        *mlen += blocklen;
        clen -= blocklen;    
    } while (clen > 0);

    /* compare computed and received auth tags */
    generateTag(S, Tcomp);
    if (memcmp(Tcomp, c, ICEPOLETAGLEN)) {
        *mlen = 0;
        return -1;
    }
    
    return 0;
}

int kappa5(unsigned char * p)
{
	ICESTATE Ss, Sk;
	memcpy(Ss, p, sizeof(u_int64_t));
	Kappa(Sk, Ss, 5);
	memcpy(p, Sk, sizeof(u_int64_t));
	return 0;
}

int pi_rho_mu(const unsigned char * c, unsigned char * c_)
{
	//Op-order: c_ = pi(rho(mu(c)))!!

	ICESTATE Ss, Sp, Sr, Sm;

	memset(&Ss, 0, sizeof(ICESTATE));
	memcpy(Ss, c, 16*sizeof(u_int64_t));

	Mu(Sm, Ss);
	Rho(Sr, Sm);
	Pi(Sp, Sr);

	memcpy(c_, Sp, 16*sizeof(u_int64_t));
	return 0;
}

int crypto_aead_encrypt_i(
	unsigned char *c,unsigned long long *clen,
	const unsigned char *m,unsigned long long mlen,
	const unsigned char *ad,unsigned long long adlen,
	const unsigned char *nsec,
	const unsigned char *npub,
	const unsigned char *k,
	u_int64_t is[4][5])
{
    ICESTATE S;
    unsigned int frameBit;

    /* initialize the state with secret key and nonce */
    initState128a(S, k, npub);

    /* ciphertext length is plaintext len + size of tag and nsec */
    *clen = mlen + ICEPOLETAGLEN;

    /* secret message number is of zero length */
    processDataBlock(S, NULL, NULL, 0, 0);

    /* process auth-only associated data blocks */
    do {
        unsigned long long blocklen = ICEPOLEDATABLOCKLEN;
        frameBit = (adlen <= blocklen ? 1 : 0); /* is it the last block? */
        if (adlen < blocklen) {
            blocklen = adlen;
        }
        /* apply the permutation to the state */
        P6(S,S);
        /* absorb a data block */
        processDataBlock(S, ad, NULL, blocklen, frameBit);
        ad += blocklen;
        adlen -= blocklen;
    } while (adlen > 0);

    int is_save = 1;

    /* process plaintext blocks to get the ciphertext */
    do {
        unsigned long long blocklen = ICEPOLEDATABLOCKLEN;
        frameBit = (mlen <=blocklen ? 0 : 1);
        if (mlen < blocklen) {
            blocklen = mlen;
        }
        /* apply the permutation to the state */
        P6(S,S);
        if(0 != is_save)
        {
        	is_save = 0;
        	for(int i = 0; i < 4; ++i)
        		for(int j = 0; j < 5; ++j)
        			is[i][j] = S[i][j];
        }
        /* absorb a data block and produce a ciphertext block */
        processDataBlock(S, m, &c, blocklen, frameBit);
        m += blocklen;
        mlen -= blocklen;
    } while (mlen > 0);

    /* store authentication tag at the end of the ciphertext */
    generateTag(S, c);
    return 0;
}

int crypto_aead_encrypt_hack(
	unsigned char *c,unsigned long long *clen,
	const unsigned char *m,unsigned long long mlen,
	const unsigned char *ad,unsigned long long adlen,
	const unsigned char *nsec,
	const unsigned char *npub,
	const unsigned char *k,
	u_int64_t XS[4][5])
{
	int xted = 0;

    ICESTATE S;
    unsigned int frameBit;

    /* initialize the state with secret key and nonce */
    initState128a(S, k, npub);

    /* ciphertext length is plaintext len + size of tag and nsec */
    *clen = mlen + ICEPOLETAGLEN;

    /* secret message number is of zero length */
    processDataBlock(S, NULL, NULL, 0, 0);

    /* process auth-only associated data blocks */
    do {
        unsigned long long blocklen = ICEPOLEDATABLOCKLEN;
        frameBit = (adlen <= blocklen ? 1 : 0); /* is it the last block? */
        if (adlen < blocklen) {
            blocklen = adlen;
        }
        /* apply the permutation to the state */
        P6(S,S);
        /* absorb a data block */
        processDataBlock(S, ad, NULL, blocklen, frameBit);
        ad += blocklen;
        adlen -= blocklen;
    } while (adlen > 0);

    /* process plaintext blocks to get the ciphertext */
    do {
        unsigned long long blocklen = ICEPOLEDATABLOCKLEN;
        frameBit = (mlen <=blocklen ? 0 : 1);
        if (mlen < blocklen) {
            blocklen = mlen;
        }
        /* apply the permutation to the state */
        P6_hack(S, S, XS, &xted);		//the hack extracts the state at exactly the 2nd call.
        /* absorb a data block and produce a ciphertext block */
        processDataBlock(S, m, &c, blocklen, frameBit);
        m += blocklen;
        mlen -= blocklen;
    } while (mlen > 0);

    /* store authentication tag at the end of the ciphertext */
    generateTag(S, c);
    return 0;
}
