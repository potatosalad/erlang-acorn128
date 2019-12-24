#ifndef CRYPTO_ONE_TIME_AEAD_H
#define CRYPTO_ONE_TIME_AEAD_H

int acorn128v3_crypto_one_time_aead_encrypt(unsigned char *c, unsigned char *tag, const unsigned char *m, unsigned long long mlen,
                                            const unsigned char *ad, unsigned long long adlen, const unsigned char *npub,
                                            const unsigned char *k);
int acorn128v3_crypto_one_time_aead_decrypt(unsigned char *m, const unsigned char *c, unsigned long long clen,
                                            const unsigned char *tag, const unsigned char *ad, unsigned long long adlen,
                                            const unsigned char *npub, const unsigned char *k);

#endif // CRYPTO_ONE_TIME_AEAD_H
