#include <string.h>
#include "crypto_one_time_aead.h"

#define maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define ch(x, y, z) (((x) & (y)) ^ (((x) ^ 1) & (z)))

static unsigned char KSG128(unsigned char *state);
static unsigned char FBK128(unsigned char *state, unsigned char *ks, unsigned char ca, unsigned char cb);
static void Encrypt_StateUpdate128_1bit(unsigned char *state, unsigned char plaintextbit, unsigned char *ciphertextbit,
                                        unsigned char *ks, unsigned char ca, unsigned char cb);
static void Decrypt_StateUpdate128_1bit(unsigned char *state, unsigned char *plaintextbit, unsigned char ciphertextbit,
                                        unsigned char *ks, unsigned char ca, unsigned char cb);
static void acorn128_enc_onebyte(unsigned char *state, unsigned char plaintextbyte, unsigned char *ciphertextbyte,
                                 unsigned char *ksbyte, unsigned char cabyte, unsigned char cbbyte);
static void acorn128_dec_onebyte(unsigned char *state, unsigned char *plaintextbyte, unsigned char ciphertextbyte,
                                 unsigned char *ksbyte, unsigned char cabyte, unsigned char cbbyte);
static void acorn128_initialization(const unsigned char *key, const unsigned char *iv, unsigned char *state);
static void acorn128_tag_generation(unsigned long long msglen, unsigned long long adlen, unsigned char maclen, unsigned char *mac,
                                    unsigned char *state);
static void acorn128_memzero(void *const pnt, const size_t len);

static unsigned char
KSG128(unsigned char *state)
{
    return (state[12] ^ state[154] ^ maj(state[235], state[61], state[193]) ^ ch(state[230], state[111], state[66]));
}

static unsigned char
FBK128(unsigned char *state, unsigned char *ks, unsigned char ca, unsigned char cb)
{
    unsigned char f;
    *ks = KSG128(state);
    f = state[0] ^ (state[107] ^ 1) ^ maj(state[244], state[23], state[160]) ^ (ca & state[196]) ^ (cb & (*ks));
    return f;
}

// encrypt one bit
static void
Encrypt_StateUpdate128_1bit(unsigned char *state, unsigned char plaintextbit, unsigned char *ciphertextbit, unsigned char *ks,
                            unsigned char ca, unsigned char cb)
{
    unsigned int j;
    unsigned char f;

    state[289] ^= state[235] ^ state[230];
    state[230] ^= state[196] ^ state[193];
    state[193] ^= state[160] ^ state[154];
    state[154] ^= state[111] ^ state[107];
    state[107] ^= state[66] ^ state[61];
    state[61] ^= state[23] ^ state[0];

    f = FBK128(state, ks, ca, cb);

    for (j = 0; j <= 291; j++)
        state[j] = state[j + 1];
    state[292] = f ^ plaintextbit;
    *ciphertextbit = *ks ^ plaintextbit;
}

// decrypt one bit
static void
Decrypt_StateUpdate128_1bit(unsigned char *state, unsigned char *plaintextbit, unsigned char ciphertextbit, unsigned char *ks,
                            unsigned char ca, unsigned char cb)
{
    unsigned int j;
    unsigned char f;

    state[289] ^= state[235] ^ state[230];
    state[230] ^= state[196] ^ state[193];
    state[193] ^= state[160] ^ state[154];
    state[154] ^= state[111] ^ state[107];
    state[107] ^= state[66] ^ state[61];
    state[61] ^= state[23] ^ state[0];

    f = FBK128(state, ks, ca, cb);

    for (j = 0; j <= 291; j++)
        state[j] = state[j + 1];
    *plaintextbit = *ks ^ ciphertextbit;
    state[292] = f ^ *plaintextbit;
}

// encrypt one byte
static void
acorn128_enc_onebyte(unsigned char *state, unsigned char plaintextbyte, unsigned char *ciphertextbyte, unsigned char *ksbyte,
                     unsigned char cabyte, unsigned char cbbyte)
{
    // unsigned char i, t[4]; // t[4] is unused
    unsigned char i;
    unsigned char plaintextbit, ciphertextbit, kstem, ca, cb;

    *ciphertextbyte = 0;
    kstem = 0;
    *ksbyte = 0;
    for (i = 0; i < 8; i++) {
        ca = (cabyte >> i) & 1;
        cb = (cbbyte >> i) & 1;
        plaintextbit = (plaintextbyte >> i) & 1;
        Encrypt_StateUpdate128_1bit(state, plaintextbit, &ciphertextbit, &kstem, ca, cb);
        *ciphertextbyte |= (ciphertextbit << i);
        *ksbyte |= (kstem << i);
    }
}

// decrypt one byte
static void
acorn128_dec_onebyte(unsigned char *state, unsigned char *plaintextbyte, unsigned char ciphertextbyte, unsigned char *ksbyte,
                     unsigned char cabyte, unsigned char cbbyte)
{
    unsigned char i;
    unsigned char plaintextbit, ciphertextbit, ks, ca, cb;

    (void)ksbyte;

    *plaintextbyte = 0;
    for (i = 0; i < 8; i++) {
        ca = (cabyte >> i) & 1;
        cb = (cbbyte >> i) & 1;
        ciphertextbit = (ciphertextbyte >> i) & 1;
        Decrypt_StateUpdate128_1bit(state, &plaintextbit, ciphertextbit, &ks, ca, cb);
        *plaintextbyte |= (plaintextbit << i);
    }
}

// The initialization state of ACORN
/*The input to initialization is the 128-bit key; 128-bit IV;*/
static void
acorn128_initialization(const unsigned char *key, const unsigned char *iv, unsigned char *state)
{
    int i, j;
    unsigned char m[293], ks, tem;

    // initialize the state to 0
    for (j = 0; j <= 292; j++)
        state[j] = 0;

    // set the value of m
    for (j = 0; j <= 15; j++)
        m[j] = key[j];
    for (j = 16; j <= 31; j++)
        m[j] = iv[j - 16];
    for (j = 32; j <= 223; j++)
        m[j] = key[j & 0xf];
    m[32] ^= 1;

    // run the cipher for 1792 steps
    for (i = 0; i < 224; i++) {
        acorn128_enc_onebyte(state, m[i], &tem, &ks, 0xff, 0xff);
    }
}

// the finalization state of acorn
static void
acorn128_tag_generation(unsigned long long msglen, unsigned long long adlen, unsigned char maclen, unsigned char *mac,
                        unsigned char *state)
{
    int i;
    unsigned char plaintextbyte = 0;
    unsigned char ciphertextbyte = 0;
    unsigned char ksbyte = 0;

    // unused
    (void)msglen;
    (void)adlen;
    (void)maclen;

    for (i = 0; i < 768 / 8; i++) {
        acorn128_enc_onebyte(state, plaintextbyte, &ciphertextbyte, &ksbyte, 0xff, 0xff);
        if (i >= (768 / 8 - 16)) {
            mac[i - (768 / 8 - 16)] = ksbyte;
        }
    }
}

static void
acorn128_memzero(void *const pnt, const size_t len)
{
    volatile unsigned char *volatile pnt_ = (volatile unsigned char *volatile)pnt;
    size_t i = (size_t)0U;

    while (i < len) {
        pnt_[i++] = 0U;
    }
}

// encrypt a message
int
acorn128v3_crypto_one_time_aead_encrypt(unsigned char *c, unsigned char *tag, const unsigned char *m, unsigned long long mlen,
                                        const unsigned char *ad, unsigned long long adlen, const unsigned char *npub,
                                        const unsigned char *k)
{
    unsigned long long i;
    unsigned char plaintextbyte, ciphertextbyte, ksbyte;
    unsigned char state[293];
    unsigned char ca, cb;

    // initialization stage
    acorn128_initialization(k, npub, state);

    // process the associated data
    for (i = 0; i < adlen; i++) {
        acorn128_enc_onebyte(state, ad[i], &ciphertextbyte, &ksbyte, 0xff, 0xff);
    }

    for (i = 0; i < 256 / 8; i++) {
        if (i == 0)
            plaintextbyte = 0x1;
        else
            plaintextbyte = 0;

        if (i < 128 / 8)
            ca = 0xff;
        else
            ca = 0;

        cb = 0xff;

        acorn128_enc_onebyte(state, plaintextbyte, &ciphertextbyte, &ksbyte, ca, cb);
    }

    // process the plaintext
    for (i = 0; i < mlen; i++) {
        acorn128_enc_onebyte(state, m[i], &(c[i]), &ksbyte, 0xff, 0);
    }

    for (i = 0; i < 256 / 8; i++) {
        if (i == 0)
            plaintextbyte = 0x1;
        else
            plaintextbyte = 0;

        if (i < 128 / 8)
            ca = 0xff;
        else
            ca = 0;

        cb = 0;

        acorn128_enc_onebyte(state, plaintextbyte, &ciphertextbyte, &ksbyte, ca, cb);
    }

    // finalization stage, we assume that the tag length is a multiple of bytes
    acorn128_tag_generation(mlen, adlen, 16, tag, state);

    // Zero out all state
    acorn128_memzero(&i, sizeof(unsigned long long));
    acorn128_memzero(&plaintextbyte, sizeof(unsigned char));
    acorn128_memzero(&ciphertextbyte, sizeof(unsigned char));
    acorn128_memzero(&ksbyte, sizeof(unsigned char));
    acorn128_memzero(&state, 293 * sizeof(unsigned char));
    acorn128_memzero(&ca, sizeof(unsigned char));
    acorn128_memzero(&cb, sizeof(unsigned char));

    return 0;
}

// decrypt a message
int
acorn128v3_crypto_one_time_aead_decrypt(unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *tag,
                                        const unsigned char *ad, unsigned long long adlen, const unsigned char *npub,
                                        const unsigned char *k)
{
    unsigned long long i;
    unsigned char plaintextbyte, ciphertextbyte, ksbyte;
    unsigned char state[293];
    unsigned char challenge[16];
    unsigned char check = 0;
    unsigned char ca, cb;

    // initialization stage
    acorn128_initialization(k, npub, state);

    // process the associated data
    for (i = 0; i < adlen; i++) {
        acorn128_enc_onebyte(state, ad[i], &ciphertextbyte, &ksbyte, 0xff, 0xff);
    }

    for (i = 0; i < 256 / 8; i++) {
        if (i == 0)
            plaintextbyte = 0x1;
        else
            plaintextbyte = 0;

        if (i < 128 / 8)
            ca = 0xff;
        else
            ca = 0;

        cb = 0xff;

        acorn128_enc_onebyte(state, plaintextbyte, &ciphertextbyte, &ksbyte, ca, cb);
    }

    // process the ciphertext
    for (i = 0; i < clen; i++) {
        acorn128_dec_onebyte(state, &m[i], c[i], &ksbyte, 0xff, 0);
    }

    for (i = 0; i < 256 / 8; i++) {
        if (i == 0)
            plaintextbyte = 0x1;
        else
            plaintextbyte = 0;

        if (i < 128 / 8)
            ca = 0xff;
        else
            ca = 0;

        cb = 0;

        acorn128_enc_onebyte(state, plaintextbyte, &ciphertextbyte, &ksbyte, ca, cb);
    }

    // finalization stage, we assume that the tag length is a multiple of bytes
    acorn128_tag_generation(clen, adlen, 16, challenge, state);

    for (i = 0; i < 16; i++)
        check |= (challenge[i] ^ tag[i]);

    // Zero out all state
    acorn128_memzero(&i, sizeof(unsigned long long));
    acorn128_memzero(&challenge, 16 * sizeof(unsigned char));
    acorn128_memzero(&plaintextbyte, sizeof(unsigned char));
    acorn128_memzero(&ciphertextbyte, sizeof(unsigned char));
    acorn128_memzero(&ksbyte, sizeof(unsigned char));
    acorn128_memzero(&state, 293 * sizeof(unsigned char));
    acorn128_memzero(&ca, sizeof(unsigned char));
    acorn128_memzero(&cb, sizeof(unsigned char));

    if (check == 0) {
        return 0;
    } else {
        return -1;
    }
}
