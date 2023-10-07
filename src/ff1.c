#include <stdint.h>
#include <string.h>
#include <math.h>
#include <assert.h>
#include <openssl/aes.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>
#include "fpe.h"
#include "fpe_locl.h"

typedef unsigned __int128 uint128_t;

// convert numeral string to number
void str2num(BIGNUM *Y, const unsigned int *X, unsigned long long radix, unsigned int len, BN_CTX *ctx)
{
    BN_CTX_start(ctx);
    BIGNUM *r = BN_CTX_get(ctx),
           *x = BN_CTX_get(ctx);

    BN_set_word(Y, 0);
    BN_set_word(r, radix);
    for (int i = 0; i < len; ++i) {
        // Y = Y * radix + X[i]
        BN_set_word(x, X[i]);
        BN_mul(Y, Y, r, ctx);
        BN_add(Y, Y, x);
    }

    BN_CTX_end(ctx);
    return;
}

// convert number to numeral string
void num2str(const BIGNUM *X, unsigned int *Y, unsigned int radix, int len, BN_CTX *ctx)
{
    memset(Y, 0, len << 2);
    unsigned int X_num_bytes = BN_num_bytes(X);
    if (X_num_bytes == 0) {
        // answer is zero (which is set above) irrespective of other parameters
        return;
    }
    if (X_num_bytes <= 32 / 8) {
        uint32_t dv_32;
        uint32_t rem_32;
        uint32_t XX_32;
        BN_bn2lebinpad(X, (unsigned char *)&XX_32, 32 / 8);
        for (int i = len - 1; i >= 0; --i) {
            // XX / r = dv ... rem
            dv_32 = XX_32 / radix;
            rem_32 = XX_32 % radix;
            // Y[i] = XX % r
            Y[i] = (unsigned int)rem_32;
            // XX = XX / r
            XX_32 = dv_32;
        }
        return;
    }
    if (X_num_bytes <= 64 / 8) {
        uint64_t dv_64;
        uint64_t rem_64;
        uint64_t XX_64;
        BN_bn2lebinpad(X, (unsigned char *)&XX_64, 64 / 8);
        for (int i = len - 1; i >= 0; --i) {
            // XX / r = dv ... rem
            dv_64 = XX_64 / radix;
            rem_64 = XX_64 % radix;
            // Y[i] = XX % r
            Y[i] = (unsigned int)rem_64;
            // XX = XX / r
            XX_64 = dv_64;
        }
        return;
    }
    if (X_num_bytes <= 128 / 8) {
        uint128_t dv_128;
        uint128_t rem_128;
        uint128_t XX_128;
        BN_bn2lebinpad(X, (unsigned char *)&XX_128, 128 / 8);
        for (int i = len - 1; i >= 0; --i) {
            // XX / r = dv ... rem
            dv_128 = XX_128 / radix;
            rem_128 = XX_128 % radix;
            // Y[i] = XX % r
            Y[i] = (unsigned int)rem_128;
            // XX = XX / r
            XX_128 = dv_128;
        }
        return;
    }

    BN_CTX_start(ctx);
    BIGNUM *XX = BN_CTX_get(ctx);

    BN_copy(XX, X);
    
    for (int i = len - 1; i >= 0; --i) {
        // XX = XX / r
        // Y[i] = XX % r
        Y[i] = BN_div_word(XX, radix);
    }

    BN_CTX_end(ctx);
    return;
}

static void initialize_P_Q(unsigned char *P, unsigned char *Q, size_t Qlen, int radix, size_t inlen, int u, const unsigned char *tweak, size_t tweaklen, int pad)
{
    unsigned int temp;
    union {
        long one;
        char little;
    } is_endian = { 1 };
    // initialize P, note that P is constant once initialized
    P[0] = 0x1; /* VERS */
    P[1] = 0x2; /* method */
    P[2] = 0x1; /* addition */
    P[7] = u % 256; /* split(n) == n/2, note this is the location after radix | 10(rounds?) */
    if (is_endian.little) {
        temp = (radix << 8) | 10; /* radix | 10(rounds?) */
        P[3] = (temp >> 24) & 0xff;
        P[4] = (temp >> 16) & 0xff;
        P[5] = (temp >> 8) & 0xff;
        P[6] = temp & 0xff;
        P[8] = (inlen >> 24) & 0xff; /* n */
        P[9] = (inlen >> 16) & 0xff;
        P[10] = (inlen >> 8) & 0xff;
        P[11] = inlen & 0xff;
        P[12] = (tweaklen >> 24) & 0xff; /* t */
        P[13] = (tweaklen >> 16) & 0xff;
        P[14] = (tweaklen >> 8) & 0xff;
        P[15] = tweaklen & 0xff;
    } else {
        *( (unsigned int *)(P + 3) ) = (radix << 8) | 10; /* radix | 10(rounds?) */
        *( (unsigned int *)(P + 8) ) = inlen; /* n */
        *( (unsigned int *)(P + 12) ) = tweaklen; /* t */
    }
    // initialize Q, note that the tweak+pad part of Q is constant once initialized
    memcpy(Q, tweak, tweaklen);
    memset(Q + tweaklen, 0x00, pad);
    assert(tweaklen + pad - 1 <= Qlen);
}

// if using precalculated and R_PT is not NULL then use R_PT as the start value and only encrypt Q after (tweaklen+pad)/16 * 16 bytes
// if using precalculated and R_PT is NULL then encrypt P and Q only as far as (tweaklen+pad)/16 * 16 bytes
// if not using precalculated then encrypt all of P and Q
static void PRF(unsigned char *R, const unsigned char *P, unsigned char *Q, size_t Qlen, const unsigned char *R_PT, size_t tweaklen, int pad, 
                EVP_CIPHER_CTX *evp_ctx)
{
    int outl;
    int rc;
    if (R_PT != NULL) {
        // ii PRF(P || Q), but using precalculated value, PRF(PT), for the constant part
        memcpy(R, R_PT, 16);
    } else {
        // ii PRF(P || Q), P is always 16 bytes long
        rc = EVP_EncryptUpdate(evp_ctx, R, &outl, P, 16);
        assert(rc == 1);
    }
    int count = Qlen / 16;
    unsigned char Ri[16];
    unsigned char *Qi = Q;
    size_t tweak_full_blocks = (tweaklen + pad) / 16;
    if (R_PT != NULL) {
        count -= (int)tweak_full_blocks;
        Qi += tweak_full_blocks * 16;
    } else {
        count = (int)tweak_full_blocks;
    }
    for (int cc = 0; cc < count; ++cc) {
        for (int j = 0; j < 16; ++j)    Ri[j] = Qi[j] ^ R[j];
        rc = EVP_EncryptUpdate(evp_ctx, R, &outl, Ri, 16);
        assert(rc == 1);
        Qi += 16;
    }
}

void FF1_encrypt(const unsigned int *in, unsigned int *out, const unsigned char *tweak, const unsigned int radix, size_t inlen, size_t tweaklen,
                 EVP_CIPHER_CTX *evp_ctx)
{
    BIGNUM *bnum = BN_new(),
           *y = BN_new(),
           *c = BN_new(),
           *anum = BN_new(),
           *qpow_u = BN_new(),
           *qpow_v = BN_new();
    BN_CTX *ctx = BN_CTX_new();
	int rc = 0;
	int outl;
	
    union {
        long one;
        char little;
    } is_endian = { 1 };

    memcpy(out, in, inlen << 2);
    int u = floor2(inlen, 1);
    int v = inlen - u;
    unsigned int *A = out, *B = out + u;
    pow_uv(qpow_u, qpow_v, radix, u, v, ctx);

    unsigned int temp = (unsigned int)ceil(v * log2(radix));
    const int b = ceil2(temp, 3);
    const int d = 4 * ceil2(b, 2) + 4;

    int pad = ( (-tweaklen - b - 1) % 16 + 16 ) % 16;
    int Qlen = tweaklen + pad + 1 + b;
    unsigned char P[16];
    unsigned char *Q = (unsigned char *)OPENSSL_malloc(Qlen), *Bytes = (unsigned char *)OPENSSL_malloc(b);
    initialize_P_Q(P, Q, Qlen, radix, inlen, u, tweak, tweaklen, pad);
    unsigned char R_PT[16]; // R value as far as P+tweak+pad, constant once initialized
    PRF(R_PT, P, Q, Qlen, NULL, tweaklen, pad, evp_ctx);
    unsigned char R[16];
    int cnt = ceil2(d, 4) - 1;
    int Slen = 16 + cnt * 16;
    unsigned char *S = (unsigned char *)OPENSSL_malloc(Slen);
    for (int i = 0; i < FF1_ROUNDS; ++i) {
        // v
        int m = (i & 1)? v: u;

        // i
        Q[tweaklen + pad] = i & 0xff;
        str2num(bnum, B, radix, inlen - m, ctx);
        int BytesLen = BN_bn2bin(bnum, Bytes);
        memset(Q + Qlen - b, 0x00, b);

        int qtmp = Qlen - BytesLen;
        memcpy(Q + qtmp, Bytes, BytesLen);
        // ii
        // 6.ii. Let R = PRF(P || Q).
        PRF(R, P, Q, Qlen, R_PT, tweaklen, pad, evp_ctx);
        
        // iii 
        unsigned char tmp[16], SS[16];
        memset(S, 0x00, Slen);
        assert(Slen >= 16);
        memcpy(S, R, 16);
        for (int j = 1; j <= cnt; ++j) {
            memset(tmp, 0x00, 16);

            if (is_endian.little) {
                // convert to big endian
                // full unroll
                tmp[15] = j & 0xff;
                tmp[14] = (j >> 8) & 0xff;
                tmp[13] = (j >> 16) & 0xff;
                tmp[12] = (j >> 24) & 0xff;
            } else *( (unsigned int *)tmp + 3 ) = j;

            for (int k = 0; k < 16; ++k)    tmp[k] ^= R[k];
            rc = EVP_EncryptUpdate(evp_ctx, SS, &outl, tmp, 16);
            assert(rc == 1);
            assert((S + 16 * j)[0] == 0x00);
            assert(16 + 16 * j <= Slen);
            memcpy(S + 16 * j, SS, 16);
        }

        // iv
        BN_bin2bn(S, d, y);
        // vi
        // (num(A, radix, m) + y) % qpow(radix, m);
        str2num(anum, A, radix, m, ctx);
        // anum = (anum + y) mod qpow_uv
        if (m == u)    BN_mod_add(c, anum, y, qpow_u, ctx);
        else    BN_mod_add(c, anum, y, qpow_v, ctx);

        // swap A and B
        assert(A != B);
        A = (unsigned int *)( (uintptr_t)A ^ (uintptr_t)B );
        B = (unsigned int *)( (uintptr_t)B ^ (uintptr_t)A );
        A = (unsigned int *)( (uintptr_t)A ^ (uintptr_t)B );
        num2str(c, B, radix, m, ctx);

    }

    // free the space
    BN_clear_free(anum);
    BN_clear_free(bnum);
    BN_clear_free(c);
    BN_clear_free(y);
    BN_clear_free(qpow_u);
    BN_clear_free(qpow_v);
    BN_CTX_free(ctx);
    OPENSSL_free(Bytes);
    OPENSSL_free(Q);
    OPENSSL_free(S);
    return;
}

void FF1_decrypt(const unsigned int *in, unsigned int *out, const unsigned char *tweak, const unsigned int radix, size_t inlen, size_t tweaklen,
                 EVP_CIPHER_CTX *evp_ctx)
{
    BIGNUM *bnum = BN_new(),
           *y = BN_new(),
           *c = BN_new(),
           *anum = BN_new(),
           *qpow_u = BN_new(),
           *qpow_v = BN_new();
    BN_CTX *ctx = BN_CTX_new();
	int rc = 0;
	int outl;

    union {
        long one;
        char little;
    } is_endian = { 1 };

    memcpy(out, in, inlen << 2);
    int u = floor2(inlen, 1);
    int v = inlen - u;
    unsigned int *A = out, *B = out + u;
    pow_uv(qpow_u, qpow_v, radix, u, v, ctx);

    unsigned int temp = (unsigned int)ceil(v * log2(radix));
    const int b = ceil2(temp, 3);
    const int d = 4 * ceil2(b, 2) + 4;

    int pad = ( (-tweaklen - b - 1) % 16 + 16 ) % 16;
    int Qlen = tweaklen + pad + 1 + b;
    unsigned char P[16];
    unsigned char *Q = (unsigned char *)OPENSSL_malloc(Qlen), *Bytes = (unsigned char *)OPENSSL_malloc(b);
    initialize_P_Q(P, Q, Qlen, radix, inlen, u, tweak, tweaklen, pad);
    unsigned char R_PT[16]; // R value as far as P+tweak+pad, constant once initialized
    PRF(R_PT, P, Q, Qlen, NULL, tweaklen, pad, evp_ctx);
    unsigned char R[16];
    int cnt = ceil2(d, 4) - 1;
    int Slen = 16 + cnt * 16;
    unsigned char *S = (unsigned char *)OPENSSL_malloc(Slen);
    for (int i = FF1_ROUNDS - 1; i >= 0; --i) {
        // v
        int m = (i & 1)? v: u;

        // i
        Q[tweaklen + pad] = i & 0xff;
        str2num(anum, A, radix, inlen - m, ctx);
        memset(Q + Qlen - b, 0x00, b);
        int BytesLen = BN_bn2bin(anum, Bytes);
        int qtmp = Qlen - BytesLen;
        memcpy(Q + qtmp, Bytes, BytesLen);

        // ii PRF(P || Q)
        PRF(R, P, Q, Qlen, R_PT, tweaklen, pad, evp_ctx);

        // iii 
        unsigned char tmp[16], SS[16];
        memset(S, 0x00, Slen);
        memcpy(S, R, 16);
        for (int j = 1; j <= cnt; ++j) {
            memset(tmp, 0x00, 16);

            if (is_endian.little) {
                // convert to big endian
                // full unroll
                tmp[15] = j & 0xff;
                tmp[14] = (j >> 8) & 0xff;
                tmp[13] = (j >> 16) & 0xff;
                tmp[12] = (j >> 24) & 0xff;
            } else *( (unsigned int *)tmp + 3 ) = j;

            for (int k = 0; k < 16; ++k)    tmp[k] ^= R[k];
            rc = EVP_EncryptUpdate(evp_ctx, SS, &outl, tmp, 16);
            assert(rc == 1);
            assert((S + 16 * j)[0] == 0x00);
            memcpy(S + 16 * j, SS, 16);
        }

        // iv
        BN_bin2bn(S, d, y);
        // vi
        // (num(B, radix, m) - y) % qpow(radix, m);
        str2num(bnum, B, radix, m, ctx);
        if (m == u)    BN_mod_sub(c, bnum, y, qpow_u, ctx);
        else    BN_mod_sub(c, bnum, y, qpow_v, ctx);

        // swap A and B
        assert(A != B);
        A = (unsigned int *)( (uintptr_t)A ^ (uintptr_t)B );
        B = (unsigned int *)( (uintptr_t)B ^ (uintptr_t)A );
        A = (unsigned int *)( (uintptr_t)A ^ (uintptr_t)B );
        num2str(c, A, radix, m, ctx);
    }

    // free the space
    BN_clear_free(anum);
    BN_clear_free(bnum);
    BN_clear_free(y);
    BN_clear_free(c);
    BN_clear_free(qpow_u);
    BN_clear_free(qpow_v);
    BN_CTX_free(ctx);
    OPENSSL_free(Bytes);
    OPENSSL_free(Q);
    OPENSSL_free(S);
    return;
}



int FPE_set_ff1_key(const unsigned char *userKey, const int bits, const unsigned char *tweak, const unsigned int tweaklen, const int radix, FPE_KEY *key)
{
    int ret;
    if (bits != 128 && bits != 192 && bits != 256) {
        ret = -1;
        return ret;
    }
    if (key == NULL) {
      key = malloc( sizeof( FPE_KEY ));
    }
//    printf("Tweak:");
//    for(int i =0; i < tweaklen; i++) {
//        printf("%d", tweak[i]);
//    }
//    printf("\n");
    key->radix = radix;
    key->tweaklen = tweaklen;
    key->tweak = (unsigned char *)OPENSSL_malloc(tweaklen);
    memcpy(key->tweak, tweak, tweaklen);
    key->evp_ctx = NULL;
    const EVP_CIPHER *evp_cipher =
            bits == 128 ? EVP_aes_128_ecb() : bits == 192 ? EVP_aes_192_ecb() : EVP_aes_256_ecb();
    key->evp_ctx = EVP_CIPHER_CTX_new();
    if (key->evp_ctx == NULL) {
        return -3;
    }
    if (!EVP_CipherInit_ex(key->evp_ctx, evp_cipher, NULL,
                           userKey, NULL, 1)) {
        return -4;
    }
    EVP_CIPHER_CTX_set_padding(key->evp_ctx, 0);
    ret = 0;
    return ret;
}

void FPE_unset_ff1_key(FPE_KEY *key)
{
    OPENSSL_free(key->tweak);
    EVP_CIPHER_CTX_free(key->evp_ctx);
}

void FPE_ff1_encrypt(unsigned int *in, unsigned int *out, unsigned int inlen, FPE_KEY *key, const int enc)
{
    if (enc)
        FF1_encrypt(in, out, key->tweak,
                    key->radix, inlen, key->tweaklen, key->evp_ctx);

    else
        FF1_decrypt(in, out, key->tweak,
                    key->radix, inlen, key->tweaklen, key->evp_ctx);
}
