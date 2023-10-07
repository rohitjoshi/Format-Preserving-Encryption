#include <stdint.h>
#include <string.h>
#include <math.h>
#include <assert.h>
#include <openssl/aes.h>
#include <openssl/crypto.h>
#include "fpe.h"
#include "fpe_locl.h"

typedef unsigned __int128 uint128_t;
typedef signed __int128 int128_t;

// declare the size for this implementation, expected to be one of uint32_t, uint64_t, uint128_t
// size MUST be even number of bytes
typedef uint128_t native_size_t; 
typedef int128_t native_signed_t; 

// replace all BIGNUM operations with local native operations
// NOTE: openssl/bn.h gets included indirectly via openssl/crypto.h
// so we can't just recode them here, we need to use macros
// to point to our local native implementation
#include "bignum_native.h"



static union {
	long one;
	char little;
} is_endian = { 1 };

// convert numeral string to number
static void str2num(BIGNUM *Y, const unsigned int *X, unsigned long long radix, unsigned int len, BN_CTX *ctx)
{
    *Y = 0;
    for (int i = 0; i < len; ++i) {
        // Y = Y * radix + X[i]
		*Y = *Y * radix + X[i];
    }

    return;
}

// convert number to numeral string
static void num2str(const BIGNUM *X, unsigned int *Y, unsigned int radix, int len, BN_CTX *ctx)
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

    BIGNUM r = 0,
           XX = 0;

    XX = *X;
    r = radix;
    
    for (int i = len - 1; i >= 0; --i) {
        // XX / r = dv ... rem
        // Y[i] = XX % r
        Y[i] = XX % r;
        // XX = XX / r
        XX = XX / r;
    }

    return;
}

static void initialize_P_Q(unsigned char *P, unsigned char *Q, size_t Qlen, int radix, size_t inlen, int u, const unsigned char *tweak, size_t tweaklen, int pad)
{
    unsigned int temp;
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

void FF1_encrypt_128(const unsigned int *in, unsigned int *out, const unsigned char *tweak, const unsigned int radix, size_t inlen, size_t tweaklen,
                 EVP_CIPHER_CTX *evp_ctx)
{
   // printf("FF1_encrypt_128: evp_ctx:%p\n", evp_ctx);
    BIGNUM bnum = 0,
           y = 0,
           c = 0,
           anum = 0,
           qpow_u = 0,
           qpow_v = 0;
    BN_CTX *ctx = BN_CTX_new();
	int rc = 0;
	int outl;

	//printf("FF1_encrypt_128:inlen: %zu, tweaklen:%zu\n", inlen, tweaklen);
	// printf("FF1_encrypt_128: radix: %zu\n", radix);
    memcpy(out, in, inlen << 2);
	// 1.Let u = floor(n/2); v = n – u. 
    int u = floor2(inlen, 1);
    int v = inlen - u;
	// 2. Let A = X[1..u]; B = X[u + 1 ..n].
    unsigned int *A = out, *B = out + u;

    //printf("FF1_encrypt_128-2\n");
	
	// save pow(u, radix) and pow(v, radix) for step 6.vi.
    pow_uv(&qpow_u, &qpow_v, radix, u, v, ctx);

    // printf("FF1_encrypt_128-3\n");

	// 3.Let b = ceil(ceil(v*LOG(radix))/8).
    unsigned int temp = (unsigned int)ceil(v * log2(radix));
    const int b = ceil2(temp, 3);
	// 4.Let d = 4 * ceil(b/4) + 4.
    const int d = 4 * ceil2(b, 2) + 4;

     //printf("FF1_encrypt_128-4\n");

	// 5.Let P = [1]1 || [2]1 || [1]1 || [radix]3 || [10]1 || [u mod 256]1 || [n]4 || [t]4. 
	// 6.i. (constant part) Let Q = T || [0](−t−b−1) mod 16
    int pad = ( (-tweaklen - b - 1) % 16 + 16 ) % 16;
    int Qlen = tweaklen + pad + 1 + b;

    // printf("FF1_encrypt_128-5\n");
    unsigned char P[16];
    unsigned char *Q = (unsigned char *)OPENSSL_malloc(Qlen), *Bytes = (unsigned char *)OPENSSL_malloc(b);
     //printf("FF1_encrypt_128-6\n");
    initialize_P_Q(P, Q, Qlen, radix, inlen, u, tweak, tweaklen, pad);
    // printf("FF1_encrypt_128-7\n");
    unsigned char R_PT[16]; // R value as far as P+tweak+pad, constant once initialized
    PRF(R_PT, P, Q, Qlen, NULL, tweaklen, pad, evp_ctx);
    // printf("FF1_encrypt_128-8\n");
    unsigned char R[16];
    int cnt = ceil2(d, 4) - 1;
    int Slen = 16 + cnt * 16;
    unsigned char *S = (unsigned char *)OPENSSL_malloc(Slen);

    //printf("FF1_encrypt_128:before loop");
	// 6.For i from 0 to 9: 
    for (int i = 0; i < FF1_ROUNDS; ++i) {
         //printf("FF1_encrypt_128: round: %d\n", i);
        // v
		// 6.v. If i is even, let m = u; else, let m = v.
		// (do this early so we have m for length of bnum) 
        int m = (i & 1)? v: u;

        // i
		// 6.i. (variable part) Let Q = (constant part) || [i]1 || [NUMradix(B)]b.
        Q[tweaklen + pad] = i & 0xff;
        str2num(&bnum, B, radix, inlen - m, ctx);
        int BytesLen = BN_bn2bin(&bnum, Bytes);
        memset(Q + Qlen - b, 0x00, b);

        int qtmp = Qlen - BytesLen;
        memcpy(Q + qtmp, Bytes, BytesLen);

        // ii
		// 6.ii. Let R = PRF(P || Q). 
        PRF(R, P, Q, Qlen, R_PT, tweaklen, pad, evp_ctx);
        
        // iii 
		// 6.iii. Let S be the first d bytes of the following string of ceil(d/16)blocks:
		//        R || CIPHK (R ^ [1]16) || CIPHK (R ^ [2]16) ... CIPHK (R ^ [ceil(d/16)–1]16).
        unsigned char tmp[16], SS[16];
        memset(S, 0x00, Slen);
        assert(Slen >= 16);
        memcpy(S, R, 16);
        for (int j = 1; j <= cnt; ++j) {
        //printf("FF1_encrypt_128: j loop: %d\n", j);
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
		// 6.iv. Let y = NUM(S).
        BN_bin2bn(S, d, &y);
		// 6.v. If i is even, let m = u; else, let m = v.
		// (did this at top of loop)
        // vi
        // (num(A, radix, m) + y) % qpow(radix, m);
		// 6.vi. Let c = (NUMradix (A) + y) mod radix m .
        str2num(&anum, A, radix, m, ctx);
		// anum = (anum + y) mod qpow_uv
		// 6.vii. Let C = STR mradix (c).
		if (m == u) {   BN_mod_add(&c, &anum, &y, &qpow_u, ctx); }
		else {   BN_mod_add(&c, &anum, &y, &qpow_v, ctx); }

        // swap A and B
		// 6.viii. Let A = B. 
        assert(A != B);
        A = (unsigned int *)( (uintptr_t)A ^ (uintptr_t)B );
        B = (unsigned int *)( (uintptr_t)B ^ (uintptr_t)A );
        A = (unsigned int *)( (uintptr_t)A ^ (uintptr_t)B );
		// 6.ix. Let B = C. 
        num2str(&c, B, radix, m, ctx);
    }
    //printf("FF1_encrypt_128: done\n");
    // 7. Return A || B
	// we stored directly in "out"
    // free the space
    BN_CTX_free(ctx);
    OPENSSL_free(Bytes);
    OPENSSL_free(Q);
    OPENSSL_free(S);
    //printf("FF1_encrypt_128: before return\n");
    return;
}

void FF1_decrypt_128(const unsigned int *in, unsigned int *out, const unsigned char *tweak, const unsigned int radix, size_t inlen, size_t tweaklen,
                 EVP_CIPHER_CTX *evp_ctx)
{
    BIGNUM bnum = 0,
           y = 0,
           c = 0,
           anum = 0,
           qpow_u = 0,
           qpow_v = 0;
    BN_CTX *ctx = BN_CTX_new();
	int rc = 0;
	int outl;

    memcpy(out, in, inlen << 2);
    int u = floor2(inlen, 1);
    int v = inlen - u;
    unsigned int *A = out, *B = out + u;
    pow_uv(&qpow_u, &qpow_v, radix, u, v, ctx);

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
        str2num(&anum, A, radix, inlen - m, ctx);
        memset(Q + Qlen - b, 0x00, b);
        int BytesLen = BN_bn2bin(&anum, Bytes);
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
        BN_bin2bn(S, d, &y);
        // vi
        // (num(B, radix, m) - y) % qpow(radix, m);
        str2num(&bnum, B, radix, m, ctx);
        if (m == u)    BN_mod_sub(&c, &bnum, &y, &qpow_u, ctx);
        else    BN_mod_sub(&c, &bnum, &y, &qpow_v, ctx);

        // swap A and B
        assert(A != B);
        A = (unsigned int *)( (uintptr_t)A ^ (uintptr_t)B );
        B = (unsigned int *)( (uintptr_t)B ^ (uintptr_t)A );
        A = (unsigned int *)( (uintptr_t)A ^ (uintptr_t)B );
        num2str(&c, A, radix, m, ctx);
    }

    // free the space
    BN_CTX_free(ctx);
    OPENSSL_free(Bytes);
    OPENSSL_free(Q);
    OPENSSL_free(S);
    return;
}

void FPE_ff1_encrypt_128(unsigned int *in, unsigned int *out, unsigned int inlen, FPE_KEY *key, const int enc)
{
    if (enc)
        FF1_encrypt_128(in, out, key->tweak, key->radix, inlen, key->tweaklen, key->evp_ctx);

    else
        FF1_decrypt_128(in, out, key->tweak, key->radix, inlen, key->tweaklen, key->evp_ctx);
}

 struct fpe_ctx_st
    {
        EVP_CIPHER_CTX *evp_ctx;
    };
 typedef struct fpe_ctx_st FPE_CTX;
int FPE_NATIVE_set_ff1_key(const unsigned char *userKey, const int bits, FPE_CTX *fpe_ctx)
{
    int ret;
    if (bits != 128 && bits != 192 && bits != 256) {
        ret = -1;
        return ret;
    }

    const EVP_CIPHER *evp_cipher =
            bits == 128 ? EVP_aes_128_ecb() : bits == 192 ? EVP_aes_192_ecb() : EVP_aes_256_ecb();
    fpe_ctx->evp_ctx = EVP_CIPHER_CTX_new();
    if (fpe_ctx->evp_ctx == NULL) {
        return -3;
    }
    if (!EVP_CipherInit_ex( fpe_ctx->evp_ctx, evp_cipher, NULL,
                           userKey, NULL, 1)) {
        return -4;
    }
    EVP_CIPHER_CTX_set_padding( fpe_ctx->evp_ctx, 0);
    ret = 0;
    return ret;
}

void FPE_NATIVE_unset_ff1_key(FPE_CTX *fpe_ctx)
{
    if ( fpe_ctx->evp_ctx == NULL) {
      EVP_CIPHER_CTX_free( fpe_ctx->evp_ctx);
      fpe_ctx->evp_ctx = NULL;
    }
}

void FPE_NATIVE_ff1_encrypt(unsigned int *in, unsigned int inlen, const unsigned char *tweak, const unsigned int tweaklen, const unsigned int radix, FPE_CTX *fpe_ctx, unsigned int *out)
{
  FF1_encrypt_128(in, out, tweak,
                      radix, inlen, tweaklen,  fpe_ctx->evp_ctx);
}
void FPE_NATIVE_ff1_decrypt(unsigned int *in, unsigned int inlen, const unsigned char *tweak, const unsigned int tweaklen, const unsigned int radix, FPE_CTX *fpe_ctx, unsigned int *out)
{
 FF1_decrypt_128(in, out, tweak,
                            radix, inlen, tweaklen,  fpe_ctx->evp_ctx);
}




