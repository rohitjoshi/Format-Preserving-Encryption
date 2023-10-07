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

// g_ variables defined in ff3.c

static void rev_bytes(unsigned char X[], int len)
{
    int hlen = len >> 1;
    for (int i = 0; i < hlen; ++i)
    {
        unsigned char tmp = X[i];
        X[i] = X[len - i - 1];
        X[len - i - 1] = tmp;
    }
    return;
}

// convert numeral string in reverse order to number
static void str2num_rev(BIGNUM *Y, const unsigned int *X, unsigned int radix, unsigned int len, BN_CTX *ctx)
{
    BIGNUM r = radix;

    *Y = 0;
    for (int i = len; i > 0;)
    {
        // Y = Y * radix + X[i]
        *Y = *Y * r + X[--i];
    }

    return;
}

// convert number to numeral string in reverse order
static void num2str_rev(const BIGNUM *X, unsigned int *Y, unsigned int radix, int len, BN_CTX *ctx)
{
    BIGNUM dv = 0,
           rem = 0,
           r = radix,
           XX = *X;

    memset(Y, 0, len << 2);

    for (int i = 0; i < len; ++i)
    {
        // XX / r = dv ... rem
        BN_div(&dv, &rem, &XX, &r, ctx);
        // Y[i] = XX % r
        Y[i] = BN_get_word(&rem);
        // XX = XX / r
        XX = dv;
    }

    return;
}

void FF3_encrypt_128(unsigned int *in, unsigned int *out, const unsigned char *tweak, unsigned int radix, unsigned int inlen,
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
    int u = ceil2(inlen, 1);
    int v = inlen - u;
    unsigned int *A = out, *B = out + u;
    pow_uv(&qpow_u, &qpow_v, radix, u, v, ctx);
    unsigned int temp = (unsigned int)ceil(u * log2(radix));
    const int b = ceil2(temp, 3);

    unsigned char S[16], P[16];
    unsigned char *Bytes = (unsigned char *)OPENSSL_malloc(b);

    for (int i = 0; i < FF3_ROUNDS; ++i)
    {
        // i
        unsigned int m;
        if (i & 1)
        {
            m = v;
            memcpy(P, tweak, 4);
        }
        else
        {
            m = u;
            memcpy(P, tweak + 4, 4);
        }
        P[3] ^= i & 0xff;

        str2num_rev(&bnum, B, radix, inlen - m, ctx);
        memset(Bytes, 0x00, b);
        int BytesLen = BN_bn2bin(&bnum, Bytes);
        BytesLen = BytesLen > 12 ? 12 : BytesLen;
        memset(P + 4, 0x00, 12);
        memcpy(P + 16 - BytesLen, Bytes, BytesLen);

        // iii
        rev_bytes(P, 16);
        // for (int i = 0; i < 16; ++i)
        //     printf(" %d", P[i]);
        // printf("\n");
        rc = EVP_EncryptUpdate(evp_ctx, S, &outl, P, 16);
        assert(rc == 1);
        rev_bytes(S, 16);
        // for (int i = 0; i < 16; ++i)
        //     printf(" %d", S[i]);
        // printf("\n");

        // iv
        BN_bin2bn(S, 16, &y);
        native2be(&y);

        // printf("y:%llx\n", (unsigned long long)(y & 0xFFFFFFFFFFFFFFFF));
        // printf("\n");

        // v
        str2num_rev(&anum, A, radix, m, ctx);
        if (i & 1)
            BN_mod_add(&c, &anum, &y, &qpow_v, ctx);
        else
            BN_mod_add(&c, &anum, &y, &qpow_u, ctx);
        //printf("c:%llx\n", (unsigned long long)(y & 0xFFFFFFFFFFFFFFFF));
        assert(A != B);
        // printf("A");
        // for (int i = 0; i < 16; ++i)
        //     printf(" %d", A[i]);
        // printf("\n");
        // printf("B");
        // for (int i = 0; i < 16; ++i)
        //     printf(" %d", B[i]);
        // printf("\n");
        A = (unsigned int *)((uintptr_t)A ^ (uintptr_t)B);
        B = (unsigned int *)((uintptr_t)B ^ (uintptr_t)A);
        A = (unsigned int *)((uintptr_t)A ^ (uintptr_t)B);

        num2str_rev(&c, B, radix, m, ctx);
    }

    // free the space
    BN_CTX_free(ctx);
    OPENSSL_free(Bytes);
    return;
}

void FF3_decrypt_128(unsigned int *in, unsigned int *out, const unsigned char *tweak, unsigned int radix, unsigned int inlen,
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
    int u = ceil2(inlen, 1);
    int v = inlen - u;
    unsigned int *A = out, *B = out + u;
    pow_uv(&qpow_u, &qpow_v, radix, u, v, ctx);
    unsigned int temp = (unsigned int)ceil(u * log2(radix));
    const int b = ceil2(temp, 3);

    unsigned char S[16], P[16];
    unsigned char *Bytes = (unsigned char *)OPENSSL_malloc(b);
    for (int i = FF3_ROUNDS - 1; i >= 0; --i)
    {
        // i
        int m;
        if (i & 1)
        {
            m = v;
            memcpy(P, tweak, 4);
        }
        else
        {
            m = u;
            memcpy(P, tweak + 4, 4);
        }
        P[3] ^= i & 0xff;

        // ii

        str2num_rev(&anum, A, radix, inlen - m, ctx);
        memset(Bytes, 0x00, b);
        int BytesLen = BN_bn2bin(&anum, Bytes);
        BytesLen = BytesLen > 12 ? 12 : BytesLen;
        memset(P + 4, 0x00, 12);
        memcpy(P + 16 - BytesLen, Bytes, BytesLen);

        // iii
        rev_bytes(P, 16);
        memset(S, 0x00, sizeof(S));
        rc = EVP_EncryptUpdate(evp_ctx, S, &outl, P, 16);
        assert(rc == 1);
        rev_bytes(S, 16);

        // iv
        BN_bin2bn(S, 16, &y);
        native2be(&y);

        // v
        str2num_rev(&bnum, B, radix, m, ctx);
        if (i & 1)
            BN_mod_sub(&c, &bnum, &y, &qpow_v, ctx);
        else
            BN_mod_sub(&c, &bnum, &y, &qpow_u, ctx);

        assert(A != B);
        A = (unsigned int *)((uintptr_t)A ^ (uintptr_t)B);
        B = (unsigned int *)((uintptr_t)B ^ (uintptr_t)A);
        A = (unsigned int *)((uintptr_t)A ^ (uintptr_t)B);

        num2str_rev(&c, A, radix, m, ctx);
    }

    // free the space
    BN_CTX_free(ctx);
    OPENSSL_free(Bytes);
    return;
}

void FPE_ff3_encrypt_128(unsigned int *in, unsigned int *out, unsigned int inlen, FPE_KEY *key, const int enc)
{
    if (enc)
        FF3_encrypt_128(in, out, key->tweak, key->radix, inlen, key->evp_ctx);

    else
        FF3_decrypt_128(in, out, key->tweak, key->radix, inlen, key->evp_ctx);
}

 struct fpe_ctx_st
    {
        EVP_CIPHER_CTX *evp_ctx;
    };

 typedef struct fpe_ctx_st FPE_CTX;
int FPE_NATIVE_set_ff3_key(const unsigned char *userKey, const int bits, FPE_CTX *fpe_ctx)
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
     unsigned char tmp[32];
     memcpy(tmp, userKey, bits >> 3);
     rev_bytes(tmp, bits >> 3);
    if (!EVP_CipherInit_ex(fpe_ctx->evp_ctx, evp_cipher, NULL,
                           tmp, NULL, 1)) {
        return -4;
    }
    EVP_CIPHER_CTX_set_padding(fpe_ctx->evp_ctx, 0);
    ret = 0;
    return ret;
}

void FPE_NATIVE_unset_ff3_key(FPE_CTX *fpe_ctx)
{
    if (fpe_ctx->evp_ctx == NULL) {
      EVP_CIPHER_CTX_free(fpe_ctx->evp_ctx);
      fpe_ctx->evp_ctx = NULL;
    }
}

void FPE_NATIVE_ff3_encrypt(unsigned int *in, unsigned int inlen, const unsigned char *tweak,  const unsigned int radix, FPE_CTX *fpe_ctx, unsigned int *out)
{
  FF3_encrypt_128(in, out, tweak,
                      radix, inlen, fpe_ctx->evp_ctx);
}
void FPE_NATIVE_ff3_decrypt(unsigned int *in, unsigned int inlen, const unsigned char *tweak, const unsigned int radix, FPE_CTX *fpe_ctx, unsigned int *out)
{
 FF3_decrypt_128(in, out, tweak,
                            radix, inlen, fpe_ctx->evp_ctx);
}
