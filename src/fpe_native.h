#ifndef HEADER_FPE_H
#define HEADER_FPE_H

#include <openssl/evp.h>

#ifdef __cplusplus
extern "C"
{
#endif

//#define FF1_ROUNDS 10
//#define FF3_ROUNDS 8
//#define FF3_TWEAK_SIZE 8

   struct fpe_ctx_st
    {
        EVP_CIPHER_CTX *evp_ctx;
    };

    typedef struct fpe_ctx_st FPE_CTX;

    /*** FF1 ***/
    int FPE_NATIVE_set_ff1_key(const unsigned char *userKey, const int bits, FPE_CTX *fpe_ctx);
    void FPE_NATIVE_unset_ff1_key(FPE_CTX *fpe_ctx);

    void FPE_NATIVE_ff1_encrypt(unsigned int *in, unsigned int inlen, const unsigned char *tweak, const unsigned int tweaklen, const unsigned int radix, FPE_CTX *fpe_ctx, unsigned int *out);
    void FPE_NATIVE_ff1_decrypt(unsigned int *in, unsigned int inlen, const unsigned char *tweak, const unsigned int tweaklen, const unsigned int radix, FPE_CTX *fpe_ctx, unsigned int *out);

    /*** FF3 ***/
   int FPE_NATIVE_set_ff3_key(const unsigned char *userKey, const int bits, FPE_CTX *fpe_ctx);
   void FPE_NATIVE_unset_ff3_key(FPE_CTX *fpe_ctx);

   void FPE_NATIVE_ff3_encrypt(unsigned int *in, unsigned int inlen, const unsigned char *tweak,  const unsigned int radix, FPE_CTX *fpe_ctx, unsigned int *out);
   void FPE_NATIVE_ff3_decrypt(unsigned int *in, unsigned int inlen, const unsigned char *tweak,  const unsigned int radix, FPE_CTX *fpe_ctx, unsigned int *out);


#ifdef __cplusplus
}
#endif

#endif
