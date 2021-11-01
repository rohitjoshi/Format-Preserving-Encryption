#ifndef BIGNUM_NATIVE_H
#define BIGNUM_NATIVE_H

/* NOTE the complete implmentation is in the header file to give
 * the compiler the maximum opportunity to optimize things
 */

#undef BN_num_bytes
#define BIGNUM BIGNUM_NATIVE
#define BN_CTX BN_CTX_NATIVE
#define BN_STACK BN_STACK_NATIVE
#define BN_CTX_new BN_CTX_new_native
#define BN_CTX_free BN_CTX_free_native
#define BN_CTX_start BN_CTX_start_native
#define BN_CTX_get BN_CTX_get_native
#define BN_CTX_end BN_CTX_end_native
#define BN_new BN_new_native
#define BN_clear_free BN_clear_free_native
#define BN_copy BN_copy_native
#define BN_mod_add BN_mod_add_native
#define BN_mod_sub BN_mod_sub_native
#define BN_bn2bin BN_bn2bin_native
#define BN_bin2bn BN_bin2bn_native
#define BN_set_word BN_set_word_native
#define BN_get_word BN_get_word_native
#define BN_add BN_add_native
#define BN_mul BN_mul_native
#define BN_div BN_div_native
#define BN_exp BN_exp_native
#define BN_num_bytes BN_num_bytes_native
#define BN_bn2lebinpad BN_bn2lebinpad_native
#define pow_uv pow_uv_native

#include "fpe_locl.h"

typedef native_size_t BIGNUM;

static union {
	long one;
	char little;
} BNN_is_endian = { 1 };

#define MAX_BIGNUMS_PER_STACK 64
struct bn_stack {
	int inuse[MAX_BIGNUMS_PER_STACK];
	BIGNUM num[MAX_BIGNUMS_PER_STACK];
};
typedef struct bn_stack BN_STACK;

#define MAX_STACKS_PER_CTX 10
struct bn_ctx_native {
	int top;
	BN_STACK stack[MAX_STACKS_PER_CTX];
};
typedef struct bn_ctx_native BN_CTX;

static void BNN_myabort(const char *text)
{
	printf("aborting: %s\n", text);
	abort();
}

static unsigned int BN_num_bytes(const BIGNUM *num);

static BN_CTX *BN_CTX_new(void)
{
	return NULL;
}
static void BN_CTX_free(BN_CTX *ctx)
{
}
static void BN_CTX_start(BN_CTX *ctx)
{
	if (ctx->top >= MAX_STACKS_PER_CTX) BNN_myabort("BN_CTX_start");
	++ctx->top;
	memset(ctx->stack->inuse, 0, sizeof(ctx->stack->inuse));
}
static BIGNUM *BN_CTX_get(BN_CTX *ctx)
{
	int i;
	BN_STACK *stack = &ctx->stack[ctx->top];
	for (i = 0; i < MAX_BIGNUMS_PER_STACK; ++i) {
		if (!stack->inuse[i]) {
			stack->inuse[i] = 1;
			stack->num[i] = 0;
			return &stack->num[i];
		}
	}
	// if we get here we didn't have a BIGNUM left
	BNN_myabort("BN_CTX_get");
	return NULL;
}
static void BN_CTX_end(BN_CTX *ctx)
{
	if (ctx->top <= 0) BNN_myabort("BN_CTX_end");
	--ctx->top;
}
static BIGNUM *BN_new(void)
{
	BIGNUM *num = (BIGNUM *)malloc(sizeof(BIGNUM));
	if (num == NULL) BNN_myabort("BN_new");
	*num = 0;
	return num;
}
static void BN_clear_free(BIGNUM *num)
{
	free(num);
}
static BIGNUM *BN_copy(BIGNUM *to, const BIGNUM *from)
{
	*to = *from;
	return to;
}
// NOTE: BN_mod_add result (*r) must be non-negative
static int BN_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx)
{
	*r = (*a + *b) % *m;
	if (*r >= 0)
		return 1;
	*r += *m;
	return 1;
}
// NOTE: BN_mod_sub result (*r) must be non-negative
static int BN_mod_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx)
{
	native_signed_t signed_r;
	signed_r = ((native_signed_t)(*a) % (*m) - (native_signed_t)(*b) % (*m));
	if (signed_r >= 0) {
		*r = signed_r;
		return 1;
	}
	signed_r += *m;
	*r = signed_r;
	return 1;
}

static int NonZeroLength(const BIGNUM *a)
{
	unsigned char *t = (unsigned char *)a;
	if (BNN_is_endian.little) {
		for (int i = sizeof(BIGNUM); i > 0; --i) {
			if (t[i - 1] != 0) {
				return i;
			}
		}
	} else {
		for (int i = 0; i < sizeof(BIGNUM); ++i) {
			if (t[i] != 0) {
				return sizeof(BIGNUM) - i;
			}
		}
	}
	return 0;
}

static void native2be(BIGNUM *a)
{
	if (BNN_is_endian.little) {
		char *c = (char *)a;
		for (int i = 0; i < sizeof(BIGNUM) / 2; ++i) {
			char temp = c[i];
			c[i] = c[sizeof(BIGNUM) - i - 1];
			c[sizeof(BIGNUM) - i - 1] = temp;
		}
	} else {
		// we are big-endian, so nothing needed
	}
}

// convert BIGNUM to BIG-ENDIAN bytes, minimum possible length
static int BN_bn2bin(const BIGNUM *a, unsigned char *to)
{
	// does this need to be big-endian?
	if (*a == 0) {
		*to = '\0';
		return 1;
	}
	int nzl = NonZeroLength(a);
	int zeros = (sizeof(BIGNUM) - nzl);
	if (BNN_is_endian.little) {
		if (nzl == sizeof(BIGNUM)) {
			*(BIGNUM *)to = *a;
			native2be((BIGNUM *)to);
		} else {
			BIGNUM temp = *a;
			unsigned char *t = (unsigned char *)&temp + zeros;
			native2be(&temp);
			memcpy(to, t, nzl);
		}
	} else {
		int zeros = (sizeof(BIGNUM) - nzl);
		char *ac = (char *)a + zeros;
		memcpy(to, ac, nzl);
	}
	return nzl;
}

static BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret)
{
	// does this need to be big-endian?
	if (len > sizeof(BIGNUM)) BNN_myabort("BN_bin2bn");
	if (len == sizeof(BIGNUM)) {
		*ret = *(BIGNUM *)s;
		return ret;
	}
	*ret = 0;
	while (len--) {
		*ret <<= 8;
		*ret |= *s++;
	}
	return ret;
}
static int BN_set_word(BIGNUM *a, BN_ULONG w)
{
	*a = (BIGNUM)w;
	return 1;
}
static BN_ULONG BN_get_word(BIGNUM *a)
{
	return (BN_ULONG)*a;
}
static int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
	*r = *a + *b;
	return 1;
}
static int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
	*r = *a * *b;
	return 1;
}
static int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *a, const BIGNUM *d, BN_CTX *ctx)
{
	if (dv)
		*dv = *a / *d;
	if (rem)
		*rem = *a % *d;
	return 1;
}
static BIGNUM power(BIGNUM base, BIGNUM exp) 
{
    if (exp == 0)
        return 1;
    else if (exp % 2)
        return base * power(base, exp - 1);
    else {
        BIGNUM temp = power(base, exp / 2);
        return temp * temp;
    }
}
static int BN_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)
{
	*r = power(*a, *p);
	return 1;
}
static unsigned int BN_num_bytes(const BIGNUM *num)
{
	return (unsigned int)NonZeroLength(num);
}

static int BN_bn2lebinpad(const BIGNUM *a, unsigned char *to, int tolen)
{
	int nb = BN_num_bytes(a);
	if (tolen < nb)
		return 0;
	if (tolen > nb)
		memset(to + nb, 0, tolen - nb);
	*(BIGNUM *)to = *a;
	return 1;
}

static void pow_uv(BIGNUM *pow_u, BIGNUM *pow_v, unsigned int x, int u, int v, BN_CTX *ctx)
{
    BIGNUM base = 0,
           e = 0;

    base = x;
    if (u > v) {
        e = v;
        BN_exp(pow_v, &base, &e, ctx);
        *pow_u = *pow_v * base;
    } else {
        e = u;
        BN_exp(pow_u, &base, &e, ctx);
        if (u == v)    *pow_v = *pow_u;
        else    *pow_v = *pow_u * base;
    }

    return;
}

#endif
