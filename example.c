#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <fpe.h>
#include <time.h>

void hex2chars(unsigned char hex[], unsigned char result[])
{
    int len = strlen(hex);
    unsigned char temp[3];
    temp[2] = 0x00;

    int j = 0;
    for (int i = 0; i < len; i += 2)
    {
        temp[0] = hex[i];
        temp[1] = hex[i + 1];
        result[j] = (char)strtol(temp, NULL, 16);
        ++j;
    }
}

void map_chars(unsigned char str[], unsigned int result[])
{
    int len = strlen(str);

    for (int i = 0; i < len; ++i)
        if (str[i] >= 'a')
            result[i] = str[i] - 'a' + 10;
        else
            result[i] = str[i] - '0';
}

void inverse_map_chars(unsigned result[], unsigned char str[], int len)
{
    for (int i = 0; i < len; ++i)
        if (result[i] < 10)
            str[i] = result[i] + '0';
        else
            str[i] = result[i] - 10 + 'a';

    str[len] = 0x00;
}

void benchmark_ff1(unsigned int *in, unsigned int inlen, FPE_KEY *key)
{
    unsigned int total = 10000000;
    clock_t start_time = clock();

    for (uint16_t i = 0; i < total; i++)
    {
        unsigned int y[inlen];
        FPE_ff1_encrypt_128(in, y, inlen, &key, FPE_ENCRYPT);
    }
    double elapsed_time = (double)(clock() - start_time) / CLOCKS_PER_SEC;
    printf("Done in %f seconds\n", elapsed_time);
    printf("TPS: in %f seconds\n", total / elapsed_time);
}

int main(int argc, char *argv[])
{
    if (argc != 5)
    {
        printf("Usage: %s <key> <tweak> <radix> <plaintext>\n", argv[0]);
        return 0;
    }

    unsigned int total = 10000000;

    unsigned char k[100],
        t[100],
        result[100];
    int xlen = strlen(argv[4]),
        klen = strlen(argv[1]) / 2,
        tlen = strlen(argv[2]) / 2,
        radix = atoi(argv[3]);
    unsigned int x[100],
        y[xlen];
    unsigned int tmp;

    hex2chars(argv[1], k);
    hex2chars(argv[2], t);
    map_chars(argv[4], x);

    for (int i = 0; i < xlen; ++i)
        assert(x[i] < radix);

    FPE_KEY ff1, ff3;

    printf("key:");
    for (int i = 0; i < klen; ++i)
        printf(" %02x", k[i]);
    puts("");
    if (tlen)
        printf("tweak:");
    for (int i = 0; i < tlen; ++i)
        printf(" %02x:%d", t[i],t[i]);
    if (tlen)
        puts("");

    printf("BITS:%d\n",klen * 8 );
    FPE_set_ff1_key(k, klen * 8, t, tlen, radix, &ff1);
    FPE_set_ff3_key(k, klen * 8, t, radix, &ff3);

    printf("after map: ");
    for (int i = 0; i < xlen; ++i)
        printf("%d", x[i]);
    printf("\n\n");


    printf("========== FF1 native 128 test==========\n");
    FPE_ff1_encrypt_128(x, y, xlen, &ff1, FPE_ENCRYPT);

    printf("ciphertext(numeral string):");
        for (int i = 0; i < xlen; ++i)
            printf(" %d", y[i]);
        printf("\n");

    inverse_map_chars(y, result, xlen);
    printf("ciphertext: %s\n\n", result);

    printf("========== FF1  test==========\n");
        FPE_ff1_encrypt(x, y, xlen, &ff1, FPE_ENCRYPT);

        printf("ciphertext(numeral string):");
            for (int i = 0; i < xlen; ++i)
                printf(" %d", y[i]);
            printf("\n");

        inverse_map_chars(y, result, xlen);
        printf("ciphertext: %s\n\n", result);

    printf("========== FF3 native 128 test==========\n");
        FPE_ff3_encrypt_128(x, y, xlen, &ff3, FPE_ENCRYPT);

        printf("ciphertext(numeral string):");
            for (int i = 0; i < xlen; ++i)
                printf(" %d", y[i]);
            printf("\n");

        inverse_map_chars(y, result, xlen);
        printf("ciphertext: %s\n\n", result);

   printf("========== FF3  test==========\n");
           FPE_ff3_encrypt(x, y, xlen, &ff3, FPE_ENCRYPT);

           printf("ciphertext(numeral string):");
               for (int i = 0; i < xlen; ++i)
                   printf(" %d", y[i]);
               printf("\n");

           inverse_map_chars(y, result, xlen);
           printf("ciphertext: %s\n\n", result);
    printf("========== FF1 native 128 benchmark==========\n");
    // benchmark_ff1(x, xlen, &ff1);

    clock_t start_time = clock();
    for (uint32_t i = 0; i < total; i++)
    {
        //sprintf(x, "%09d", i);
        map_chars(argv[4], x);
        unsigned int y[xlen];
        //sprintf(x, "%09d", i);
        FPE_ff1_encrypt_128(x, y, xlen, &ff1, FPE_ENCRYPT);
        inverse_map_chars(y, result, xlen);
    }
    double elapsed_time = (double)(clock() - start_time) / CLOCKS_PER_SEC;
    printf("Total iterations: %ld completed in %f seconds\n", total, elapsed_time);
    printf("TPS: in %f seconds\n", total / elapsed_time);
    printf("Per Operation ns: in %f ns\n", elapsed_time * 1000 * 1000 * 1000 / total);

    printf("========== FF1 benchmark==========\n");
    // benchmark_ff1(x, xlen, &ff1);

    start_time = clock();
    for (uint32_t i = 0; i < total; i++)
    {
        sprintf(x, "%09d", i);
        int xlen = strlen(x);
        unsigned int y[xlen];
        sprintf(x, "%09d", i);
        FPE_ff1_encrypt(x, y, xlen, &ff1, FPE_ENCRYPT);
    }
    elapsed_time = (double)(clock() - start_time) / CLOCKS_PER_SEC;
    printf("Total iterations: %d completed in %f seconds\n", total, elapsed_time);
    printf("TPS: in %f seconds\n", total / elapsed_time);
    printf("Per Operation ns: in %f ns\n", (elapsed_time * 1000 * 1000 * 1000) / total);

    printf("========== FF1 ==========\n");
    FPE_ff1_encrypt_128(x, y, xlen, &ff1, FPE_ENCRYPT);

    printf("ciphertext(numeral string):");
    for (int i = 0; i < xlen; ++i)
        printf(" %d", y[i]);
    printf("\n");

    inverse_map_chars(y, result, xlen);
    printf("ciphertext: %s\n\n", result);

    memset(x, 0, sizeof(x));
    FPE_ff1_encrypt_128(y, x, xlen, &ff1, FPE_DECRYPT);

    printf("plaintext:");
    for (int i = 0; i < xlen; ++i)
        printf(" %d", x[i]);
    printf("\n\n");

    printf("========== FF3 native 128 benchmark==========\n");
    // benchmark_ff1(x, xlen, &ff1);

    start_time = clock();
    for (uint32_t i = 0; i < total; i++)
    {
        sprintf(x, "%09d", i);
        int xlen = strlen(x);
        unsigned int y[xlen];
        sprintf(x, "%09d", i);
        FPE_ff3_encrypt_128(x, y, xlen, &ff1, FPE_ENCRYPT);
    }
    elapsed_time = (double)(clock() - start_time) / CLOCKS_PER_SEC;
    printf("Total iterations: %d completed in %f seconds\n", total, elapsed_time);
    printf("TPS: in %f seconds\n", total / elapsed_time);
    printf("Per Operation ns: in %f ns\n", (elapsed_time * 1000 * 1000 * 1000) / total);
    printf("========== FF3 ==========\n");

    printf("========== FF3 benchmark==========\n");
    // benchmark_ff1(x, xlen, &ff1);

    start_time = clock();
    for (uint32_t i = 0; i < total; i++)
    {
        sprintf(x, "%09d", i);
        int xlen = strlen(x);
        unsigned int y[xlen];
        sprintf(x, "%09d", i);
        FPE_ff3_encrypt(x, y, xlen, &ff1, FPE_ENCRYPT);
    }
    elapsed_time = (double)(clock() - start_time) / CLOCKS_PER_SEC;
    printf("Total iterations: %d completed in %f seconds\n", total, elapsed_time);
    printf("TPS: in %f seconds\n", total / elapsed_time);
    printf("Per Operation ns: in %f ns\n", (elapsed_time * 1000 * 1000 * 1000) / total);
    printf("========== FF3 ==========\n");

    FPE_ff3_encrypt_128(x, y, xlen, &ff3, FPE_ENCRYPT);

    printf("ciphertext(numeral string):");
    for (int i = 0; i < xlen; ++i)
        printf(" %d", y[i]);
    printf("\n");

    inverse_map_chars(y, result, xlen);
    printf("ciphertext: %s\n\n", result);

    memset(x, 0, sizeof(x));
    FPE_ff3_encrypt_128(y, x, xlen, &ff3, FPE_DECRYPT);

    printf("plaintext:");
    for (int i = 0; i < xlen; ++i)
        printf(" %d", x[i]);
    printf("\n");

    FPE_unset_ff1_key(&ff1);
    FPE_unset_ff3_key(&ff3);

    return 0;
}
