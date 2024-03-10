#ifndef SHA_H_
#define SHA_H_


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "helpers.h"


#define SHA256_ROTRn(x, n)     ((x >> n) | (x << (32-n)))          // circular right shift (32-bits operand)
#define SHA256_SHRn(x,n)       (x >> n)                            // right shift
#define SHA256_Ch(x,y,z)       ((x & y) ^ ((~x) & z))
#define SHA256_Maj(x,y,z)      ((x & y) ^ (x & z) ^ (y & z))
#define SHA256_SIGMA0(x)       (SHA256_ROTRn(x,2) ^ SHA256_ROTRn(x,13) ^ SHA256_ROTRn(x,22))
#define SHA256_SIGMA1(x)       (SHA256_ROTRn(x,6) ^ SHA256_ROTRn(x,11) ^ SHA256_ROTRn(x,25))
#define SHA256_sigma0(x)       (SHA256_ROTRn(x,7) ^ SHA256_ROTRn(x,18) ^ SHA256_SHRn(x,3))
#define SHA256_sigma1(x)       (SHA256_ROTRn(x,17) ^ SHA256_ROTRn(x,19) ^ SHA256_SHRn(x,10))


typedef struct {
    uint32_t h0;        // most significant word
    uint32_t h1;
    uint32_t h2;
    uint32_t h3;
    uint32_t h4;
    uint32_t h5;
    uint32_t h6;
    uint32_t h7;        // least significant word
} SHA256_HASH_STRUCT;


int SHA256_hash(const char* const file_name, SHA256_HASH_STRUCT *sha256_hash);
void SHA256_Print_Hash(SHA256_HASH_STRUCT *sha256_hash);
void SHA256_test(void);


#endif      // SHA_H_
