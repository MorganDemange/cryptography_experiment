#ifndef MD5_H_
#define MD5_H_


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "helpers.h"


/*
    MD5 hash structure.
*/
typedef struct {
    uint32_t h0;            // h0 is the most significant word
    uint32_t h1;
    uint32_t h2;
    uint32_t h3;            // h3 is the least significant word
} MD5_HASH_STRUCT;


int MD5_hash(const char* const filename, MD5_HASH_STRUCT *md5_hash);
void MD5_Print_Hash(MD5_HASH_STRUCT *md5_hash);
void MD5_test(void);

#endif      // MD5_H_