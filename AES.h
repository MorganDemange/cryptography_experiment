#ifndef AES_H_
#define AES_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "helpers.h"

#define AES_FORWARD_S_BOX           0
#define AES_ROUND_USE_MIXCOLUMNS    0
#define AES_ROUND_NO_MIXCOLUMNS     1

/* Each AES data block is represented by a matrix; 4 columns of 1 word (32-bits value) */
typedef struct {
    uint32_t w0;        // first column
    uint32_t w1;        // second column
    uint32_t w2;        // third column
    uint32_t w3;        // fourth column
} AES_Block_Struct;


int AES128_encryption(const char* const plain_file_name, uint64_t key_msb, uint64_t key_lsb, const char* const encrypted_file_name);
int AES128_decryption(const char* const encrypted_file_name, uint64_t key_msb, uint64_t key_lsb, const char* const decrypted_file_name);
void AES_test(void);


#endif      // AES_H_

