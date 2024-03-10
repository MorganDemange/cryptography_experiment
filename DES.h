#ifndef DES_H_
#define DES_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "helpers.h"

#define DES_ENCRYPTION_MODE         0
#define DES_DECRYPTION_MODE         1


int DES_encryption(const char* const plain_file_name, uint64_t key, const char* const encrypted_file_name);
int DES_decryption(const char* const encrypted_file_name, uint64_t key, const char* const decrypted_file_name);
void DES_test(void);

#endif      // DES_H_
