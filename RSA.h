#ifndef RSA_H_
#define RSA_H_

#include <stdint.h>
#include <stdlib.h>
#include <gmp.h>
#include "PRNGs.h"
#include "helpers.h"
#include <string.h>



#define RSA_1024_BITS           1024
#define RSA_2048_BITS           2048
#define RSA_4096_BITS           4096

#define RSA_KEYSIZE_BITS        RSA_1024_BITS           // select the RSA key size, must be an even number
#define RSA_KEYSIZE_BYTES       (RSA_KEYSIZE_BITS/8)
#define RSA_KEYSIZE_WORDS       (RSA_KEYSIZE_BITS/32)


typedef struct {
    mpz_t n;            // modulus n
    mpz_t e;            // public exponent e
} RSA_PUBLIC_KEY_T;

typedef mpz_t   RSA_PRIVATE_KEY_T;


int RSA_Create_Keys(RSA_PUBLIC_KEY_T *public_key, RSA_PRIVATE_KEY_T *d);
int RSA_Destroy_Keys(RSA_PUBLIC_KEY_T *public_key, RSA_PRIVATE_KEY_T *d);
void RSA_Print_Keys(const RSA_PUBLIC_KEY_T *public_key, const RSA_PRIVATE_KEY_T *d, const char* const keys_title);
int RSA_Generate_Keys(RSA_PUBLIC_KEY_T *public_key, RSA_PRIVATE_KEY_T *d);

char* RSA_Encryption(const char* const plain_message, const RSA_PUBLIC_KEY_T *public_key);
char* RSA_Decryption(const char* const encrypted_message, const RSA_PUBLIC_KEY_T *public_key, const RSA_PRIVATE_KEY_T *d);
void RSA_test(void);

#endif          // RSA_H_
