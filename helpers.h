#ifndef HELPERS_H_
#define HELPERS_H_

#include <stdint.h>
#include <stdio.h>
#include "PRNGs.h"
#include <gmp.h>
#include <stdlib.h>
#include <string.h>


#define __min_(a,b)      (  ( (a) > (b) ) ? (b) : (a)  )
#define __max_(a,b)      (  ( (a) > (b) ) ? (a) : (b)  )

#define TO_STRING_(X)                       (#X)
#define TO_STRING(X)                        TO_STRING_(X)           // convert X to the string "X"
#define GET_VARIABLE_NAME(variable)         TO_STRING(variable)


typedef enum {
    PRINT_FORMAT_HEX = 16,
    PRINT_FORMAT_DEC = 10,
    PRINT_FORMAT_BIN = 2
} PRINT_FORMAT_T;


void random_array(uint32_t *arr, unsigned int size);
int get_filesize(const char* const filename);
void swap_bytes(uint8_t *x, uint8_t *y);

uint32_t left_circular_shift_32(uint32_t number, int shift);
uint32_t switch_endianness_32(uint32_t number);
uint64_t switch_endianness_64(uint64_t number);

size_t get_char_len_mpz_t(const mpz_t number, PRINT_FORMAT_T format);
char* get_str_mpz_t(const mpz_t number, size_t *str_len, PRINT_FORMAT_T format);
void print_mpz_t(const mpz_t number, const char* const var_name, PRINT_FORMAT_T format);
void random_mpz_t(mpz_t *rand_number, const mpz_t max_limit);


#endif          // HELPERS_H_
