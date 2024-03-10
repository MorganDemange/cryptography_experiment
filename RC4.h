#ifndef RC4_H_
#define RC4_H_

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "helpers.h"

int RC4(const char* const data_out_filename, const char* const data_in_filename, uint8_t *key, int keysize);
void RC4_test(void);


#endif      // RC4_H_