#ifndef OTP_H_
#define OTP_H_

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "PRNGs.h"
#include "helpers.h"

typedef struct {
    uint8_t *key;
    int keysize;            // keysize in bytes
} OTP_KEY_Struct;


int OTP_Init_Key(OTP_KEY_Struct *otp_key, int n);
void OTP_Destroy_Key(OTP_KEY_Struct *otp_key);
int OTP_Generate_Key(OTP_KEY_Struct *otp_key);
int OTP_Process_File(char* const output_file_name, const OTP_KEY_Struct* const otp_key, const char* const input_file_name);
void OTP_test(void);

#endif      // OTP_H_