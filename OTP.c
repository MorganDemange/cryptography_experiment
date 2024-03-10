/*
    One Time Pad (OTP) implementation.
*/
#include "OTP.h"


/*
    Initialize a OTP key of size n bytes.
*/
int OTP_Init_Key(OTP_KEY_Struct *otp_key, int n)
{
    if( (otp_key == NULL) || (n < 0) ){
        return EXIT_FAILURE;
    }

    otp_key->key = (uint8_t*)malloc(sizeof(uint8_t) * n);
    if(otp_key->key == NULL){
        otp_key->keysize = 0;
        return EXIT_FAILURE;
    }

    otp_key->keysize = n;
    return EXIT_SUCCESS;
}


/*
    Destroy a OTP key.
*/
void OTP_Destroy_Key(OTP_KEY_Struct *otp_key)
{
    if(otp_key->key != NULL){
        free(otp_key->key);
    }
    otp_key->keysize = 0;
}


/*
    Generate a random OTP key of size n bytes, using a linear congruential pseudorandom number generator.
*/
int OTP_Generate_Key(OTP_KEY_Struct *otp_key)
{
    if(otp_key == NULL){
        return EXIT_FAILURE;
    }

    for(int i = 0; i < otp_key->keysize; i++){
        otp_key->key[i] = (uint8_t)PRNG_LCG();
    }

    return EXIT_SUCCESS;
}



/*
    Encryption/Decryption of a file.

    Condition: size(otp_key) >= size(input_file)
*/
int OTP_Process_File(char* const output_file_name, const OTP_KEY_Struct* const otp_key, const char* const input_file_name)
{
    FILE *input_file = fopen(input_file_name, "rb");
    FILE *output_file = fopen(output_file_name, "wb");
    int filesize = get_filesize(input_file_name);

    if(  (input_file == NULL) || (output_file == NULL) || (filesize == -1)  ){
        printf("OTP Error: Cannot open files.\n");
        return EXIT_FAILURE;
    }

    if(otp_key->keysize < filesize){
        printf("OTP Error: keysize too small.\n");
        return EXIT_FAILURE;
    }

    uint8_t byte;
    for(int i = 0; i < filesize; i++){
        fread(&byte, sizeof(uint8_t), 1, input_file);
        byte ^= otp_key->key[i]; 
        fwrite(&byte, sizeof(uint8_t), 1, output_file);
    }

    fclose(input_file);
    fclose(output_file);
    return EXIT_SUCCESS;
}



void OTP_test(void)
{
    int filesize = get_filesize("plain_data_test.txt");

    OTP_KEY_Struct key;
    OTP_Init_Key(&key, filesize);
    OTP_Generate_Key(&key);

    OTP_Process_File("OTP_encrypted_file.txt", &key, "plain_data_test.txt");
    OTP_Process_File("OTP_decrypted_file.txt", &key, "OTP_encrypted_file.txt");

    OTP_Destroy_Key(&key);
}