/*
    RC4 (Rivest Cipher 4) implementation.
*/
#include "RC4.h"


/*
    Encrypt/Decrypt (encryption and decryption algorithms are the same) a data byte stream with the RC4 cipher.

    Parameters:
        - data_in_filename : input data file (file to be encrypted or decrypted)
        - data_out_filename: output data file (encryption or decryption of the input data file)
        - key              : encryption/decryption key (byte array)
        - keysize          : number of elements in the key array

    Return: error status (EXIT_SUCCESS / EXIT_FAILURE)
*/
int RC4(const char* const data_out_filename, const char* const data_in_filename, uint8_t *key, int keysize)
{
    FILE *data_in_file = fopen(data_in_filename, "rb");
    FILE *data_out_file = fopen(data_out_filename, "wb");
    int filesize = get_filesize(data_in_filename);      // filesize (in bytes)

    if(  (data_in_file == NULL) || (data_out_file == NULL) || (filesize == -1)  ){
        printf("RC4 error: cannot open file.\n");
        return EXIT_FAILURE;
    }


    int i,j;
    uint8_t temp;
    /* Key schedule */
    uint8_t state[256];
    for(i = 0; i < 256; i++){
        state[i] = i;
    }
    j = 0;
    for(i = 0; i < 256; i++){
        j = (j + state[i] + key[i % keysize]) % 256;
        swap_bytes(&state[i], &state[j]);       // swap state[i] and state[j]
    }

    /* Encryption/Decryption */
    i = j = 0;
    for(int k = 0; k < filesize; k++){
        i = (i+1) % 256;
        j = (j + state[i]) % 256;
        swap_bytes(&state[i], &state[j]);       // swap state[i] and state[j]
        fread(&temp, sizeof(uint8_t), 1, data_in_file);
        temp ^= state[ (state[i] + state[j]) % 256 ];
        fwrite(&temp, sizeof(uint8_t), 1, data_out_file);;
    }

    fclose(data_in_file);
    fclose(data_out_file);

    return EXIT_SUCCESS;
}


void RC4_test(void)
{
    uint8_t key[] = {0x53,0x65,0x63,0x72,0x65,0x74};
    RC4("RC4_encrypted.txt", "plain_data_test.txt", key, sizeof(key));
    RC4("RC4_decrypted.txt", "RC4_encrypted.txt", key, sizeof(key));
}