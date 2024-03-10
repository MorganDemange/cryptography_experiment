/* 
    DES in ECB mode with ANSI X9.23 Padding.
    All values are in little-endian format.
*/
#include "DES.h"


static int IP_table[64] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

static int IP_INV_table[64] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
};

static int PC1_table[56] = {
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
};

static int PC2_table[48] = {
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

static int S1[64] = {
    14, 0, 4, 15,
    4, 15, 1, 12,
    13, 7, 14, 8,
    1, 4, 8, 2,
    2, 14, 13, 4,
    15, 2, 6, 9,
    11, 13, 2, 1,
    8, 1, 11, 7,
    3, 10, 15, 5,
    10, 6, 12, 11,
    6, 12, 9, 3,
    12, 11, 7, 14,
    5, 9, 3, 10,
    9, 5, 10, 0,
    0, 3, 5, 6,
    7, 8, 0, 13
};

static int S2[64] = {
    15, 3, 0, 13,
    1, 13, 14, 8,
    8, 4, 7, 10,
    14, 7, 11, 1,
    6, 15, 10, 3,
    11, 2, 4, 15,
    3, 8, 13, 4,
    4, 14, 1, 2,
    9, 12, 5, 11,
    7, 0, 8, 6,
    2, 1, 12, 7,
    13, 10, 6, 12,
    12, 6, 9, 0,
    0, 9, 3, 5,
    5, 11, 2, 14,
    10, 5, 15, 9
};

static int S3[64] = {
    10, 13, 13, 1,
    0, 7, 6, 10,
    9, 0, 4, 13,
    14, 9, 9, 0,
    6, 3, 8, 6,
    3, 4, 15, 9,
    15, 6, 3, 8,
    5, 10, 0, 7,
    1, 2, 11, 4,
    13, 8, 1, 15,
    12, 5, 2, 14,
    7, 14, 12, 3,
    11, 12, 5, 11,
    4, 11, 10, 5,
    2, 15, 14, 2,
    8, 1, 7, 12
};

static int S4[64] = {
    7, 13, 10, 3,
    13, 8, 6, 15,
    14, 11, 9, 0,
    3, 5, 0, 6,
    0, 6, 12, 10,
    6, 15, 11, 1,
    9, 0, 7, 13,
    10, 3, 13, 8,
    1, 4, 15, 9,
    2, 7, 1, 4,
    8, 2, 3, 5,
    5, 12, 14, 11,
    11, 1, 5, 12,
    12, 10, 2, 7,
    4, 14, 8, 2,
    15, 9, 4, 14
};

static int S5[64] = {
    2, 14, 4, 11,
    12, 11, 2, 8,
    4, 2, 1, 12,
    1, 12, 11, 7,
    7, 4, 10, 1,
    10, 7, 13, 14,
    11, 13, 7, 2,
    6, 1, 8, 13,
    8, 5, 15, 6,
    5, 0, 9, 15,
    3, 15, 12, 0,
    15, 10, 5, 9,
    13, 3, 6, 10,
    0, 9, 3, 4,
    14, 8, 0, 5,
    9, 6, 14, 3
};

static int S6[64] = {
    12, 10, 9, 4,
    1, 15, 14, 3,
    10, 4, 15, 2,
    15, 2, 5, 12,
    9, 7, 2, 9,
    2, 12, 8, 5,
    6, 9, 12, 15,
    8, 5, 3, 10,
    0, 6, 7, 11,
    13, 1, 0, 14,
    3, 13, 4, 1,
    4, 14, 10, 7,
    14, 0, 1, 6,
    7, 11, 13, 0,
    5, 3, 11, 8,
    11, 8, 6, 13
};

static int S7[64] = {
    4, 13, 1, 6,
    11, 0, 4, 11,
    2, 11, 11, 13,
    14, 7, 13, 8,
    15, 4, 12, 1,
    0, 9, 3, 4,
    8, 1, 7, 10,
    13, 10, 14, 7,
    3, 14, 10, 9,
    12, 3, 15, 5,
    9, 5, 6, 0,
    7, 12, 8, 15,
    5, 2, 0, 14,
    10, 15, 5, 2,
    6, 8, 9, 3,
    1, 6, 2, 12
};

static int S8[64] = {
    13, 1, 7, 2,
    2, 15, 11, 1,
    8, 13, 4, 14,
    4, 8, 1, 7,
    6, 10, 9, 4,
    15, 3, 12, 10,
    11, 7, 14, 8,
    1, 4, 2, 13,
    10, 12, 0, 15,
    9, 5, 6, 12,
    3, 6, 10, 9,
    14, 11, 13, 0,
    5, 0, 15, 3,
    0, 14, 3, 5,
    12, 9, 5, 6,
    7, 2, 8, 11
};

static int E_table[48] = {
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
};

static int P_table[32] = {
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
};


static uint64_t IP(uint64_t data)
{
    uint64_t result = 0;

    for(int i = 0; i < 64; i++){
        // bit at pos (64-1-i) in the output is taken from the bit at pos (64 - IP_table[i]) in the input
        result <<= 1;
        result |= (data >> (    64 - IP_table[i]    )   ) & 1;
    }

    return result;
}



static uint64_t IP_INV(uint64_t data)
{
    uint64_t result = 0;

    for(int i = 0; i < 64; i++){
        // bit at pos (64-1-i) in the output is taken from the bit at pos (64 - IP_INV_table[i]) in the input
        result <<= 1;
        result |= (data >> (    64 - IP_INV_table[i]    )   ) & 1;
    }

    return result;
}


static uint64_t PC1(uint64_t input_key)
{
    uint64_t output_key = 0;

    for(int i = 0; i < 56; i++){
        // bit at pos (56-1-i) in the output key is taken from the bit at pos (64 - PC1_table[i]) in the input key
        output_key <<= 1;
        output_key |= (input_key >> (    64 - PC1_table[i]    )   ) & 1;
    }

    return output_key;
}


static uint64_t PC2(uint64_t input_key)
{
    uint64_t output_key = 0;

    for(int i = 0; i < 48; i++){
        // bit at pos (48-1-i) in the output key is taken from the bit at pos (56 - PC2_table[i]) in the input key
        output_key <<= 1;
        output_key |= (input_key >> (    56 - PC2_table[i]    )   ) & 1;
    }

    return output_key;
}

static uint64_t E(uint64_t input_block)
{
    uint64_t output_block = 0;

    for(int i = 0; i < 48; i++){
        // bit at pos (48-1-i) in the output block is taken from the bit at pos (32 - E_table[i]) in the input block
        output_block <<= 1;
        output_block |= (input_block >> (    32 - E_table[i]    )   ) & 1;
    }

    return output_block;
}



static uint64_t P(uint64_t input_block)
{
    uint64_t output_block = 0;

    for(int i = 0; i < 32; i++){
        // bit at pos (32-1-i) in the output block is taken from the bit at pos (32 - P_table[i]) in the input block
        output_block <<= 1;
        output_block |= (input_block >> (    32 - P_table[i]    )   ) & 1;
    }

    return output_block;
}



static uint8_t S_box(uint8_t input, uint8_t S_box_number)
{
    int column = (input & 0b011110) >> 1;               // 0 to 15
    int row = (input & 1) | ((input & 0x20) >> 4);      // 0 to 3
    int* S_boxes[8] = {S1, S2, S3, S4, S5, S6, S7, S8};
    int* S_box_ = S_boxes[S_box_number-1];

    return (uint8_t)S_box_[row + column*4];
}



static uint64_t Round(uint64_t data, uint64_t sub_key)
{
    uint64_t left_block = (data & 0xFFFFFFFF00000000) >> 32;
    uint64_t right_block = data & 0xFFFFFFFF;

    uint64_t temp_block = E(right_block);
    temp_block = temp_block ^ sub_key;

    /* at this step, temp_block is 48-bits wide (8 chunks of 6-bits) */
    uint64_t temp_temp_block = 0;
    for(int i = 0; i < 8; i++){
        uint8_t input = (   temp_block & (  (uint64_t)(0b111111) << (6*i) )    ) >> (6*i);
        temp_temp_block |= (    (uint64_t)S_box(input, 8-i) << (4*i) );
    }

    temp_block = temp_temp_block;
    temp_block = P(temp_block);
    temp_block = temp_block ^ left_block;

    left_block = right_block;
    right_block = temp_block;

    uint64_t result = (left_block << 32) | right_block;
    return result;
}


static uint64_t DES_block(uint64_t data, uint64_t key, int mode)
{
    uint64_t result;
    uint64_t initial_sub_key;

    result = IP(data);

    initial_sub_key = PC1(key);
    uint64_t left_sub_key = (initial_sub_key & 0xFFFFFFF0000000) >> 28;
    uint64_t right_sub_key = initial_sub_key & 0xFFFFFFF;

    /* generate all sub-keys */
    uint64_t sub_keys[16];
    for(int i = 1; i <= 16; i++){
        int shift;

        switch(i)
        {
            case 1:
            case 2:
            case 9:
            case 16:
            {
                shift = 1;
                break;
            }
            default:
            {
                shift = 2;
                break;
            }
        }

        /* circular (28-bits) left shift */
        left_sub_key = (    (left_sub_key << shift) | (  left_sub_key >> (28-shift)  )   ) & 0xFFFFFFF;
        right_sub_key = (    (right_sub_key << shift) | (  right_sub_key >> (28-shift)  )   ) & 0xFFFFFFF;

        uint64_t temp = ((left_sub_key << 28) | right_sub_key);
        sub_keys[i-1] = PC2(temp);
    }

    if(mode == DES_ENCRYPTION_MODE){
        for(int i = 1; i <= 16; i++){
            result = Round(result, sub_keys[i-1]);
        }
    }
    else{
        for(int i = 1; i <= 16; i++){
            /* use sub-keys in reverse-order for decryption */
            result = Round(result, sub_keys[16-i]);
        }
    }

    result = (  ((result & 0xFFFFFFFF) << 32) | (result >> 32) );

    return IP_INV(result);
}



/*
    Encryption of a file using the DES algorithm.
*/
int DES_encryption(const char* const plain_file_name, uint64_t key, const char* const encrypted_file_name)
{
    FILE *plain_file = fopen(plain_file_name, "rb");
    FILE *encrypted_file = fopen(encrypted_file_name, "wb");
    int filesize = get_filesize(plain_file_name);

    if(  (plain_file == NULL) || (encrypted_file == NULL) || (filesize == -1)  ){
        printf("DES Error: cannot open files.\n");
        return EXIT_FAILURE;
    }


    /* DES operates on 64-bits (8-bytes) wide blocks */
    int remainder = filesize % 8;      // number of bytes to pad (if necessary)
    int q = filesize / 8;           // number of 64-bits blocks

    uint64_t data;

    /* Process all blocks except the last one (special case) */
    for(int i = 0; i < q; i++){
        fread(&data, sizeof(uint64_t), 1, plain_file);
        data = switch_endianness_64(data);
        data = DES_block(data, key, DES_ENCRYPTION_MODE);
        data = switch_endianness_64(data);
        fwrite(&data, sizeof(uint64_t), 1, encrypted_file);
    }

    /* Last block: Padding */
    data = 0;
    fread(&data, sizeof(uint8_t), remainder, plain_file);
    data = switch_endianness_64(data);
    data |= (8-remainder  );                  // padded last block with (8 - remainder - 1) null bytes + 1 byte for the length

    data = DES_block(data, key, DES_ENCRYPTION_MODE);
    data = switch_endianness_64(data);
    fwrite(&data, sizeof(uint64_t), 1, encrypted_file);


    fclose(plain_file);
    fclose(encrypted_file);

    return EXIT_SUCCESS;
}





/*
    Decryption of a file using the DES algorithm.
*/
int DES_decryption(const char* const encrypted_file_name, uint64_t key, const char* const decrypted_file_name)
{
    FILE *encrypted_file = fopen(encrypted_file_name, "rb");
    FILE *decrypted_file = fopen(decrypted_file_name, "wb");
    int filesize = get_filesize(encrypted_file_name);

    if(  (encrypted_file == NULL) || (decrypted_file == NULL) || (filesize == -1)  ){
        printf("DES Error: cannot open files.\n");
        return EXIT_FAILURE;
    }

    /* DES operates on 64-bits (8-bytes) wide blocks */
    int q = filesize / 8;           // number of 64-bits blocks (no remainder because a DES encrypted file is necessary padded to a multiple of 64-bits)

    uint64_t data;

    /* Process all blocks except the last one (special case) */
    for(int i = 0; i < q-1; i++){
        fread(&data, sizeof(uint64_t), 1, encrypted_file);
        data = switch_endianness_64(data);
        data = DES_block(data, key, DES_DECRYPTION_MODE);
        data = switch_endianness_64(data);
        fwrite(&data, sizeof(uint64_t), 1, decrypted_file);
    }

    /* Last block: Padded block */
    fread(&data, sizeof(uint64_t), 1, encrypted_file);
    data = switch_endianness_64(data);
    data = DES_block(data, key, DES_DECRYPTION_MODE);

    int padded_bytes_count = data & 0xFF;
    data = switch_endianness_64(data);
    fwrite(&data, sizeof(uint8_t), 8-padded_bytes_count, decrypted_file);


    fclose(encrypted_file);
    fclose(decrypted_file);

    return EXIT_SUCCESS;
}






void DES_test(void)
{
    DES_encryption("plain_data_test.txt", 0x1654987456258526, "DES_encrypted_data_test.txt");
    DES_decryption("DES_encrypted_data_test.txt", 0x1654987456258526, "DES_decrypted_data_test.txt");
}