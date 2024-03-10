/* 
    Implementation of the AES module in ECB mode with ANSI X9.23 Padding.
*/
#include "AES.h"


static int Forward_S_Box[16*16] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static int rcon_table[16*16] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
};


static int Inv_S_Box[16*16] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};


static uint8_t S_box_8(uint8_t data, int *sbox)
{
    int row = (data & 0xF0) >> 4;
    int column = data & 0xF;
    
    return (uint8_t)sbox[column + 16*row];
}

static uint32_t S_box_32(uint32_t data, int *sbox)
{
    uint32_t result = 0;
    uint8_t b;

    for(int i = 0; i < 4; i++){
        b = (uint8_t)data;
        data = data >> 8;
        
        result |= (uint32_t)S_box_8(b, sbox) << (8*i);
    }

    return result;
}


static void S_box(AES_Block_Struct *block, int *sbox)
{
    block->w0 = S_box_32(block->w0, sbox);
    block->w1 = S_box_32(block->w1, sbox);
    block->w2 = S_box_32(block->w2, sbox);
    block->w3 = S_box_32(block->w3, sbox);
}


static void read_block(FILE *file, AES_Block_Struct *block)
{
    fread(&block->w0, sizeof(uint32_t), 1, file);
    fread(&block->w1, sizeof(uint32_t), 1, file);
    fread(&block->w2, sizeof(uint32_t), 1, file);
    fread(&block->w3, sizeof(uint32_t), 1, file);

    block->w0 = switch_endianness_32(block->w0);
    block->w1 = switch_endianness_32(block->w1);
    block->w2 = switch_endianness_32(block->w2);
    block->w3 = switch_endianness_32(block->w3);
}


static void write_block(FILE *file, AES_Block_Struct *block)
{
    uint32_t data;

    data = switch_endianness_32(block->w0);
    fwrite(&data, sizeof(uint32_t), 1, file);

    data = switch_endianness_32(block->w1);
    fwrite(&data, sizeof(uint32_t), 1, file);

    data = switch_endianness_32(block->w2);
    fwrite(&data, sizeof(uint32_t), 1, file);

    data = switch_endianness_32(block->w3);
    fwrite(&data, sizeof(uint32_t), 1, file);
}



static void generate_subkey(AES_Block_Struct *input_subkey, AES_Block_Struct *output_subkey, int rcon_index)
{
    output_subkey->w0 = left_circular_shift_32(input_subkey->w3, 8);
    output_subkey->w0 = S_box_32(output_subkey->w0, Forward_S_Box);
    output_subkey->w0 ^= input_subkey->w0;
    output_subkey->w0 ^= ((uint32_t)rcon_table[rcon_index] << 24);

    output_subkey->w1 = output_subkey->w0 ^ input_subkey->w1;
    output_subkey->w2 = output_subkey->w1 ^ input_subkey->w2;
    output_subkey->w3 = output_subkey->w2 ^ input_subkey->w3;
}


static void SubBytes(AES_Block_Struct *block)
{
    S_box(block, Forward_S_Box);
}

static void InvSubBytes(AES_Block_Struct *block)
{
    S_box(block, Inv_S_Box);
}

static void ShiftRows(AES_Block_Struct *block)
{
    uint8_t b[16];
    b[0] = (block->w0 & 0xFF000000) >> 24;
    b[13] = (block->w0 & 0x00FF0000) >> 16;
    b[10] = (block->w0 & 0x0000FF00) >> 8;
    b[7] = (block->w0 & 0x000000FF) >> 0;
    b[4] = (block->w1 & 0xFF000000) >> 24;
    b[1] = (block->w1 & 0x00FF0000) >> 16;
    b[14] = (block->w1 & 0x0000FF00) >> 8;
    b[11] = (block->w1 & 0x000000FF) >> 0;
    b[8] = (block->w2 & 0xFF000000) >> 24;
    b[5] = (block->w2 & 0x00FF0000) >> 16;
    b[2] = (block->w2 & 0x0000FF00) >> 8;
    b[15] = (block->w2 & 0x000000FF) >> 0;
    b[12] = (block->w3 & 0xFF000000) >> 24;
    b[9] = (block->w3 & 0x00FF0000) >> 16;
    b[6] = (block->w3 & 0x0000FF00) >> 8;
    b[3] = (block->w3 & 0x000000FF) >> 0;

    block->w0 = switch_endianness_32(*(uint32_t*)&b[0]);
    block->w1 = switch_endianness_32(*(uint32_t*)&b[4]);
    block->w2 = switch_endianness_32(*(uint32_t*)&b[8]);
    block->w3 = switch_endianness_32(*(uint32_t*)&b[12]);
}

static void InvShiftRows(AES_Block_Struct *block)
{
    uint8_t b[16];
    b[0] = (block->w0 & 0xFF000000) >> 24;
    b[5] = (block->w0 & 0x00FF0000) >> 16;
    b[10] = (block->w0 & 0x0000FF00) >> 8;
    b[15] = (block->w0 & 0x000000FF) >> 0;
    b[4] = (block->w1 & 0xFF000000) >> 24;
    b[9] = (block->w1 & 0x00FF0000) >> 16;
    b[14] = (block->w1 & 0x0000FF00) >> 8;
    b[3] = (block->w1 & 0x000000FF) >> 0;
    b[8] = (block->w2 & 0xFF000000) >> 24;
    b[13] = (block->w2 & 0x00FF0000) >> 16;
    b[2] = (block->w2 & 0x0000FF00) >> 8;
    b[7] = (block->w2 & 0x000000FF) >> 0;
    b[12] = (block->w3 & 0xFF000000) >> 24;
    b[1] = (block->w3 & 0x00FF0000) >> 16;
    b[6] = (block->w3 & 0x0000FF00) >> 8;
    b[11] = (block->w3 & 0x000000FF) >> 0;

    block->w0 = switch_endianness_32(*(uint32_t*)&b[0]);
    block->w1 = switch_endianness_32(*(uint32_t*)&b[4]);
    block->w2 = switch_endianness_32(*(uint32_t*)&b[8]);
    block->w3 = switch_endianness_32(*(uint32_t*)&b[12]);
}

static inline uint8_t GF_2_8_multiply_by_two(uint8_t x)
{
    return (    (x << 1) ^ ((x & 0x80) ? 0x1b : 0x00)   );
}

static uint32_t MixSingleColumn(uint32_t column)
{
    uint8_t x, y, z, t;
    uint8_t power_x[3];
    uint8_t power_y[3];
    uint8_t power_z[3];
    uint8_t power_t[3];
    uint8_t new_column[4];


    x = (column & 0xFF000000) >> 24;
    y = (column & 0x00FF0000) >> 16;
    z = (column & 0x0000FF00) >> 8;
    t = (column & 0x000000FF) >> 0;


    /* multiplication in GF(2^8) */
    power_x[0] = x;       // 1.x
    power_x[1] = GF_2_8_multiply_by_two(x);     // 2.x
    power_x[2] = power_x[1] ^ power_x[0];         // 3.x

    power_y[0] = y;       // 1.y
    power_y[1] = GF_2_8_multiply_by_two(y);     // 2.y
    power_y[2] = power_y[1] ^ power_y[0];         // 3.y

    power_z[0] = z;       // 1.z
    power_z[1] = GF_2_8_multiply_by_two(z);     // 2.z
    power_z[2] = power_z[1] ^ power_z[0];         // 3.z

    power_t[0] = t;       // 1.t
    power_t[1] = GF_2_8_multiply_by_two(t);     // 2.t
    power_t[2] = power_t[1] ^ power_t[0];         // 3.t



    /* Addition in GF(2^8) */
    new_column[0] = power_x[1] ^ power_y[2] ^ power_z[0] ^ power_t[0];
    new_column[1] = power_x[0] ^ power_y[1] ^ power_z[2] ^ power_t[0];
    new_column[2] = power_x[0] ^ power_y[0] ^ power_z[1] ^ power_t[2];
    new_column[3] = power_x[2] ^ power_y[0] ^ power_z[0] ^ power_t[1];

    uint32_t result = switch_endianness_32(*(uint32_t*)&new_column);
    return result;
}

static inline uint8_t GF_2_8_multiply_by_0x9(uint8_t x)
{
    uint8_t temp = GF_2_8_multiply_by_two(x);
    temp = GF_2_8_multiply_by_two(temp);
    temp = GF_2_8_multiply_by_two(temp);

    return (x ^ temp);
}

static inline uint8_t GF_2_8_multiply_by_0xb(uint8_t x)
{
    uint8_t temp = GF_2_8_multiply_by_two(x);
    temp = GF_2_8_multiply_by_two(temp);
    temp ^= x;
    temp = GF_2_8_multiply_by_two(temp);

    return (x ^ temp);
}

static inline uint8_t GF_2_8_multiply_by_0xd(uint8_t x)
{
    uint8_t temp = GF_2_8_multiply_by_two(x);
    temp ^= x;
    temp = GF_2_8_multiply_by_two(temp);
    temp = GF_2_8_multiply_by_two(temp);

    return (x ^ temp);
}

static inline uint8_t GF_2_8_multiply_by_0xe(uint8_t x)
{
    uint8_t temp = GF_2_8_multiply_by_two(x);
    temp ^= x;
    temp = GF_2_8_multiply_by_two(temp);
    temp ^= x;
    temp = GF_2_8_multiply_by_two(temp);

    return temp;
}

static uint32_t InvMixSingleColumn(uint32_t column)
{
    uint8_t x, y, z, t;
    uint8_t power_x[4];
    uint8_t power_y[4];
    uint8_t power_z[4];
    uint8_t power_t[4];
    uint8_t new_column[4];


    x = (column & 0xFF000000) >> 24;
    y = (column & 0x00FF0000) >> 16;
    z = (column & 0x0000FF00) >> 8;
    t = (column & 0x000000FF) >> 0;


    /* multiplication in GF(2^8) */
    power_x[0] = GF_2_8_multiply_by_0x9(x);       // 9.x
    power_x[1] = GF_2_8_multiply_by_0xb(x);     // 0xb.x
    power_x[2] = GF_2_8_multiply_by_0xd(x);         // 0xd.x
    power_x[3] = GF_2_8_multiply_by_0xe(x);         // 0xe.x

    power_y[0] = GF_2_8_multiply_by_0x9(y);       // 9.y
    power_y[1] = GF_2_8_multiply_by_0xb(y);     // 0xb.y
    power_y[2] = GF_2_8_multiply_by_0xd(y);         // 0xd.y
    power_y[3] = GF_2_8_multiply_by_0xe(y);         // 0xe.y

    power_z[0] = GF_2_8_multiply_by_0x9(z);       // 9.z
    power_z[1] = GF_2_8_multiply_by_0xb(z);     // 0xb.z
    power_z[2] = GF_2_8_multiply_by_0xd(z);         // 0xd.z
    power_z[3] = GF_2_8_multiply_by_0xe(z);         // 0xe.z

    power_t[0] = GF_2_8_multiply_by_0x9(t);       // 9.t
    power_t[1] = GF_2_8_multiply_by_0xb(t);     // 0xb.t
    power_t[2] = GF_2_8_multiply_by_0xd(t);         // 0xd.t
    power_t[3] = GF_2_8_multiply_by_0xe(t);         // 0xe.t



    /* Addition in GF(2^8) */
    new_column[0] = power_x[3] ^ power_y[1] ^ power_z[2] ^ power_t[0];
    new_column[1] = power_x[0] ^ power_y[3] ^ power_z[1] ^ power_t[2];
    new_column[2] = power_x[2] ^ power_y[0] ^ power_z[3] ^ power_t[1];
    new_column[3] = power_x[1] ^ power_y[2] ^ power_z[0] ^ power_t[3];

    uint32_t result = switch_endianness_32(*(uint32_t*)&new_column);
    return result;
}


static void MixColumns(AES_Block_Struct *block)
{
    block->w0 = MixSingleColumn(block->w0);
    block->w1 = MixSingleColumn(block->w1);
    block->w2 = MixSingleColumn(block->w2);
    block->w3 = MixSingleColumn(block->w3);
}


static void InvMixColumns(AES_Block_Struct *block)
{
    block->w0 = InvMixSingleColumn(block->w0);
    block->w1 = InvMixSingleColumn(block->w1);
    block->w2 = InvMixSingleColumn(block->w2);
    block->w3 = InvMixSingleColumn(block->w3);
}

static void Round(AES_Block_Struct *block, AES_Block_Struct *sub_key, int useMixColumns)
{
    SubBytes(block);
    ShiftRows(block);

    if(useMixColumns == AES_ROUND_USE_MIXCOLUMNS)
        MixColumns(block);

    block->w0 ^= sub_key->w0;
    block->w1 ^= sub_key->w1;
    block->w2 ^= sub_key->w2;
    block->w3 ^= sub_key->w3;
}


static void InvRound(AES_Block_Struct *block, AES_Block_Struct *sub_key, int useMixColumns)
{
    InvShiftRows(block);
    InvSubBytes(block);

    block->w0 ^= sub_key->w0;
    block->w1 ^= sub_key->w1;
    block->w2 ^= sub_key->w2;
    block->w3 ^= sub_key->w3;

    if(useMixColumns == AES_ROUND_USE_MIXCOLUMNS)
        InvMixColumns(block);
}

static void EncryptBlock(AES_Block_Struct *block, AES_Block_Struct *private_key, AES_Block_Struct *sub_keys)
{
    /* initial round key addition */
    block->w0 ^= private_key->w0;
    block->w1 ^= private_key->w1;
    block->w2 ^= private_key->w2;
    block->w3 ^= private_key->w3;

    /* rounds */
    for(int i = 0; i < 9; i++){
        Round(block, &(sub_keys[i]), AES_ROUND_USE_MIXCOLUMNS);
    }
    Round(block, &(sub_keys[9]), AES_ROUND_NO_MIXCOLUMNS);
}


static void DecryptBlock(AES_Block_Struct *block, AES_Block_Struct *private_key, AES_Block_Struct *sub_keys)
{
    /* initial round key addition */
    block->w0 ^= sub_keys[9].w0;
    block->w1 ^= sub_keys[9].w1;
    block->w2 ^= sub_keys[9].w2;
    block->w3 ^= sub_keys[9].w3;

    /* rounds */
    for(int i = 0; i < 9; i++){
        InvRound(block, &(sub_keys[9-1-i]), AES_ROUND_USE_MIXCOLUMNS);
    }
    InvRound(block, private_key, AES_ROUND_NO_MIXCOLUMNS);
}



int AES128_encryption(const char* const plain_file_name, uint64_t key_msb, uint64_t key_lsb, const char* const encrypted_file_name)
{
    FILE *plain_file = fopen(plain_file_name, "rb");
    FILE *encrypted_file = fopen(encrypted_file_name, "wb");
    int filesize = get_filesize(plain_file_name);

    if(  (plain_file == NULL) || (encrypted_file == NULL) || (filesize == -1)  ){
        printf("AES Error: cannot open files.\n");
        return EXIT_FAILURE;
    }

    /*
        Format the private key in a matrix form.
    */
    AES_Block_Struct private_key;
    private_key.w0 = (uint32_t)(key_msb >> 32);
    private_key.w1 = (uint32_t)(key_msb);
    private_key.w2 = (uint32_t)(key_lsb >> 32);
    private_key.w3 = (uint32_t)(key_lsb);

    /*
        Generate all sub-keys
    */
    AES_Block_Struct sub_keys[10];
    generate_subkey(&private_key, &sub_keys[0], 1);
    for(int i = 1; i < 10; i++){
        generate_subkey(&sub_keys[i-1], &sub_keys[i], i+1);
    }

    
    /* Process blocks */

    /* AES operates on 128-bits (16-bytes) wide blocks */
    int remainder = filesize % 16;      // number of bytes to pad (if necessary)
    int q = filesize / 16;                // number of 128-bits blocks

    AES_Block_Struct block;


    for(int i = 0; i < q; i++){
        read_block(plain_file, &block);
        EncryptBlock(&block, &private_key, sub_keys);
        write_block(encrypted_file, &block);
    }

    /* Last block: padding */
    uint8_t data_buffer[16] = {0};
    fread(data_buffer, sizeof(uint8_t), remainder, plain_file);

    block.w0 = switch_endianness_32(*(uint32_t*)&data_buffer[0]);
    block.w1 = switch_endianness_32(*(uint32_t*)&data_buffer[4]);
    block.w2 = switch_endianness_32(*(uint32_t*)&data_buffer[8]);
    block.w3 = switch_endianness_32(*(uint32_t*)&data_buffer[12]);

    block.w3 |= (16-remainder );        // padding last block with (16-remainder-1) null bytes + 1 byte for the length

    EncryptBlock(&block, &private_key, sub_keys);
    write_block(encrypted_file, &block);


    fclose(plain_file);
    fclose(encrypted_file);

    return EXIT_SUCCESS;
}





int AES128_decryption(const char* const encrypted_file_name, uint64_t key_msb, uint64_t key_lsb, const char* const decrypted_file_name)
{
    FILE *encrypted_file = fopen(encrypted_file_name, "rb");
    FILE *decrypted_file = fopen(decrypted_file_name, "wb");
    int filesize = get_filesize(encrypted_file_name);

    if(  (encrypted_file == NULL) || (decrypted_file == NULL) || (filesize == -1) || ((filesize % 16) > 0)  ){
        printf("AES Error: cannot open files.\n");
        return EXIT_FAILURE;
    }

    /*
        Format the private key in a matrix form.
    */
    AES_Block_Struct private_key;
    private_key.w0 = (uint32_t)(key_msb >> 32);
    private_key.w1 = (uint32_t)(key_msb);
    private_key.w2 = (uint32_t)(key_lsb >> 32);
    private_key.w3 = (uint32_t)(key_lsb);

    /*
        Generate all sub-keys
    */
    AES_Block_Struct sub_keys[10];
    generate_subkey(&private_key, &sub_keys[0], 1);
    for(int i = 1; i < 10; i++){
        generate_subkey(&sub_keys[i-1], &sub_keys[i], i+1);
    }

    /* Process blocks */

    /* AES operates on 128-bits (16-bytes) wide blocks */
    int q = filesize / 16;           // number of 128-bits blocks

    AES_Block_Struct block;


    for(int i = 0; i < q-1; i++){
        read_block(encrypted_file, &block);
        DecryptBlock(&block, &private_key, sub_keys);
        write_block(decrypted_file, &block);
    }

    /* Last block: padding */
    read_block(encrypted_file, &block);
    DecryptBlock(&block, &private_key, sub_keys);

    int data_bytes_count = 16 - (block.w3 & 0xFF);
    uint8_t temp_buffer[16];
    *(uint32_t*)&temp_buffer[0] = switch_endianness_32(block.w0);
    *(uint32_t*)&temp_buffer[4] = switch_endianness_32(block.w1);
    *(uint32_t*)&temp_buffer[8] = switch_endianness_32(block.w2);
    *(uint32_t*)&temp_buffer[12] = switch_endianness_32(block.w3);

    fwrite(temp_buffer, sizeof(uint8_t), data_bytes_count, decrypted_file);


    fclose(encrypted_file);
    fclose(decrypted_file);

    return EXIT_SUCCESS;
}





void AES_test(void)
{
   AES128_encryption("plain_data_test.txt", 0x1457896585214589, 0x4578962585412596, "AES_encrypted_data_test.txt");
   AES128_decryption("AES_encrypted_data_test.txt", 0x1457896585214589, 0x4578962585412596, "AES_decrypted_data_test.txt");
}