/*
    MD5 Hashing Algorithm implementation.
*/
#include "MD5.h"


static uint8_t shift[64] = {
    7, 12, 17, 22, 7, 12, 17, 22,
    7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20,
    5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23,
    4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21,
    6, 10, 15, 21, 6, 10, 15, 21
};


static uint32_t K[64] = 
{
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};



/*
    block = 512-bits data block (64 * 8-bits words)
    hash = 128-bits data (4 * 32-bits words)

    - md5_hash.h0 is the most significant word
    - all values are expressed in little-endian format
*/
static void MD5_Process_Block(uint8_t *block, MD5_HASH_STRUCT *md5_hash)
{
    uint32_t a = md5_hash->h0;
    uint32_t b = md5_hash->h1;
    uint32_t c = md5_hash->h2;
    uint32_t d = md5_hash->h3;

    uint32_t f;
    uint8_t g;

    for(int i = 0; i < 64; i++)
    {
        if(i <= 15){
            f = (   (b & c) | ((~b) & d)    );
            g = i;
        }
        else if(i <= 31){
            f = (   (b & d) | ((~d) & c)    );
            g = (5*i + 1) % 16;
        }
        else if(i <= 47){
            f = (b ^ c ^ d);
            g = (3*i + 5) % 16;
        }
        else{
            f = (   c ^ (b | (~d))  );
            g = (7*i) % 16;
        }


        f = f + a + K[i] + *(uint32_t*)&block[4*g];
        a = d;
        d = c;
        c = b;
        b += left_circular_shift_32(f, shift[i]);
    }

    md5_hash->h0 += a;
    md5_hash->h1 += b;
    md5_hash->h2 += c;
    md5_hash->h3 += d;
}


/*
    Compute the MD5 hash of a given file.

    - md5_hash.h0 is the most significant word.
*/
int MD5_hash(const char* const filename, MD5_HASH_STRUCT *md5_hash)
{
    FILE *file = fopen(filename, "rb");
    int filesize = get_filesize(filename);      // filesize (in bytes)

    if((file == NULL) || (filesize == -1)){
        printf("MD5 Error: cannot open file.\n");
        return EXIT_FAILURE;
    }


    /* MD5 operates on 512-bits (64 * 8-bits) wide blocks
    *  Filesize (bits) = 512*q + r
    *  q = number of 512-bits (64 bytes) wide blocks; r = remainder (bytes)
    */
    int r = filesize % (512/8);
    int q = filesize / (512/8);


    /* hash initialization */
    md5_hash->h0 = 0x67452301;
    md5_hash->h1 = 0xEFCDAB89;
    md5_hash->h2 = 0x98BADCFE;
    md5_hash->h3 = 0x10325476;


    uint8_t block[64];     // 512-bits block

    /* process each 512-bits block */
    for(int i = 0; i < q; i++){
        fread(&block, sizeof(uint8_t), 64, file);
        MD5_Process_Block(block, md5_hash);
    }

    /* process last block (+ padding) */
    uint8_t last_block[64];     // 512-bits last block
    fread(&last_block, sizeof(uint8_t), r, file);
    last_block[r] = 0x80;           // append a "1" bit

    if((r+1) <= 64-8)           // enough space to put the file length (64-bits = 8 bytes)
    {
        for(int i = r+1; i < 64-8; i++){
            last_block[i] = 0;      // 0-padding
        }
    }
    else        // not enough space, we need a second block
    {
        for(int i = r+1; i < 64; i++){
            last_block[i] = 0;          // 0-padding
        }
        MD5_Process_Block(last_block, md5_hash);

        /* add a second "last block" */
        for(int i = 0; i < 64-8; i++){
            last_block[i] = 0;          // 0-padding
        }
    }

    /* file length */
    *(uint64_t*)&last_block[64-8] = (uint64_t)filesize * 8;
    MD5_Process_Block(last_block, md5_hash);            // process the very last block

    fclose(file);

    return EXIT_SUCCESS;
}


/*
    Print a MD5 hash.
*/
static void print_x(uint32_t number)
{
    for(int i = 0; i < 4; i++){
        printf("%02hhx ", (  number >> 8*i  ) & 0xff);
    }
}
void MD5_Print_Hash(MD5_HASH_STRUCT *md5_hash)
{
    printf("0x ");
    print_x(md5_hash->h0);
    print_x(md5_hash->h1);
    print_x(md5_hash->h2);
    print_x(md5_hash->h3);
    printf("\n");
}





void MD5_test(void)
{
    MD5_HASH_STRUCT md5_hash;
    MD5_hash("plain_data_test.txt", &md5_hash);

    printf("MD5 hash = ");
    MD5_Print_Hash(&md5_hash);
}