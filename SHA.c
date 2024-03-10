/*
    SHA hashing algorithm implementations.
*/
#include "SHA.h"



static uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


/*
    M = 512-bits wide block (array of 64 uint8_t elements)
    hash = 256-bits hash (array of 8 uint32_t elements)

    - sha256_hash.h0 is the most significant word
    - in the SHA algorithm, all values are processed in big-endian format
*/
static void SHA256_Process_Block(uint8_t* M, SHA256_HASH_STRUCT *sha256_hash)
{
    uint32_t W[64];

    for(int i = 0; i < 64; i += 1){
        if(i <= 15){
            /* the value is expressed in big-endian format */
            W[i] = switch_endianness_32(*(uint32_t*)&M[4*i]);
        }
        else{
            W[i] = SHA256_sigma1(W[i-2]) + W[i-7] + SHA256_sigma0(W[i-15]) + W[i-16];
        }
    }

    uint32_t a, b, c, d, e, f, g, h;
    a = sha256_hash->h0;
    b = sha256_hash->h1;
    c = sha256_hash->h2;
    d = sha256_hash->h3;
    e = sha256_hash->h4;
    f = sha256_hash->h5;
    g = sha256_hash->h6;
    h = sha256_hash->h7;

    for(int i = 0; i < 64; i++){
        uint32_t T1 = h + SHA256_SIGMA1(e) + SHA256_Ch(e,f,g) + K[i] + W[i];
        uint32_t T2 = SHA256_SIGMA0(a) + SHA256_Maj(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    sha256_hash->h0 += a;
    sha256_hash->h1 += b;
    sha256_hash->h2 += c;
    sha256_hash->h3 += d;
    sha256_hash->h4 += e;
    sha256_hash->h5 += f;
    sha256_hash->h6 += g;
    sha256_hash->h7 += h;
}







/*
    Compute the SHA256 hash of a given file.

    sha256_hash.h0 is the most significant word
    all values are processed in big-endian format

    Return the error status (EXIT_FAILURE or EXIT_SUCCESS)
*/
int SHA256_hash(const char* const filename, SHA256_HASH_STRUCT *sha256_hash)
{
    FILE *file = fopen(filename, "rb");
    int filesize = get_filesize(filename);

    if( (file == NULL) || (filesize == -1) ){
        printf("SHA256 Error: cannot open file.\n");
        return EXIT_FAILURE;
    }



    /* SHA256 operates on 512-bits (64 * 8-bits) wide blocks
    *  Filesize (bits) = 512*q + r
    *  q = number of 512-bits (64 bytes) wide blocks; r = remainder (bytes)
    */
    int r = filesize % (512/8);
    int q = filesize / (512/8);


    /* hash initialization */
    sha256_hash->h0 = 0x6a09e667;
    sha256_hash->h1 = 0xbb67ae85;
    sha256_hash->h2 = 0x3c6ef372;
    sha256_hash->h3 = 0xa54ff53a;
    sha256_hash->h4 = 0x510e527f;
    sha256_hash->h5 = 0x9b05688c;
    sha256_hash->h6 = 0x1f83d9ab;
    sha256_hash->h7 = 0x5be0cd19;


    uint8_t block[64];     // 512-bits block

    /* process each 512-bits block */
    for(int i = 0; i < q; i++){
        fread(&block, sizeof(uint8_t), 64, file);
        SHA256_Process_Block(block, sha256_hash);
    }

    /* process last block (+ padding) */
    uint8_t last_block[64];     // 512-bits last block
    fread(&last_block, sizeof(uint8_t), r, file);           // r <= 63
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
        SHA256_Process_Block(last_block, sha256_hash);

        /* add a second "last block" */
        for(int i = 0; i < 64-8; i++){
            last_block[i] = 0;          // 0-padding
        }
    }

    /* append file length, in 64-bits big-endian format */
    *(uint64_t*)&last_block[64-8] = switch_endianness_64((uint64_t)filesize * 8);

    SHA256_Process_Block(last_block, sha256_hash);            // process the very last block


    fclose(file);

    return EXIT_SUCCESS;
}


/*
    Print a SHA-256 hash.
*/
static void print_x(uint32_t number)
{
    for(int i = 3; i >= 0; i--){
        printf("%02hhx ", (  number >> 8*i  ) & 0xff);
    }
}
void SHA256_Print_Hash(SHA256_HASH_STRUCT *sha256_hash)
{
    printf("0x ");
    print_x(sha256_hash->h0);
    print_x(sha256_hash->h1);
    print_x(sha256_hash->h2);
    print_x(sha256_hash->h3);
    print_x(sha256_hash->h4);
    print_x(sha256_hash->h5);
    print_x(sha256_hash->h6);
    print_x(sha256_hash->h7);
    printf("\n");
}



void SHA256_test(void)
{
    SHA256_HASH_STRUCT sha256_hash;
    SHA256_hash("plain_data_test.txt", &sha256_hash);

    printf("SHA256 hash: ");
    SHA256_Print_Hash(&sha256_hash);
}