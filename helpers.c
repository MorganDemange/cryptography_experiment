/*
    Helpers functions
*/
#include "helpers.h"


/*
    Generate a random uint32_t array using a linear-feedback shift register pseudo random number generator.

    Parameters:
        - arr : pointer to the array
        - size: number of elements
*/
void random_array(uint32_t *arr, unsigned int size)
{
    for(int i = 0; i < size; i++){
        arr[i] = PRNG_LFSR_Fibonacci();
    }
}


/*
    Get the size in bytes of a given file.

    Parameter: the filename
    Return   : the filesize, in bytes (or -1 in case of error)
*/
int get_filesize(const char* const filename)
{
    FILE *file = fopen(filename, "rb");
    if(file == NULL){
        return -1;
    }

    fseek(file, 0, SEEK_END);           // move the cursor to the end of the file
    int size = ftell(file);             // get the filesize (in bytes)
    fclose(file);

    return size;
}


/*
    Swap two byte elements.

    Parameters:
        - x,y : pointer to the elements to swap
*/
void swap_bytes(uint8_t *x, uint8_t *y)
{
    uint8_t temp = *x;
    *x = *y;
    *y = temp;
}




/*
    Perform a left-circular shift on a 32-bits number.
*/
uint32_t left_circular_shift_32(uint32_t number, int shift)
{
    return ((number << shift) | (number >> (32 - shift)));
}


/*
    Change the endianness of a uint32_t number.
*/
uint32_t switch_endianness_32(uint32_t number)
{
    return (number >> 24) | ((number & 0x00FF0000) >> 8) | ((number & 0x0000FF00) << 8) | ((number & 0x000000FF) << 24);
}


/*
    Change the endianness of a uint64_t number.
*/
uint64_t switch_endianness_64(uint64_t number)
{
    uint64_t res = 0;
    for(int i = 0; i < 8; i++){
        res |= ((number >> (7-i) * 8) & 0xFF) << (i * 8);
    }
    return res;
}




/*
    Return the maximum number of characters required to represent a mpz_t variable as a string.

    Return 0 in case of error (wrong format parameter).
*/
size_t get_char_len_mpz_t(const mpz_t number, PRINT_FORMAT_T format)
{
    size_t prefix_len;
    if(format == PRINT_FORMAT_DEC){
        prefix_len = 0;
    }
    else{
        prefix_len = 2;     // "0x" or "0b"
    }

    return ((mpz_sizeinbase(number, format) + 2) + prefix_len);     // +2 for sign character and null terminator character
}


/*
    Get the string representation of a mpz_t variable.
*/
char* get_str_mpz_t(const mpz_t number, size_t *str_len, PRINT_FORMAT_T format)
{
    size_t len = get_char_len_mpz_t(number, format);
    char *str = (char*)malloc(len * sizeof(char));

    switch(format)
    {
        case PRINT_FORMAT_HEX: str[0] = '0'; str[1] = 'x'; mpz_get_str(str+2, format, number); break;
        case PRINT_FORMAT_DEC: mpz_get_str(str, format, number); break;
        case PRINT_FORMAT_BIN: str[0] = '0'; str[1] = 'b'; mpz_get_str(str+2, format, number); break;
        default: NULL;            // cannot occur
    }

    if(str_len != NULL){
        *str_len = strlen(str);     // get the actual string length, ignoring the null terminator character
    }

    return str;
}


/*
    Print a mpz_t variable.
*/
void print_mpz_t(const mpz_t number, const char* const var_name, PRINT_FORMAT_T format)
{
    char *str = get_str_mpz_t(number, NULL, format);
    printf("%s = %s\n", var_name, str);
    free(str);
}


/*
    Generate a random mpz_t number between 0 (including) and max_limit (excluding).

    Output: 0 <= rand_number < max_limit.
*/
void random_mpz_t(mpz_t *rand_number, const mpz_t max_limit)
{
    /* generate a random seed for the random generator */
    unsigned int n = (PRNG_LCG() % 10) + 1;     // limit n to 1..10 for speed
    uint32_t *seed_arr = (uint32_t*)malloc(n * sizeof(uint32_t));
    random_array(seed_arr, n);

    mpz_t seed;
    mpz_init(seed);
    mpz_import(seed, n, -1, sizeof(uint32_t), 0, 0, seed_arr);
    free(seed_arr);

    /* initialize the random generator */
    gmp_randstate_t randstate;
    gmp_randinit_default(randstate);
    gmp_randseed(randstate, seed);
    mpz_clear(seed);

    /* generate a random number x (2 <= x < n) */
    mpz_urandomm(*rand_number, randstate, max_limit);
    gmp_randclear(randstate);
}

