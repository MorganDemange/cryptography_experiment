#ifndef PRNGS_H_
#define PRNGS_H_

#include <stdint.h>


#define PRNG_MIDDLESQUARE_SEED          0xA6C7112E


#define PRNG_LCG_SEED                   0xCC8DA544
#define PRNG_LCG_A                      1103515245          // LCG multiplier a
#define PRNG_LCG_C                      12345               // LCG increment c
#define PRNG_LCG_M                      2147483648          // LCG modulus m


#define PRNG_LFG_J                      24
#define PRNG_LFG_K                      55
#define PRNG_LFG_M                      2147483648


#define PRNG_LFSR_FIBONACCI_SEED        0xEE5F98DA
/* 
    degrees of the non-null coefficients of the polynomial (all coefficients are either 1 or 0), not including the one of degree 0 which is always 1
    e.g: {8, 6, 5, 4} represents x^8+x^6+x^5+x^4+1
*/
#define PRNG_LFSR_FIBONACCI_POLY        {8, 6, 5, 4}



/*
    Mersenne Twister parameters (MT19937 implementation)
*/
#define PRNG_MERSENNE_TWISTER_SEED              0xF8DA24E4
#define PRNG_MERSENNE_TWISTER_W                 32
#define PRNG_MERSENNE_TWISTER_N                 624
#define PRNG_MERSENNE_TWISTER_M                 397
#define PRNG_MERSENNE_TWISTER_R                 31
#define PRNG_MERSENNE_TWISTER_A                 0x9908B0DF
#define PRNG_MERSENNE_TWISTER_U                 11
#define PRNG_MERSENNE_TWISTER_D                 0xFFFFFFFF
#define PRNG_MERSENNE_TWISTER_S                 7
#define PRNG_MERSENNE_TWISTER_B                 0x9D2C5680
#define PRNG_MERSENNE_TWISTER_T                 15
#define PRNG_MERSENNE_TWISTER_C                 0xEFC60000
#define PRNG_MERSENNE_TWISTER_L                 18
#define PRNG_MERSENNE_TWISTER_F                 1812433253
#define PRNG_MERSENNE_TWISTER_LOWER_MASK        (((uint32_t)1 << PRNG_MERSENNE_TWISTER_R) - 1)                                                               // lower r bits
#define PRNG_MERSENNE_TWISTER_UPPER_MASK        ((((uint32_t)1 << (PRNG_MERSENNE_TWISTER_W - PRNG_MERSENNE_TWISTER_R)) - 1) << PRNG_MERSENNE_TWISTER_R)      // upper (w-r) bits




uint32_t PRNG_MiddleSquare(void);
uint32_t PRNG_LCG(void);
void PRNG_LFG_Init(void);
uint32_t PRNG_LFG(void);
uint32_t PRNG_LFSR_Fibonacci(void);
void PRNG_Mersenne_Twister_Init(void);
uint32_t PRNG_Mersenne_Twister(void);


#endif      // PRNGS_H_