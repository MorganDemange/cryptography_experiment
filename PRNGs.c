/*
    PseudoRandom Number Generators
    Implementation of some pseudorandom number generators.
*/
#include "PRNGs.h"


/*
    Middle-square method. Invented by John von Neumann in 1949.
    In its original form, it is of poor quality and of historical interest only.
*/
uint32_t PRNG_MiddleSquare(void)
{
    static uint32_t random_number = PRNG_MIDDLESQUARE_SEED;                 // initialize the random number
    uint64_t square = (uint64_t)random_number*(uint64_t)random_number;      // random_number^2
    random_number = square >> (32/2);                                       // middle digits
    return random_number;
}


/*
    Linear Congruential Generator (LCG).
    A generalisation of the Lehmer generator and historically the most influential and studied generator.
*/
uint32_t PRNG_LCG(void)
{
    static uint32_t random_number = PRNG_LCG_SEED;                                  // initialize the random number
    random_number = (PRNG_LCG_A * random_number + PRNG_LCG_C) % PRNG_LCG_M;         // X_(n+1) = (X_n * a + c) mod m
    return random_number;
}


/*
    Lagged Fibonacci generator (LFG).
    This class of random number generator is aimed at being an improvement on the 'standard' linear congruential generator.
    These are based on a generalisation of the Fibonacci sequence.

    Before use, the LFG generator must be initialized using the PRNG_LFG_Init function.
*/
static uint32_t PRNG_LFG_State[PRNG_LFG_K];
void PRNG_LFG_Init(void)
{
    for(int i = 0; i < PRNG_LFG_K; i++){
        PRNG_LFG_State[i] = (PRNG_LCG() | 1);       // at least one of the first k values must be odd, let's make them all odd
    }
}

uint32_t PRNG_LFG(void)
{
    static int n = PRNG_LFG_K;
    uint32_t random_number = PRNG_LFG_State[n] + PRNG_LFG_State[ (n-PRNG_LFG_J) % PRNG_LFG_K ];     // S_(n-k) + S_(n-j)   mod m
    random_number = random_number % PRNG_LFG_M;
    PRNG_LFG_State[n] = random_number;
    n = (n + 1) % PRNG_LFG_K;
    return random_number;
}


/*
    Linear-feedback shift register generators.

    A linear-feedback shift register (LFSR) is a shift register whose input bit is a linear function of its previous state.
    The most commonly used linear function of single bits is exclusive-or (XOR).
    Thus, an LFSR is most often a shift register whose input bit is driven by the XOR of some bits of the overall shift register value.
*/
static int PRNG_LFSR_Fibonacci_Polynomial[] = PRNG_LFSR_FIBONACCI_POLY;
static size_t PRNG_LFSR_Fibonacci_Polynomial_Size = sizeof(PRNG_LFSR_Fibonacci_Polynomial)/sizeof(int);
uint32_t PRNG_LFSR_Fibonacci(void)
{
    static uint32_t state = PRNG_LFSR_FIBONACCI_SEED;
    uint32_t output_bit = 0;
    for(int i = 0; i < PRNG_LFSR_Fibonacci_Polynomial_Size; i++){
        output_bit ^= (state >> (32-PRNG_LFSR_Fibonacci_Polynomial[i]));
    }
    state = (state >> 1) | (output_bit << 31);
    return state;
}



/*
    Mersenne Twister generator.
    The Mersenne Twister is a general-purpose pseudorandom number generator (PRNG) developed in 1997 by Makoto Matsumoto and Takuji Nishimura.
    Its name derives from the fact that its period length is chosen to be a Mersenne prime.

    Before use, the Mersenne Twister generator must be initialized using the PRNG_Mersenne_Twister_Init function.
*/
static uint32_t PRNG_Mersenne_Twister_State[PRNG_MERSENNE_TWISTER_N] = {0};
void PRNG_Mersenne_Twister_Init(void)
{
    PRNG_Mersenne_Twister_State[0] = PRNG_MERSENNE_TWISTER_SEED;

    for(int i = 1; i < PRNG_MERSENNE_TWISTER_N; i++){
        PRNG_Mersenne_Twister_State[i] = PRNG_MERSENNE_TWISTER_F * (    PRNG_Mersenne_Twister_State[i-1] ^ (  PRNG_Mersenne_Twister_State[i-1] >> (PRNG_MERSENNE_TWISTER_W-2) )   ) + i;
    }
}

uint32_t PRNG_Mersenne_Twister(void)
{
    static int index = PRNG_MERSENNE_TWISTER_N;

    if(index >= PRNG_MERSENNE_TWISTER_N)
    {
        for(int i = 0; i < PRNG_MERSENNE_TWISTER_N; i++)
        {
            uint32_t x = (PRNG_Mersenne_Twister_State[i] & PRNG_MERSENNE_TWISTER_UPPER_MASK) | ( PRNG_Mersenne_Twister_State[  (i+1) % PRNG_MERSENNE_TWISTER_N   ] & PRNG_MERSENNE_TWISTER_LOWER_MASK);
            uint32_t xA = (x >> 1);

            if(x % 2)
                xA = xA ^ PRNG_MERSENNE_TWISTER_A;

            PRNG_Mersenne_Twister_State[i] = PRNG_Mersenne_Twister_State[   (i+PRNG_MERSENNE_TWISTER_M) % PRNG_MERSENNE_TWISTER_N   ] ^ xA;
        }

        index = 0;
    }

    uint32_t y = PRNG_Mersenne_Twister_State[index];
    y = y ^ ((y >> PRNG_MERSENNE_TWISTER_U) & PRNG_MERSENNE_TWISTER_D);
    y = y ^ ((y >> PRNG_MERSENNE_TWISTER_S) & PRNG_MERSENNE_TWISTER_B);
    y = y ^ ((y >> PRNG_MERSENNE_TWISTER_T) & PRNG_MERSENNE_TWISTER_C);
    y = y ^ (y >> 1);
    
    index += 1;

    return y;
}

