/*
    RSA algorithm implementation.
*/
#include "RSA.h"


/*
    Generate a random array of size n.
    Make sure that at least the most significant word is != 0, to ensure that we get a "big number"
*/
static void RSA_Generate_Random_Array(uint32_t *arr, unsigned int n)
{
    random_array(arr, n);
    while(arr[n-1] == 0){
        arr[n-1] = PRNG_LFSR_Fibonacci();
    }
}


/*
    Generate a large prime number.
*/
static int RSA_Generate_Large_Prime_Number(mpz_t *p)
{
    uint32_t arr[RSA_KEYSIZE_WORDS/2];
    RSA_Generate_Random_Array(arr, RSA_KEYSIZE_WORDS/2);
    mpz_t rand_num;
    mpz_init(rand_num);
    
    mpz_import(rand_num, RSA_KEYSIZE_WORDS/2, -1, sizeof(uint32_t), 0, 0, arr);

    int status;
    if(mpz_prevprime(*p, rand_num) == 0){
        status = EXIT_FAILURE;
    }
    else{
        status = EXIT_SUCCESS;
    }

    mpz_clear(rand_num);
    return status;
}



/*
    Initialize RSA keys.
*/
int RSA_Create_Keys(RSA_PUBLIC_KEY_T *public_key, RSA_PRIVATE_KEY_T *d)
{
    mpz_init(public_key->n);
    mpz_init(public_key->e);
    mpz_init(*d);

    return EXIT_SUCCESS;
}


/*
    Destroy RSA keys.
*/
int RSA_Destroy_Keys(RSA_PUBLIC_KEY_T *public_key, RSA_PRIVATE_KEY_T *d)
{
    mpz_clear(public_key->n);
    mpz_clear(public_key->e);
    mpz_clear(*d);

    return EXIT_SUCCESS;
}


/*
    Print RSA keys.
*/
void RSA_Print_Keys(const RSA_PUBLIC_KEY_T *public_key, const RSA_PRIVATE_KEY_T *d, const char* const keys_title)
{
    printf("RSA keys %s: {\n", keys_title);
    print_mpz_t(public_key->n, "public key n", PRINT_FORMAT_HEX);
    print_mpz_t(public_key->e, "public key e", PRINT_FORMAT_DEC);
    print_mpz_t(*d, "d", PRINT_FORMAT_HEX);
    printf("}\n");
}



/*
    Generate RSA keys.
*/
int RSA_Generate_Keys(RSA_PUBLIC_KEY_T *public_key, RSA_PRIVATE_KEY_T *d)
{
    mpz_t p,q;
    mpz_init(p); mpz_init(q);

    /* p,q are "big" prime numbers */
    if(  (RSA_Generate_Large_Prime_Number(&p) == EXIT_FAILURE) || (RSA_Generate_Large_Prime_Number(&q) == EXIT_FAILURE)  ){
        printf("RSA Error: cannot generate keys.\n");
        return EXIT_FAILURE;
    }
    mpz_mul(public_key->n, p, q);       // n = p*q

    mpz_t lambda; mpz_init(lambda);
    mpz_sub_ui(p,p,1);          // p <-- (p-1)
    mpz_sub_ui(q,q,1);          // q <-- (q-1)
    mpz_mul(lambda, p, q);      // lambda = (p-1)*(q-1)

    mpz_set_ui(public_key->e, 65537);       // e = 65537

    /* d is the modular multiplicative inverse of e modulo lambda; its existence is guaranteed since e and lambda are coprime (in particular, e si prime) */
    mpz_invert(*d, public_key->e, lambda);

    mpz_clear(p); mpz_clear(q);
    mpz_clear(lambda);

    return EXIT_SUCCESS;
}




/*
    Encrypt a message with the RSA protocol.
    Condition: message length < size(key)

    Parameters:
        - plain_message     : the message to encrypt (input)
        - public_key        : the public key with which the message will be encrypted

    The plain message is a string representing a (strictly positive) number in decimal, hex (0x) or bin (0b) format.
    Example:    RSA_Encryption("0x151055ded755", &key);

    Return: a pointer to the encrypted message (stored in hex format).
*/
char* RSA_Encryption(const char* const plain_message, const RSA_PUBLIC_KEY_T *public_key)
{
    if(  (plain_message == NULL) || (public_key == NULL)  ){
        printf("RSA Error: cannot encrypt message.\n");
        return NULL;
    }

    mpz_t c, m;
    mpz_init(c); mpz_init(m);
    mpz_set_str(m, plain_message, 0);                                                   // m is the plain message
    mpz_powm(c, m, public_key->e, public_key->n);                                       // c = (m^e) [mod n] is the encrypted message

    char *encrypted_message = get_str_mpz_t(c, NULL, PRINT_FORMAT_HEX);
    mpz_clear(c); mpz_clear(m);

    return encrypted_message;
}




/*
    Decrypt a message encrypted with the RSA protocol.
    Condition: message length < size(key)

    Parameters:
        - encrypted_message    : the message to decrypt (input)
        - public_key           : the public key that was used to encrypt the plain message
        - d                    : the private key that will be used to decrypt the message

    The encrypted message is a string representing a (strictly positive) number in decimal, hex (0x) or bin (0b) format.
    Example:    RSA_Decryption("0x151055ded755", &public_key, &d);

    Return: a pointer to the decrypted message (stored in hex format).
*/
char* RSA_Decryption(const char* const encrypted_message, const RSA_PUBLIC_KEY_T *public_key, const RSA_PRIVATE_KEY_T *d)
{
    if(  (encrypted_message == NULL) || (public_key == NULL) || (d == NULL)  ){
        printf("RSA Error: cannot encrypt message.\n");
        return NULL;
    }

    mpz_t c, m;
    mpz_init(c); mpz_init(m);

    mpz_set_str(c, encrypted_message, 0);           // c is the encrypted message
    mpz_powm(m, c, *d, public_key->n);              // m = (c^d) [mod n] is the decrypted message
    
    char *decrypted_message = get_str_mpz_t(m, NULL, PRINT_FORMAT_HEX);
    mpz_clear(c); mpz_clear(m);

    return decrypted_message;
}



void RSA_test(void)
{
    RSA_PUBLIC_KEY_T public_key; RSA_PRIVATE_KEY_T d;
    RSA_Create_Keys(&public_key,&d);
    RSA_Generate_Keys(&public_key,&d);
    RSA_Print_Keys(&public_key, &d, "RSA Keys");

    char plain_message[] = "0x16564441bbbbdedefa464848f48e4d85e458dfde415fd1d151a51511b51d154e15f5414154ff01fae";
    char *encrypted_message = RSA_Encryption(plain_message, &public_key);
    char *decrypted_message = RSA_Decryption(encrypted_message, &public_key, &d);

    RSA_Destroy_Keys(&public_key,&d);

    printf("Uncrypted Message: %s\n", plain_message);
    printf("Encrypted Message: %s\n", encrypted_message);
    printf("Decrypted Message: %s\n", decrypted_message);

    if(strcmp(plain_message, decrypted_message) != 0){
        printf("RSA error: the decrypted message does not match the plain message !\n");
    }
    else {
        printf("RSA success: the decrypted message matches the plain message !\n");
    }


    free(encrypted_message);
    free(decrypted_message);
}