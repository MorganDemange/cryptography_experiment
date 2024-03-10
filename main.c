#include "MD5.h"
#include "RC4.h"
#include "SHA.h"
#include "AES.h"
#include "OTP.h"
#include "DES.h"
#include "RSA.h"
#include "ECC.h"


int main(void)
{
    MD5_test();
    SHA256_test();
    printf("\n\n\n\n\n");

    OTP_test();
    RC4_test();
    DES_test();
    AES_test();

    RSA_test();
    printf("\n\n\n\n\n");

    ECC_test();

    return 0;
}