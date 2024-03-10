#ifndef ECC_H_
#define ECC_H_

#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include "helpers.h"
#include "PRNGs.h"


#define ECC_SINGULAR_ELLIPTIC_CURVE         0
#define ECC_NONSINGULAR_ELLIPTIC_CURVE      1
#define ECC_POINT_ON_CURVE                  0
#define ECC_POINT_NOT_ON_CURVE              1
#define ECC_POINTS_SAME                     0
#define ECC_POINTS_INVERSE                  1
#define ECC_POINTS_DIFFERENT                2
#define ECC_ECDSA_SIGNATURE_VALID           0
#define ECC_ECDSA_SIGNATURE_INVALID         1


#define ECC_FRP256V1_PARAM_A            "0xf1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c00"            // parameter a for the FRP256v1 elliptic curve
#define ECC_FRP256V1_PARAM_B            "0xee353fca5428a9300d4aba754a44c00fdfec0c9ae4b1a1803075ed967b7bb73f"            // parameter b for the FRP256v1 elliptic curve
#define ECC_FRP256V1_PARAM_P            "0xf1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c03"            // parameter p for the FRP256v1 elliptic curve
#define ECC_FRP256V1_PARAM_G_X          "0xb6b3d4c356c139eb31183d4749d423958c27d2dcaf98b70164c97a2dd98f5cff"            // parameter G (X coordinate) for the FRP256v1 elliptic curve
#define ECC_FRP256V1_PARAM_G_Y          "0x6142e0f7c8b204911f9271f0f3ecef8c2701c307e8e4c9e183115a1554062cfb"            // parameter G (Y coordinate) for the FRP256v1 elliptic curve
#define ECC_FRP256V1_PARAM_G_N          "0xf1fd178c0b3ad58f10126de8ce42435b53dc67e140d2bf941ffdd459c6d655e1"            // Generator order for the FRP256v1 elliptic curve


typedef enum {
    ECC_POINT_TYPE_INF,      // "point at infinity"
    ECC_POINT_TYPE_REG       // "regular point" (i.e not the point at infinity)
} ECC_POINT_TYPE_ENUM;


/* This structure represents a point on an elliptic curve */
typedef struct {
    mpz_t x;
    mpz_t y;
    ECC_POINT_TYPE_ENUM type;
} ECC_POINT_STRUCT;


/* This structure represents an elliptic curve in the Weierstrass form:  y^2 = x^3 + a*x + b, defined over the finitie field Fp with p > 3 a prime number */
typedef struct {
    mpz_t a;
    mpz_t b;
    mpz_t p;
    ECC_POINT_STRUCT G;         // generator point
    mpz_t n;                    // generator order
} ECC_ELLIPTIC_CURVE_STRUCT;


/* ECC keys (public and private) */
typedef struct {
    mpz_t private_key;
    ECC_POINT_STRUCT public_key;
} ECC_KEY_STRUCT;


/* 
    Elliptic Curve Digital Signature for the ECDSA algorithm.

    In our implementation, a message is a point M = (m1,m2). M.m1 and M.m2 each have their own signature (which is a point).
*/
typedef struct {
    ECC_POINT_STRUCT m1_sig;            // M.m1 signature
    ECC_POINT_STRUCT m2_sig;            // M.m2 signature
} ECC_MESSAGE_SIGNATURE_STRUCT;




void ECC_Point_Print(const ECC_POINT_STRUCT *point, const char* const point_name, PRINT_FORMAT_T format);
void ECC_Point_Set_Value(ECC_POINT_STRUCT *point, const char* const x_val, const char* const y_val);
void ECC_Point_Reset(ECC_POINT_STRUCT *point);
void ECC_Point_Init(ECC_POINT_STRUCT *point, const char* const x_init_val, const char* const y_init_val);
void ECC_Point_Destroy(ECC_POINT_STRUCT *point);
void ECC_Point_Copy(ECC_POINT_STRUCT *R, const ECC_POINT_STRUCT *P);

void ECC_Elliptic_Curve_Init(ECC_ELLIPTIC_CURVE_STRUCT *curve, const char* const a, const char* const b, const char* const p, const char* const g_x, const char* const g_y, const char* const n);
void ECC_Elliptic_Curve_Destroy(ECC_ELLIPTIC_CURVE_STRUCT *curve);
int ECC_Check_Elliptic_Curve_Singularity(const ECC_ELLIPTIC_CURVE_STRUCT *curve);
void ECC_Elliptic_Curve_Print(const ECC_ELLIPTIC_CURVE_STRUCT *curve, const char* const curve_name, PRINT_FORMAT_T format);

int ECC_Check_Point_On_Elliptic_Curve(const ECC_POINT_STRUCT *point, const ECC_ELLIPTIC_CURVE_STRUCT *curve);
int ECC_Check_Point_Equality(const ECC_POINT_STRUCT *P, const ECC_POINT_STRUCT *Q, const ECC_ELLIPTIC_CURVE_STRUCT *curve);

void ECC_Point_Inverse(ECC_POINT_STRUCT *R, const ECC_POINT_STRUCT *P, const ECC_ELLIPTIC_CURVE_STRUCT *curve);
void ECC_Add_Points(ECC_POINT_STRUCT *R, const ECC_POINT_STRUCT *P, const ECC_POINT_STRUCT *Q, const ECC_ELLIPTIC_CURVE_STRUCT *curve);
void ECC_Point_Multiplication_str(ECC_POINT_STRUCT *R, const ECC_POINT_STRUCT *P, const char* const n, const ECC_ELLIPTIC_CURVE_STRUCT *curve);
void ECC_Point_Multiplication_mpz(ECC_POINT_STRUCT *R, const ECC_POINT_STRUCT *P, const mpz_t n, const ECC_ELLIPTIC_CURVE_STRUCT *curve);

void ECC_Key_Init(ECC_KEY_STRUCT *ecc_key);
void ECC_Key_Destroy(ECC_KEY_STRUCT *ecc_key);
void ECC_Key_Print(const ECC_KEY_STRUCT *ecc_key, const char* const key_name, PRINT_FORMAT_T format);

void ECC_DH_Generate_Random_Point(ECC_POINT_STRUCT *R, mpz_t *x, const ECC_ELLIPTIC_CURVE_STRUCT *curve);
void ECC_Generate_Keys(ECC_KEY_STRUCT *keys, const ECC_ELLIPTIC_CURVE_STRUCT *curve);
void ECC_DH_Generate_Secret_Key(ECC_POINT_STRUCT *secret_key, const ECC_ELLIPTIC_CURVE_STRUCT *curve);
void ECC_MV_ElGamal_Encryption(const ECC_POINT_STRUCT *plain_message, const ECC_ELLIPTIC_CURVE_STRUCT *curve);

void ECC_Message_Signature_Init(ECC_MESSAGE_SIGNATURE_STRUCT *message_signature);
void ECC_Message_Signature_Destroy(ECC_MESSAGE_SIGNATURE_STRUCT *message_signature);
void ECC_Message_Signature_Print(const ECC_MESSAGE_SIGNATURE_STRUCT *message_signature, const char* const signature_name, PRINT_FORMAT_T format);

void ECDSA_Generate_Message_Signature(ECC_MESSAGE_SIGNATURE_STRUCT *message_signature, const ECC_POINT_STRUCT *message,
                        const mpz_t Alice_Private_Key, const ECC_ELLIPTIC_CURVE_STRUCT *curve);
void ECDSA_Message_Signature_Check(const ECC_POINT_STRUCT *message_content, const ECC_MESSAGE_SIGNATURE_STRUCT *message_signature,
                        const ECC_POINT_STRUCT *Alice_Public_Key, const ECC_ELLIPTIC_CURVE_STRUCT *curve);

void ECC_test(void);


#endif          // ECC_H_