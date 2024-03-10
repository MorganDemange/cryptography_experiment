/*
    Elliptic curve cryptography (ECC) implementation.

    Any ECC_POINT_STRUCT and ECC_ELLIPTIC_CURVE_STRUCT variable must be initialized with the ECC_Point_Init and ECC_Elliptic_Curve_Init functions before use.
*/
#include "ECC.h"


/*
    Reduce a point modulo m, meaning:

    point.x <=== point.x [mod m]
    point.y <=== point.y [mod m]

    Mandatory: m > 0
*/
static inline void ECC_Reduce_Point_Mod(ECC_POINT_STRUCT *point, const mpz_t m)
{
    mpz_mod(point->x, point->x, m);
    mpz_mod(point->y, point->y, m);
}




/*
    Print an elliptic curve point structure info.
*/
void ECC_Point_Print(const ECC_POINT_STRUCT *point, const char* const point_name, PRINT_FORMAT_T format)
{
    if(point->type == ECC_POINT_TYPE_REG){
        char *str_x = get_str_mpz_t(point->x, NULL, format);
        char *str_y = get_str_mpz_t(point->y, NULL, format);

        printf("Point %s = (%s; %s)\n", point_name, str_x, str_y);
        free(str_x); free(str_y);
    }
    else{
        printf("Point %s = +oo\n", point_name);
    }
}


/*
    Set an elliptic curve point structure coordinates.
*/
void ECC_Point_Set_Value(ECC_POINT_STRUCT *point, const char* const x_val, const char* const y_val)
{
    mpz_set_str(point->x, x_val, 0);
    mpz_set_str(point->y, y_val, 0);

    point->type = ECC_POINT_TYPE_REG;
}


/*
    Reset an elliptic curve point structure.
*/
void ECC_Point_Reset(ECC_POINT_STRUCT *point)
{
    ECC_Point_Set_Value(point, "0", "0");
}


/*
    Initialize an elliptic curve point structure.
*/
void ECC_Point_Init(ECC_POINT_STRUCT *point, const char* const x_init_val, const char* const y_init_val)
{
    mpz_init(point->x);
    mpz_init(point->y);

    ECC_Point_Set_Value(point, x_init_val, y_init_val);
}


/*
    Destroy an elliptic curve point structure.
*/
void ECC_Point_Destroy(ECC_POINT_STRUCT *point)
{
    mpz_clear(point->x);
    mpz_clear(point->y);
}


/*
    Copy a point: R = P
*/
void ECC_Point_Copy(ECC_POINT_STRUCT *R, const ECC_POINT_STRUCT *P)
{
    mpz_set(R->x, P->x);
    mpz_set(R->y, P->y);
    R->type = P->type;
}




/*
    Initialize an elliptic curve structure with parameters a,b,p and generator (g_x; g_y). The generator must be a point on the curve (this function does not perform any check).
    Each parameter must be a string representing an integer; 
    e.g: ECC_Elliptic_Curve_Init("25", "0x25", "0b1111", "0", "0x1111", "23") will set a=25, b=37, p=15; g_x=0; g_y=4369; n=23

    Mandatory: - p > 0,
               - the generator point is on the curve.
*/
void ECC_Elliptic_Curve_Init(ECC_ELLIPTIC_CURVE_STRUCT *curve, const char* const a, const char* const b, const char* const p, const char* const g_x, const char* const g_y, const char* const n)
{
    mpz_init(curve->a);
    mpz_init(curve->b);
    mpz_init(curve->p);
    mpz_init(curve->n);

    mpz_set_str(curve->a, a, 0);
    mpz_set_str(curve->b, b, 0);
    mpz_set_str(curve->p, p, 0);
    mpz_set_str(curve->n, n, 0);

    ECC_Point_Init(&(curve->G), g_x, g_y);
}


/*
    Destroy an elliptic curve structure.
*/
void ECC_Elliptic_Curve_Destroy(ECC_ELLIPTIC_CURVE_STRUCT *curve)
{
    mpz_clear(curve->a);
    mpz_clear(curve->b);
    mpz_clear(curve->p);
    mpz_clear(curve->n);

    ECC_Point_Destroy(&(curve->G));
}


/*
    Check if an elliptic curve is singular or non-singular.
*/
int ECC_Check_Elliptic_Curve_Singularity(const ECC_ELLIPTIC_CURVE_STRUCT *curve)
{
    int status;

    mpz_t m,n;
    mpz_init(m); mpz_init(n);

    mpz_pow_ui(m, curve->a, 3);     // m = a^3
    mpz_mul_ui(m, m, 4);            // m = 4*a^3

    mpz_pow_ui(n, curve->b, 2);     // n = b^2
    mpz_mul_ui(n, n, 27);           // n = 27*b^2

    mpz_add(m, m, n);               // m = 4*a^3 + 27*b^2
    mpz_mod(m, m, curve->p);        // m = (4*a^3 + 27*b^2) [mod p]

    status = mpz_sgn(m);
    mpz_clear(m); mpz_clear(n);

    if(status == 0){
        return ECC_SINGULAR_ELLIPTIC_CURVE;             // (4*a^3 + 27*b^2) [mod p] is null so the curve is singular
    }

    return ECC_NONSINGULAR_ELLIPTIC_CURVE;              // (4*a^3 + 27*b^2) [mod p] is non-null so the curve is non-singular
}


/*
    Print an elliptic curve structure info.
*/
void ECC_Elliptic_Curve_Print(const ECC_ELLIPTIC_CURVE_STRUCT *curve, const char* const curve_name, PRINT_FORMAT_T format)
{
    char *str_a = get_str_mpz_t(curve->a, NULL, format);
    char *str_b = get_str_mpz_t(curve->b, NULL, format);
    char *str_p = get_str_mpz_t(curve->p, NULL, format);
    char *str_n = get_str_mpz_t(curve->n, NULL, format);

    printf("Elliptic curve %s = {\n", curve_name);
    printf("a : %s\n", str_a);
    printf("b : %s\n", str_b);
    printf("p : %s\n", str_p);
    printf("n : %s\n", str_n);
    free(str_a); free(str_b); free(str_p); free(str_n);

    ECC_Point_Print(&(curve->G), "G", format);
    printf("}\n");

    int singular_check = ECC_Check_Elliptic_Curve_Singularity(curve);
    if(singular_check == ECC_SINGULAR_ELLIPTIC_CURVE){
        printf("The curve is singular.\n\n");
    }
    else {
        printf("The curve is non-singular.\n\n");
    }
}




/*
    Check if a given point is on a given elliptic curve.
*/
int ECC_Check_Point_On_Elliptic_Curve(const ECC_POINT_STRUCT *point, const ECC_ELLIPTIC_CURVE_STRUCT *curve)
{
    int status;

    if(point->type == ECC_POINT_TYPE_INF){
        return ECC_POINT_ON_CURVE;                     // consider that the "point at infinity" is on every curve
    }

    mpz_t m,n;
    mpz_init(m); mpz_init(n);

    mpz_pow_ui(m, point->x, 3);             // m = x^3
    mpz_mul(n, point->x, curve->a);         // n = a*x
    mpz_add(m, m, n);                       // m = x^3 + a*x
    mpz_add(m, m, curve->b);                // m = x^3 + a*x + b
    mpz_mod(m, m, curve->p);                // m = (x^3 + a*x + b) [mod p]

    mpz_pow_ui(n, point->y, 2);             // n = y^2
    mpz_mod(n, n, curve->p);                // n = y^2 [mod p]

    status = mpz_cmp(m, n);
    mpz_clear(m); mpz_clear(n);

    if(status == 0){
        return ECC_POINT_ON_CURVE;          // y^2 is congruent to (x^3 + a*x + b) [mod p]; the point is on the curve
    }
    return ECC_POINT_NOT_ON_CURVE;          // not congruent [mod p]; the point is not on the curve
}


/*
    Check if two point structures P and Q represent the same point on a given elliptic curve.

    Return:
            - ECC_POINTS_SAME if P == Q,
            - ECC_POINTS_INVERSE if P == (-Q),
            - ECC_POINTS_DIFFERENT otherwise.
*/
int ECC_Check_Point_Equality(const ECC_POINT_STRUCT *P, const ECC_POINT_STRUCT *Q, const ECC_ELLIPTIC_CURVE_STRUCT *curve)
{
    if(P->type != Q->type){
        return ECC_POINTS_DIFFERENT;
    }
    
    if(P->type == ECC_POINT_TYPE_INF){
        return ECC_POINTS_SAME;             // both represent the "point at infinity"
    }

    ECC_POINT_STRUCT P_copy, Q_copy;
    ECC_Point_Init(&P_copy, "0", "0"); ECC_Point_Init(&Q_copy, "0", "0");
    ECC_Point_Copy(&P_copy, P); ECC_Point_Copy(&Q_copy, Q);
    ECC_Reduce_Point_Mod(&P_copy, curve->p);
    ECC_Reduce_Point_Mod(&Q_copy, curve->p);
    
    if(mpz_cmp(P_copy.x, Q_copy.x) != 0){
        return ECC_POINTS_DIFFERENT;         // P.x != Q.x [mod p]
    }

    if(mpz_cmp(P_copy.y, Q_copy.y) == 0) {           // P.y == Q.y [mod p]
        if(mpz_cmp_ui(P_copy.y, 0) == 0){
            return ECC_POINTS_INVERSE;       // special case: Q == P == (-P); return ECC_POINTS_INVERSE (for point addition)
        }
        return ECC_POINTS_SAME;             // Q == P != (-P)
    }

    ECC_Point_Destroy(&P_copy); ECC_Point_Destroy(&Q_copy);

    int status;
    mpz_t m; mpz_init(m);
    mpz_add(m, P->y, Q->y);
    mpz_mod(m, m, curve->p);            // m = (P.y + Q.y) [mod p]
    status = mpz_cmp_ui(m, 0);          // if (P.y + Q.y) = 0 [mod p], then Q.y = (-P.y)[mod p]
    mpz_clear(m);

    if(status == 0){
        return ECC_POINTS_INVERSE;           // Q.y = (-P.y) [mod p]
    }
    return ECC_POINTS_DIFFERENT;
}


/*
    Compute the inverse on an elliptic curve of a point P.

    R = (-P) , computed on the given elliptic curve.
*/
void ECC_Point_Inverse(ECC_POINT_STRUCT *R, const ECC_POINT_STRUCT *P, const ECC_ELLIPTIC_CURVE_STRUCT *curve)
{
    ECC_Point_Copy(R, P);

    if(P->type == ECC_POINT_TYPE_INF){
        return;         // -oo = +oo ; do nothing
    }

    /* -P = ( xp, (-yp) [mod p] ) */
    mpz_sub(R->y, curve->p, P->y);
    mpz_mod(R->y, R->y, curve->p);
}


/*
    Add two different points on a given elliptic curve. The two points should not be the inverse of each other.
    R = P + Q;  
    
    Conditions:
        P != Q, P != (-Q), P != +oo, Q != +oo

    Under these conditions, we necessarily have P.x != Q.x [mod p] (because we're additionning on an elliptic curve).
    Hence, as p is prime, the modular inverse of (P.x - Q.x) exists.
*/
static void ECC_Distinct_Points_Addition(ECC_POINT_STRUCT *R, const ECC_POINT_STRUCT *P, const ECC_POINT_STRUCT *Q, const ECC_ELLIPTIC_CURVE_STRUCT *curve)
{
    ECC_POINT_STRUCT R_temp;
    ECC_Point_Init(&R_temp, "0", "0");

    mpz_t m, s;
    mpz_init(m); mpz_init(s);


    mpz_sub(s, P->y, Q->y);             // s = (P.y - Q.y)
    mpz_sub(m, P->x, Q->x);
    mpz_invert(m, m, curve->p);         // m = (P.x - Q.x)^(-1) [mod p]
    mpz_mul(s, s, m);                   // s = (P.y - Q.y) * (  (P.x - Q.x)^(-1) [mod p]  )
    mpz_mod(s, s, curve->p);            // s = (  (P.y - Q.y) * (P.x - Q.x)^(-1)  ) [mod p]

    mpz_pow_ui(m, s, 2);
    mpz_sub(m, m, P->x);
    mpz_sub(m, m, Q->x);
    mpz_mod(R_temp.x, m, curve->p);         // R_temp.x = (s^2 - P.x - Q.x) [mod p]

    mpz_sub(m, P->x, R_temp.x);
    mpz_mul(s, s, m);
    mpz_sub(s, s, P->y);
    mpz_mod(R_temp.y, s, curve->p);         // R_temp.y = (s * (P.x - R_temp.x) - P.y) [mod p]

    R_temp.type = ECC_POINT_TYPE_REG;


    mpz_clear(m); mpz_clear(s);

    ECC_Point_Copy(R, &R_temp);
    ECC_Point_Destroy(&R_temp);
}


/*
    Double the same point on a given elliptic curve. The point should not be its own inverse (i.e yp != 0 [mod p]).
    R = P + P = 2*P;    P != +oo; P != (-P)
*/
static void ECC_Point_Doubling(ECC_POINT_STRUCT *R, const ECC_POINT_STRUCT *P, const ECC_ELLIPTIC_CURVE_STRUCT *curve)
{
    ECC_POINT_STRUCT R_temp;
    ECC_Point_Init(&R_temp, "0", "0");

    mpz_t m, s;
    mpz_init(m); mpz_init(s);


    mpz_pow_ui(s, P->x, 2);
    mpz_mul_ui(s, s, 3);
    mpz_add(s, s, curve->a);            // s = 3*(P.x ^ 2) + a

    mpz_mul_ui(m, P->y, 2);
    mpz_invert(m, m, curve->p);         // m = (2 * P.y)^(-1) [mod p]
    mpz_mul(s, s, m);
    mpz_mod(s, s, curve->p);            // s = (  (3*(P.x ^ 2) + a) * (2 * P.y)^(-1)  ) [mod p]

    mpz_pow_ui(m, s, 2);
    mpz_sub(m, m, P->x);
    mpz_sub(m, m, P->x);
    mpz_mod(R_temp.x, m, curve->p);         // R_temp.x = (s^2 - 2*P.x) [mod p]

    mpz_sub(m, P->x, R_temp.x);
    mpz_mul(s, s, m);
    mpz_sub(s, s, P->y);
    mpz_mod(R_temp.y, s, curve->p);         // R_temp.y = (s * (P.x - R_temp.x) - P.y) [mod p]

    R_temp.type = ECC_POINT_TYPE_REG;


    mpz_clear(m); mpz_clear(s);

    ECC_Point_Copy(R, &R_temp);
    ECC_Point_Destroy(&R_temp);
}


/*
    Add two points on a given elliptic curve.
    R = P + Q.
*/
void ECC_Add_Points(ECC_POINT_STRUCT *R, const ECC_POINT_STRUCT *P, const ECC_POINT_STRUCT *Q, const ECC_ELLIPTIC_CURVE_STRUCT *curve)
{
    /* the point at infinity +oo is the identity element: for all P, P + oo == oo + P == P */
    if(P->type == ECC_POINT_TYPE_INF) {
        ECC_Point_Copy(R, Q);
    }
    else if(Q->type == ECC_POINT_TYPE_INF) {
        ECC_Point_Copy(R, P);
    }
    else {
        switch(  ECC_Check_Point_Equality(P, Q, curve)  ) {
            case ECC_POINTS_SAME:
            {
                ECC_Point_Doubling(R, P, curve);
                break;
            }
            case ECC_POINTS_INVERSE:
            {
                R->type = ECC_POINT_TYPE_INF;            // P + (-P) == +oo
                break;
            }
            case ECC_POINTS_DIFFERENT:
            {
                ECC_Distinct_Points_Addition(R, P, Q, curve);
                break;
            }
            default:
            {
                break;          // should never occur
            }
        }
    }
}


/*
    Multiplication of a point by a given integer IN STRING FORMAT, implemented with the Double-and-add algorithm.
    R = n*P with n > 0. P must be a point on the given elliptic curve.

    E.g:    ECC_Point_Multiplication(R, P, "1444", curve) will compute R = 1444*P on the given elliptic curve.
*/
void ECC_Point_Multiplication_str(ECC_POINT_STRUCT *R, const ECC_POINT_STRUCT *P, const char* const n, const ECC_ELLIPTIC_CURVE_STRUCT *curve)
{
    /* get n as a mpz variable */
    mpz_t n_mpz;
    mpz_init(n_mpz);
    mpz_set_str(n_mpz, n, 0);

    /* get the binary representation of n */
    size_t str_len;
    char *n_bin_str = get_str_mpz_t(n_mpz, &str_len, PRINT_FORMAT_BIN);
    mpz_clear(n_mpz);


    ECC_POINT_STRUCT res, temp;
    ECC_Point_Init(&res, "0", "0"); ECC_Point_Init(&temp, "0", "0");
    res.type = ECC_POINT_TYPE_INF;          // start with res = +oo
    ECC_Point_Copy(&temp, P);               // start with temp = P

    char c;
    for(size_t i = str_len-1; i > 1; i--){          // go from 2 ... str_len-1 (ignore the prefix "0b" and the null terminator character), in reverse order
        c = n_bin_str[i];
        
        if((c != '0') && (c != '1')){
            continue;       // skip (for safety, but should never happen)
        }

        if(c == '1'){
            ECC_Add_Points(&res, &res, &temp, curve);          // res += temp
        }
        ECC_Add_Points(&temp, &temp, &temp, curve);          // temp *= 2
    }

    free(n_bin_str);
    ECC_Point_Destroy(&temp);

    ECC_Point_Copy(R, &res);
    ECC_Point_Destroy(&res);
}


/*
    Multiplication of a point by a given integer IN MPZ FORMAT, implemented with the Double-and-add algorithm.
    R = n*P with n > 0. P must be a point on the given elliptic curve.
*/
void ECC_Point_Multiplication_mpz(ECC_POINT_STRUCT *R, const ECC_POINT_STRUCT *P, const mpz_t n, const ECC_ELLIPTIC_CURVE_STRUCT *curve)
{
    /* get n in string format */
    char *n_str = get_str_mpz_t(n, NULL, PRINT_FORMAT_DEC);

    ECC_Point_Multiplication_str(R, P, n_str, curve);

    free(n_str);
}




/*
    Initialize an ECC_KEY_STRUCT variable.
*/
void ECC_Key_Init(ECC_KEY_STRUCT *ecc_key)
{
    mpz_init(ecc_key->private_key);
    mpz_set_ui(ecc_key->private_key, 0);        // default value is 0
    ECC_Point_Init(&(ecc_key->public_key), "0", "0");
}


/*
    Destroy an ECC_KEY_STRUCT variable.
*/
void ECC_Key_Destroy(ECC_KEY_STRUCT *ecc_key)
{
    mpz_clear(ecc_key->private_key);
    ECC_Point_Destroy(&(ecc_key->public_key));
}


/*
    Print an ECC_KEY_STRUCT variable.
*/
void ECC_Key_Print(const ECC_KEY_STRUCT *ecc_key, const char* const key_name, PRINT_FORMAT_T format)
{
    printf("ECC Key %s = {\n", key_name);
    print_mpz_t(ecc_key->private_key, "private key", format);
    ECC_Point_Print(&(ecc_key->public_key), "public key", format);
    printf("}\n");
}



/*
    Generate a random point R = x*G on a given elliptic curve for the ECC Diffie-Hellman algorithm.
    G is the generator of the given curve and x a random number.
    2 <= x < n;    (n is the generator order)
*/
void ECC_DH_Generate_Random_Point(ECC_POINT_STRUCT *R, mpz_t *x, const ECC_ELLIPTIC_CURVE_STRUCT *curve)
{
    /* generate a random number */
    random_mpz_t(x, curve->n);

    /* R = x*G */
    ECC_Point_Multiplication_mpz(R, &(curve->G), *x, curve);
}


/*
    ECC public and private keys generation
*/
void ECC_Generate_Keys(ECC_KEY_STRUCT *keys, const ECC_ELLIPTIC_CURVE_STRUCT *curve)
{
    /* let's make sure that all of the key's components are non-null */
    do {
        ECC_DH_Generate_Random_Point(&(keys->public_key), &(keys->private_key), curve);
    } while(  (mpz_cmp_ui(keys->private_key, 0) == 0) || (mpz_cmp_ui(keys->public_key.x, 0) == 0) || (mpz_cmp_ui(keys->public_key.y, 0) == 0)  );
}


/*
    Generate a random secret key using the ECC Diffie-Hellman algorithm.
*/
void ECC_DH_Generate_Secret_Key(ECC_POINT_STRUCT *secret_key, const ECC_ELLIPTIC_CURVE_STRUCT *curve)
{
    /* Alice generates her own keys */
    ECC_KEY_STRUCT Alice_Key;
    ECC_Key_Init(&Alice_Key);
    ECC_Generate_Keys(&Alice_Key, curve);

    /* Bob generates his own private key */
    ECC_KEY_STRUCT Bob_Key;
    ECC_Key_Init(&Bob_Key);
    ECC_Generate_Keys(&Bob_Key, curve);

    /* Now Alice can recover the secret key */
    ECC_POINT_STRUCT Alice_Secret_Key;
    ECC_Point_Init(&Alice_Secret_Key, "0", "0");
    ECC_Point_Multiplication_mpz(&Alice_Secret_Key, &(Bob_Key.public_key), Alice_Key.private_key, curve);

    /* Bob does the same thing on his side */
    ECC_POINT_STRUCT Bob_Secret_Key;
    ECC_Point_Init(&Bob_Secret_Key, "0", "0");
    ECC_Point_Multiplication_mpz(&Bob_Secret_Key, &(Alice_Key.public_key), Bob_Key.private_key, curve);


    /* at this stade, Alice and Bob are supposed to have the same secret key */
    if(  ECC_Check_Point_Equality(&Alice_Secret_Key, &Bob_Secret_Key, curve) != ECC_POINTS_SAME  ){
        printf("ECC Diffie-Hellman error: Alice and Bob didn't recover the same secret key !\n");
        ECC_Point_Reset(secret_key);
    }
    else {
        printf("ECC Diffie-Hellman success: Alice and Bob recovered the same secret key !\n");
        ECC_Point_Copy(secret_key, &Alice_Secret_Key);
    }

    ECC_Key_Destroy(&Alice_Key);
    ECC_Key_Destroy(&Bob_Key);
    ECC_Point_Destroy(&Alice_Secret_Key);
    ECC_Point_Destroy(&Bob_Secret_Key);
}


/*
    ECC encryption using the ECC MV-ElGamal cryptosystem.
    While in the ECC-ElGamal cryptosystem the plain message must be somehow mapped to a point on the given elliptic curve,
    the ECC MV-ElGamal cryptosystem does not have this requirement.

    The plain message (m1,m2) is a point such that:    0 < m1,m2 < curve.p
    As said above, the plain message doesn't need to be on the curve.
*/
void ECC_MV_ElGamal_Encryption(const ECC_POINT_STRUCT *plain_message, const ECC_ELLIPTIC_CURVE_STRUCT *curve)
{
    /* Alice generates her own keys */
    ECC_KEY_STRUCT Alice_Key;
    ECC_Key_Init(&Alice_Key);
    ECC_Generate_Keys(&Alice_Key, curve);

    /* Bob generates his own keys */
    ECC_KEY_STRUCT Bob_Key;
    ECC_Key_Init(&Bob_Key);
    ECC_Generate_Keys(&Bob_Key, curve);

    /* S = k*A, where A is Alice's public key and k is Bob's private key */
    ECC_POINT_STRUCT S;
    ECC_Point_Init(&S, "0", "0");
    ECC_Point_Multiplication_mpz(&S, &(Alice_Key.public_key), Bob_Key.private_key, curve);              // S = k*A


    /* The encrypted message is (R, c1, c2), where:
        - R = Bob's public key
        - c1 = (S.x * m1) [mod p]
        - c2 = (S.y * m2) [mod p]
    */
   mpz_t c1, c2;
   mpz_init(c1); mpz_init(c2);
   mpz_mul(c1, S.x, plain_message->x);
   mpz_mod(c1, c1, curve->p);
   mpz_mul(c2, S.y, plain_message->y);
   mpz_mod(c2, c2, curve->p);


   /* Bob tranmits the encrypted message to Alice; Alice computes T = a*R where a is her private key. */
   ECC_POINT_STRUCT T;
   ECC_Point_Init(&T, "0", "0");
   ECC_Point_Multiplication_mpz(&T, &(Bob_Key.public_key), Alice_Key.private_key, curve);                   // T = a*R

   /* Alice then uses T to get the decrypted message */
   ECC_POINT_STRUCT Decrypted_message;
   ECC_Point_Init(&Decrypted_message, "0", "0");
   mpz_t inv; mpz_init(inv);
   
   mpz_invert(inv, T.x, curve->p);                                  // inv = T.x^(-1) [mod p]
   mpz_mul(Decrypted_message.x, inv, c1);
   mpz_mod(Decrypted_message.x, Decrypted_message.x, curve->p);     // Decrypted_message.x = (T.x^(-1) * c1) [mod p]

   mpz_invert(inv, T.y, curve->p);                                  // inv = T.y^(-1) [mod p]
   mpz_mul(Decrypted_message.y, inv, c2);
   mpz_mod(Decrypted_message.y, Decrypted_message.y, curve->p);     // Decrypted_message.y = (T.y^(-1) * c2) [mod p]

   /* just for printing purpose */
   ECC_POINT_STRUCT Encrypted_message;
   ECC_Point_Init(&Encrypted_message, "0", "0");                    // Encrypted_message = (c1,c2)
   mpz_set(Encrypted_message.x, c1);
   mpz_set(Encrypted_message.y, c2);


   ECC_Point_Print(plain_message, "    plain message", PRINT_FORMAT_HEX);
   ECC_Point_Print(&Encrypted_message, "encrypted message", PRINT_FORMAT_HEX);
   ECC_Point_Print(&Decrypted_message, "decrypted message", PRINT_FORMAT_HEX);

   if(  ECC_Check_Point_Equality(plain_message, &Decrypted_message, curve) != ECC_POINTS_SAME  ){
        printf("ECC_MV_ElGamal_Encryption error: the plain message and the decrypted message do not match !\n");
   }
   else {
        printf("ECC_MV_ElGamal_Encryption success: the plain message and the decrypted message match !\n");
   }

   ECC_Key_Destroy(&Alice_Key); ECC_Key_Destroy(&Bob_Key);
   ECC_Point_Destroy(&S); ECC_Point_Destroy(&T);
   mpz_clear(c1); mpz_clear(c2); mpz_clear(inv);
   ECC_Point_Destroy(&Encrypted_message); ECC_Point_Destroy(&Decrypted_message);
}




/*
    Initialize an ECC_MESSAGE_SIGNATURE_STRUCT variable.
*/
void ECC_Message_Signature_Init(ECC_MESSAGE_SIGNATURE_STRUCT *message_signature)
{
    ECC_Point_Init(&(message_signature->m1_sig), "0", "0");
    ECC_Point_Init(&(message_signature->m2_sig), "0", "0");
}


/*
    Destroy an ECC_MESSAGE_SIGNATURE_STRUCT variable.
*/
void ECC_Message_Signature_Destroy(ECC_MESSAGE_SIGNATURE_STRUCT *message_signature)
{
    ECC_Point_Destroy(&(message_signature->m1_sig));
    ECC_Point_Destroy(&(message_signature->m2_sig));
}


/*
    Print an ECC_MESSAGE_SIGNATURE_STRUCT variable.
*/
void ECC_Message_Signature_Print(const ECC_MESSAGE_SIGNATURE_STRUCT *message_signature, const char* const signature_name, PRINT_FORMAT_T format)
{
    printf("Message Signature %s: {\n", signature_name);
    ECC_Point_Print(&(message_signature->m1_sig), "m1", format);
    ECC_Point_Print(&(message_signature->m2_sig), "m2", format);
    printf("}\n");
}




/*
    Elliptic Curve Digital Signature Algorithm (ECDSA).
    
    Alice can sign her messages so when Bob receives one, he can check if it really comes from her or not.
    This function generates the signature of a single given number.

    Condition:  1 <= number < curve.n
*/
static void ECDSA_Generate_Single_Signature(ECC_POINT_STRUCT *number_signature, const mpz_t number, const mpz_t Alice_Private_Key, const ECC_ELLIPTIC_CURVE_STRUCT *curve)
{
    ECC_KEY_STRUCT random_key;
    ECC_Key_Init(&random_key);

    mpz_t z, inv;
    mpz_init(z); mpz_init(inv);

    /* the signature is (s1,s2); make sure that neither s1 nor s2 are null */
    do {
        ECC_Generate_Keys(&random_key, curve);                          // Alice generates a random key (k, k*G) to sign the message.

        mpz_set(number_signature->x, random_key.public_key.x);
        mpz_mod(number_signature->x, number_signature->x, curve->n);    // s1 = x_k [mod n]

        mpz_invert(inv, random_key.private_key, curve->n);              // inv = k^(-1) [mod n]
        
        mpz_mul(z, Alice_Private_Key, number_signature->x);
        mpz_add(z, z, number);                                          // z = (D + a*s1)
        mpz_mul(number_signature->y, z, inv);
        mpz_mod(number_signature->y, number_signature->y, curve->n);    // s2 = ( (D + a*s1) * k^(-1) ) [mod n]
    
    } while(  (mpz_cmp_ui(number_signature->x, 0) == 0) || (mpz_cmp_ui(number_signature->y, 0) == 0)  );


    mpz_clear(z); mpz_init(inv);
    ECC_Key_Destroy(&random_key);
}


/*
    Elliptic Curve Digital Signature Algorithm (ECDSA).
    
    Alice can sign her messages so when Bob receives one, he can check if it really comes from her or not.
    This function generates the signature of a given message M = (m1,m2).

    Condition:  1 <= m1,m2 < curve.n
*/
void ECDSA_Generate_Message_Signature(ECC_MESSAGE_SIGNATURE_STRUCT *message_signature, const ECC_POINT_STRUCT *message,
                        const mpz_t Alice_Private_Key, const ECC_ELLIPTIC_CURVE_STRUCT *curve)
{
    ECDSA_Generate_Single_Signature(&(message_signature->m1_sig), message->x, Alice_Private_Key, curve);        // generate m1 signature
    ECDSA_Generate_Single_Signature(&(message_signature->m2_sig), message->y, Alice_Private_Key, curve);        // generate m2 signature
}


/*
    Elliptic Curve Digital Signature Algorithm (ECDSA).
    
    Alice can sign her messages so when Bob receives one, he can check if it really comes from her or not.
    This function checks the signature of a single given received number.

    Return:
            - ECC_ECDSA_SIGNATURE_VALID if the signature is valid;
            - ECC_ECDSA_SIGNATURE_INVALID otherwise.
*/
static int ECDSA_Single_Signature_Check(const mpz_t number, const ECC_POINT_STRUCT *number_signature,
                        const ECC_POINT_STRUCT *Alice_Public_Key, const ECC_ELLIPTIC_CURVE_STRUCT *curve)
{
    mpz_t v1, v2, inv;
    mpz_init(v1); mpz_init(v2); mpz_init(inv);

    mpz_invert(inv, number_signature->y, curve->n);         // inv = s2^(-1) [mod n]

    mpz_mul(v1, number, inv);
    mpz_mod(v1, v1, curve->n);                              // v1 = ( D * s2^(-1) ) [mod n]

    mpz_mul(v2, number_signature->x, inv);
    mpz_mod(v2, v2, curve->n);                              // v2 =  ( s1 * s2^(-1) ) [mod n]

    ECC_POINT_STRUCT z1, z2;
    ECC_Point_Init(&z1, "0", "0");
    ECC_Point_Init(&z2, "0", "0");
    ECC_Point_Multiplication_mpz(&z1, &(curve->G), v1, curve);              // z1 = v1*G
    ECC_Point_Multiplication_mpz(&z2, Alice_Public_Key, v2, curve);         // z2 = v2*A
    ECC_Add_Points(&z1, &z1, &z2, curve);                                   // z1 = (v1*G + v2*A)

    mpz_set(v1, z1.x);
    mpz_set(v2, number_signature->x);
    mpz_mod(v1, v1, curve->n);              // v1 <==== (v1*G + v2*A).x [mod n]
    mpz_mod(v2, v2, curve->n);              // v2 <==== s1 [mod n]

    int status = ECC_ECDSA_SIGNATURE_VALID;
    if(mpz_cmp(v1, v2) != 0){
        status = ECC_ECDSA_SIGNATURE_INVALID;           // v1 != v2, the signature is invalid
    }

    mpz_clear(v1); mpz_clear(v2); mpz_clear(inv);
    ECC_Point_Destroy(&z1);
    ECC_Point_Destroy(&z2);

    return status;
}


/*
    Elliptic Curve Digital Signature Algorithm (ECDSA).
    
    Alice can sign her messages so when Bob receives one, he can check if it really comes from her or not.
    This function checks the signature of a given message M = (m1,m2).
*/
void ECDSA_Message_Signature_Check(const ECC_POINT_STRUCT *message_content, const ECC_MESSAGE_SIGNATURE_STRUCT *message_signature,
                        const ECC_POINT_STRUCT *Alice_Public_Key, const ECC_ELLIPTIC_CURVE_STRUCT *curve)
{
    int status_1, status_2;
    status_1 = ECDSA_Single_Signature_Check(message_content->x, &(message_signature->m1_sig), Alice_Public_Key, curve);     // check m1's signature
    status_2 = ECDSA_Single_Signature_Check(message_content->y, &(message_signature->m2_sig), Alice_Public_Key, curve);     // check m2's signature

    if(  (status_1 == ECC_ECDSA_SIGNATURE_INVALID) || (status_2 == ECC_ECDSA_SIGNATURE_INVALID)  ){
        printf("ECDSA Signature Check Error: the message was not send by Alice.\n");
    }
    else{
        printf("ECDSA Signature Check Success: the message was sent by Alice.\n");
    }
}




void ECC_test(void)
{
    ECC_ELLIPTIC_CURVE_STRUCT curve;
    ECC_Elliptic_Curve_Init(&curve, ECC_FRP256V1_PARAM_A, ECC_FRP256V1_PARAM_B, ECC_FRP256V1_PARAM_P, ECC_FRP256V1_PARAM_G_X, ECC_FRP256V1_PARAM_G_Y, ECC_FRP256V1_PARAM_G_N);


    /*
        ECC_DH_Generate_Secret_Key example.
    */
    ECC_POINT_STRUCT ECC_Diffie_Hellman_Secret_Key;
    ECC_Point_Init(&ECC_Diffie_Hellman_Secret_Key, "0", "0");

    ECC_DH_Generate_Secret_Key(&ECC_Diffie_Hellman_Secret_Key, &curve);

    ECC_Point_Print(&ECC_Diffie_Hellman_Secret_Key, "ECC Diffie-Hellman secret key", PRINT_FORMAT_HEX);
    ECC_Point_Destroy(&ECC_Diffie_Hellman_Secret_Key); 
    printf("\n");



    /*
        ECC_MV_ElGamal_Encryption example.
    */
    ECC_POINT_STRUCT ECC_Plain_Message;
    ECC_Point_Init(&ECC_Plain_Message, "0x5a2f6bb522c82ea7397955e9e8350b0871c7845d9746a4979650231ddb15c005",
                "0xbb63b52f3a8106413bb697073a0c50a7e7ba989656aa8120ec3a7861a6cae9d3");
    ECC_MV_ElGamal_Encryption(&ECC_Plain_Message, &curve);
    ECC_Point_Destroy(&ECC_Plain_Message);
    printf("\n");



    /*
        ECDSA example.
    */
    ECC_POINT_STRUCT message;
    ECC_Point_Init(&message, "0x4815abc84c4c84c841c5c41c8de48d48ed48f4b84f4b4f84158184a14515bf51", "0xa254589855825fd2f52d5f2e52d25f52a525255a555c5c5d5c5dd4e4f4f45544");

    ECC_KEY_STRUCT Alice_Keys;
    ECC_Key_Init(&Alice_Keys);
    ECC_Generate_Keys(&Alice_Keys, &curve);
    ECC_Key_Print(&Alice_Keys, "Alice's key", PRINT_FORMAT_HEX);

    ECC_MESSAGE_SIGNATURE_STRUCT message_signature;
    ECC_Message_Signature_Init(&message_signature);
    ECDSA_Generate_Message_Signature(&message_signature, &message, Alice_Keys.private_key, &curve);
    ECC_Message_Signature_Print(&message_signature, "message signature", PRINT_FORMAT_HEX);

    ECDSA_Message_Signature_Check(&message, &message_signature, &Alice_Keys.public_key, &curve);

    ECC_Key_Destroy(&Alice_Keys);
    ECC_Message_Signature_Destroy(&message_signature);
    ECC_Point_Destroy(&message);



    ECC_Elliptic_Curve_Destroy(&curve);
}