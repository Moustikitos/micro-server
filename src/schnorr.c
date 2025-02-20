#include "secp256k1.h"


/**
 * @brief Lifts an x-coordinate to a point on the SECP256K1 curve.
 *
 * @param x The x-coordinate as a big number.
 * @return A pointer to a Point structure representing the lifted point.
 */
Point *lift_x(mpz_t x) {
    Point *result = malloc(sizeof(Point));
    mpz_init_set(result->x, x);
    mpz_init_set_ui(result->y, 0);
    y_from_x(result->y, result->x);
    if (!mpz_even_p(result->y)){
        mpz_sub(result->y, P, result->y);
    }
    return result;
}


/**
 * @brief Converts an mpz_t number to a zero-padded hexadecimal string.
 *
 * @param value The big number to convert.
 * @return A zero-padded hexadecimal string representation of the number.
 */
char *secure_mpz_get_str_16(mpz_t value) {
    char *str_16 = malloc((SHA256_HASH_HEX_SIZE + 1) * sizeof(char));
    char tmp[SHA256_HASH_HEX_SIZE];
    for (size_t i=0; i < SHA256_HASH_HEX_SIZE; i++) {
        str_16[i] = '0';
    }
    mpz_get_str(tmp, 16, value);
    sprintf(&str_16[SHA256_HASH_HEX_SIZE - strlen(tmp)], "%s", tmp);
    str_16[SHA256_HASH_HEX_SIZE] = '\0';
    return str_16;
}


/**
 * @brief Generates a Schnorr signature according to BIP0340.
 *
 * @param message  The message to be signed.
 * @param secret   The secret key as a hexadecimal big number.
 * @param aux_rand Optional auxiliary random value (64-character hex string).
 * @return A string containing the concatenated R and S values of the signature.
 */
EXPORT char *sign(const char *message, const char *secret, char *aux_rand) {
    Point public_key, ephemeral_key;
    mpz_t d0, k0, t, e, r, sig_s, sig_r;
    unsigned char *tgh, *shh;
    char *msg, *rnd, *hex, *s16, *xpuk;
    char tmp[SHA256_HASH_HEX_SIZE * 3 + 1];
    char *result = malloc((SHA256_HASH_HEX_SIZE * 2 + 1) * sizeof(char));

    // printf("msg : %s\n", message);
    // printf("secret : %s\n", secret);
    // printf("aux_rand : %s\n", aux_rand);

    if (aux_rand == NULL) {
        rnd = hexlify(random_bytes(SHA256_HASH_SIZE), SHA256_HASH_SIZE);
    } else {
        mpz_init_set_str(r, aux_rand, 16);
        rnd = secure_mpz_get_str_16(r);
        mpz_clears(r, NULL);
    }

    // printf("rand : %s\n", rnd);

    mpz_init_set_str(d0, secret, 16);
    if ((mpz_cmp_ui(d0, 1) <= 0) || (mpz_cmp(d0, N) > 0)) {
        fprintf(stderr, "The secret key must be an integer in the range 1..N-1.\n");
        return NULL;
    }

    point_create(&public_key, NULL);
    point_mul(&public_key, d0, &G);
    assert(!is_infinity(&public_key));
    
    // gmp_printf("puk.x = %Zx\n", public_key.x);
    // gmp_printf("puk.y = %Zx\n---\n", public_key.y);

    if (!mpz_even_p(public_key.y)) {
        mpz_sub(d0, N, d0);    
    }

    tgh = tagged_hash("BIP0340/aux", rnd);
    hex = hexlify(tgh, SHA256_HASH_SIZE);
    mpz_init_set_str(t, hex, 16);
    mpz_xor(t, d0, t);

    // gmp_printf("t : %ZX\n", t);

    hex = secure_mpz_get_str_16(t);
    xpuk = secure_mpz_get_str_16(public_key.x);
    shh = sha256_hash(message);
    msg = hexlify(shh, SHA256_HASH_SIZE);
    sprintf(&tmp[0], "%s", hex);
    // printf("hex[tmp1] : %s - %s\n", hex, tmp);
    sprintf(&tmp[SHA256_HASH_HEX_SIZE], "%s", xpuk);
    // printf("xpuk[tmp1] : %s - %s\n", xpuk, tmp);
    sprintf(&tmp[2 * SHA256_HASH_HEX_SIZE], "%s", msg);

    // printf("tmp1 : %s\n", tmp);

    tgh = tagged_hash("BIP0340/nonce", tmp);
    hex = hexlify(tgh, SHA256_HASH_SIZE);
    mpz_init_set_str(k0, hex, 16);
    mpz_mod(k0, k0, N);

    if (mpz_cmp_ui(k0, 0) == 0) {
        fprintf(stderr, "Failure. This happens only with negligible probability.\n");
        return NULL;
    }

    // gmp_printf("k0 : %ZX\n", k0);

    point_create(&ephemeral_key, NULL);
    point_mul(&ephemeral_key, k0, &G);
    assert(!is_infinity(&ephemeral_key));
    if (!mpz_even_p(ephemeral_key.y)) {
        mpz_sub(k0, N, k0);
    }

    s16 = secure_mpz_get_str_16(ephemeral_key.x);
    sprintf(&tmp[0], "%s", s16);
    sprintf(&tmp[SHA256_HASH_HEX_SIZE], "%s", xpuk);
    sprintf(&tmp[2 * SHA256_HASH_HEX_SIZE], "%s", msg);

    // printf("tmp2 : %s\n", tmp);

    mpz_init_set_str(e, hexlify(tagged_hash("BIP0340/challenge", tmp), SHA256_HASH_SIZE), 16);
    mpz_mod(e, e, N);

    
    mpz_init_set(sig_r, ephemeral_key.x);
    mpz_init_set(sig_s, e);
    mpz_mul(sig_s, sig_s, d0);
    mpz_add(sig_s, sig_s, k0);
    mpz_mod(sig_s, sig_s, N);

    s16 = secure_mpz_get_str_16(sig_r);
    sprintf(&result[0], "%s", s16);
    s16 = secure_mpz_get_str_16(sig_s);
    sprintf(&result[SHA256_HASH_HEX_SIZE], "%s", s16);

    mpz_clears(d0, t, k0, e, NULL);

    mpz_clears(public_key.x, public_key.y, NULL);
    mpz_clears(ephemeral_key.x, ephemeral_key.y, NULL);
    mpz_clears(sig_s, sig_r, NULL);
    free(rnd); free(msg); free(shh);
    free(hex);free(tgh); free(s16); free(xpuk);

    return result;
}


/**
 * @brief Verifies a Schnorr signature according to BIP0340.
 *
 * @param message The signed message.
 * @param sig     The signature (concatenated R and S values in hexadecimal).
 * @param puk_x   The x-coordinate of the public key in hexadecimal.
 * @return 1 if the signature is valid, 0 otherwise.
 */
EXPORT short verify(const char *message, const char *sig, const char *puk_x) {
    Point *l_puk, R, sG;
    mpz_t e, r, s, x;
    unsigned char *msg, *tgh;
    char *hex, *s16;
    char part[SHA256_HASH_HEX_SIZE + 1];
    char tmp[SHA256_HASH_HEX_SIZE * 3 + 1];
    short result;

    // printf("msg : %s\n", message);
    // printf("sig : %s\n", sig);
    // printf("puk_x : %s\n", puk_x);

    strncpy(part, &sig[0], SHA256_HASH_HEX_SIZE);
    part[SHA256_HASH_HEX_SIZE] = '\0';
    mpz_init_set_str(r, part, 16);
    strncpy(part, &sig[SHA256_HASH_HEX_SIZE], SHA256_HASH_HEX_SIZE);
    part[SHA256_HASH_HEX_SIZE] = '\0';
    mpz_init_set_str(s, part, 16);

    if (mpz_cmp(r, N) >= 0 || mpz_cmp(s, N) >= 0){
        mpz_clears(r, s, NULL);
        return 0;
    }

    mpz_init_set_str(x, puk_x, 16);
    l_puk = lift_x(x);

    if (is_infinity(l_puk)){
        mpz_clears(x, r, s, l_puk->x, l_puk->y, NULL);
        free(l_puk);
        return 0;
    }

    s16 = secure_mpz_get_str_16(r);
    sprintf(&tmp[0], "%s", s16);
    s16 = secure_mpz_get_str_16(l_puk->x);
    sprintf(&tmp[SHA256_HASH_HEX_SIZE], "%s", s16);
    msg = sha256_hash(message);
    hex = hexlify(msg, SHA256_HASH_SIZE);
    sprintf(&tmp[2 * SHA256_HASH_HEX_SIZE], "%s", hex);

    // printf("tmp2 : %s\n", tmp);

    tgh = tagged_hash("BIP0340/challenge", tmp);
    hex = hexlify(tgh, SHA256_HASH_SIZE);
    mpz_init_set_str(e, hex, 16);
    mpz_mod(e, e, N);

    point_create(&R, NULL);
    point_create(&sG, NULL);
    point_mul(&sG, s, &G);

    mpz_sub(e, N, e);
    point_mul(&R, e, l_puk);
    point_add(&R, &sG, &R);

    result = !mpz_cmp(R.x, r);
    mpz_clears(e, x, r, s, l_puk->x, l_puk->y, R.x, R.y, sG.x, sG.y, NULL);
    free(l_puk);
    free(msg);
    free(hex);free(tgh); free(s16);

    return result;
}


/**
 * @brief Main function demonstrating Schnorr signing and verification.
 *
 * @return 0 on successful execution.
 */
int main() {
    Point puk;
    mpz_t d0;
    char *x, *sig;

    x = hexlify(sha256_hash("my very 12 word secret"), SHA256_HASH_SIZE);
    mpz_init_set_str(d0, x, 16);

    set_infinity(&puk);
    point_mul(&puk, d0, &G);

    gmp_printf("d0 = %Zx\n", d0);
    gmp_printf("puk.x = %Zx\n", puk.x);
    gmp_printf("puk.y = %Zx\n---\n", puk.y);

    printf("SCHNORR:\n");
    sig = sign("test", x, NULL);
    printf("sig = %s\n---\n", sig);

    printf("VERIFY:\n");
    printf("signature check with bad msg: %u\n", verify("test0", sig, secure_mpz_get_str_16(puk.x)));
    printf("signature check with original msg: %u\n", verify("test", sig, secure_mpz_get_str_16(puk.x)));

    free(x); free(sig);
    return 0;
}
