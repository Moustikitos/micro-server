#include "secp256k1.h"


Point *lift_x(mpz_t x) {
    Point *result = malloc(sizeof(Point));
	point_create(result, NULL);
    mpz_init_set(result->x, x);
    y_from_x(result->y, result->x);
    if (!mpz_even_p(result->y)){
		mpz_sub(result->y, P, result->y);
	}
    return result;
}


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
 * @brief Generates SCHNORR signature according to [SPEC].
 *
 * @param message  message to be signed.
 * @param secret   secret abcisa on SECP256k curve (BIG NUM hexadecimal representation).
 * @param aux_rand salt (64-len-hexadecimal string).
 * @return         Signature structure.
 */
EXPORT char *sign(const char *message, const char *secret, char *aux_rand) {
	Signature sig;
	Point public_key, ephemeral_key;
	mpz_t d0, k0, t, e, r;
	unsigned char *rnd, *xpuk, *msg;
	char tmp[SHA256_HASH_HEX_SIZE * 3 + 1];
	char *result = malloc((SHA256_HASH_HEX_SIZE * 2 + 1) * sizeof(char));

	if (aux_rand == NULL) {
		rnd = hexlify(random_bytes(32), 32);
	} else {
		mpz_init_set_str(r, aux_rand, 16);
		rnd = secure_mpz_get_str_16(r);
		mpz_clears(r, NULL);
	}

	mpz_init_set_str(d0, secret, 16);
	if ((mpz_cmp_ui(d0, 1) <= 0) || (mpz_cmp(d0, N) > 0)) {
		fprintf(stderr, "The secret key must be an integer in the range 1..N-1.\n");
		exit(EXIT_FAILURE);
	}

	point_create(&public_key, NULL);
	point_mul(&public_key, d0, &G);
	assert(!is_infinity(&public_key));

	if (!mpz_even_p(public_key.y)) {
		mpz_sub(d0, N, d0);    
	}

	mpz_init_set_str(t, hexlify(tagged_hash("BIP0340/aux", rnd), SHA256_HASH_SIZE), 16);
	mpz_xor(t, d0, t);

	sprintf(&tmp[0], "%s", secure_mpz_get_str_16(t));
	xpuk = secure_mpz_get_str_16(public_key.x);
	msg = hexlify(sha256_hash(message), SHA256_HASH_SIZE);
	sprintf(&tmp[SHA256_HASH_HEX_SIZE], "%s", xpuk);
	sprintf(&tmp[2 * SHA256_HASH_HEX_SIZE], "%s", msg);

	mpz_init_set_str(k0, hexlify(tagged_hash("BIP0340/nonce", tmp), SHA256_HASH_SIZE), 16);
	mpz_mod(k0, k0, N);

	if (mpz_cmp_ui(k0, 0) == 0) {
		fprintf(stderr, "Failure. This happens only with negligible probability.\n");
		exit(EXIT_FAILURE);
	}

	point_create(&ephemeral_key, NULL);
	point_mul(&ephemeral_key, k0, &G);
	assert(!is_infinity(&ephemeral_key));
	if (!mpz_even_p(ephemeral_key.y)) {
		mpz_sub(k0, N, k0);
	}

	sprintf(&tmp[0], "%s", secure_mpz_get_str_16(ephemeral_key.x));
	sprintf(&tmp[SHA256_HASH_HEX_SIZE], "%s", xpuk);
	sprintf(&tmp[2 * SHA256_HASH_HEX_SIZE], "%s", msg);
	mpz_init_set_str(e, hexlify(tagged_hash("BIP0340/challenge", tmp), SHA256_HASH_SIZE), 16);
	mpz_mod(e, e, N);

	mpz_init_set(sig.r, ephemeral_key.x);
	mpz_init_set(sig.s, e);
	mpz_mul(sig.s, sig.s, d0);
	mpz_add(sig.s, sig.s, k0);
	mpz_mod(sig.s, sig.s, N);

	sprintf(&result[0], "%s", secure_mpz_get_str_16(sig.r));
	sprintf(&result[SHA256_HASH_HEX_SIZE], "%s", secure_mpz_get_str_16(sig.s));

	mpz_clears(d0, t, k0, e, NULL);
	mpz_clears(public_key.x, public_key.y, NULL);
	mpz_clears(ephemeral_key.x, ephemeral_key.y, NULL);
	mpz_clears(sig.s, sig.r, NULL);
	free(xpuk);

	return result;
}


EXPORT short verify(const char *message, const char *sig, const char *puk_x) {
    Point *l_puk, R, sG;
    mpz_t e, r, s, x;
	char part[SHA256_HASH_HEX_SIZE + 1];
	char tmp[SHA256_HASH_HEX_SIZE * 3 + 1];
    short result;

	strncpy(part, sig, SHA256_HASH_HEX_SIZE);
	mpz_init_set_str(r, part, 16);
	strncpy(part, sig + SHA256_HASH_HEX_SIZE, SHA256_HASH_HEX_SIZE);
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

	sprintf(&tmp[0], "%s", secure_mpz_get_str_16(r));
	sprintf(&tmp[SHA256_HASH_HEX_SIZE], "%s", secure_mpz_get_str_16(l_puk->x));
	sprintf(&tmp[2 * SHA256_HASH_HEX_SIZE], "%s", hexlify(sha256_hash(message), SHA256_HASH_SIZE));
    mpz_init_set_str(e, hexlify(tagged_hash("BIP0340/challenge", tmp), SHA256_HASH_SIZE), 16);
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

    return result;
}


int main() {
    Point puk;
    mpz_t d0;
    char *tag = "BIP0340/challenge\0";
    char *x, *sig;

	set_infinity(&puk);

	x = hexlify(sha256_hash("my very 12 word secret"), SHA256_HASH_SIZE);
    mpz_init_set_str(d0, x, 16);
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

    return 0;
}
