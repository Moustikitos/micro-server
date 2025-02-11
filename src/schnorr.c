#include "secp256k1.h"


char *secure_mpz_get_str_16(mpz_t value){
    char *str_16 = malloc((SHA256_HASH_HEX_SIZE + 1) *sizeof(char));
    for (size_t i=0; i < 64; i++) { str_16[i] = '0'; }
    mpz_get_str(str_16, 16, value);
    str_16[SHA256_HASH_HEX_SIZE] = '\0';
    return str_16;
}


EXPORT Signature *sign(const char *message, const char *secret, unsigned char *aux_rand){
    static Signature result;
    Point public_key, ephemeral_key;
    mpz_t d0, k0, t, e;
    unsigned char *msg, *rand, *sct, *tagged;
    char tmp[256], *str_16;
    int i, len_digest;

    msg = sha256_hash(message);
    len_digest = strlen(msg);

    if (aux_rand == NULL){ rand = random_bytes(32); }

    sct = sha256_hash(secret);
    mpz_init_set_str(d0, hexlify(sct,  SHA256_HASH_SIZE), 16);

//     if not (1 <= d0 <= N - 1):
//         raise ValueError(
//             'The secret key must be an integer in the range 1..N-1.'
//         )

    point_mul(&public_key, &G, d0);
//     assert public_key is not None
    if (mpz_fdiv_ui(public_key.y, 2) != 0) {mpz_sub(d0, N, d0);}

    tagged = tagged_hash("BIP0340/aux", rand);
    mpz_init_set_str(t, hexlify(tagged, SHA256_HASH_SIZE), 16);
    mpz_xor(t, d0, t);

    str_16 = secure_mpz_get_str_16(t);
    for (i = 0; i < 64; i++){ tmp[i] = str_16[i]; }
    str_16 = secure_mpz_get_str_16(public_key.x);
    for (i = 64; i < 128; i++){ tmp[i] = str_16[i-64]; }
    for (i = 128; i < 128 + len_digest; i++){ tmp[i] = msg[i-128]; }
    tmp[i] = '\0';
    tagged = tagged_hash("BIP0340/nonce", tmp);
    mpz_init_set_str(k0, hexlify(tagged, SHA256_HASH_SIZE), 16);
    mpz_mod(k0, k0, N);

//     if k0 == 0:
//         raise RuntimeError(
//             'Failure. This happens only with negligible probability.'
//         )

    point_mul(&ephemeral_key, &G, k0);
//     assert R is not None
    if (mpz_fdiv_ui(ephemeral_key.y, 2) != 0) {mpz_sub(k0, N, k0);}

    str_16 = secure_mpz_get_str_16(ephemeral_key.x);
    for (i=0; i < 64; i++){ tmp[i] = str_16[i]; }
    tagged = tagged_hash("BIP0340/challenge", tmp);
    mpz_init_set_str(e, hexlify(tagged, SHA256_HASH_SIZE), 16);
    mpz_mod(e, e, N);
    
    mpz_init_set(result.r, ephemeral_key.x);
    mpz_init_set(result.s, e);
    mpz_mul(result.s, result.s, d0);
    mpz_add(result.s, result.s, k0);
    mpz_mod(result.s, result.s, N);

    mpz_clears(d0, t, k0, e, NULL);
    mpz_clears(public_key.x, public_key.y, ephemeral_key.x, ephemeral_key.y, NULL);

    return &result;
}


int main() {
    const char *tag = "BIP0340/challenge";
    const char *message = "Hello, Schnorr!";
    Signature *sig;

    printf("Tagged hash: %s\n", hexlify(tagged_hash(tag, message), SHA256_HASH_SIZE));
    printf("Random 32 bytes buffer: %s\n", hexlify(random_bytes(SHA256_HASH_SIZE), SHA256_HASH_SIZE));
    printf("SHA256: %s\n", hexlify(sha256_hash(message), SHA256_HASH_SIZE));

    sig = sign("test", "my 12 word secret", NULL);
    printf("SCHNORR:\n");
    gmp_printf("r = %Zx \n", sig->r);
    gmp_printf("s = %Zx \n", sig->s);
    return 0;
}
