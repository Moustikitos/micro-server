#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <gmp.h>

#if __linux__ 
    #define EXPORT extern
#elif _WIN32
    #define _USE_MATH_DEFINES // for C
    #define EXPORT __declspec(dllexport)
#endif

#define EVP_SHA256_SIZE EVP_MD_size(EVP_sha256())
#define SHA256_HASH_SIZE 32
#define SHA256_HASH_HEX_SIZE 64

typedef struct { mpz_t x, y; } Point;
typedef struct { mpz_t r, s; } Signature;

// Déclaration des variables globales (exposées aux autres fichiers)
mpz_t P, N, A, B;
Point G;


// Fonction d'initialisation automatique (exécutée à l'inclusion du fichier)
static inline void init_secp256k1_params(void) {
    mpz_init_set_str(A, "00", 16);
    mpz_init_set_str(B, "07", 16);
    mpz_init_set_str(P, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    mpz_init_set_str(N, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    mpz_init_set_str(G.x, "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
    mpz_init_set_str(G.y, "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
}


// Fonction pour libérer la mémoire des BIGNUM
static inline void cleanup_secp256k1_params(void) {
    mpz_clears(G.x, G.y, A, B, N, P, NULL);
}


// Exécution automatique de l'initialisation
__attribute__((constructor)) static void auto_init() { init_secp256k1_params(); }
__attribute__((destructor)) static void auto_cleanup() { cleanup_secp256k1_params(); }


/**
 * @brief Affiche un tableau d'octets en hexadécimal.
 *
 * @param data  Tableau d'octets.
 * @param len   Taille du tableau.
 */
void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}


/**
 * @brief Effectue un Tagged Hash (SIPA Schnorr) avec SHA256.
 *
 * @param tag  Le tag à utiliser (chaîne de caractères).
 * @param message  Le message à hasher (chaîne de caractères).
 * @return Tableau de 32 octets pour stocker le hash résultant.
 */
unsigned char *tagged_hash(const char *tag, const char *message) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    unsigned char *output = malloc(SHA256_HASH_SIZE * sizeof(unsigned char));
    unsigned char tag_hash[SHA256_HASH_SIZE];
    unsigned int tag_hash_len;

    if (mdctx == NULL) {
        fprintf(stderr, "Erreur lors de la création du contexte EVP_MD_CTX\n");
        exit(EXIT_FAILURE);
    }
    // 1. Hasher le tag une première fois
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(mdctx, tag, strlen(tag)) != 1 ||
        EVP_DigestFinal_ex(mdctx, tag_hash, &tag_hash_len) != 1) {
        fprintf(stderr, "Erreur lors du hachage du tag\n");
        EVP_MD_CTX_free(mdctx);
        exit(EXIT_FAILURE);
    }
    // 2. Concaténer tag_hash || tag_hash || message et calculer le hash final
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(mdctx, tag_hash, tag_hash_len) != 1 ||
        EVP_DigestUpdate(mdctx, tag_hash, tag_hash_len) != 1 ||
        EVP_DigestUpdate(mdctx, message, strlen(message)) != 1 ||
        EVP_DigestFinal_ex(mdctx, output, NULL) != 1) {
        fprintf(stderr, "Erreur lors du hachage final\n");
        EVP_MD_CTX_free(mdctx);
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX_free(mdctx);
    // output[SHA256_HASH_SIZE] = '\0'; // Ajouter le caractère nul de fin
    return output;
}


/**
 * Calcule le hachage SHA-256 d'une chaîne de caractères en utilisant OpenSSL EVP.
 *
 * @param input La chaîne de caractères à hacher.
 * @return Le tableau de caractères où le hachage hexadécimal sera stocké.
 */
unsigned char *sha256_hash(const char *input) { //}, char output[EVP_SHA256_SIZE]) {
    EVP_MD_CTX *mdctx; // Contexte de message pour le hachage
    unsigned char *output = malloc(SHA256_HASH_SIZE * sizeof(unsigned char));
    unsigned int hash_len; // Longueur du hachage

    // Créer un nouveau contexte de hachage
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        fprintf(stderr, "Erreur lors de la création du contexte EVP_MD_CTX\n");
        exit(EXIT_FAILURE);
    }
    // Initialiser le contexte pour SHA-256
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(mdctx, input, strlen(input)) != 1 ||
        EVP_DigestFinal_ex(mdctx, output, &hash_len) != 1) {
        fprintf(stderr, "Erreur lors du hachage\n");
        EVP_MD_CTX_free(mdctx);
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX_free(mdctx);
    // output[SHA256_HASH_SIZE] = '\0'; // Ajouter le caractère nul de fin
    return output;
}


/**
 * Génère une chaîne hexadécimale aléatoire de taille spécifiée.
 *
 * @param size Nombre d'octets aléatoires à générer.
 * @return Tableau où stocker la chaîne hexadécimale.
 */
unsigned char *random_bytes(size_t size) {
    unsigned char *output = malloc(size * sizeof(unsigned char));
    // Générer des octets aléatoires avec OpenSSL
    if (RAND_bytes(output, size) != 1) {
        fprintf(stderr, "Erreur : Échec de la génération aléatoire.\n");
        exit(EXIT_FAILURE);
    }
    // output[size] = '\0'; // Ajouter le caractère nul de fin
    return output;
}


/**
 * Génère une chaîne hexadécimale à partir d'un buffer.
 *
 * @param input Tableau où stocker la chaîne de bytes.
 * @param size Ttaille du tableau d'entrée.
 * @return Tableau où stocker la chaîne hexadécimale.
 */
char *hexlify(const unsigned char *input, size_t size) {
    char *output = malloc(2 * size * sizeof(char) +1); 
    // Convertir chaque octet en sa représentation hexadécimale
    for (size_t i = 0; i < size; i++) { sprintf(&output[i * 2], "%02x", input[i]); }
    output[size * 2] = '\0'; // Ajouter le caractère nul de fin
    return output;
}


void set_infinity(Point *M) {
    mpz_init_set_ui(M->x, 0);
    mpz_init_set_ui(M->y, 0);
}


short is_infinity(const Point *M) {
    return mpz_cmp_ui(M->x, 0) == 0 && mpz_cmp_ui(M->y, 0) == 0 ? 1 : 0;
}


short has_square_y(const Point *M) {
    return is_infinity(M)== 0 && mpz_jacobi(M->y, P) == 1 ? 1 : 0;
}


short point_on_curve(Point *M) {
    mpz_t tmp, x3;
    mpz_init_set(tmp, M->y);
    mpz_init_set(x3, M->x);

    mpz_mul(tmp, tmp, M->y);
    mpz_mul(x3, x3, M->x);
    mpz_mul(x3, x3, M->x);
    mpz_sub(tmp, tmp, x3);
    mpz_sub_ui(tmp, tmp, 7);

    short test = mpz_cmp_ui(tmp, 0) == 0 ? 1 : 0;
    mpz_clears(tmp, x3, NULL);
    return test;
}


void destroy_point(Point *M) {
    mpz_clears(M->x, M->y, NULL);
    free(M);
}


void destroy_sig(Signature *sig) {
    mpz_clears(sig->r, sig->s, NULL);
    free(sig);
}


// Compute `y` from `x` according to `y²=x³+7`
void y_from_x(mpz_t y, mpz_t x) {
    mpz_t y_sq, y_2, pp1s4;
    // unsigned long int pp1s4;
    mpz_inits(y_sq, y_2, pp1s4, NULL);
    // y_sq = (pow(x, 3, p) + 7) % p
    mpz_powm_ui(y_sq, x, 3, P);
    mpz_add_ui(y_sq, y_sq, 7);
    mpz_mod(y_sq, y_sq, P);
    // y = pow(y_sq, (p + 1) // 4, p)
    mpz_add_ui(pp1s4, P, 1);
    mpz_fdiv_q_ui(pp1s4, pp1s4, 4);
    mpz_powm(y, y_sq, pp1s4, P);
    // if pow(y, 2, p) != y_sq:
    //     return None
    mpz_powm_ui(y_2, y, 2, P);
    if (mpz_cmp(y_2, y_sq) != 0) {
        mpz_init_set_ui(y, 0);
    }
    mpz_clears(y_sq, y_2, pp1s4, NULL);
}


Point *point_copy(const Point *M){
    static Point copy;
    mpz_init_set(copy.x, M->x);
    mpz_init_set(copy.y, M->y);
    return &copy;
}


void point_add(Point *sum, Point *P1, Point *P2) {
    if (is_infinity(P1)) {
        if (is_infinity(P2)) {
            return set_infinity(sum);
        } else {
            mpz_init_set(sum->x, P2->x);
            mpz_init_set(sum->y, P2->y);
            return;   
        }
    } else if (is_infinity(P2)) {
        mpz_init_set(sum->x, P1->x);
        mpz_init_set(sum->y, P1->y);
        return;
    } else {
        // check if points sum is infinity element
        mpz_t negy;
        mpz_init(negy);
        mpz_sub(negy, P, P2->y);
        if (mpz_cmp(P1->x, P2->x) == 0 && mpz_cmp(P1->y, negy) == 0) {
            mpz_clear(negy);
            return set_infinity(sum);
        }
    }

    mpz_t pm2, lambda;
    mpz_inits(pm2, lambda, NULL);
    mpz_sub_ui(pm2, P, 2);
    // if (xP1 == xP2):
    if (mpz_cmp(P1->x, P2->x) == 0) {
        // if yP1 != yP2: --> point P2 not on curve
        if (mpz_cmp(P1->y, P2->y) != 0) {
            mpz_clears(pm2, lambda, NULL);
            return set_infinity(sum);
        } else {
            mpz_t xp1_2, _2yp1;
            mpz_inits(xp1_2, _2yp1, NULL);
            // lam = (3 * xP1 * xP1 * pow(2 * yP1, p - 2, p)) % p
            mpz_mul(xp1_2, P1->x, P1->x);   // xp1_2 <- P1.x * P1.x 
            mpz_mul_ui(xp1_2, xp1_2, 3);    // xp1_2 <- 3 * xp1_2
            mpz_mul_ui(_2yp1, P1->y, 2);    // _2yp1 <- 2 * P1.y
            mpz_powm(_2yp1, _2yp1, pm2, P); // _2yp1 <- pow(_2yp1, pm2, p)
            mpz_mul(lambda, xp1_2, _2yp1);
            mpz_clears(xp1_2, _2yp1, NULL);
        }
    } else {
        mpz_t diff_x, diff_y;
        mpz_inits(diff_x, diff_y, NULL);
        // lam = ((yP2 - yP1) * pow(xP2 - xP1, p - 2, p)) % p
        mpz_sub(diff_y, P2->y, P1->y);
        mpz_sub(diff_x, P2->x, P1->x);
        mpz_powm(diff_x, diff_x, pm2, P);
        mpz_mul(lambda, diff_y, diff_x);
        mpz_clears(diff_x, diff_y, NULL);
    }
    mpz_mod(lambda, lambda, P);
    // x3 = (lam * lam - xP1 - xP2) % p
    mpz_inits(sum->x, sum->y, NULL);
    mpz_mul(sum->x, lambda, lambda);
    mpz_sub(sum->x, sum->x, P1->x);
    mpz_sub(sum->x, sum->x, P2->x);
    mpz_mod(sum->x, sum->x, P);
    // return [x3, (lam * (xP1 - x3) - yP1) % p]
    mpz_sub(sum->y, P1->x, sum->x);
    mpz_mul(sum->y, sum->y, lambda);
    mpz_sub(sum->y, sum->y, P1->y);
    mpz_mod(sum->y, sum->y, P);

    mpz_clears(pm2, lambda, NULL);
}


void point_mul(Point *prod, const Point *M, const mpz_t scalar) {
    Point R, *tmp;
    mpz_init_set(R.x, M->x);
    mpz_init_set(R.y, M->y);
    mpz_init_set_ui(prod->x, 0);
    mpz_init_set_ui(prod->y, 0);
    // for i in number of bits:
    int dbits = mpz_sizeinbase(scalar, 2);
    for (int i = 0; i < dbits; i++) {
        // if ((n >> i) & 1):
        if (mpz_tstbit(scalar, i)) {
            // R = point_add(R, P)
            point_add(prod, &R, point_copy(prod));
        }
        // P = point_add(P, P)
        tmp = point_copy(&R);
        point_add(&R, tmp, tmp);
    }
    mpz_clears(R.x, R.y, tmp->x, tmp->y, NULL);
}
