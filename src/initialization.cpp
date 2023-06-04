#include "library.h"

void printBN(const char* msg, const BIGNUM* a) {
    char* number_str = BN_bn2dec(a);
    std::cout << msg << ": " << number_str << std::endl;
    OPENSSL_free(number_str);
}

BIGNUM* generateLargePrime(int numBits) {
    BIGNUM* primeNumber = BN_new();
    // Ініціалізація генератора випадкових чисел
    RAND_poll();
    // Генерація великого простого числа
    while (1) {
        // Генерація випадкового числа заданої довжини
        BIGNUM* randomNumber = BN_new();
        BN_rand(randomNumber, numBits, 0, 1);
        // Встановлення найстаршого біту, щоб забезпечити довжину числа
        BN_set_bit(randomNumber, numBits - 1);
        // Перевірка, чи є число простим
        int isPrime = BN_generate_prime_ex(randomNumber, numBits, 0, NULL, NULL, NULL);
        if (isPrime) {
            primeNumber = randomNumber;
            break;
        }
        else {
            BN_free(randomNumber);
        }
    }
    return primeNumber;
}


BIGNUM* generateCoPrime(BIGNUM* p,BIGNUM* q) {
    BIGNUM* a = BN_new();
    BIGNUM* phi = BN_new();
    BIGNUM* gcd = BN_new();
    BN_CTX* ctx = BN_CTX_secure_new();

    // Обчислення (p-1)(q-1)
    BN_sub_word(p, 1);
    BN_sub_word(q, 1);
    BN_mul(phi, p, q, ctx);

    while (1) {
        // Генерація випадкового числа
        BN_rand_range(a, phi);

        // Перевірка, чи є a взаємно простим з phi
        BN_gcd(gcd, a, phi, ctx);
        if (BN_is_one(gcd))
            break;
    }

    // Відновлення значень p та q
    BN_add_word(p, 1);
    BN_add_word(q, 1);

    BN_free(phi);
    BN_free(gcd);
    BN_CTX_free(ctx);

    return a;
}


BIGNUM* modSquare(const BIGNUM* a, const BIGNUM* n) {
    BIGNUM* x = BN_new();
    BN_CTX* ctx = BN_CTX_secure_new();

    // Обчислення квадрата числа a за модулем n
    BN_mod_sqr(x, a, n, ctx);

    BN_CTX_free(ctx);

    return x;
}

BIGNUM* computePublicKey( BIGNUM* s,  BIGNUM* n) {
    BIGNUM* square = BN_new();
    BN_sqr(square, s, BN_CTX_secure_new());
    BN_mod(square, square, n, BN_CTX_secure_new());
    return square;
}

BIGNUM* generateRandomInRange(const BIGNUM* n) {
    BIGNUM* r = BN_new();
    BN_rand_range(r, n);
    if (BN_is_zero(r))
        BN_add_word(r, 1);
    return r;
}

BIGNUM* computeX(const BIGNUM* r, const BIGNUM* n) {
    BIGNUM* res = BN_new();
    BN_sqr(res, r, BN_CTX_secure_new());
    BN_mod(res, res, n, BN_CTX_secure_new());
    return res;

}

int generateRandomBit() {
    srand(time(NULL));
    return rand() % 2;
}

BIGNUM* computeY(const BIGNUM* r, const BIGNUM* s, int e) {
    BIGNUM* y = BN_new();
    BIGNUM* exponent = BN_new();

    // Перетворення значення e з int в BIGNUM
    BN_set_word(exponent, e);

    // Обчислення y = r * (s^e)
    BN_mod_exp(y, s, exponent, r, BN_CTX_secure_new());
    BN_mul(y, y, r, BN_CTX_secure_new());

    return y;
}

bool verifyEquivalence(const BIGNUM* y, const BIGNUM* x, const BIGNUM* v, int e, const BIGNUM* n) {
    BIGNUM* left = BN_new();
    BIGNUM* right = BN_new();
    BIGNUM* square = BN_new();
    BIGNUM* exponent = BN_new();

    // Перетворення значення e з int в BIGNUM
    BN_set_word(exponent, e);

    // Обчислення лівої частини: y^2 (mod n)
    BN_sqr(square, y, BN_CTX_secure_new());
    BN_mod(left, square, n, BN_CTX_secure_new());

    // Обчислення правої частини: x * v^e (mod n)
    BN_mod_exp(right, v, exponent, n, BN_CTX_secure_new());
    BN_mul(right, right, x, BN_CTX_secure_new());
    BN_mod(right, right, n, BN_CTX_secure_new());

    // Перевірка еквівалентності
    bool equivalence = (BN_cmp(left, right) == 0);

    
    // Очищення пам'яті
    BN_free(left);
    BN_free(right);
    BN_free(square);
    BN_free(exponent);

    return equivalence;
}



