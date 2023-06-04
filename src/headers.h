#pragma once
#include "library.h"

BIGNUM* generateLargePrime(int numBits);
void printBN(const char* msg, const BIGNUM* a);
BIGNUM* generateCoPrime(BIGNUM* p, BIGNUM* q);
BIGNUM* modSquare(const BIGNUM* a, const BIGNUM* n);
BIGNUM* computePublicKey(BIGNUM* s, BIGNUM* n);
BIGNUM* generateRandomInRange(const BIGNUM* n);
BIGNUM* computeX(const BIGNUM* r, const BIGNUM* n);
int generateRandomBit();
BIGNUM* computeY(const BIGNUM* r, const BIGNUM* s, int e);
bool verifyEquivalence(const BIGNUM* y, const BIGNUM* x, const BIGNUM* v, int e, const BIGNUM* n);