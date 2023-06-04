#include "headers.h"

int t = 5;


int main() {
	

	//створюємо секрет, відомий стороні А
	BIGNUM* s = BN_new();
	s = generateLargePrime(16);
	printBN("s", s);
	//генеруємо два великі випадкові прості числа p i q
	BIGNUM* p = BN_new();
	p = generateLargePrime(16);
	BIGNUM* q = BN_new();
	q = generateLargePrime(16);
	printBN("q", q);
	printBN("p", p);


	//обчислюємо на стороні В n = p*q, n -загальновідоме значення
	BIGNUM* n = BN_new();
	BN_mul(n,p, q, BN_CTX_secure_new());
	printBN("n", n);

	//генеруємо відкритий ключ v = s^2 mod n на стороні А
	BIGNUM* v = BN_new();
	v = computePublicKey(s, n);
	printBN("public key v", v);

	//знаходимо r яке належить проміжку {1, n - 1 }
	BIGNUM* r = BN_new();
	r = generateRandomInRange(n);
	printBN("r", r);

	//обчислюємо x = r^2 % n та передаємо на сторону B
	BIGNUM* x = BN_new();
	x = computeX(r, n);
	printBN("x", x);

	std::cout << "Alice send x to Bob" << std::endl;

	bool result = false;
	int e;

	do {
		//на стороні б генерується біт e в ренжі {0,1} та відправляєтсья на сторону А
		e = generateRandomBit();
		std::cout << "e bit : " << e << std::endl;
		std::cout << "Bob send e to Alie" << std::endl;

		//Alice обчислює y = r*s^e та відправляє на сторону B
		BIGNUM* y = BN_new();
		y = computeY(r, s, e);
		printBN("y", y);

		std::cout << "Alice send y to Bob" << std::endl;
		//y = generateCoPrime(p, q);
		//Боб перевіряє знання секрету алісою виконуючи y^2 == x*v^e (mod n)
		y = generateLargePrime(128);
		if (verifyEquivalence(y, x, v, e, n) == true)
			result = true;
		else
			result = false;
		BN_free(y);
		--t;
	} while (t != 0);

	if (result == true)
		std::cout << "Authentification success!" << std::endl;
	else
		std::cout << "Authentification failed!" << std::endl;



	BN_free(x);
	BN_free(r);
	BN_free(v);
	BN_free(n);
	BN_free(p);
	BN_free(q);
	return 0;
}

