all: ufsend ufrec

ufsend: ufsend.c
	gcc -o ufsend ufsend.c -lssl -lcrypto 

ufrec: ufrec.c
	gcc -o ufrec ufrec.c -lssl -lcrypto
