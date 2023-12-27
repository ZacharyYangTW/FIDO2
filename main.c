#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


//my code
#include "./tinycbor/src/cbor.h"
#include "mycbor.h"

#include "mycrypto.h"

/*
 * main
 */
int main(int argc, char *argv[])          
{
    printf("\nhi, Zach\n");
    printf("argc=%d\n", argc);
    printf("argc[0]=%s\n", argv[0]);
    printf("argc[1]=%s\n", argv[1]);
    printf("argc[2]=%s\n", argv[2]);
    printf("\n\n");
	
    //mycrypto.c
    //test_sha256_org();
    //test_sha256_ctap();
    //test_encrypt_cbc();
    //test_decrypt_cbc();
    //test_ecc_256();
    //test_myecdsa();

    //test_myecc256();

    //mycbor.c
    //test_cbor(argc, argv);

    myctap();
    //mystring();

    return 0;
}
