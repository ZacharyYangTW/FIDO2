#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


//external library
#include "./crypto/sha256/sha256.h"
#include "./crypto/tiny-AES-c/aes.h"
#include "./crypto/ecc/uECC.h"

//cbor
#include "./tinycbor/src/cbor.h"
#include "mycbor.h"

#include "mycrypto.h"

/*
 * SHA256
 */
static SHA256_CTX sha256_ctx;
#define SHA256_DIGEST_LENGTH 32

/*
 * AES
 */
struct AES_ctx aes_ctx;
static uint8_t transport_secret[32];

#define CRYPTO_TRANSPORT_KEY            ((uint8_t*)1)

/*
 * ECC
 */
uint8_t KEY_AGREEMENT_PRIV[32] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
uint8_t KEY_AGREEMENT_PUB[32];
static const struct uECC_Curve_t * _es256_curve = NULL;

/*
 * SHA256
 */
void crypto_sha256_init(void)
{
    sha256_init(&sha256_ctx);
}

void crypto_sha256_update(uint8_t * data, size_t len)
{
    sha256_update(&sha256_ctx, data, len);
}
void crypto_sha256_final(uint8_t * hash)
{
    sha256_final(&sha256_ctx, hash);
}


/*
 * SHA - 256 origin
 */
void test_sha256_org(void)
{
    uint8_t buf[64]="abc";
    static uint8_t hash[32];
    char outputBuffer[65];
	
    int i;

    printf("buf: %s\n", buf);
    crypto_sha256_init();
    printf("strlen(buf): %d\n", (int)strlen(buf));
    crypto_sha256_update(buf, strlen(buf));
    crypto_sha256_final(hash);

    printf("hash: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

/*
 * SHA - 256 ctap
 */
void test_sha256_ctap(void)
{

    uint8_t buf[64]="abc";
    static uint8_t hash[32];
    char outputBuffer[65];
	
    int i;

    printf("buf: %s\n", buf);
    crypto_sha256_init();
    crypto_sha256_update(buf, 64);
    crypto_sha256_final(hash);

    printf("hash: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

/*
 * AES
 */

void crypto_aes256_init(uint8_t * key, uint8_t * nonce)
{
    if (key == CRYPTO_TRANSPORT_KEY)
    {
        AES_init_ctx(&aes_ctx, transport_secret);
    }
    else
    {
        AES_init_ctx(&aes_ctx, key);
    }
    if (nonce == NULL)
    {
        memset(aes_ctx.Iv, 0, 16);
    }
    else
    {
        memmove(aes_ctx.Iv, nonce, 16);
    }
}
void crypto_aes256_decrypt(uint8_t * buf, int length)
{
    AES_CBC_decrypt_buffer(&aes_ctx, buf, length);
}

void crypto_aes256_encrypt(uint8_t * buf, int length)
{
    AES_CBC_encrypt_buffer(&aes_ctx, buf, length);
}

void test_encrypt_cbc(void)
{
    int i;

#ifdef AES128
    uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    uint8_t out[] = { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
                      0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
                      0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
                      0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7 };
#elif defined(AES192)
    uint8_t key[] = { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
    uint8_t out[] = { 0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d, 0x71, 0x78, 0x18, 0x3a, 0x9f, 0xa0, 0x71, 0xe8,
                      0xb4, 0xd9, 0xad, 0xa9, 0xad, 0x7d, 0xed, 0xf4, 0xe5, 0xe7, 0x38, 0x76, 0x3f, 0x69, 0x14, 0x5a,
                      0x57, 0x1b, 0x24, 0x20, 0x12, 0xfb, 0x7a, 0xe0, 0x7f, 0xa9, 0xba, 0xac, 0x3d, 0xf1, 0x02, 0xe0,
                      0x08, 0xb0, 0xe2, 0x79, 0x88, 0x59, 0x88, 0x81, 0xd9, 0x20, 0xa9, 0xe6, 0x4f, 0x56, 0x15, 0xcd };
#elif defined(AES256)
    uint8_t key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                      0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
    uint8_t out[] = { 0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
                      0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
                      0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
                      0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b };
#endif
    uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    uint8_t in[]  = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                      0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                      0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                      0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
    struct AES_ctx ctx;

    printf("key: ");
    for (int i = 0; i < strlen(key); i++) {
        printf("%02x", key[i]);
    }
    printf("\n");
    printf("in: ");
    for (int i = 0; i < strlen(in); i++) {
        printf("%02x", in[i]);
    }
    printf("\n");

    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, in, 64);
    printf("in: ");
    for (int i = 0; i < strlen(in); i++) {
        printf("%02x", in[i]);
    }
    printf("\n");

    printf("CBC encrypt: ");

    if (0 == memcmp((char*) out, (char*) in, 64))
    {
        printf("SUCCESS!\n");
    }
    else
    {
        printf("FAILURE!\n");
    }
}

void test_decrypt_cbc(void)
{
    int i;

#ifdef AES128
    uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    uint8_t in[]  = { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
                      0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
                      0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
                      0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7 };
#elif defined(AES192)
    uint8_t key[] = { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
    uint8_t in[]  = { 0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d, 0x71, 0x78, 0x18, 0x3a, 0x9f, 0xa0, 0x71, 0xe8,
                      0xb4, 0xd9, 0xad, 0xa9, 0xad, 0x7d, 0xed, 0xf4, 0xe5, 0xe7, 0x38, 0x76, 0x3f, 0x69, 0x14, 0x5a,
                      0x57, 0x1b, 0x24, 0x20, 0x12, 0xfb, 0x7a, 0xe0, 0x7f, 0xa9, 0xba, 0xac, 0x3d, 0xf1, 0x02, 0xe0,
                      0x08, 0xb0, 0xe2, 0x79, 0x88, 0x59, 0x88, 0x81, 0xd9, 0x20, 0xa9, 0xe6, 0x4f, 0x56, 0x15, 0xcd };
#elif defined(AES256)
    uint8_t key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                      0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
    uint8_t in[]  = { 0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
                      0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
                      0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
                      0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b };
#endif
    uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    uint8_t out[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                      0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                      0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                      0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
//  uint8_t buffer[64];
    struct AES_ctx ctx;

    printf("key: ");
    for (int i = 0; i < strlen(key); i++) {
        printf("%02x", key[i]);
    }
    printf("\n");
    printf("in: ");
    for (int i = 0; i < strlen(in); i++) {
        printf("%02x", in[i]);
    }
    printf("\n");

    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_decrypt_buffer(&ctx, in, 64);
    printf("in: ");
    for (int i = 0; i < strlen(in); i++) {
        printf("%02x", in[i]);
    }
    printf("\n");

    printf("CBC decrypt: ");

    if (0 == memcmp((char*) out, (char*) in, 64))
    {
        printf("SUCCESS!\n");
    }
    else
    {
        printf("FAILURE!\n");
    }
}

/*
 * ECC
 */
void crypto_ecc256_compute_public_key(uint8_t * privkey, uint8_t * pubkey)
{
    uECC_compute_public_key(privkey, pubkey, _es256_curve);
}

#define RUN_TESTS(curve) \
    printf(#curve ":\n"); \
    if (run(curve##_tests, sizeof(curve##_tests) / sizeof(curve##_tests[0]), uECC_##curve()) ) { \
        printf("  All passed\n"); \
    } else { \
        printf("  Failed\n"); \
    }

typedef struct {
  const char* k;
  const char* Q;
  int success;
} Test;

void vli_print(uint8_t *vli, unsigned int size) {
    for(unsigned i=0; i<size; ++i) {
        printf("%02X ", (unsigned)vli[i]);
    }
    printf("\n");
}

void strtobytes(const char* str, uint8_t* bytes, int count) {
  for (int c = 0; c < count; ++c) {
    if (sscanf(str, "%2hhx", &bytes[c]) != 1) {
      printf("Failed to read string to bytes");
      exit(1);
    }
    str += 2;
  }
}

int run(Test* tests, int num_tests, uECC_Curve curve) {
    uint8_t private[32] = {0};
    uint8_t public[64] = {0};
    uint8_t expected[64] = {0};
    int result;
    int i;
    int private_key_size;
    int public_key_size;
    int all_success = 1;

    private_key_size = uECC_curve_private_key_size(curve);
    public_key_size = uECC_curve_public_key_size(curve);
    printf("private_key_size %d\n", private_key_size);
    printf("public_key_size %d\n", public_key_size);




    for (i = 0; i < num_tests; ++i) {
    printf("\ni=%d, tests[i].k=%s:\n", i, tests[i].k);
    printf("\ni=%d, tests[i].Q=%s:\n", i, tests[i].Q);

        strtobytes(tests[i].k, private, private_key_size);
        result = uECC_compute_public_key(private, public, curve);
        if (result != tests[i].success) {
            all_success = 0;
            printf("  Got unexpected result from test %d: %d\n", i, result);
        }
//    printf("\ni=%d, private:\n", i);
//    dump_hex_mycrypto(private, private_key_size);

//    printf("\ni=%d, public(Calculated):\n", i);
//    dump_hex_mycrypto(public, public_key_size);

    printf("\nresult: %d\n", result);

        //if (result) {
        if (1) {
            strtobytes(tests[i].Q, expected, public_key_size);
            if (memcmp(public, expected, public_key_size) != 0) {
                all_success = 0;
                printf("  Got incorrect public key for test %d\n", i);
                printf("    Expected: ");
                vli_print(expected, public_key_size);
                printf("    Calculated: ");
                vli_print(public, public_key_size);
            }
        }
    }

    return all_success;
}

void test_public_key_test_vector(void)
{
Test my_tests[] = {
    {   /* n - 3 */
        "8e91efdeb33cb27d787facd2970addd8e7bd7e111e65ac463870363d8600d63c",
        "d7da800758e222a07f4ec5b7e3f6d34b91c9e53e8ab3e2b002f86c07347a01c7358c3a8e387c5a4b2347ceaf40798d5bf3ca10a0a6a8ca5c83bc76f95afbb9b3",
        1
    },

};
Test secp256r1_tests[] = {
    {
        "0000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        0
    },
    {
        "0000000000000000000000000000000000000000000000000000000000000001",
        "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
        0
    },
    {
        "0000000000000000000000000000000000000000000000000000000000000002",
        "7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC4766997807775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1",
        1
    },
    {
        "0000000000000000000000000000000000000000000000000000000000000003",
        "5ECBE4D1A6330A44C8F7EF951D4BF165E6C6B721EFADA985FB41661BC6E7FD6C8734640C4998FF7E374B06CE1A64A2ECD82AB036384FB83D9A79B127A27D5032",
        1
    },
    {   /* n - 4 */
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254D",
        "E2534A3532D08FBBA02DDE659EE62BD0031FE2DB785596EF509302446B0308521F0EA8A4B39CC339E62011A02579D289B103693D0CF11FFAA3BD3DC0E7B12739",
        1
    },
    {   /* n - 3 */
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254E",
        "5ECBE4D1A6330A44C8F7EF951D4BF165E6C6B721EFADA985FB41661BC6E7FD6C78CB9BF2B6670082C8B4F931E59B5D1327D54FCAC7B047C265864ED85D82AFCD",
        1
    },
    {   /* n - 2 */
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254F",
        "7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978F888AAEE24712FC0D6C26539608BCF244582521AC3167DD661FB4862DD878C2E",
        0
    },
    {   /* n - 1 */
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550",
        "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296B01CBD1C01E58065711814B583F061E9D431CCA994CEA1313449BF97C840AE0A",
        0
    },
    {   /* n */
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        0
    },
};
Test secp256k1_tests[] = {
    {
        "0000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        0
    },
    {
        "0000000000000000000000000000000000000000000000000000000000000001",
        "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
        0
    },
    {
        "0000000000000000000000000000000000000000000000000000000000000002",
        "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE51AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A",
        1
    },
    {
        "0000000000000000000000000000000000000000000000000000000000000003",
        "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672",
        1
    },
    {   /* n - 4 */
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413D",
        "E493DBF1C10D80F3581E4904930B1404CC6C13900EE0758474FA94ABE8C4CD13AE1266C15F2BAA48A9BD1DF6715AEBB7269851CC404201BF30168422B88C630D",
        1
    },
    {   /* n - 3 */
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413E",
        "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9C77084F09CD217EBF01CC819D5C80CA99AFF5666CB3DDCE4934602897B4715BD",
        1
    },
    {   /* n - 2 */
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413F",
        "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5E51E970159C23CC65C3A7BE6B99315110809CD9ACD992F1EDC9BCE55AF301705",
        0
    },
    {   /* n - 1 */
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140",
        "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798B7C52588D95C3B9AA25B0403F1EEF75702E84BB7597AABE663B82F6F04EF2777",
        0
    },
    {   /* n */
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        0
    },
};
/*
    printf("secp256k1:\n"); \
    if (run(secp256k1_tests, sizeof(secp256k1_tests) / sizeof(secp256k1_tests[0]), uECC_secp256k1()) ) { \
        printf("  All passed\n"); \
    } else { \
        printf("  Failed\n"); \
    }
*/
/*
    printf("secp256r1:\n"); \
    if (run(secp256r1_tests, sizeof(secp256r1_tests) / sizeof(secp256r1_tests[0]), uECC_secp256r1()) ) { \
        printf("  All passed\n"); \
    } else { \
        printf("  Failed\n"); \
    }
*/
    printf("secp256r1:\n"); \
    if (run(my_tests, sizeof(my_tests) / sizeof(my_tests[0]), uECC_secp256r1()) ) { \
        printf("  All passed\n"); \
    } else { \
        printf("  Failed\n"); \
    }
}


typedef struct {
  const char* private_key;
  const char* public_key;
  const char* k;
  const char* hash;
  const char* r;
  const char* s;
} Test2;

int run2(Test2* tests, int num_tests, uECC_Curve curve) {
    uint8_t private[32] = {0};
    uint8_t public[64] = {0};
    uint8_t k[32] = {0};
    uint8_t hash[32] = {0};
    uint8_t r[32] = {0};
    uint8_t s[32] = {0};

    uint8_t signature[64] = {0};

    int result;
    int i;
    int private_key_size;
    int public_key_size;
    int all_success = 1;

    private_key_size = uECC_curve_private_key_size(curve);
    public_key_size = uECC_curve_public_key_size(curve);

    for (i = 0; i < num_tests; ++i) {
        strtobytes(tests[i].private_key, private, private_key_size);
        strtobytes(tests[i].public_key, public, public_key_size);
        strtobytes(tests[i].k, k, private_key_size);
        strtobytes(tests[i].hash, hash, private_key_size);
        strtobytes(tests[i].r, r, private_key_size);
        strtobytes(tests[i].s, s, private_key_size);

        result = uECC_sign_with_k(private, hash, private_key_size, k, signature, curve);
        if (!result) {
            all_success = 0;
            printf("  Sign failed for test %d\n", i);
        }
        if (result) {
            if (memcmp(signature, r, private_key_size) != 0) {
                all_success = 0;
                printf("  Got incorrect r for test %d\n", i);
                printf("    Expected: ");
                vli_print(r, private_key_size);
                printf("    Calculated: ");
                vli_print(signature, private_key_size);
            }
            if (memcmp(signature + private_key_size, s, private_key_size) != 0) {
                all_success = 0;
                printf("  Got incorrect s for test %d\n", i);
                printf("    Expected: ");
                vli_print(s, private_key_size);
                printf("    Calculated: ");
                vli_print(signature + private_key_size, private_key_size);
            }

            result = uECC_verify(public, hash, private_key_size, signature, curve);
            if (!result) {
                printf("  Verify failed for test %d\n", i);
            }
        }

    }

    return all_success;
}

int run3(Test2* tests, int num_tests, uECC_Curve curve) {
    uint8_t private[32] = {0};
    uint8_t public[64] = {0};
    uint8_t k[32] = {0};
    uint8_t hash[32] = {0};
    uint8_t r[32] = {0};
    uint8_t s[32] = {0};

    uint8_t mysignature[64] = {0};

    int result;
    int i;
    int private_key_size;
    int public_key_size;
    int all_success = 1;

    private_key_size = uECC_curve_private_key_size(curve);
    public_key_size = uECC_curve_public_key_size(curve);

    for (i = 0; i < num_tests; ++i) {
        strtobytes(tests[i].public_key, public, public_key_size);
        strtobytes(tests[i].hash, hash, private_key_size);
        strtobytes(tests[i].r, r, private_key_size);
        strtobytes(tests[i].s, s, private_key_size);
		
	    int j;
	    for (j = 0; j < private_key_size; ++j) {
	        mysignature[j] = r[j];
	    }
	    for (j = 0; j < private_key_size; ++j) {
	        mysignature[private_key_size+j] = s[j];
	    }

	    //printf("\nmysignature: \n"); 
	    //dump_hex_mycrypto(mysignature, private_key_size+private_key_size);
	
            result = uECC_verify(public, hash, private_key_size, mysignature, curve);
            if (!result) {
                printf("  run3 Verify failed for test %d\n", i);
            }else
            {
                printf("  run3 Verify pass for test %d\n", i);
            }

    }

    return all_success;
}

void test_ecdsa_test_vector(void)
{
/*
Test2 secp256k1_tests2[] = {
    {
        "ebb2c082fd7727890a28ac82f6bdf97bad8de9f5d7c9028692de1a255cad3e0f",
        "779dd197a5df977ed2cf6cb31d82d43328b790dc6b3b7d4437a427bd5847dfcde94b724a555b6d017bb7607c3e3281daf5b1699d6ef4124975c9237b917d426f",
        "49a0d7b786ec9cde0d0721d72804befd06571c974b191efb42ecf322ba9ddd9a",
        "4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a",
        "241097efbf8b63bf145c8961dbdf10c310efbb3b2676bbc0f8b08505c9e2f795",
        "021006b7838609339e8b415a7f9acb1b661828131aef1ecbc7955dfb01f3ca0e"
    },
};
    printf("secp256k1:\n"); \
    if (run2(secp256k1_tests2, sizeof(secp256k1_tests2) / sizeof(secp256k1_tests2[0]), uECC_secp256k1()) ) { \
        printf("  All passed\n"); \
    } else { \
        printf("  Failed\n"); \
    }
*/

/*
typedef struct {
  const char* private_key;
  const char* public_key;
  const char* k;
  const char* hash;
  const char* r;
  const char* s;
} Test2;
*/


/*
Test2 secp256r1_tests2[] = {
    {
        "8e91efdeb33cb27d787facd2970addd8e7bd7e111e65ac463870363d8600d63c",//private_key
        "d7da800758e222a07f4ec5b7e3f6d34b91c9e53e8ab3e2b002f86c07347a01c7358c3a8e387c5a4b2347ceaf40798d5bf3ca10a0a6a8ca5c83bc76f95afbb9b3",//public_key
        "000000000000000000000000000000000000000000000000000000000007000a",//k=0x7000a
        "bd8ddc45bfbf83d71d2b29f2fe8604e0ebdcd06b4b25ae17cf033caeeb1fcaa3",//hash (Reter: hashbuf)
        "84105e1296e8d2541255de8edb5df5b96ceaf61d7f63d06981eebd0f202028d8",//r
        "28ab66ddd141b9c17e5160482bc14dab2ab5234dda7eab007fa6ac53ed538002"//s
    },
};
    printf("secp256r1:\n"); \
    if (run2(secp256r1_tests2, sizeof(secp256r1_tests2) / sizeof(secp256r1_tests2[0]), uECC_secp256r1()) ) { \
        printf("  All passed\n"); \
    } else { \
        printf("  Failed\n"); \
    }
*/

Test2 secp256r1_tests2[] = {
    {
        "0000000000000000000000000000000000000000000000000000000000000000",//empty private_key
        "d7da800758e222a07f4ec5b7e3f6d34b91c9e53e8ab3e2b002f86c07347a01c7358c3a8e387c5a4b2347ceaf40798d5bf3ca10a0a6a8ca5c83bc76f95afbb9b3",//public_key
        "0000000000000000000000000000000000000000000000000000000000000000",//empty k
        "7996a39bf8aa90874ed1c1198fcaecf6c6dfeaf6a5a3687873befd187da92cf3",//hash (Reter: hashbuf)
        "84105e1296e8d2541255de8edb5df5b96ceaf61d7f63d06981eebd0f202028d8",//r
        "1a77284e554f4e61e6bed2315579b91b486373e09493d52cdcf972a66c70e70f"//s
    },
};
    printf("secp256r1:\n"); \
    if (run3(secp256r1_tests2, sizeof(secp256r1_tests2) / sizeof(secp256r1_tests2[0]), uECC_secp256r1()) ) { \
        printf("  All passed\n"); \
    } else { \
        printf("  Failed\n"); \
    }
}

void dump_hex_mycrypto(uint8_t * buf, int size)
{
    while(size--)
    {
        printf("%02x ", *buf++);
    }
    printf("\n");

}

int test_myecdsa(void)
{
    int i, c;
    uint8_t private[32] = {0};
    uint8_t public[64] = {0};
    uint8_t hash[32] = {0};
    uint8_t sig[64] = {0};

    const struct uECC_Curve_t * curves[5];
    int num_curves = 0;

#if uECC_SUPPORTS_secp256r1
    curves[num_curves++] = uECC_secp256r1();
#endif
    
    printf("Testing 256 signatures\n");
    printf("num_curves=%d\n", num_curves);

    for (c = 0; c < num_curves; ++c) {
        for (i = 0; i < 256; ++i) {
            printf(".");
            fflush(stdout);

            if (!uECC_make_key(public, private, curves[c])) {
                printf("uECC_make_key() failed\n");
                return 1;
            }
            memcpy(hash, public, sizeof(hash));

    //printf("\ni=%d, private:\n", i);
    //dump_hex_mycrypto(public, 32);//reter debug
			
    //printf("\ni=%d, public:\n", i);
    //dump_hex_mycrypto(public, 64);//reter debug

            if (!uECC_sign(private, hash, sizeof(hash), sig, curves[c])) {
                printf("uECC_sign() failed\n");
                return 1;
            }
			
    //printf("\ni=%d, sig:\n", i);
    //dump_hex_mycrypto(sig, 64);//reter debug

            if (!uECC_verify(public, hash, sizeof(hash), sig, curves[c])) {
                printf("uECC_verify() failed\n");
                return 1;
            }
        }
        printf("\n");
    }
    
}

void test_myecc256()
{
    uint8_t private[32] = {0};
    uint8_t public[64] = {0};
    uint8_t expected[64] = {0};
    int result;
    int i;
    int private_key_size;
    int public_key_size;
    int all_success = 1;

    printf("test_myecc256\n");


Test secp256r1_tests[] = {
    {
        "0000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        0
    },
    {
        "0000000000000000000000000000000000000000000000000000000000000001",
        "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
        0
    },
    {
        "0000000000000000000000000000000000000000000000000000000000000002",
        "7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC4766997807775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1",
        1
    },
    {
        "0000000000000000000000000000000000000000000000000000000000000003",
        "5ECBE4D1A6330A44C8F7EF951D4BF165E6C6B721EFADA985FB41661BC6E7FD6C8734640C4998FF7E374B06CE1A64A2ECD82AB036384FB83D9A79B127A27D5032",
        1
    },
    {   /* n - 4 */
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254D",
        "E2534A3532D08FBBA02DDE659EE62BD0031FE2DB785596EF509302446B0308521F0EA8A4B39CC339E62011A02579D289B103693D0CF11FFAA3BD3DC0E7B12739",
        1
    },
    {   /* n - 3 */
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254E",
        "5ECBE4D1A6330A44C8F7EF951D4BF165E6C6B721EFADA985FB41661BC6E7FD6C78CB9BF2B6670082C8B4F931E59B5D1327D54FCAC7B047C265864ED85D82AFCD",
        1
    },
    {   /* n - 2 */
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254F",
        "7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978F888AAEE24712FC0D6C26539608BCF244582521AC3167DD661FB4862DD878C2E",
        0
    },
    {   /* n - 1 */
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550",
        "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296B01CBD1C01E58065711814B583F061E9D431CCA994CEA1313449BF97C840AE0A",
        0
    },
    {   /* n */
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        0
    },
    { //Reter add
        "cd67aa310d091ed16e7e9892aa070e1994fcd714ae7c408fb946b72e5fe75d30",
        "45a902c12e9c0a33fa3e84504ab802dc4db9af15b1b63aea8d3f030355657d703fb402a497f483b8a6f93cd018ad920cb78a5a3e144892ef08f8caeafb32ab20",
        0
    },

};

/*
	in array
	{
	private key, 
	public key,
	1=should be matched, 0=not matched
	}
*/

    private_key_size = uECC_curve_private_key_size(uECC_secp256r1());
    public_key_size = uECC_curve_public_key_size(uECC_secp256r1());
    printf("private_key_size %d\n", private_key_size);
    printf("public_key_size %d\n", public_key_size);

    int test_item_number=9;
	
    strtobytes(secp256r1_tests[test_item_number].k, private, private_key_size);

    printf("\nprivate:\n");
    dump_hex_mycrypto(private, private_key_size);


    result = uECC_compute_public_key(private, public, uECC_secp256r1());
    printf("\npublic(calculated):\n");
    dump_hex_mycrypto(public, public_key_size);

//just for check public_key in array
    strtobytes(secp256r1_tests[test_item_number].Q, expected, public_key_size);

    printf("\npublic:\n");
    dump_hex_mycrypto(expected, public_key_size);

    my_uECC_secp256r1_info();

}

//-------------------------------- test for ctap functions ------------------------------------------
static uint8_t * _signing_key = NULL;
static int _key_len = 0;


uint8_t * device_get_attestation_key(){
    //origin
    /*
    static uint8_t attestation_key[] =
        "\xcd\x67\xaa\x31\x0d\x09\x1e\xd1\x6e\x7e\x98\x92\xaa"
        "\x07\x0e\x19\x94\xfc\xd7\x14\xae\x7c\x40\x8f\xb9\x46"
        "\xb7\x2e\x5f\xe7\x5d\x30";
    */
    //vianext
    static uint8_t attestation_key[] =
        "\x8e\x91\xef\xde\xb3\x3c\xb2\x7d\x78\x7f\xac\xd2\x97\x0a\xdd"
        "\xd8\xe7\xbd\x7e\x11\x1e\x65\xac\x46\x38\x70\x36\x3d\x86\x00"
        "\xd6\x3c";
	return attestation_key;
}

void crypto_ecc256_load_attestation_key(void)
{
    _signing_key = device_get_attestation_key();
    //printf("\n_signing_key:\n");
    //dump_hex_mycrypto(_signing_key, 32);//reter debug
    _key_len = 32;
}

void crypto_ecc256_sign(uint8_t * data, int len, uint8_t * sig)
{
    printf("\n================ crypto_ecc256_sign - entry\n");


    printf("\ncrypto_ecc256_sign _signing_key:\n");
    dump_hex_mycrypto(_signing_key, 32);//reter debug

    printf("\ncrypto_ecc256_sign data:\n");
    dump_hex_mycrypto(data, 32);//reter debug

    printf("\ncrypto_ecc256_sign len: %d\n", len);

    printf("\ncrypto_ecc256_sign sig:\n");
    dump_hex_mycrypto(sig, 32);//reter debug


    if ( uECC_sign(_signing_key, data, len, sig, _es256_curve) == 0)
    {
        printf("error, uECC failed\n");
        exit(1);
    }
    printf("\ncrypto_ecc256_sign sig_after:\n");
    dump_hex_mycrypto(sig, 32);//reter debug
    
    printf("\n================ crypto_ecc256_sign - exit\n");

}

/**
 *
 * @param in_sigbuf IN location to deposit signature (must be 64 bytes)
 * @param out_sigder OUT location to deposit der signature (must be 72 bytes)
 * @return length of der signature
 * // FIXME add tests for maximum and minimum length of the input and output
 */
int ctap_encode_der_sig(const uint8_t * const in_sigbuf, uint8_t * const out_sigder)
{
    // Need to caress into dumb der format ..
    uint8_t i;
    uint8_t lead_s = 0;  // leading zeros
    uint8_t lead_r = 0;
    for (i=0; i < 32; i++)
    {
        if (in_sigbuf[i] == 0)
        {
            lead_r++;
        }
        else
        {
            break;
        }
    }

    for (i=0; i < 32; i++)
    {
        if (in_sigbuf[i+32] == 0)
        {
            lead_s++;
        }
        else
        {
            break;
        }
    }

    int8_t pad_s = ((in_sigbuf[32 + lead_s] & 0x80) == 0x80);
    int8_t pad_r = ((in_sigbuf[0 + lead_r] & 0x80) == 0x80);

    //printf("\nlead_s=%u\n", lead_s);
    //printf("lead_r=%u\n", lead_r);
    //printf("pad_s=%u\n", pad_s);
    //printf("pad_r=%u\n", pad_r);
	
    memset(out_sigder, 0, 72);
    out_sigder[0] = 0x30;
    out_sigder[1] = 0x44 + pad_s + pad_r - lead_s - lead_r;

    // R ingredient
    out_sigder[2] = 0x02;
    out_sigder[3 + pad_r] = 0;
    out_sigder[3] = 0x20 + pad_r - lead_r;
    memmove(out_sigder + 4 + pad_r, in_sigbuf + lead_r, 32u - lead_r);

    // S ingredient
    out_sigder[4 + 32 + pad_r - lead_r] = 0x02;
    out_sigder[5 + 32 + pad_r + pad_s - lead_r] = 0;
    out_sigder[5 + 32 + pad_r - lead_r] = 0x20 + pad_s - lead_s;
    memmove(out_sigder + 6 + 32 + pad_r + pad_s - lead_r, in_sigbuf + 32u + lead_s, 32u - lead_s);

    return 0x46 + pad_s + pad_r - lead_r - lead_s;
}


// require load_key prior to this
// @data data to hash before signature, MUST have room to append clientDataHash for ED25519
// @clientDataHash for signature
// @tmp buffer for hash.  (can be same as data if data >= 32 bytes)
// @sigbuf OUT location to deposit signature (must be 64 bytes)
// @sigder OUT location to deposit der signature (must be 72 bytes)
// @return length of der signature
int ctap_calculate_signature(uint8_t * data, int datalen, uint8_t * clientDataHash, uint8_t * hashbuf, uint8_t * sigbuf, uint8_t * sigder, int32_t alg)
{
    // calculate attestation sig
    if (alg == COSE_ALG_EDDSA)
    {
        //reter debugcrypto_ed25519_sign(data, datalen, clientDataHash, CLIENT_DATA_HASH_SIZE, sigder); // not DER, just plain binary!
        return 64;
    }
    else
    {
        //printf("\nsha256 datalen=%u:\n", datalen);
        //printf("\nsha256 clientDataHash=%lu:\n", sizeof(clientDataHash));
        //printf("\nsha256 CLIENT_DATA_HASH_SIZE=%u:\n", CLIENT_DATA_HASH_SIZE);

        crypto_sha256_init();
        crypto_sha256_update(data, datalen);
        crypto_sha256_update(clientDataHash, CLIENT_DATA_HASH_SIZE);
        crypto_sha256_final(hashbuf);
		
        printf("\nsha256 hashbuf:\n");
        dump_hex_mycrypto(hashbuf, 32);//reter debug

        crypto_ecc256_sign(hashbuf, 32, sigbuf);
        return ctap_encode_der_sig(sigbuf,sigder);
    }
}

static uint8_t _attestation_cert_der[] =
"\x30\x82\x01\xfb\x30\x82\x01\xa1\xa0\x03\x02\x01\x02\x02\x01\x00\x30\x0a\x06\x08"
"\x2a\x86\x48\xce\x3d\x04\x03\x02\x30\x2c\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13"
"\x02\x55\x53\x31\x0b\x30\x09\x06\x03\x55\x04\x08\x0c\x02\x4d\x44\x31\x10\x30\x0e"
"\x06\x03\x55\x04\x0a\x0c\x07\x54\x45\x53\x54\x20\x43\x41\x30\x20\x17\x0d\x31\x38"
"\x30\x35\x31\x30\x30\x33\x30\x36\x32\x30\x5a\x18\x0f\x32\x30\x36\x38\x30\x34\x32"
"\x37\x30\x33\x30\x36\x32\x30\x5a\x30\x7c\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13"
"\x02\x55\x53\x31\x0b\x30\x09\x06\x03\x55\x04\x08\x0c\x02\x4d\x44\x31\x0f\x30\x0d"
"\x06\x03\x55\x04\x07\x0c\x06\x4c\x61\x75\x72\x65\x6c\x31\x15\x30\x13\x06\x03\x55"
"\x04\x0a\x0c\x0c\x54\x45\x53\x54\x20\x43\x4f\x4d\x50\x41\x4e\x59\x31\x22\x30\x20"
"\x06\x03\x55\x04\x0b\x0c\x19\x41\x75\x74\x68\x65\x6e\x74\x69\x63\x61\x74\x6f\x72"
"\x20\x41\x74\x74\x65\x73\x74\x61\x74\x69\x6f\x6e\x31\x14\x30\x12\x06\x03\x55\x04"
"\x03\x0c\x0b\x63\x6f\x6e\x6f\x72\x70\x70\x2e\x63\x6f\x6d\x30\x59\x30\x13\x06\x07"
"\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00"
"\x04\x45\xa9\x02\xc1\x2e\x9c\x0a\x33\xfa\x3e\x84\x50\x4a\xb8\x02\xdc\x4d\xb9\xaf"
"\x15\xb1\xb6\x3a\xea\x8d\x3f\x03\x03\x55\x65\x7d\x70\x3f\xb4\x02\xa4\x97\xf4\x83"
"\xb8\xa6\xf9\x3c\xd0\x18\xad\x92\x0c\xb7\x8a\x5a\x3e\x14\x48\x92\xef\x08\xf8\xca"
"\xea\xfb\x32\xab\x20\xa3\x62\x30\x60\x30\x46\x06\x03\x55\x1d\x23\x04\x3f\x30\x3d"
"\xa1\x30\xa4\x2e\x30\x2c\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31"
"\x0b\x30\x09\x06\x03\x55\x04\x08\x0c\x02\x4d\x44\x31\x10\x30\x0e\x06\x03\x55\x04"
"\x0a\x0c\x07\x54\x45\x53\x54\x20\x43\x41\x82\x09\x00\xf7\xc9\xec\x89\xf2\x63\x94"
"\xd9\x30\x09\x06\x03\x55\x1d\x13\x04\x02\x30\x00\x30\x0b\x06\x03\x55\x1d\x0f\x04"
"\x04\x03\x02\x04\xf0\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02\x03\x48\x00"
"\x30\x45\x02\x20\x18\x38\xb0\x45\x03\x69\xaa\xa7\xb7\x38\x62\x01\xaf\x24\x97\x5e"
"\x7e\x74\x64\x1b\xa3\x7b\xf7\xe6\xd3\xaf\x79\x28\xdb\xdc\xa5\x88\x02\x21\x00\xcd"
"\x06\xf1\xe3\xab\x16\x21\x8e\xd8\xc0\x14\xaf\x09\x4f\x5b\x73\xef\x5e\x9e\x4b\xe7"
"\x35\xeb\xdd\x9b\x6d\x8f\x7d\xf3\xc4\x3a\xd7";

uint16_t device_attestation_cert_der_get_size(){
    return sizeof(_attestation_cert_der)-1;
}

void device_attestation_read_cert_der(uint8_t * dst){
    memmove(dst, _attestation_cert_der, device_attestation_cert_der_get_size());
}

int ctap_generate_rng(uint8_t * dst, size_t num)
{
    int ret;
    FILE * urand = fopen("/dev/urandom","r");
    if (urand == NULL)
    {
        perror("fopen");
        exit(1);
    }
    if (fread(dst, 1, num, urand) != num)
    {
        perror("fread");
    }

    fclose(urand);

    return 1;
}

void crypto_ecc256_init(void)
{
    uECC_set_rng((uECC_RNG_Function)ctap_generate_rng);
    _es256_curve = uECC_secp256r1();
}


    static uint8_t auth_data_buf[] =
//"\xc2\x89\xc5\xca\x9b\x04\x60\xf9\x34\x6a\xb4\xe4\x2d\x84\x27\x43\x40\x4d\x31\xf4\x84\x68\x25\xa6\xd0\x65\xbe\x59\x7a\x87\x05\x1d\x41\x00\x00\x00\x0b\xf8\xa0\x11\xf3\x8c\x0a\x4d\x15\x80\x06\x17\x11\x1f\x9e\xdc\x7d\x00\x10\x89\x59\xce\xad\x5b\x5c\x48\x16\x4e\x8a\xbc\xd6\xd9\x43\x5c\x6f\xa3\x63\x61\x6c\x67\x65\x45\x53\x32\x35\x36\x61\x78\x58\x20\xf7\xc4\xf4\xa6\xf1\xd7\x95\x38\xdf\xa4\xc9\xac\x50\x84\x8d\xf7\x08\xbc\x1c\x99\xf5\xe6\x0e\x51\xb4\x2a\x52\x1b\x35\xd3\xb6\x9a\x61\x79\x58\x20\xde\x7b\x7d\x6c\xa5\x64\xe7\x0e\xa3\x21\xa4\xd5\xd9\x6e\xa0\x0e\xf0\xe2\xdb\x89\xdd\x61\xd4\x89\x4c\x15\xac\x58\x5b\xd2\x36\x84";
"\x74\x96\x7e\x7a\xb8\x1d\xe9\x51\xe6\x42\xf3\x18\xc1\x1a\xc5\x3c\xb5\x69\x63\x74\x1b\x44\x59\x7d\x46\x06\x8e\xa9\x06\xdb\x6e\x28\x45\x00\x00\x00\x1a\x3a\x70\xbe\xb8\x2c\x29\x7b\xba\xc1\x3d\x44\xc6\x6f\x3f\x7d\xb1\x00\x46\x3c\x66\xf3\x79\x5c\x7a\x78\x2e\xf6\xca\x5a\xb8\xfc\x90\x9a\x94\xab\xb2\xcd\xc6\x9b\xb4\x54\x11\x0e\x82\x74\x41\x21\x3d\x8b\x95\xde\xc9\x74\x96\x7e\x7a\xb8\x1d\xe9\x51\xe6\x42\xf3\x18\xc1\x1a\xc5\x3c\xb5\x69\x63\x74\x1b\x44\x59\x7d\x46\x06\x8e\xa9\x06\xdb\x6e\x28\x1a\x00\x00\x00\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20\xc4\xa6\x0d\xde\x02\x7b\x38\x82\x14\x27\x20\x39\x88\x08\x53\xbd\x43\xe0\x7f\x79\x9b\xbe\x22\x6a\x42\x80\x5b\x95\xfd\x8c\x96\x15\x22\x58\x20\x65\x0f\xbe\x0c\x2a\x42\x4b\xd1\x94\x55\x1e\x3d\x69\x1a\x10\x5c\x06\xb1\x6b\xa8\x96\x82\x7b\x73\x77\x93\x72\x58\xbc\xd9\xb0\xfe";

uint16_t device_auth_data_get_size(){
    return sizeof(auth_data_buf)-1;
}

void device_read_auth_data_buf(uint8_t * dst){
    memmove(dst, auth_data_buf, device_auth_data_get_size());
}

    static uint8_t attestation_key2[] =
        "\x8e\x91\xef\xde\xb3\x3c\xb2\x7d\x78\x7f\xac\xd2\x97\x0a\xdd"
        "\xd8\xe7\xbd\x7e\x11\x1e\x65\xac\x46\x38\x70\x36\x3d\x86\x00"
        "\xd6\x3c";

void ctap_make_credential_input_authData_calculate_sig()
{
//refer to ctap_make_credential in ctap.c
    CTAP_makeCredential MC;

   printf("\nhi, ctap_make_credential_input_authData_calculate_sig\n");

    uint8_t auth_data_buf[310];
    uint8_t * sigbuf = auth_data_buf + 32;
    uint8_t * sigder = auth_data_buf + 32 + 64;
    //uint32_t auth_data_sz = sizeof(auth_data_buf);

//must initial
	crypto_ecc256_init();

//fake data
    device_read_auth_data_buf(auth_data_buf);
    uint32_t auth_data_sz = device_auth_data_get_size();
    printf("\nauth_data_sz=%d\n", auth_data_sz);

    dump_hex_mycrypto(auth_data_buf, auth_data_sz);
	
    crypto_ecc256_load_attestation_key();

//reter debug - start
    uint8_t myclientDataHash[CLIENT_DATA_HASH_SIZE]=
    {0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd};
    //{0x68, 0x71, 0x34, 0x96, 0x82, 0x22, 0xec, 0x17, 0x20, 0x2e, 0x42, 0x50, 0x5f, 0x8e, 0xd2, 0xb1, 0x6a, 0xe2, 0x2f, 0x16, 0xbb, 0x05, 0xb8, 0x8c, 0x25, 0xdb, 0x9e, 0x60, 0x26, 0x45, 0xf1, 0x41};

    printf("\nMC.clientDataHash: \n"); 
    dump_hex_mycrypto(myclientDataHash, CLIENT_DATA_HASH_SIZE);
//reter debug - end

/*
    int i;
    for (i = 0; i < CLIENT_DATA_HASH_SIZE; ++i) {
        MC.clientDataHash[i] = myclientDataHash[i];
    }
    printf("\nMC.clientDataHash: \n"); 
    dump_hex_mycrypto(MC.clientDataHash, CLIENT_DATA_HASH_SIZE);
    int sigder_sz = ctap_calculate_signature(auth_data_buf, auth_data_sz, MC.clientDataHash, auth_data_buf, sigbuf, sigder, COSE_ALG_ES256);
*/

    int sigder_sz = ctap_calculate_signature(auth_data_buf, auth_data_sz, myclientDataHash, auth_data_buf, sigbuf, sigder, COSE_ALG_ES256);

    printf("\nsig: \n"); 
    dump_hex_mycrypto(sigbuf, 64);

    printf("\nder sig [%d]: \n", sigder_sz); 
    dump_hex_mycrypto(sigder, sigder_sz);

}

static uint8_t aaguid[] =
	"\x3a\x70\xbe\xb8\x2c\x29\x7b\xba\xc1\x3d\x44\xc6\x6f\x3f\x7d\xb1";

void device_read_aaguid(uint8_t * dst){
    memmove(dst, aaguid, 16);
}
uint16_t device_aaguid_get_size(){
    return sizeof(aaguid)-1;
}

static uint8_t vianext_attestation_key[] =
        "\x8e\x91\xef\xde\xb3\x3c\xb2\x7d\x78\x7f\xac\xd2\x97\x0a\xdd"
        "\xd8\xe7\xbd\x7e\x11\x1e\x65\xac\x46\x38\x70\x36\x3d\x86\x00"
        "\xd6\x3c";

uint16_t device_attestation_key_get_size(){
    return sizeof(vianext_attestation_key)-1;
}

void device_attestation_key_read(uint8_t * dst){
    memmove(dst, vianext_attestation_key, device_attestation_key_get_size());
}


void print_byte_array()
{
    uint8_t aaguid[16];
    uint16_t aaguid_size = device_aaguid_get_size();
    printf("\naaguid_size=%d\n", aaguid_size);

    device_read_aaguid(aaguid);
    dump_hex_mycrypto(aaguid, aaguid_size);//reter debug


    uint8_t vianext_attestation_key[32];
    uint16_t vianext_attestation_key_size = device_attestation_key_get_size();
    printf("\nvianext_attestation_key_size=%d\n", vianext_attestation_key_size);

    device_attestation_key_read(vianext_attestation_key);
    dump_hex_mycrypto(vianext_attestation_key, vianext_attestation_key_size);//reter debug
}
void write_byte_array_to_der_file()
{
//write key to file

    static uint8_t attestation_key[] =
"\x68\x71\x34\x96\x82\x22\xec\x17\x20\x2e\x42\x50\x5f\x8e\xd2\xb1\x6a\xe2\x2f\x16\xbb\x05\xb8\x8c\x25\xdb\x9e\x60\x26\x45\xf1\x41\xc2\x89\xc5\xca\x9b\x04\x60\xf9\x34\x6a\xb4\xe4\x2d\x84\x27\x43\x40\x4d\x31\xf4\x84\x68\x25\xa6\xd0\x65\xbe\x59\x7a\x87\x05\x1d\x41\x00\x00\x00\x0b\xf8\xa0\x11\xf3\x8c\x0a\x4d\x15\x80\x06\x17\x11\x1f\x9e\xdc\x7d\x00\x10\x89\x59\xce\xad\x5b\x5c\x48\x16\x4e\x8a\xbc\xd6\xd9\x43\x5c\x6f\xa3\x63\x61\x6c\x67\x65\x45\x53\x32\x35\x36\x61\x78\x58\x20\xf7\xc4\xf4\xa6\xf1\xd7\x95\x38\xdf\xa4\xc9\xac\x50\x84\x8d\xf7\x08\xbc\x1c\x99\xf5\xe6\x0e\x51\xb4\x2a\x52\x1b\x35\xd3\xb6\x9a\x61\x79\x58\x20\xde\x7b\x7d\x6c\xa5\x64\xe7\x0e\xa3\x21\xa4\xd5\xd9\x6e\xa0\x0e\xf0\xe2\xdb\x89\xdd\x61\xd4\x89\x4c\x15\xac\x58\x5b\xd2\x36\x84";

    FILE *fptr;
    int i;
    fptr = fopen("hashbuf2.txt","w");

    for(i=0;i<sizeof(attestation_key)-1;i++)
       fprintf(fptr, "%c", attestation_key[i]);

    fclose(fptr);
    printf("\ncreate attestation_key\n");
    printf("\n size = %ld\n", sizeof(attestation_key)-1);

}
void read_der_file_to_byte_array()
{

    printf("\nprint my.crt.der\n");

    FILE *fptr;
    fptr = fopen("my.crt.der","r");
    //fptr = fopen("my.key.der","r");

	unsigned char ch;
	int count =0;

	putchar('"');

	while(!feof(fptr)){
		fread(&ch, sizeof(char), 1, fptr);
		printf("\\x%02X", ch);
		count++;
		if(count >= 20) {
			putchar('"');
			putchar('\n');
			putchar('"');
			count = 0;
		}
	}
	putchar('"');
	printf("\n");

}

