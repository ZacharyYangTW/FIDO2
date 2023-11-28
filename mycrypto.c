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
        strtobytes(tests[i].k, private, private_key_size);
        result = uECC_compute_public_key(private, public, curve);
        if (result != tests[i].success) {
            all_success = 0;
            printf("  Got unexpected result from test %d: %d\n", i, result);
        }
        if (result) {
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

void test_ecc_256(void)
{

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

    printf("secp256k1:\n"); \
    if (run(secp256k1_tests, sizeof(secp256k1_tests) / sizeof(secp256k1_tests[0]), uECC_secp256k1()) ) { \
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

    printf("\ni=%d, private:\n", i);
    //dump_hex_mycrypto(public, 32);//reter debug
			
    printf("\ni=%d, public:\n", i);
    //dump_hex_mycrypto(public, 64);//reter debug

            if (!uECC_sign(private, hash, sizeof(hash), sig, curves[c])) {
                printf("uECC_sign() failed\n");
                return 1;
            }
			
    printf("\ni=%d, sig:\n", i);
    //dump_hex_mycrypto(sig, 64);//reter debug

            if (!uECC_verify(public, hash, sizeof(hash), sig, curves[c])) {
                printf("uECC_verify() failed\n");
                return 1;
            }
        }
        printf("\n");
    }
    
}

//-------------------------------- test for ctap functions ------------------------------------------
static uint8_t * _signing_key = NULL;
static int _key_len = 0;


uint8_t * device_get_attestation_key(){
    static uint8_t attestation_key[] =
        "\xcd\x67\xaa\x31\x0d\x09\x1e\xd1\x6e\x7e\x98\x92\xaa"
        "\x07\x0e\x19\x94\xfc\xd7\x14\xae\x7c\x40\x8f\xb9\x46"
        "\xb7\x2e\x5f\xe7\x5d\x30";
	
    return attestation_key;
}

void crypto_ecc256_load_attestation_key(void)
{
    _signing_key = device_get_attestation_key();
    printf("\n_signing_key:\n");
    dump_hex_mycrypto(_signing_key, 32);//reter debug
    _key_len = 32;
}

void crypto_ecc256_sign(uint8_t * data, int len, uint8_t * sig)
{

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
    printf("\nsha256 datalen=%u:\n", datalen);
    printf("\nsha256 clientDataHash=%lu:\n", sizeof(clientDataHash));
    printf("\nsha256 CLIENT_DATA_HASH_SIZE=%u:\n", CLIENT_DATA_HASH_SIZE);

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


void myctap()
{
//refer to ctap_make_credential in ctap.c
    CTAP_makeCredential MC;

   
    uint8_t auth_data_buf[310];
    uint8_t * sigbuf = auth_data_buf + 32;
    uint8_t * sigder = auth_data_buf + 32 + 64;
    uint32_t auth_data_sz = sizeof(auth_data_buf);

//must initial
	crypto_ecc256_init();;

//fake data
	*auth_data_buf='\0';//reter debug
	*MC.clientDataHash='\0';//reter debug

    printf("\nhi, Zach myctap\n");
    crypto_ecc256_load_attestation_key();
    int sigder_sz = ctap_calculate_signature(auth_data_buf, auth_data_sz, MC.clientDataHash, auth_data_buf, sigbuf, sigder, COSE_ALG_ES256);

    printf("\nsig: \n"); 
    dump_hex_mycrypto(sigbuf, 32);

    printf("\nder sig [%d]: \n", sigder_sz); 
    dump_hex_mycrypto(sigder, sigder_sz);

    uint8_t cert[1024];
    uint16_t cert_size = device_attestation_cert_der_get_size();
    printf("\ncert_size=%d\n", cert_size);

    device_attestation_read_cert_der(cert);
    dump_hex_mycrypto(cert, cert_size);//reter debug

    static uint8_t attestation_key[] =
        "\xcd\x67\xaa\x31\x0d\x09\x1e\xd1\x6e\x7e\x98\x92\xaa"
        "\x07\x0e\x19\x94\xfc\xd7\x14\xae\x7c\x40\x8f\xb9\x46"
        "\xb7\x2e\x5f\xe7\x5d\x30";

//write key to file
/*
    FILE *fptr;
    int i;
    fptr = fopen("_attestation_cert_der.der","w");

    for(i=0;i<sizeof(_attestation_cert_der)-1;i++)
       fprintf(fptr, "%c", _attestation_cert_der[i]);

    fclose(fptr);
*/

}
