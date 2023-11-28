CC:=gcc
exe:=main

src = main.c
src += ./mycrypto.c
//src += ./mycbor.c
src += ./cJSON.c

# Crypto libs
src += ./crypto/sha256/sha256.c
src += ./crypto/tiny-AES-c/aes.c
src += ./crypto/ecc/uECC.c

# CBOR libs
//src += ./tinycbor/src/cborencoder.c
//src += ./tinycbor/src/cborencoder_close_container_checked.c
//src += ./tinycbor/src/cborerrorstrings.c

obj = $(src:.c=.o)

all: $(obj)
	$(CC) -o $(exe) $(obj)  -lm
%.o: %.c
	$(CC) $^ -c -o $@

.PHONY:clean
clean:
	rm -rf $(obj) $(exe)


