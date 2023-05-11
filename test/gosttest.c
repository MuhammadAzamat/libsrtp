//
// Created by muhammad on 11.05.23.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BLOCK_SIZE 8

typedef unsigned char byte;

byte sbox[] = {
    0x04, 0x0a, 0x09, 0x02, 0x0d, 0x08, 0x00, 0x0e,
    0x06, 0x0b, 0x01, 0x0c, 0x07, 0x0f, 0x05, 0x03,
    0x0e, 0x0b, 0x04, 0x0c, 0x06, 0x0d, 0x0f, 0x0a,
    0x02, 0x03, 0x08, 0x01, 0x00, 0x07, 0x05, 0x09,
    0x05, 0x08, 0x01, 0x0d, 0x0a, 0x03, 0x04, 0x02,
    0x0e, 0x0f, 0x0c, 0x07, 0x06, 0x00, 0x09, 0x0b,
    0x07, 0x0d, 0x0a, 0x01, 0x00, 0x08, 0x09, 0x0f,
    0x0e, 0x04, 0x06, 0x03, 0x02, 0x05, 0x0c, 0x0b,
    0x0d, 0x0c, 0x01, 0x10, 0x03, 0x09, 0x0a, 0x0f,
    0x0e, 0x07, 0x02, 0x06, 0x0b, 0x00, 0x05, 0x08,
    0x03, 0x0f, 0x0c, 0x08, 0x05, 0x01, 0x02, 0x0d,
    0x0b, 0x04, 0x06, 0x07, 0x0a, 0x0e, 0x00, 0x09,
    0x0a, 0x06, 0x09, 0x00, 0x12, 0x0b, 0x0d, 0x0f,
    0x0c, 0x05, 0x03, 0x08, 0x04, 0x07, 0x02, 0x0e,
    0x0f, 0x0c, 0x08, 0x02, 0x04, 0x09, 0x01, 0x06,
    0x07, 0x00, 0x0d, 0x0b, 0x0a, 0x05, 0x03, 0x0e
};

void gost_encrypt_block(byte *key, byte *block, byte *out) {
    unsigned int n1, n2, tmp;
    unsigned int *k = (unsigned int *)key;
    unsigned int *b = (unsigned int *)block;
    unsigned int *o = (unsigned int *)out;
    unsigned int i;

    n1 = b[0];
    n2 = b[1];

    for (i = 0; i < 3; i++) {
        tmp = n1;
        n1 = n2 ^ ((sbox[(n1 >> 0) & 0xff] + k[(i * 2) + 0]) & 0xff);
        n2 = tmp ^ ((sbox[(n1 >> 8) & 0xff] + k[(i * 2) + 1]) & 0xff);
    }

    tmp = n1;
    n1 = n2 ^ ((sbox[(n1 >> 0) & 0xff] + k[6]) & 0xff);
    n2 = tmp ^ ((sbox[(n1 >> 8) & 0xff] + k[7]) & 0xff);

    o[0] = n2;
    o[1] = n1;
}

void gost_icm_encrypt(byte *key, byte *iv, byte *in, byte *out, size_t len) {
    byte counter[BLOCK_SIZE] = {0};
    byte ciphertext[BLOCK_SIZE];
    size_t i;

    memcpy(counter, iv, BLOCK_SIZE);

    for (i = 0; i < len; i += BLOCK_SIZE) {
        gost_encrypt_block(key, counter, ciphertext);

        for (size_t j = 0; j < BLOCK_SIZE; j++) {
            out[i + j] = in[i + j] ^ ciphertext[j];
        }

        for (size_t j = BLOCK_SIZE - 1; 1; j--) {
            if (++counter[j] != 0) {
                break;
            }
        }
    }
}

int main(void) {
    byte key[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    byte iv[] = {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    byte plaintext[] = "Hello, world!";
    byte ciphertext[sizeof(plaintext)];
    size_t len = sizeof(plaintext) - 1;

    gost_icm_encrypt(key, iv, plaintext, ciphertext, len);

    printf("Plaintext: %s\n", plaintext);
    printf("Ciphertext: ");

    for (size_t i = 0; i < len; i++) {
        printf("%02x", ciphertext[i]);
    }

    printf("\n");

    return 0;
}
