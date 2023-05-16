#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define ALIGN_32 0

#include "gost_icm.h"
#include "alloc.h"
#include "cipher_types.h"
#include "cipher_test_cases.h"

static srtp_err_status_t srtp_gost_icm_alloc(srtp_cipher_t **c,
                                             int key_len,
                                             int tlen)
{
    gost_ctx *icm;
    (void)tlen;

    /* allocate memory a cipher of type gost_icm */
    *c = (srtp_cipher_t *)srtp_crypto_alloc(sizeof(srtp_cipher_t));
    if (*c == NULL) {
        return srtp_err_status_alloc_fail;
    }

    icm = (gost_ctx *)srtp_crypto_alloc(sizeof(gost_ctx));
    if (icm == NULL) {
        srtp_crypto_free(*c);
        *c = NULL;
        return srtp_err_status_alloc_fail;
    }

    /* set pointers */
    (*c)->state = icm;

    (*c)->algorithm = SRTP_GOST_28147_89;
    (*c)->type = &srtp_gost_icm_28147;

    /* set key size        */
    icm->key_size = key_len;
    (*c)->key_len = key_len;

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_gost_icm_dealloc(srtp_cipher_t *c)
{
    gost_ctx *ctx;

    if (c == NULL) {
        return srtp_err_status_bad_param;
    }

    ctx = (gost_ctx *)c->state;
    if (ctx) {
        /* zeroize the key material */
        octet_string_set_to_zero(ctx, sizeof(gost_ctx));
        srtp_crypto_free(ctx);
    }
    gost_destroy(ctx);

    /* free the cipher context */
    srtp_crypto_free(c);

    return srtp_err_status_ok;
}

/*
 * aes_icm_context_init(...) initializes the aes_icm_context
 * using the value in key[].
 *
 * the key is the secret key
 *
 * the salt is unpredictable (but not necessarily secret) data which
 * randomizes the starting point in the keystream
 */

static srtp_err_status_t srtp_gost_icm_context_init(void *cv,
                                                    const uint8_t *key)
{
    gost_ctx *c = (gost_ctx *)cv;
    (void)c;
    (void)key;
    int base_key_len, copy_len;

    base_key_len = c->key_size;

    /*
     * set counter and initial values to 'offset' value, being careful not to
     * go past the end of the key buffer
     */
    v128_set_to_zero(&c->counter);
    v128_set_to_zero(&c->offset);

    copy_len = c->key_size - base_key_len;

    memcpy(&c->counter, key + base_key_len, copy_len);
    memcpy(&c->offset, key + base_key_len, copy_len);

    gost_init(c, NULL);
    gost_key(c, key);

    /* indicate that the keystream_buffer is empty */
    c->bytes_in_buffer = 0;

    return srtp_err_status_ok;
}

/*
 * gost_icm_set_iv(c, iv) sets the counter value to the exor of iv with
 * the offset
 */

static srtp_err_status_t srtp_gost_icm_set_iv(void *cv,
                                              uint8_t *iv,
                                              srtp_cipher_direction_t direction)
{
    gost_ctx *c = (gost_ctx *)cv;
    (void)c;
    (void)iv;
    v128_t nonce;
    (void)direction;

    /* set nonce (for alignment) */
    v128_copy_octet_string(&nonce, iv);

    v128_xor(&c->counter, &c->offset, &nonce);

    debug_print(srtp_mod_aes_icm, "set_counter: %s",
                v128_hex_string(&c->counter));

    /* indicate that the keystream_buffer is empty */
    c->bytes_in_buffer = 0;

    return srtp_err_status_ok;
}

/*
 * aes_icm_advance(...) refills the keystream_buffer and
 * advances the block index of the sicm_context forward by one
 *
 * this is an internal, hopefully inlined function
 */
static void srtp_gost_icm_advance(gost_ctx *c)
{
    /* fill buffer with new keystream */
    v128_copy(&c->keystream_buffer, &c->counter);
    gost_enc(c, (byte *)&c->keystream_buffer);

    c->bytes_in_buffer = sizeof(v128_t);

    /* clock counter forward */
    if (!++(c->counter.v8[15])) {
        ++(c->counter.v8[14]);
    }
}

/*
 * icm_encrypt deals with the following cases:
 *
 * bytes_to_encr < bytes_in_buffer
 *  - add keystream into data
 *
 * bytes_to_encr > bytes_in_buffer
 *  - add keystream into data until keystream_buffer is depleted
 *  - loop over blocks, filling keystream_buffer and then
 *    adding keystream into data
 *  - fill buffer then add in remaining (< 16) bytes of keystream
 */

static srtp_err_status_t srtp_gost_icm_encrypt(void *cv,
                                               unsigned char *buf,
                                               unsigned int *enc_len)
{
    gost_ctx *c = (gost_ctx *)cv;
    unsigned int bytes_to_encr = *enc_len;
    (void)c;
    (void)buf;
    (void)bytes_to_encr;

    byte ciphertext[16];
    (void)ciphertext;

    unsigned int i;
    uint32_t *b;

    /* check that there's enough segment left*/
    unsigned int bytes_of_new_keystream = bytes_to_encr - c->bytes_in_buffer;
    unsigned int blocks_of_new_keystream = (bytes_of_new_keystream + 15) >> 4;
    if ((blocks_of_new_keystream + htons(c->counter.v16[7])) > 0xffff) {
        return srtp_err_status_terminus;
    }

    if (bytes_to_encr <= (unsigned int)c->bytes_in_buffer) {
        /* deal with odd case of small bytes_to_encr */
        for (i = (sizeof(v128_t) - c->bytes_in_buffer);
             i < (sizeof(v128_t) - c->bytes_in_buffer + bytes_to_encr); i++) {
            *buf++ ^= c->keystream_buffer.v8[i];
        }

        c->bytes_in_buffer -= bytes_to_encr;

        /* return now to avoid the main loop */
        return srtp_err_status_ok;

    } else {
        /* encrypt bytes until the remaining data is 16-byte aligned */
        for (i = (sizeof(v128_t) - c->bytes_in_buffer); i < sizeof(v128_t);
             i++) {
            *buf++ ^= c->keystream_buffer.v8[i];
        }

        bytes_to_encr -= c->bytes_in_buffer;
        c->bytes_in_buffer = 0;
    }

    /* now loop over entire 16-byte blocks of keystream */
    for (i = 0; i < (bytes_to_encr / sizeof(v128_t)); i++) {
        /* fill buffer with new keystream */
        srtp_gost_icm_advance(c);

        /*
         * add keystream into the data buffer (this would be a lot faster
         * if we could assume 32-bit alignment!)
         */

#if ALIGN_32
        b = (uint32_t *)buf;
        *b++ ^= c->keystream_buffer.v32[0];
        *b++ ^= c->keystream_buffer.v32[1];
        *b++ ^= c->keystream_buffer.v32[2];
        *b++ ^= c->keystream_buffer.v32[3];
        buf = (uint8_t *)b;
#else
        if ((((uintptr_t)buf) & 0x03) != 0) {
            *buf++ ^= c->keystream_buffer.v8[0];
            *buf++ ^= c->keystream_buffer.v8[1];
            *buf++ ^= c->keystream_buffer.v8[2];
            *buf++ ^= c->keystream_buffer.v8[3];
            *buf++ ^= c->keystream_buffer.v8[4];
            *buf++ ^= c->keystream_buffer.v8[5];
            *buf++ ^= c->keystream_buffer.v8[6];
            *buf++ ^= c->keystream_buffer.v8[7];
            *buf++ ^= c->keystream_buffer.v8[8];
            *buf++ ^= c->keystream_buffer.v8[9];
            *buf++ ^= c->keystream_buffer.v8[10];
            *buf++ ^= c->keystream_buffer.v8[11];
            *buf++ ^= c->keystream_buffer.v8[12];
            *buf++ ^= c->keystream_buffer.v8[13];
            *buf++ ^= c->keystream_buffer.v8[14];
            *buf++ ^= c->keystream_buffer.v8[15];
        } else {
            b = (uint32_t *)buf;
            *b++ ^= c->keystream_buffer.v32[0];
            *b++ ^= c->keystream_buffer.v32[1];
            *b++ ^= c->keystream_buffer.v32[2];
            *b++ ^= c->keystream_buffer.v32[3];
            buf = (uint8_t *)b;
        }
#endif /* #if ALIGN_32 */
    }

    /* if there is a tail end of the data, process it */
    if ((bytes_to_encr & 0xf) != 0) {
        /* fill buffer with new keystream */
        srtp_gost_icm_advance(c);

        for (i = 0; i < (bytes_to_encr & 0xf); i++) {
            *buf++ ^= c->keystream_buffer.v8[i];
        }

        /* reset the keystream buffer size to right value */
        c->bytes_in_buffer = sizeof(v128_t) - i;
    } else {
        /* no tail, so just reset the keystream buffer size to zero */
        c->bytes_in_buffer = 0;
    }

    // Encrypt
    //    gost_enc(c, buf, ciphertext, 2);
    //    for (size_t i = 0; i < bytes_to_encr; i++) {
    //        buf[0] ^= ciphertext[i];
    //    }
    //    printf("Plaintext: %s\n", buf);
//    memccpy(buf, ciphertext, 0, 16);
    //    printf("Plaintext: %s\n", ciphertext);

    return srtp_err_status_ok;
}

static const char srtp_gost_icm_256_description[] =
    "GOST-28147 integer counter mode";

/*
 * note: the encrypt function is identical to the decrypt function
 */

const srtp_cipher_type_t srtp_gost_icm_28147 = {
    srtp_gost_icm_alloc,           /* */
    srtp_gost_icm_dealloc,         /* */
    srtp_gost_icm_context_init,    /* */
    0,                             /* set_aad */
    srtp_gost_icm_encrypt,         /* */
    srtp_gost_icm_encrypt,         /* */
    srtp_gost_icm_set_iv,          /* */
    0,                             /* get_tag */
    srtp_gost_icm_256_description, /* */
    &srtp_gost_test_case_0,        /* */
    SRTP_GOST_28147_89             /* */
};
