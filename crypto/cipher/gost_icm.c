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

    /*
     * set counter and initial values to 'offset' value, being careful not to
     * go past the end of the key buffer
     */
    v128_set_to_zero(&c->counter);
    v128_set_to_zero(&c->offset);
    gost_init(c, NULL);
    gost_key(c, key);

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
    (void)direction;

    return srtp_err_status_ok;
}

/*
 * aes_icm_advance(...) refills the keystream_buffer and
 * advances the block index of the sicm_context forward by one
 *
 * this is an internal, hopefully inlined function
 */
// static void srtp_gost_icm_advance(srtp_gost_icm_ctx_t *c)
//{
//     printf("%s", (const char *)c);
//
////    srtp_gost_encrypt(&c->keystream_buffer, &c->expanded_key);
//
//}

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

    // Encrypt
    gost_enc(c, buf, ciphertext, 2);
    //    for (size_t i = 0; i < bytes_to_encr; i++) {
    //        buf[0] ^= ciphertext[i];
    //    }
    //    printf("Plaintext: %s\n", buf);
    memccpy(buf, ciphertext, 0, 16);
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
