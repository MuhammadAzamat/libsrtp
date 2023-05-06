#ifndef GOST_H
#define GOST_H

#include "datatypes.h"
#include "err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* gost internals */

typedef struct {
    v128_t round[15];
    int num_rounds;
} srtp_gost_expanded_key_t;

srtp_err_status_t srtp_gost_expand_encryption_key(
    const uint8_t *key,
    int key_len,
    srtp_gost_expanded_key_t *expanded_key);

srtp_err_status_t srtp_gost_expand_decryption_key(
    const uint8_t *key,
    int key_len,
    srtp_gost_expanded_key_t *expanded_key);

void srtp_gost_encrypt(v128_t *plaintext,
                      const srtp_gost_expanded_key_t *exp_key);

void srtp_gost_decrypt(v128_t *plaintext,
                      const srtp_gost_expanded_key_t *exp_key);

#ifdef __cplusplus
}
#endif

#endif /* GOST_H */
