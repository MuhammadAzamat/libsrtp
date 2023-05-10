#ifndef GOST_H
#define GOST_H

#include "datatypes.h"
#include "err.h"

#ifdef __cplusplus
extern "C" {
#endif
/* Typedef for unsigned 32-bit integer */
#if __LONG_MAX__ > 2147483647L
typedef unsigned int u4;
#else
typedef unsigned long u4;
#endif
/* Typedef for unsigned 8-bit integer */
typedef unsigned char byte;
typedef struct {
    byte k8[16];
    byte k7[16];
    byte k6[16];
    byte k5[16];
    byte k4[16];
    byte k3[16];
    byte k2[16];
    byte k1[16];
} gost_subst_block;
/* Cipher context includes key and preprocessed  substitution block */
typedef struct {
    u4 k[8];
    /* Constant s-boxes -- set up in gost_init(). */
    u4 k87[256],k65[256],k43[256],k21[256];
} gost_ctx;


#if __LONG_MAX__ > 2147483647L
typedef unsigned int word32;
#else
typedef unsigned long word32;
#endif 

#ifdef __cplusplus
}
#endif

#endif /* GOST_H */
