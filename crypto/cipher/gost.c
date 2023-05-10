
/*
 *
 * Copyright (c) 2001-2017, Cisco Systems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 *
 *   Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "gost.h"
#include "err.h"


/* gost internals */

    /* Substitution blocks from test examples for GOST R 34.11-94*/
    gost_subst_block GostR3411_94_TestParamSet = {
    {0X1,0XF,0XD,0X0,0X5,0X7,0XA,0X4,0X9,0X2,0X3,0XE,0X6,0XB,0X8,0XC},
    {0XD,0XB,0X4,0X1,0X3,0XF,0X5,0X9,0X0,0XA,0XE,0X7,0X6,0X8,0X2,0XC},
    {0X4,0XB,0XA,0X0,0X7,0X2,0X1,0XD,0X3,0X6,0X8,0X5,0X9,0XC,0XF,0XE},
    {0X6,0XC,0X7,0X1,0X5,0XF,0XD,0X8,0X4,0XA,0X9,0XE,0X0,0X3,0XB,0X2},
    {0X7,0XD,0XA,0X1,0X0,0X8,0X9,0XF,0XE,0X4,0X6,0XC,0XB,0X2,0X5,0X3},
    {0X5,0X8,0X1,0XD,0XA,0X3,0X4,0X2,0XE,0XF,0XC,0X7,0X6,0X0,0X9,0XB},
    {0XE,0XB,0X4,0XC,0X6,0XD,0XF,0XA,0X2,0X3,0X8,0X1,0X0,0X7,0X5,0X9},
    {0X4,0XA,0X9,0X2,0XD,0X8,0X0,0XE,0X6,0XB,0X1,0XC,0X7,0XF,0X5,0X3}
};
/* Substitution blocks for hash function 1.2.643.2.9.1.6.1  */
gost_subst_block GostR3411_94_CryptoProParamSet= {
    {0x1,0x3,0xA,0x9,0x5,0xB,0x4,0xF,0x8,0x6,0x7,0xE,0xD,0x0,0x2,0xC},
    {0xD,0xE,0x4,0x1,0x7,0x0,0x5,0xA,0x3,0xC,0x8,0xF,0x6,0x2,0x9,0xB},
    {0x7,0x6,0x2,0x4,0xD,0x9,0xF,0x0,0xA,0x1,0x5,0xB,0x8,0xE,0xC,0x3},
    {0x7,0x6,0x4,0xB,0x9,0xC,0x2,0xA,0x1,0x8,0x0,0xE,0xF,0xD,0x3,0x5},
    {0x4,0xA,0x7,0xC,0x0,0xF,0x2,0x8,0xE,0x1,0x6,0x5,0xD,0xB,0x9,0x3},
    {0x7,0xF,0xC,0xE,0x9,0x4,0x1,0x0,0x3,0xB,0x5,0x2,0x6,0xA,0x8,0xD},
    {0x5,0xF,0x4,0x0,0x2,0xD,0xB,0x9,0x1,0x7,0x6,0x3,0xC,0xE,0xA,0x8},
    {0xA,0x4,0x5,0x6,0x8,0x1,0x3,0x7,0xD,0xC,0xE,0x0,0x9,0x2,0xB,0xF}
} ;
/* Test paramset from GOST 28147 */
gost_subst_block Gost28147_TestParamSet =
    {
        {0xC,0x6,0x5,0x2,0xB,0x0,0x9,0xD,0x3,0xE,0x7,0xA,0xF,0x4,0x1,0x8},
        {0x9,0xB,0xC,0x0,0x3,0x6,0x7,0x5,0x4,0x8,0xE,0xF,0x1,0xA,0x2,0xD},
        {0x8,0xF,0x6,0xB,0x1,0x9,0xC,0x5,0xD,0x3,0x7,0xA,0x0,0xE,0x2,0x4},
        {0x3,0xE,0x5,0x9,0x6,0x8,0x0,0xD,0xA,0xB,0x7,0xC,0x2,0x1,0xF,0x4},
        {0xE,0x9,0xB,0x2,0x5,0xF,0x7,0x1,0x0,0xD,0xC,0x6,0xA,0x4,0x3,0x8},
        {0xD,0x8,0xE,0xC,0x7,0x3,0x9,0xA,0x1,0x5,0x2,0x4,0x6,0xF,0x0,0xB},
        {0xC,0x9,0xF,0xE,0x8,0x1,0x3,0xA,0x2,0x7,0x4,0xD,0x6,0x0,0xB,0x5},
        {0x4,0x2,0xF,0x5,0x9,0x1,0x0,0x8,0xE,0x3,0xB,0xC,0xD,0x7,0xA,0x6}
    };
/* 1.2.643.2.2.31.1 */
gost_subst_block Gost28147_CryptoProParamSetA= {
    {0xB,0xA,0xF,0x5,0x0,0xC,0xE,0x8,0x6,0x2,0x3,0x9,0x1,0x7,0xD,0x4},
    {0x1,0xD,0x2,0x9,0x7,0xA,0x6,0x0,0x8,0xC,0x4,0x5,0xF,0x3,0xB,0xE},
    {0x3,0xA,0xD,0xC,0x1,0x2,0x0,0xB,0x7,0x5,0x9,0x4,0x8,0xF,0xE,0x6},
    {0xB,0x5,0x1,0x9,0x8,0xD,0xF,0x0,0xE,0x4,0x2,0x3,0xC,0x7,0xA,0x6},
    {0xE,0x7,0xA,0xC,0xD,0x1,0x3,0x9,0x0,0x2,0xB,0x4,0xF,0x8,0x5,0x6},
    {0xE,0x4,0x6,0x2,0xB,0x3,0xD,0x8,0xC,0xF,0x5,0xA,0x0,0x7,0x1,0x9},
    {0x3,0x7,0xE,0x9,0x8,0xA,0xF,0x0,0x5,0x2,0x6,0xC,0xB,0x4,0xD,0x1},
    {0x9,0x6,0x3,0x2,0x8,0xB,0x1,0x7,0xA,0x4,0xE,0xF,0xC,0x0,0xD,0x5}
};
/* 1.2.643.2.2.31.2 */
gost_subst_block Gost28147_CryptoProParamSetB=
    {
        {0x0,0x4,0xB,0xE,0x8,0x3,0x7,0x1,0xA,0x2,0x9,0x6,0xF,0xD,0x5,0xC},
        {0x5,0x2,0xA,0xB,0x9,0x1,0xC,0x3,0x7,0x4,0xD,0x0,0x6,0xF,0x8,0xE},
        {0x8,0x3,0x2,0x6,0x4,0xD,0xE,0xB,0xC,0x1,0x7,0xF,0xA,0x0,0x9,0x5},
        {0x2,0x7,0xC,0xF,0x9,0x5,0xA,0xB,0x1,0x4,0x0,0xD,0x6,0x8,0xE,0x3},
        {0x7,0x5,0x0,0xD,0xB,0x6,0x1,0x2,0x3,0xA,0xC,0xF,0x4,0xE,0x9,0x8},
        {0xE,0xC,0x0,0xA,0x9,0x2,0xD,0xB,0x7,0x5,0x8,0xF,0x3,0x6,0x1,0x4},
        {0x0,0x1,0x2,0xA,0x4,0xD,0x5,0xC,0x9,0x7,0x3,0xF,0xB,0x8,0x6,0xE},
        {0x8,0x4,0xB,0x1,0x3,0x5,0x0,0x9,0x2,0xE,0xA,0xC,0xD,0x6,0x7,0xF}
    };
/* 1.2.643.2.2.31.3 */
gost_subst_block Gost28147_CryptoProParamSetC=
    {
        {0x7,0x4,0x0,0x5,0xA,0x2,0xF,0xE,0xC,0x6,0x1,0xB,0xD,0x9,0x3,0x8},
        {0xA,0x9,0x6,0x8,0xD,0xE,0x2,0x0,0xF,0x3,0x5,0xB,0x4,0x1,0xC,0x7},
        {0xC,0x9,0xB,0x1,0x8,0xE,0x2,0x4,0x7,0x3,0x6,0x5,0xA,0x0,0xF,0xD},
        {0x8,0xD,0xB,0x0,0x4,0x5,0x1,0x2,0x9,0x3,0xC,0xE,0x6,0xF,0xA,0x7},
        {0x3,0x6,0x0,0x1,0x5,0xD,0xA,0x8,0xB,0x2,0x9,0x7,0xE,0xF,0xC,0x4},
        {0x8,0x2,0x5,0x0,0x4,0x9,0xF,0xA,0x3,0x7,0xC,0xD,0x6,0xE,0x1,0xB},
        {0x0,0x1,0x7,0xD,0xB,0x4,0x5,0x2,0x8,0xE,0xF,0xC,0x9,0xA,0x6,0x3},
        {0x1,0xB,0xC,0x2,0x9,0xD,0x0,0xF,0x4,0x5,0x8,0xE,0xA,0x7,0x6,0x3}
    };
/* 1.2.643.2.2.31.4 */
gost_subst_block Gost28147_CryptoProParamSetD=
    {
        {0x1,0xA,0x6,0x8,0xF,0xB,0x0,0x4,0xC,0x3,0x5,0x9,0x7,0xD,0x2,0xE},
        {0x3,0x0,0x6,0xF,0x1,0xE,0x9,0x2,0xD,0x8,0xC,0x4,0xB,0xA,0x5,0x7},
        {0x8,0x0,0xF,0x3,0x2,0x5,0xE,0xB,0x1,0xA,0x4,0x7,0xC,0x9,0xD,0x6},
        {0x0,0xC,0x8,0x9,0xD,0x2,0xA,0xB,0x7,0x3,0x6,0x5,0x4,0xE,0xF,0x1},
        {0x1,0x5,0xE,0xC,0xA,0x7,0x0,0xD,0x6,0x2,0xB,0x4,0x9,0x3,0xF,0x8},
        {0x1,0xC,0xB,0x0,0xF,0xE,0x6,0x5,0xA,0xD,0x4,0x8,0x9,0x3,0x7,0x2},
        {0xB,0x6,0x3,0x4,0xC,0xF,0xE,0x2,0x7,0xD,0x8,0x0,0x5,0xA,0x9,0x1},
        {0xF,0xC,0x2,0xA,0x6,0x4,0x5,0x0,0x7,0x9,0xE,0xD,0x1,0xB,0x8,0x3}
    };
const byte CryptoProKeyMeshingKey[]={
    0x69, 0x00, 0x72, 0x22,   0x64, 0xC9, 0x04, 0x23,
    0x8D, 0x3A, 0xDB, 0x96,   0x46, 0xE9, 0x2A, 0xC4,
    0x18, 0xFE, 0xAC, 0x94,   0x00, 0xED, 0x07, 0x12,
    0xC0, 0x86, 0xDC, 0xC2,   0xEF, 0x4C, 0xA9, 0x2B
};

/* Initialization of gost_ctx subst blocks*/
static void kboxinit(gost_ctx *c, const gost_subst_block *b)
{
    int i;

    for (i = 0; i < 256; i++)
    {
        c->k87[i] = (b->k8[i>>4] <<4 | b->k7 [i &15])<<24;
        c->k65[i] = (b->k6[i>>4] << 4 | b->k5 [i &15])<<16;
        c->k43[i] = (b->k4[i>>4] <<4  | b->k3 [i &15])<<8;
        c->k21[i] = b->k2[i>>4] <<4  | b->k1 [i &15];
    }
}

/* Part of GOST 28147 algorithm moved into separate function */
static word32 f(gost_ctx *c,word32 x)
{
    x = c->k87[x>>24 & 255] | c->k65[x>>16 & 255]|
        c->k43[x>> 8 & 255] | c->k21[x & 255];
    /* Rotate left 11 bits */
    return x<<11 | x>>(32-11);
}
/* Low-level encryption routine - encrypts one 64 bit block*/
void gostcrypt(gost_ctx *c, const byte *in, byte *out)
{
    register word32 n1, n2; /* As named in the GOST */
    n1 = in[0]|(in[1]<<8)|(in[2]<<16)|(in[3]<<24);
    n2 = in[4]|(in[5]<<8)|(in[6]<<16)|(in[7]<<24);
    /* Instead of swapping halves, swap names each round */

    n2 ^= f(c,n1+c->k[0]); n1 ^= f(c,n2+c->k[1]);
    n2 ^= f(c,n1+c->k[2]); n1 ^= f(c,n2+c->k[3]);
    n2 ^= f(c,n1+c->k[4]); n1 ^= f(c,n2+c->k[5]);
    n2 ^= f(c,n1+c->k[6]); n1 ^= f(c,n2+c->k[7]);

    n2 ^= f(c,n1+c->k[0]); n1 ^= f(c,n2+c->k[1]);
    n2 ^= f(c,n1+c->k[2]); n1 ^= f(c,n2+c->k[3]);
    n2 ^= f(c,n1+c->k[4]); n1 ^= f(c,n2+c->k[5]);
    n2 ^= f(c,n1+c->k[6]); n1 ^= f(c,n2+c->k[7]);

    n2 ^= f(c,n1+c->k[0]); n1 ^= f(c,n2+c->k[1]);
    n2 ^= f(c,n1+c->k[2]); n1 ^= f(c,n2+c->k[3]);
    n2 ^= f(c,n1+c->k[4]); n1 ^= f(c,n2+c->k[5]);
    n2 ^= f(c,n1+c->k[6]); n1 ^= f(c,n2+c->k[7]);

    n2 ^= f(c,n1+c->k[7]); n1 ^= f(c,n2+c->k[6]);
    n2 ^= f(c,n1+c->k[5]); n1 ^= f(c,n2+c->k[4]);
    n2 ^= f(c,n1+c->k[3]); n1 ^= f(c,n2+c->k[2]);
    n2 ^= f(c,n1+c->k[1]); n1 ^= f(c,n2+c->k[0]);

    out[0] = (byte)(n2&0xff);  out[1] = (byte)((n2>>8)&0xff);
    out[2] = (byte)((n2>>16)&0xff); out[3]=(byte)(n2>>24);
    out[4] = (byte)(n1&0xff);  out[5] = (byte)((n1>>8)&0xff);
    out[6] = (byte)((n1>>16)&0xff); out[7] = (byte)(n1>>24);
}

/* Encrypts several blocks in ECB mode */
void gost_enc(gost_ctx *c,const byte *clear,byte *cipher, int blocks)
{
    int i;
    for(i=0;i<blocks;i++)
    {
        gostcrypt(c,clear,cipher);
        clear+=8;
        cipher+=8;
    }
}

void gost_key(gost_ctx *c, const byte *k)
{
    int i,j;
    for(i=0,j=0;i<8;i++,j+=4)
    {
        c->k[i]=k[j]|(k[j+1]<<8)|(k[j+2]<<16)|(k[j+3]<<24);
    }
}
/* Initalize context. Provides default value for subst_block */
void gost_init(gost_ctx *c, const gost_subst_block *b)
{
    if(!b)
    {
        b=&GostR3411_94_TestParamSet;
    }
    kboxinit(c,b);
}
/* Cleans up key from context */
void gost_destroy(gost_ctx *c)
{
    int i; for(i=0;i<8;i++) c->k[i]=0;
}
