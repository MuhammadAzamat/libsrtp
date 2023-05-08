
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

void srtp_gost_encrypt()
{
//    gost_ctx *ctx;
//    unsigned char iv[8];
    // Encrypt
//    gostcrypt(ctx, iv, iv);
}
