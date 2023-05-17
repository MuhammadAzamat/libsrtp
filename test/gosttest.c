//
// Created by muhammad on 11.05.23.
//

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "getopt_s.h" /* for local getopt()  */

#include <stdio.h>    /* for printf, fprintf */
#include <stdlib.h>   /* for atoi()          */
#include <errno.h>
#include <signal.h>   /* for signal()        */

#include <string.h>   /* for strncpy()       */
#include <time.h>     /* for usleep()        */

#ifdef HAVE_UNISTD_H
#include <unistd.h> /* for close()         */
#elif defined(_MSC_VER)
#include <io.h>     /* for _close()        */
#define close _close
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#elif defined HAVE_WINSOCK2_H
#include <winsock2.h>
#include <ws2tcpip.h>
#define RTPW_USE_WINSOCK2 1
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "gost.h"

int main(void)
{
    /*
     * static String input1 = "0000000000000000";
     * static String output1 = "1b0bbc32cebcab42";
     * 546d203368656c326973652073736e62206167796967747473656865202c3d73
     * */
    const byte key[] = { 0x54, 0x6d, 0x20, 0x33, 0x68, 0x65, 0x6c, 0x32,
                         0x69, 0x73, 0x65, 0x20, 0x73, 0x73, 0x6e, 0x62,
                         0x20, 0x61, 0x67, 0x79, 0x69, 0x67, 0x74, 0x74,
                         0x73, 0x65, 0x68, 0x65, 0x20, 0x2c, 0x3d, 0x73 };

    //    const byte key[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    //                         0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    //                         0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    //                         0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };

    //        const byte key[] = { 0x73, 0x3d, 0x2c, 0x20, 0x65, 0x68, 0x65,
    //        0x73,
    //                             0x74, 0x74, 0x67, 0x69, 0x79, 0x67, 0x61,
    //                             0x20, 0x62, 0x6e, 0x73, 0x73, 0x20, 0x65,
    //                             0x73, 0x69, 0x32, 0x6c, 0x65, 0x68, 0x33,
    //                             0x20, 0x6d, 0x54 };

    //    const byte key_d[] = {
    //        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    //    };

    //{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x00, 0x00, 0x00, 0x00, 0x00};

//        byte text[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00 };

    //    const byte plaintext[] = { 0x0e, 0xe1, 0xa4, 0x62, 0x22, 0x96, 0x9c,
    //    0x23 };

    //    unsigned char plaintext[] = { 0x4e, 0x6f, 0x77, 0x20, 0x69, 0x73,
    //                                  0x20, 0x74, 0x68, 0x65, 0x20, 0x74,
    //                                  0x69, 0x6d, 0x65, 0x20, 0x66, 0x6f,
    //                                  0x72, 0x20, 0x61, 0x6c, 0x6c, 0x20 };

    //    const uint8_t output[] = { 0x1b, 0x0b, 0xbc, 0x32, 0xce, 0xbc, 0xab,
    //    0x42 };
    byte text[] = "Hello,world!!!!";
    byte *plaintext = text;
    byte ciphertext[sizeof(plaintext)];
    (void)ciphertext;
    byte deciphertext[sizeof(plaintext)];
    size_t len = sizeof(plaintext);

    gost_ctx c;
    gost_init(&c, &GostR3411_94_TestParamSet);
    gost_key(&c, key);

    printf("Plaintext : %s\n", text);
    printf("Plaintext : ");
    for (size_t i = 0; i < len; i++) {
        printf("%02x", text[i]);
    }
    printf("\n");
    for (byte i = 0; i < 2; i++) {
        gost_enc(&c, plaintext);
        plaintext += 8;
    }

    printf("Encrypting\n");

    printf("Ciphertext: %s\n", text);

    printf("Ciphertext: ");
    for (size_t i = 0; i < len; i++) {
        printf("%02x", text[i]);
    }

    printf("\n");
    printf("Decrypting\n");

    gost_dec(&c, text, deciphertext, 2);


    printf("Plaintext : ");
    for (size_t i = 0; i < len; i++) {
        printf("%02x", deciphertext[i]);
    }
    printf("\n");
    printf("Plaintext : %s\n", deciphertext);
    printf("\n");

    return 0;
}
