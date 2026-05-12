#ifndef TEST_STM32H563_WOLFSSL_IOTSAFE_USER_SETTINGS_H
#define TEST_STM32H563_WOLFSSL_IOTSAFE_USER_SETTINGS_H

#include <stdint.h>

#define IOTSAFE_ID_SIZE       2
#define CRT_CLIENT_FILE_ID    0x0002
#define CRT_SERVER_FILE_ID    0x0003
#define PRIVKEY_ID            0x0001
#define ECDH_KEYPAIR_ID       0x0004
#define PEER_PUBKEY_ID        0x0005
#define PEER_CERT_ID          0x0005

#define SOFT_SERVER_CA

#define WOLFSSL_IOTSAFE
#define WOLFSSL_SMALL_STACK
#define WOLFSSL_GENERAL_ALIGNMENT 4
#define SINGLE_THREADED
#define WOLFSSL_USER_IO
#define WOLFSSL_LOG_PRINTF
#define HAVE_PK_CALLBACKS
#define SMALL_SESSION_CACHE
#define USE_CERT_BUFFERS_256

#define HAVE_IOTSAFE_HWRNG
#define HAVE_HASHDRBG
#define NO_OLD_RNGNAME

#define TIME_OVERRIDES
extern volatile unsigned long jiffies;
static inline long XTIME(long *x)
{
    (void)x;
    return (long)jiffies;
}
#define WOLFSSL_USER_CURRTIME
#define NO_ASN_TIME

#define TFM_TIMING_RESISTANT
#define TFM_ARM
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_SP_SMALL
#define WOLFSSL_HAVE_SP_ECC
#define SP_WORD_SIZE 32

#define HAVE_ECC
#define ECC_ALT_SIZE
#define ECC_TIMING_RESISTANT

#define HAVE_AES_DECRYPT
#define HAVE_AESGCM
#define GCM_SMALL
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_DIRECT

#define HAVE_HKDF

#define NO_OLD_TLS
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES

#define NO_WRITEV
#define NO_FILESYSTEM
#define WOLFSSL_NO_SOCK
#define NO_MAIN_DRIVER

#define NO_DES3
#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_SHA
#define NO_SHA512
#define NO_PKCS12
#define NO_RSA
#define NO_DH

#define htons(x) __builtin_bswap16(x)
#define ntohs(x) __builtin_bswap16(x)
#define ntohl(x) __builtin_bswap32(x)
#define htonl(x) __builtin_bswap32(x)

#endif
