/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "m33mu/ta100.h"
#include "m33mu/spi_bus.h"
#include "m33mu/gpio.h"

#ifdef M33MU_HAS_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#endif

#define TA100_MAX 4
#define TA100_CMD_MAX 2048u
#define TA100_RSP_MAX 2048u

#define TA100_NV_SIZE 4096u
#define TA100_CONFIG_ZONE_SIZE 128u
#define TA100_DATA_ZONE_SIZE 1024u
#define TA100_KEY_SLOTS 16
#define TA100_KEY_SLOT_SIZE 72u
#define TA100_MAX_HANDLES 64
#define TA100_HANDLE_DATA_MAX 2048u
#define TA100_RSA_PRIV_DER_MAX 2048u

/* TA100 handle attribute masks (match talib_defines.h) */
#define TA_HANDLE_INFO_CLASS_SHIFT 0u
#define TA_HANDLE_INFO_CLASS_MASK  (0x07u << TA_HANDLE_INFO_CLASS_SHIFT)
#define TA_HANDLE_INFO_KEY_TYPE_SHIFT 3u
#define TA_HANDLE_INFO_KEY_TYPE_MASK  (0x0Fu << TA_HANDLE_INFO_KEY_TYPE_SHIFT)
#define TA_HANDLE_INFO_ALG_MODE_SHIFT 7u
#define TA_HANDLE_INFO_ALG_MODE_MASK  (0x01u << TA_HANDLE_INFO_ALG_MODE_SHIFT)

/* TA100 element classes */
#define TA_CLASS_PUBLIC_KEY  0x00u
#define TA_CLASS_PRIVATE_KEY 0x01u
#define TA_CLASS_SYMMETRIC_KEY 0x02u

/* TA100 key types (subset) */
#define TA_KEY_TYPE_ECCP256   0u
#define TA_KEY_TYPE_ECCP224   1u
#define TA_KEY_TYPE_ECCP384   2u
#define TA_KEY_TYPE_RSA2048   5u
#define TA_KEY_TYPE_AES128    12u

#define TA_KEY_TYPE_ECCP256_SIZE 32u
#define TA_KEY_TYPE_ECCP384_SIZE 48u
#define TA_KEY_TYPE_RSA2048_SIZE 256u
#define TA_KEY_TYPE_AES128_SIZE 16u

/* TA100 sign/verify */
#define TA_SIGN_MODE_INTERNAL_MSG 0x20u
#define TA_SIGN_MODE_EXTERNAL_MSG 0x00u
#define TA_HANDLE_INPUT_BUFFER 0x4800u

/* TA100 AES (subset) */
#define TA_AES_ACTION_MASK   0x03u
#define TA_AES_ACTION_KEY_LOAD 0x00u
#define TA_AES_ACTION_ENCRYPT  0x01u
#define TA_AES_ACTION_DECRYPT  0x02u
#define TA_AES_MODE_MASK     0x1Cu
#define TA_AES_MODE_ECB      0x04u
#define TA_AES_MODE_GCM      0x08u
#define TA_AES_RAND_IV       0x80u
#define TA_AES_GCM_IV_LENGTH 12u
#define TA_AES_GCM_TAG_LENGTH 16u
#define TA_AES_DATA_SIZE     16u
#define TA_AES_GCM_MAX_DATA_SIZE 996u

/* TA100 RSAENC (subset) */
#define TA_RSAENC_ENCRYPT2048 0x03u
#define TA_RSAENC_DECRYPT2048 0x02u
#define TA_RSAENC_PLAIN_TEXT_MAX_SIZE2048 190u
#define TA_RSAENC_CIPHER_TEXT_SIZE2048 256u

static const unsigned char ta100_rsa_modulus[256] = {
    0x92, 0x50, 0x9e, 0xf1, 0x95, 0xa4, 0x15, 0xfd, 0x0e, 0x70, 0xc5, 0x68, 0x1e, 0xc6, 0x9a, 0x8b,
    0x7e, 0x9d, 0x35, 0x3d, 0xe2, 0x5e, 0x9a, 0xba, 0x29, 0xb3, 0x03, 0xcb, 0x54, 0x64, 0x71, 0xde,
    0xe7, 0x5f, 0x66, 0xf7, 0x91, 0x60, 0xe5, 0x4b, 0xa0, 0x7f, 0x3d, 0x04, 0x06, 0x4b, 0x11, 0x43,
    0x87, 0x31, 0x55, 0x60, 0x78, 0x53, 0x94, 0x7a, 0x66, 0xc1, 0xee, 0xad, 0xcb, 0x7d, 0xc3, 0x67,
    0x5b, 0xa7, 0x6e, 0x4c, 0x6b, 0x91, 0xe8, 0x8e, 0xe2, 0xd2, 0xf1, 0x4d, 0xad, 0x6b, 0x25, 0xa6,
    0x81, 0xb2, 0x5b, 0x49, 0x22, 0xbd, 0x28, 0xe7, 0x71, 0x3f, 0x2a, 0x59, 0x66, 0x4e, 0x53, 0xe3,
    0xbd, 0x95, 0x45, 0x85, 0xcf, 0x1c, 0xdb, 0xa6, 0xd4, 0x5e, 0x52, 0x64, 0x74, 0xe7, 0x6d, 0xfc,
    0xa1, 0xcb, 0x16, 0x64, 0x44, 0x34, 0x00, 0xa1, 0xba, 0x02, 0x63, 0x39, 0x33, 0x06, 0x1b, 0x79,
    0x05, 0xe6, 0x23, 0x02, 0x84, 0x08, 0xd3, 0xfc, 0xf1, 0x53, 0x76, 0x09, 0x2f, 0x7b, 0x5f, 0x40,
    0xe7, 0x1c, 0xb9, 0x3d, 0xc7, 0x93, 0x4c, 0x5d, 0x67, 0xfe, 0x63, 0xc9, 0x86, 0xdc, 0x07, 0x03,
    0xa2, 0x43, 0x25, 0x28, 0x47, 0xb3, 0x28, 0xb6, 0x56, 0x35, 0xab, 0xaa, 0x2b, 0xc0, 0x95, 0x31,
    0x21, 0xc6, 0xa4, 0x39, 0x51, 0xc6, 0x7f, 0x49, 0xa6, 0x3f, 0xf5, 0xf9, 0x28, 0x62, 0xaa, 0x0a,
    0x6c, 0x72, 0xfa, 0x5b, 0x6a, 0x5f, 0x6c, 0xf7, 0xd1, 0x14, 0x1b, 0xe0, 0x66, 0x95, 0x83, 0x20,
    0xf1, 0x66, 0x6d, 0x52, 0x76, 0x51, 0xb6, 0x8d, 0xf7, 0x66, 0x97, 0xb3, 0x0f, 0xb6, 0x63, 0xc7,
    0x73, 0x8e, 0x62, 0x7a, 0x48, 0xc4, 0x90, 0x3e, 0x3a, 0xde, 0x75, 0xec, 0x40, 0x8a, 0x7a, 0x49,
    0x7f, 0x7e, 0xaf, 0xb8, 0x29, 0x73, 0xd6, 0x8d, 0x81, 0x5e, 0xd8, 0xb9, 0xd4, 0x45, 0xda, 0xf7,
};

static const unsigned char ta100_rsa_pkcs1_der[] = {
  0x30, 0x82, 0x04, 0xa1, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00,
  0x92, 0x50, 0x9e, 0xf1, 0x95, 0xa4, 0x15, 0xfd, 0x0e, 0x70, 0xc5, 0x68,
  0x1e, 0xc6, 0x9a, 0x8b, 0x7e, 0x9d, 0x35, 0x3d, 0xe2, 0x5e, 0x9a, 0xba,
  0x29, 0xb3, 0x03, 0xcb, 0x54, 0x64, 0x71, 0xde, 0xe7, 0x5f, 0x66, 0xf7,
  0x91, 0x60, 0xe5, 0x4b, 0xa0, 0x7f, 0x3d, 0x04, 0x06, 0x4b, 0x11, 0x43,
  0x87, 0x31, 0x55, 0x60, 0x78, 0x53, 0x94, 0x7a, 0x66, 0xc1, 0xee, 0xad,
  0xcb, 0x7d, 0xc3, 0x67, 0x5b, 0xa7, 0x6e, 0x4c, 0x6b, 0x91, 0xe8, 0x8e,
  0xe2, 0xd2, 0xf1, 0x4d, 0xad, 0x6b, 0x25, 0xa6, 0x81, 0xb2, 0x5b, 0x49,
  0x22, 0xbd, 0x28, 0xe7, 0x71, 0x3f, 0x2a, 0x59, 0x66, 0x4e, 0x53, 0xe3,
  0xbd, 0x95, 0x45, 0x85, 0xcf, 0x1c, 0xdb, 0xa6, 0xd4, 0x5e, 0x52, 0x64,
  0x74, 0xe7, 0x6d, 0xfc, 0xa1, 0xcb, 0x16, 0x64, 0x44, 0x34, 0x00, 0xa1,
  0xba, 0x02, 0x63, 0x39, 0x33, 0x06, 0x1b, 0x79, 0x05, 0xe6, 0x23, 0x02,
  0x84, 0x08, 0xd3, 0xfc, 0xf1, 0x53, 0x76, 0x09, 0x2f, 0x7b, 0x5f, 0x40,
  0xe7, 0x1c, 0xb9, 0x3d, 0xc7, 0x93, 0x4c, 0x5d, 0x67, 0xfe, 0x63, 0xc9,
  0x86, 0xdc, 0x07, 0x03, 0xa2, 0x43, 0x25, 0x28, 0x47, 0xb3, 0x28, 0xb6,
  0x56, 0x35, 0xab, 0xaa, 0x2b, 0xc0, 0x95, 0x31, 0x21, 0xc6, 0xa4, 0x39,
  0x51, 0xc6, 0x7f, 0x49, 0xa6, 0x3f, 0xf5, 0xf9, 0x28, 0x62, 0xaa, 0x0a,
  0x6c, 0x72, 0xfa, 0x5b, 0x6a, 0x5f, 0x6c, 0xf7, 0xd1, 0x14, 0x1b, 0xe0,
  0x66, 0x95, 0x83, 0x20, 0xf1, 0x66, 0x6d, 0x52, 0x76, 0x51, 0xb6, 0x8d,
  0xf7, 0x66, 0x97, 0xb3, 0x0f, 0xb6, 0x63, 0xc7, 0x73, 0x8e, 0x62, 0x7a,
  0x48, 0xc4, 0x90, 0x3e, 0x3a, 0xde, 0x75, 0xec, 0x40, 0x8a, 0x7a, 0x49,
  0x7f, 0x7e, 0xaf, 0xb8, 0x29, 0x73, 0xd6, 0x8d, 0x81, 0x5e, 0xd8, 0xb9,
  0xd4, 0x45, 0xda, 0xf7, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x81, 0xff,
  0x04, 0x49, 0x8e, 0x57, 0x5f, 0x87, 0x17, 0x8f, 0x77, 0x9d, 0x69, 0x24,
  0xc8, 0xcb, 0xab, 0x52, 0xe1, 0x20, 0x82, 0xd3, 0xf3, 0x63, 0x2c, 0x49,
  0xa7, 0x5f, 0x4a, 0x08, 0x6c, 0x86, 0x09, 0x03, 0xcd, 0x49, 0x5c, 0x0f,
  0xe2, 0x1a, 0x51, 0xb6, 0x12, 0x9a, 0x4a, 0x2c, 0x77, 0x0f, 0x48, 0xf7,
  0x03, 0x7b, 0xce, 0x7f, 0x1c, 0x09, 0xb9, 0xca, 0x8a, 0x81, 0x53, 0x7b,
  0xa2, 0x4a, 0xe3, 0xcc, 0x9d, 0x43, 0x91, 0x88, 0x6d, 0xc1, 0xe9, 0xbb,
  0xfa, 0xdd, 0xb9, 0x0a, 0x59, 0x45, 0x8f, 0x77, 0x2d, 0x6c, 0x9a, 0xe4,
  0xb0, 0x17, 0xc9, 0xe8, 0xe2, 0x34, 0xfc, 0xc9, 0xfb, 0xd7, 0xc3, 0x8e,
  0x09, 0x49, 0xe2, 0xa2, 0xdc, 0xdb, 0xf7, 0xed, 0xbd, 0xca, 0xf5, 0x86,
  0xc1, 0xc2, 0xc7, 0x96, 0x00, 0xe6, 0xc1, 0xdb, 0x08, 0xa9, 0x62, 0x22,
  0x8c, 0x7a, 0x1a, 0x75, 0x97, 0xc8, 0x3c, 0xc3, 0x67, 0xdf, 0xc4, 0x07,
  0xe9, 0x8f, 0x30, 0x70, 0xc0, 0xd5, 0x9e, 0x69, 0x8e, 0x3d, 0x4a, 0xa0,
  0xea, 0xf5, 0x76, 0x6a, 0x05, 0x29, 0xb6, 0xd2, 0x16, 0x0c, 0xd4, 0x56,
  0x23, 0xaa, 0xc9, 0x32, 0x31, 0x64, 0x12, 0x55, 0xd7, 0xeb, 0x66, 0x9f,
  0x97, 0x50, 0x63, 0xad, 0x4c, 0xa1, 0x9d, 0x03, 0xeb, 0xd6, 0x8d, 0xc7,
  0xad, 0x02, 0x2e, 0x66, 0x37, 0xa5, 0xc8, 0xc3, 0x7f, 0xe8, 0xee, 0x0e,
  0xb9, 0x2d, 0x1c, 0xf5, 0xd2, 0x9d, 0x8d, 0x4c, 0x5e, 0x65, 0xc1, 0x5a,
  0x91, 0x9b, 0x4d, 0x0e, 0xb0, 0x62, 0x15, 0x71, 0x15, 0xe2, 0x38, 0x10,
  0x43, 0x16, 0xdb, 0x70, 0xa2, 0x62, 0xde, 0xd2, 0xe8, 0x78, 0x04, 0x77,
  0xe9, 0xd2, 0x42, 0x47, 0xe6, 0xd9, 0x2e, 0x5d, 0xc0, 0x80, 0x0e, 0x87,
  0xc0, 0x15, 0x26, 0xbc, 0x94, 0xdf, 0x99, 0x70, 0x0b, 0x21, 0xa7, 0x0d,
  0x5d, 0x21, 0xa1, 0x02, 0x81, 0x81, 0x00, 0xcc, 0x91, 0x52, 0x2f, 0x45,
  0xe3, 0xc7, 0x31, 0x49, 0x86, 0x32, 0x76, 0xe0, 0xce, 0x9c, 0x9c, 0x4d,
  0xb9, 0xf8, 0x09, 0x0f, 0x98, 0x12, 0x48, 0xa2, 0x17, 0x03, 0x92, 0x1c,
  0xe1, 0xef, 0xc2, 0x60, 0x6e, 0x27, 0xce, 0xe5, 0xe7, 0x05, 0xf3, 0x8b,
  0xe1, 0x1f, 0x8e, 0xbc, 0x10, 0x50, 0x00, 0x53, 0x24, 0x3f, 0xb8, 0xf8,
  0x5b, 0x94, 0x20, 0xef, 0x57, 0x2a, 0x95, 0x75, 0x40, 0xa0, 0x47, 0xbb,
  0x1b, 0x9c, 0x6d, 0xae, 0xb5, 0x2d, 0x21, 0x09, 0x9b, 0xce, 0x48, 0xdb,
  0x8b, 0xcf, 0xb4, 0x1f, 0x64, 0x46, 0xdf, 0x52, 0xb4, 0x72, 0xc1, 0x02,
  0xaf, 0xa1, 0x35, 0xa8, 0x84, 0xf4, 0x5e, 0xe3, 0x98, 0x8f, 0xd3, 0xc1,
  0x4a, 0x27, 0xea, 0xb1, 0xbd, 0x6c, 0xc8, 0x82, 0x02, 0xf5, 0x05, 0xfa,
  0xeb, 0xec, 0xf7, 0x78, 0x70, 0xc5, 0x49, 0x48, 0x56, 0x2c, 0xc4, 0x4e,
  0x90, 0xa2, 0xf1, 0x02, 0x81, 0x81, 0x00, 0xb7, 0x19, 0xf4, 0x07, 0xd4,
  0x70, 0x5c, 0x5d, 0xe5, 0x22, 0x07, 0x9d, 0x90, 0xd9, 0x05, 0x66, 0xdf,
  0x53, 0xce, 0xa3, 0x4f, 0x82, 0xde, 0x31, 0x9e, 0x73, 0x73, 0xdf, 0x14,
  0xe1, 0x7f, 0x73, 0xa4, 0xff, 0x98, 0x0c, 0xe9, 0xf7, 0x6e, 0x59, 0xee,
  0x65, 0x58, 0x18, 0x18, 0x29, 0x90, 0x18, 0x44, 0xef, 0x05, 0x40, 0xf2,
  0x17, 0x94, 0x12, 0x29, 0x43, 0x05, 0xef, 0x67, 0x09, 0xef, 0xed, 0x03,
  0x8c, 0xbe, 0xab, 0x14, 0x33, 0xa4, 0x0c, 0x6e, 0x20, 0x60, 0x4f, 0x04,
  0x2d, 0x1f, 0xdc, 0xb0, 0x30, 0xc0, 0xbc, 0x23, 0xea, 0xe5, 0x38, 0xc0,
  0x96, 0x78, 0x71, 0x0e, 0x1e, 0xd5, 0x67, 0xdc, 0x52, 0x5a, 0x40, 0x3f,
  0x6f, 0x37, 0xb2, 0x77, 0x57, 0xf0, 0x1d, 0x2d, 0x4d, 0xa1, 0x6e, 0xaf,
  0xe0, 0xdc, 0xb0, 0x3c, 0xe4, 0x80, 0xe5, 0x68, 0x96, 0x24, 0xa8, 0xa5,
  0x81, 0x0c, 0x67, 0x02, 0x81, 0x80, 0x55, 0xff, 0x75, 0x9c, 0x57, 0xf6,
  0x44, 0xc4, 0x0c, 0x93, 0xb4, 0xdd, 0x52, 0xee, 0xa8, 0xd9, 0xf0, 0xb7,
  0x10, 0x75, 0xc6, 0xaf, 0x78, 0x68, 0x3e, 0x74, 0x0c, 0x55, 0x3d, 0x7d,
  0x22, 0x0d, 0x05, 0xfa, 0xe9, 0x13, 0x4a, 0x85, 0x0f, 0x74, 0x6e, 0x46,
  0x8a, 0xbc, 0xb7, 0x84, 0xe8, 0x0c, 0xea, 0xe6, 0xdf, 0x3f, 0x04, 0x71,
  0x83, 0x59, 0x41, 0x24, 0xd4, 0xcb, 0x16, 0x0a, 0xc0, 0x16, 0xc7, 0xaa,
  0xf8, 0xdd, 0x07, 0x48, 0x35, 0x1b, 0xa1, 0x6d, 0x75, 0x90, 0x1d, 0x73,
  0xae, 0x32, 0x9b, 0xcb, 0xcd, 0x1b, 0x8f, 0x2a, 0x3a, 0xdf, 0xb7, 0x20,
  0x5c, 0x56, 0x31, 0x6d, 0x0b, 0x4a, 0x64, 0xc5, 0xbb, 0x19, 0x1b, 0x35,
  0xf0, 0x87, 0xf2, 0x86, 0x9e, 0x97, 0xc0, 0x48, 0x3b, 0xf7, 0x72, 0xa0,
  0x01, 0xf3, 0x9b, 0x17, 0x55, 0x68, 0xd4, 0x57, 0x1d, 0xe4, 0xbc, 0xde,
  0x83, 0x11, 0x02, 0x81, 0x80, 0x4b, 0x3a, 0x40, 0x86, 0xcf, 0x03, 0x73,
  0x0f, 0xa8, 0xca, 0x78, 0x72, 0x86, 0x46, 0x83, 0xef, 0xa6, 0x25, 0xda,
  0xaa, 0x42, 0x4a, 0xb4, 0x5b, 0x92, 0x8c, 0x40, 0xb9, 0x10, 0xed, 0x2c,
  0xde, 0x28, 0x96, 0x52, 0xb4, 0x4b, 0x94, 0x3b, 0x24, 0x7b, 0xcb, 0xeb,
  0x8b, 0xca, 0xb1, 0x98, 0xe0, 0x3f, 0xc2, 0x2c, 0x58, 0x68, 0x9e, 0xc3,
  0x59, 0x4a, 0xd6, 0x9c, 0xa3, 0xa5, 0xa3, 0xf1, 0x8d, 0x61, 0x7d, 0xfc,
  0x00, 0x72, 0x06, 0x5d, 0x8a, 0x35, 0xdc, 0xdb, 0x74, 0xdb, 0x74, 0x66,
  0xb8, 0xd7, 0x32, 0xd0, 0x9c, 0xfb, 0xec, 0xd0, 0x4c, 0xa6, 0xe3, 0xab,
  0x8c, 0x57, 0x8e, 0xd7, 0x83, 0x1a, 0x84, 0x43, 0x4c, 0x4e, 0x43, 0xb5,
  0x90, 0x7f, 0x74, 0x03, 0xd5, 0x18, 0xfd, 0xe2, 0x2b, 0x85, 0xdb, 0x4f,
  0x10, 0xa1, 0x94, 0x08, 0x59, 0x38, 0xc5, 0x27, 0x3e, 0x9a, 0xf1, 0x10,
  0x55, 0x02, 0x81, 0x81, 0x00, 0xc9, 0x57, 0x75, 0xda, 0xf5, 0x9a, 0x51,
  0xc1, 0xca, 0x2a, 0xc4, 0x8c, 0x6e, 0x7f, 0x69, 0x97, 0xf8, 0xdc, 0x66,
  0xc7, 0xfd, 0x37, 0x52, 0xb2, 0xa1, 0xd5, 0x4e, 0xb3, 0x05, 0xd9, 0x8d,
  0xd6, 0x87, 0x85, 0xc3, 0x57, 0xea, 0xa6, 0xfa, 0x77, 0x41, 0x96, 0x59,
  0x9f, 0x59, 0x60, 0xb1, 0xe3, 0x8f, 0x2c, 0xcc, 0xf2, 0xae, 0xc9, 0xbe,
  0xeb, 0x59, 0x00, 0xef, 0x8b, 0x16, 0xd4, 0x08, 0x63, 0x86, 0x40, 0x2a,
  0xa5, 0xc5, 0xb0, 0x80, 0x39, 0xe6, 0xb5, 0xe6, 0xb5, 0xe3, 0xa5, 0x58,
  0xf9, 0xb1, 0x8a, 0x70, 0xdd, 0xbe, 0xe4, 0x0c, 0x01, 0xd5, 0xeb, 0x0d,
  0xfd, 0x05, 0x64, 0x67, 0x94, 0x77, 0xb7, 0x02, 0x41, 0x90, 0x16, 0x39,
  0xd2, 0x8c, 0xeb, 0x45, 0xba, 0x6a, 0xab, 0xa0, 0x8f, 0xdb, 0xde, 0xfe,
  0x1f, 0x10, 0xa2, 0xdf, 0x6a, 0x0f, 0xe1, 0x2f, 0x29, 0x08, 0xe9, 0x90,
  0x00
};
static const unsigned int ta100_rsa_pkcs1_der_len = 1189;

/* TA100 write modes (subset) */
#define TA_WRITE_ENTIRE_ELEMENT 0x01u

/* ATECC-style opcodes (legacy, for backward compat) */
#define TA100_CMD_INFO_ATECC 0x30
#define TA100_CMD_READ_ATECC 0x02
#define TA100_CMD_WRITE_ATECC 0x12
#define TA100_CMD_LOCK_ATECC 0x17
#define TA100_CMD_RANDOM_ATECC 0x1B
#define TA100_CMD_NONCE_ATECC 0x16
#define TA100_CMD_GENKEY_ATECC 0x40
#define TA100_CMD_SIGN_ATECC 0x41
#define TA100_CMD_SHA256_ATECC 0x47
#define TA100_CMD_MAC_ATECC 0x08

/* TA100-specific opcodes (from TA100 datasheet / cryptoauthlib) */
#define TA100_OP_INFO       0x00
#define TA100_OP_SECBOOT    0x01
#define TA100_OP_FCCONFIG   0x02
#define TA100_OP_POWER      0x03
#define TA100_OP_IMPORT     0x04
#define TA100_OP_EXPORT     0x05
#define TA100_OP_CREATE     0x06
#define TA100_OP_READ       0x07
#define TA100_OP_WRITE      0x08
#define TA100_OP_RANDOM     0x09
#define TA100_OP_MAC        0x0A
#define TA100_OP_DEVUPDATE  0x0B
#define TA100_OP_MANAGECERT 0x0C
#define TA100_OP_LOCK       0x0D
#define TA100_OP_COUNTER    0x0E
#define TA100_OP_SIGN       0x0F
#define TA100_OP_VERIFY     0x10
#define TA100_OP_ECDH       0x11
#define TA100_OP_KEYGEN     0x12
#define TA100_OP_DELETE     0x13
#define TA100_OP_SELFTEST   0x14
#define TA100_OP_SEQUENCE   0x15
#define TA100_OP_AUTHORIZE  0x16
#define TA100_OP_KDF        0x17
#define TA100_OP_RSAENC     0x18
#define TA100_OP_SHA        0x19
#define TA100_OP_AES        0x1A

#define TA_LOCK_CONFIG_WITHOUT_CRC 0x00
#define TA_LOCK_CONFIG_WITH_CRC    0x01
#define TA_LOCK_SHARED_ELEMENT     0x03
#define TA_LOCK_SETUP_LOCK         0x04

/* TA100 Info command modes */
#define TA100_INFO_MODE_REV             0x00
#define TA100_INFO_MODE_NV_REMAIN       0x01
#define TA100_INFO_MODE_HANDLE_VALID    0x02
#define TA100_INFO_MODE_HANDLE_INFO     0x03
#define TA100_INFO_MODE_HANDLE_ARRAY    0x04
#define TA100_INFO_MODE_AUTH_STATUS     0x05
#define TA100_INFO_MODE_VOL_REG_STATUS  0x06
#define TA100_INFO_MODE_DED_MEMORY      0x07
#define TA100_INFO_MODE_CHIP_STATUS     0x08

/* TA100 packet format constants */
#define TA100_PKT_INSTR_OFFSET    0
#define TA100_PKT_LENGTH_OFFSET   1
#define TA100_PKT_OPCODE_OFFSET   3
#define TA100_PKT_PARAM1_OFFSET   4
#define TA100_PKT_PARAM2_OFFSET   5
#define TA100_PKT_DATA_OFFSET     9
#define TA100_PKT_MIN_LEN         10  /* instr(1)+len(2)+op(1)+p1(1)+p2(4)+crc(2) = 11, but accept 10 */

/* TA100 instruction codes */
#define TA100_INSTR_WR_CMD  0x00
#define TA100_INSTR_RD_RSP  0x10
#define TA100_INSTR_WR_CCR  0x20
#define TA100_INSTR_RD_CSR  0x30

#define TA100_ZONE_CONFIG 0x00
#define TA100_ZONE_OTP 0x01
#define TA100_ZONE_DATA 0x02
#define TA100_ZONE_KEY 0x02

#define TA100_STATUS_SUCCESS 0x00
#define TA100_STATUS_CHECKMAC_FAILED 0x01
#define TA100_STATUS_PARSE_ERROR 0x03
#define TA100_STATUS_EXEC_ERROR 0x0F
#define TA100_STATUS_WAKE_OK 0x11
#define TA100_STATUS_CRC_ERROR 0xFF
#define TA100_STATUS_CALCULATION 0x8B

enum ta100_state {
    TA100_RESET = 0,
    TA100_SLEEP,
    TA100_IDLE,
    TA100_BUSY,
    TA100_RESP_READY
};

struct mm_ta100 {
    int bus;
    mm_bool cs_valid;
    int cs_bank;
    int cs_pin;
    mm_u32 cs_mask;
    mm_u8 cs_level;
    mm_bool has_nv_path;
    char nv_path[256];
    mm_bool has_profile;
    char profile[64];
    mm_bool has_serial;
    char serial[32];
    enum ta100_state state;
    mm_u8 cmd_buf[TA100_CMD_MAX];
    mm_u32 cmd_len;
    mm_u8 rsp_buf[TA100_RSP_MAX];
    mm_u32 rsp_len;
    mm_u32 rsp_read;
    mm_u32 busy_cycles;
    mm_u8 *nv_data;
    mm_u32 nv_size;
    mm_bool nv_dirty;
    mm_bool config_locked;
    mm_bool data_locked;
    mm_u8 slot_locked[TA100_KEY_SLOTS];
#ifdef M33MU_HAS_WOLFSSL
    WC_RNG rng;
    mm_bool rng_initialized;
#endif
    mm_u8 temp_nonce[32];
    mm_bool temp_nonce_valid;
    /* TA100 handle management */
    mm_u16 handles[TA100_MAX_HANDLES];
    mm_u8  handle_attrs[TA100_MAX_HANDLES][8]; /* 8-byte element attributes */
    mm_u8  handle_key_type[TA100_MAX_HANDLES];
    mm_u16 handle_key_size[TA100_MAX_HANDLES];
    mm_u8  handle_priv[TA100_MAX_HANDLES][72]; /* private key (ECC up to P384) */
    mm_u8  handle_pubx[TA100_MAX_HANDLES][72]; /* public key X */
    mm_u8  handle_puby[TA100_MAX_HANDLES][72]; /* public key Y */
    mm_u8  handle_data[TA100_MAX_HANDLES][TA100_HANDLE_DATA_MAX];
    mm_u16 handle_data_len[TA100_MAX_HANDLES];
    mm_u8  handle_rsa_pub_mod[TA100_MAX_HANDLES][TA_KEY_TYPE_RSA2048_SIZE];
    mm_u16 handle_rsa_pub_len[TA100_MAX_HANDLES];
    mm_u8  handle_rsa_priv_der[TA100_MAX_HANDLES][TA100_RSA_PRIV_DER_MAX];
    mm_u16 handle_rsa_priv_len[TA100_MAX_HANDLES];
    mm_bool handle_has_key[TA100_MAX_HANDLES]; /* key generated? */
    mm_u8  handle_locked[TA100_MAX_HANDLES]; /* lock status byte (0x04 = locked) */
    mm_u32 handle_count;
    mm_u8 rsa_sig_tmp[TA_KEY_TYPE_RSA2048_SIZE * 2];
    mm_u16 aes_loaded_handle;
    mm_bool aes_loaded_valid;
    mm_u8 aes_loaded_key[TA_KEY_TYPE_AES128_SIZE];
    mm_bool setup_locked;
    /* Current transaction instruction (for inline response handling) */
    mm_u8 cur_instr;
    mm_bool instr_started;
    mm_u8 csr_val;  /* CSR status register value */
};

static struct mm_ta100 g_ta100[TA100_MAX];
static size_t g_ta100_count = 0;

static mm_bool ta100_trace_enabled(void)
{
    static mm_bool init = MM_FALSE;
    static mm_bool enabled = MM_FALSE;
    if (!init) {
        const char *env = getenv("M33MU_TA100_TRACE");
        enabled = (env != 0 && env[0] != '\0') ? MM_TRUE : MM_FALSE;
        init = MM_TRUE;
    }
    return enabled;
}

static mm_bool ta100_spi_trace_enabled(void)
{
    static mm_bool init = MM_FALSE;
    static mm_bool enabled = MM_FALSE;
    if (!init) {
        const char *env = getenv("M33MU_SPI_TRACE");
        enabled = (env != 0 && env[0] != '\0') ? MM_TRUE : MM_FALSE;
        init = MM_TRUE;
    }
    return enabled;
}

#ifdef M33MU_HAS_WOLFSSL
static mm_bool ta100_ecc_enabled(void)
{
    static mm_bool init = MM_FALSE;
    static mm_bool enabled = MM_FALSE;
    if (!init) {
        const char *env = getenv("M33MU_TA100_ECC");
        enabled = (env != 0 && env[0] != '\0') ? MM_TRUE : MM_FALSE;
        init = MM_TRUE;
    }
    return enabled;
}
#endif

static void ta100_trace_dump(const char *tag, const mm_u8 *buf, mm_u32 len)
{
    mm_u32 i;
    mm_u32 max_len = len;
    if (!ta100_trace_enabled()) {
        return;
    }
    if (buf == 0) {
        fprintf(stderr, "[TA100_TRACE] %s len=%lu (null)\n",
                tag, (unsigned long)len);
        return;
    }
    if (max_len > 256u) {
        max_len = 256u;
    }
    fprintf(stderr, "[TA100_TRACE] %s len=%lu\n", tag, (unsigned long)len);
    for (i = 0; i < max_len; i += 16u) {
        mm_u32 j;
        mm_u32 line_len = max_len - i;
        if (line_len > 16u) line_len = 16u;
        fprintf(stderr, "[TA100_TRACE]   %04lx:", (unsigned long)i);
        for (j = 0; j < line_len; ++j) {
            fprintf(stderr, " %02x", buf[i + j]);
        }
        fprintf(stderr, "\n");
    }
    if (max_len < len) {
        fprintf(stderr, "[TA100_TRACE]   ... (%lu bytes omitted)\n",
                (unsigned long)(len - max_len));
    }
}

static mm_u8 ta100_attr_key_type(const mm_u8 attrs[8])
{
    return (mm_u8)((attrs[0] & TA_HANDLE_INFO_KEY_TYPE_MASK) >> TA_HANDLE_INFO_KEY_TYPE_SHIFT);
}

static mm_u16 ta100_key_type_size(mm_u8 key_type)
{
    switch (key_type) {
    case TA_KEY_TYPE_ECCP256:
        return TA_KEY_TYPE_ECCP256_SIZE;
    case TA_KEY_TYPE_ECCP384:
        return TA_KEY_TYPE_ECCP384_SIZE;
    case TA_KEY_TYPE_RSA2048:
        return TA_KEY_TYPE_RSA2048_SIZE;
    case TA_KEY_TYPE_AES128:
        return TA_KEY_TYPE_AES128_SIZE;
    default:
        return 0;
    }
}

static mm_u8 ta100_sample_cs(struct mm_ta100 *ta)
{
    mm_u8 level = 1u;
    mm_u32 odr;
    if (ta == 0 || !ta->cs_valid) {
        return 0u;
    }
    if (!mm_gpio_bank_reader_present()) {
        /* No GPIO reader wired up; assume CS asserted. */
        return 0u;
    }
    odr = mm_gpio_bank_read(ta->cs_bank);
    level = (odr & ta->cs_mask) ? 1u : 0u;
    return level;
}

/* TA100 uses CRC-16 CCITT (polynomial 0x1021, init 0xFFFF) */
static mm_u16 ta100_calculate_crc(const mm_u8 *data, mm_u32 len)
{
    mm_u32 i;
    mm_u16 crc = 0xFFFF;
    const mm_u16 polynom = 0x1021;
    const mm_u16 crchighbit = 0x8000;

    for (i = 0; i < len; i++) {
        mm_u16 c = (mm_u16)data[i];
        mm_u16 j;
        for (j = 0x80; j > 0u; j >>= 1) {
            mm_u16 bit = crc & crchighbit;
            crc <<= 1;
            if ((c & j) != 0u) {
                bit ^= crchighbit;
            }
            if (bit != 0u) {
                crc ^= polynom;
            }
        }
    }
    return crc;
}

static mm_bool ta100_verify_crc(const mm_u8 *packet, mm_u32 len)
{
    mm_u16 packet_crc;
    mm_u16 calc_crc;
    if (len < 2) {
        return MM_FALSE;
    }
    packet_crc = ((mm_u16)packet[len - 2] << 8) | packet[len - 1];
    calc_crc = ta100_calculate_crc(packet, len - 2);
    return (packet_crc == calc_crc) ? MM_TRUE : MM_FALSE;
}

static void ta100_init_nv_layout(struct mm_ta100 *ta)
{
    mm_u32 i;
    if (ta == 0 || ta->nv_data == 0) {
        return;
    }

    memset(ta->nv_data, 0x00, TA100_CONFIG_ZONE_SIZE);
    ta->nv_data[0] = 0x01;
    ta->nv_data[1] = 0x23;
    ta->nv_data[2] = 0x45;
    ta->nv_data[3] = 0x67;
    ta->nv_data[4] = 0x00;
    ta->nv_data[5] = 0x00;
    ta->nv_data[6] = 0x50;
    ta->nv_data[7] = 0x00;
    ta->nv_data[12] = 0xC0;
    ta->nv_data[13] = 0x00;
    ta->nv_data[14] = 0x55;
    ta->nv_data[15] = 0x00;
    ta->nv_data[16] = 0x83;
    ta->nv_data[17] = 0x20;
    ta->nv_data[18] = 0x87;
    ta->nv_data[86] = 0x00; /* data locked */
    ta->nv_data[87] = 0x00; /* config locked */

    for (i = TA100_CONFIG_ZONE_SIZE; i < ta->nv_size; i++) {
        ta->nv_data[i] = 0xFF;
    }

    ta->config_locked = MM_TRUE;
    ta->data_locked = MM_TRUE;
    ta->setup_locked = MM_TRUE;
    memset(ta->slot_locked, 0, sizeof(ta->slot_locked));
}

static mm_u32 ta100_get_zone_offset(mm_u8 zone, mm_u16 addr)
{
    mm_u32 offset;

    if (zone == TA100_ZONE_CONFIG) {
        offset = (mm_u32)addr;
        if (offset >= TA100_CONFIG_ZONE_SIZE) {
            offset = TA100_CONFIG_ZONE_SIZE - 1;
        }
    } else if (zone == TA100_ZONE_DATA || zone == TA100_ZONE_KEY) {
        offset = TA100_CONFIG_ZONE_SIZE + (mm_u32)addr;
        if (offset >= TA100_NV_SIZE) {
            offset = TA100_NV_SIZE - 1;
        }
    } else {
        offset = 0;
    }

    return offset;
}

static void ta100_cmd_read(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u8 zone;
    mm_u16 addr;
    mm_u8 count;
    mm_u32 offset;
    mm_u32 i;
    mm_u16 crc;

    if (cmd_len < 7) {
        ta->rsp_buf[0] = TA100_STATUS_PARSE_ERROR;
        ta->rsp_len = 1;
        return;
    }

    zone = cmd[1] & 0x03;
    addr = ((mm_u16)cmd[2] << 8) | cmd[3];
    count = cmd[4];

    if (count == 0 || count > 32) {
        count = 4;
    }

    offset = ta100_get_zone_offset(zone, addr);

    ta->rsp_buf[0] = TA100_STATUS_SUCCESS;
    for (i = 0; i < count && (offset + i) < ta->nv_size; i++) {
        ta->rsp_buf[1 + i] = ta->nv_data[offset + i];
    }
    ta->rsp_len = 1 + count;
    crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
}

static void ta100_cmd_write(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u8 zone;
    mm_u16 addr;
    mm_u8 count;
    mm_u32 offset;
    mm_u32 i;
    mm_u16 crc;

    if (cmd_len < 8) {
        ta->rsp_buf[0] = TA100_STATUS_PARSE_ERROR;
        ta->rsp_len = 1;
        return;
    }

    zone = cmd[1] & 0x03;
    addr = ((mm_u16)cmd[2] << 8) | cmd[3];
    count = cmd[4];

    if (zone == TA100_ZONE_CONFIG && ta->config_locked) {
        ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
        ta->rsp_len = 1;
        return;
    }

    if ((zone == TA100_ZONE_DATA || zone == TA100_ZONE_KEY) && ta->data_locked) {
        ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
        ta->rsp_len = 1;
        return;
    }

    if (count == 0 || count > 32) {
        count = 4;
    }

    if (cmd_len < (mm_u32)(7 + count)) {
        ta->rsp_buf[0] = TA100_STATUS_PARSE_ERROR;
        ta->rsp_len = 1;
        return;
    }

    offset = ta100_get_zone_offset(zone, addr);

    for (i = 0; i < count && (offset + i) < ta->nv_size; i++) {
        ta->nv_data[offset + i] = cmd[5 + i];
    }
    ta->nv_dirty = MM_TRUE;

    ta->rsp_buf[0] = TA100_STATUS_SUCCESS;
    ta->rsp_len = 1;
    crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
}

static void ta100_cmd_lock(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u8 zone;
    mm_u16 crc;

    if (cmd_len < 7) {
        ta->rsp_buf[0] = TA100_STATUS_PARSE_ERROR;
        ta->rsp_len = 1;
        return;
    }

    zone = cmd[1] & 0x03;

    if (zone == TA100_ZONE_CONFIG) {
        ta->config_locked = MM_TRUE;
    } else if (zone == TA100_ZONE_DATA || zone == TA100_ZONE_KEY) {
        ta->data_locked = MM_TRUE;
    }

    ta->rsp_buf[0] = TA100_STATUS_SUCCESS;
    ta->rsp_len = 1;
    crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
}

#ifdef M33MU_HAS_WOLFSSL
static void ta100_cmd_random(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u16 crc;
    mm_u8 count = 32;
    int ret;

    (void)cmd;

    if (cmd_len < 5) {
        ta->rsp_buf[0] = TA100_STATUS_PARSE_ERROR;
        ta->rsp_len = 1;
        return;
    }

    if (!ta->rng_initialized) {
        ret = wc_InitRng(&ta->rng);
        if (ret != 0) {
            ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
            ta->rsp_len = 1;
            crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
            ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
            ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
            return;
        }
        ta->rng_initialized = MM_TRUE;
    }

    ret = wc_RNG_GenerateBlock(&ta->rng, &ta->rsp_buf[1], count);
    if (ret != 0) {
        ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
        ta->rsp_len = 1;
    } else {
        ta->rsp_buf[0] = TA100_STATUS_SUCCESS;
        ta->rsp_len = 1 + count;
    }

    crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
}

static void ta100_cmd_nonce(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u16 crc;
    mm_u8 mode;

    if (cmd_len < 5) {
        ta->rsp_buf[0] = TA100_STATUS_PARSE_ERROR;
        ta->rsp_len = 1;
        return;
    }

    mode = cmd[1];

    if (mode == 0x00) {
        if (cmd_len < 27) {
            ta->rsp_buf[0] = TA100_STATUS_PARSE_ERROR;
            ta->rsp_len = 1;
            return;
        }
        memcpy(ta->temp_nonce, &cmd[5], 20);
        memset(ta->temp_nonce + 20, 0, 12);
        ta->temp_nonce_valid = MM_TRUE;
        ta->rsp_buf[0] = TA100_STATUS_SUCCESS;
        ta->rsp_len = 1;
    } else if (mode == 0x03) {
        if (!ta->rng_initialized) {
            int ret = wc_InitRng(&ta->rng);
            if (ret != 0) {
                ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
                ta->rsp_len = 1;
                crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
                ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
                ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
                return;
            }
            ta->rng_initialized = MM_TRUE;
        }
        wc_RNG_GenerateBlock(&ta->rng, ta->temp_nonce, 32);
        ta->temp_nonce_valid = MM_TRUE;
        ta->rsp_buf[0] = TA100_STATUS_SUCCESS;
        ta->rsp_len = 1;
    } else {
        ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
        ta->rsp_len = 1;
    }

    crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
}

static mm_u32 ta100_get_slot_offset(mm_u8 slot_id)
{
    mm_u32 offset = TA100_CONFIG_ZONE_SIZE + (slot_id * TA100_KEY_SLOT_SIZE);
    return offset;
}

static void ta100_cmd_genkey(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u16 crc;
    mm_u8 mode;
    mm_u8 slot_id;
#ifdef M33MU_HAS_WOLFSSL
    ecc_key key;
    int ret;
    mm_u32 x_len = 32;
    mm_u32 y_len = 32;
#endif
    mm_u32 offset;

    if (cmd_len < 6) {
        ta->rsp_buf[0] = TA100_STATUS_PARSE_ERROR;
        ta->rsp_len = 1;
        return;
    }

    mode = cmd[1];
    slot_id = ((mm_u16)cmd[2] << 8) | cmd[3];

    if (slot_id >= TA100_KEY_SLOTS) {
        ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
    (void)mode;
        ta->rsp_len = 1;
        crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
        return;
    }

    if (ta->data_locked || ta->slot_locked[slot_id]) {
        ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
        ta->rsp_len = 1;
        crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
        return;
    }

#ifdef M33MU_HAS_WOLFSSL
    if (!ta100_ecc_enabled()) {
        mm_u8 *priv;
        mm_u8 *pub_x;
        mm_u8 *pub_y;
        if (ta->nv_data == 0) {
            ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
            ta->rsp_len = 1;
            crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
            ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
            ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
            return;
        }
        if (!ta->rng_initialized) {
            ret = wc_InitRng(&ta->rng);
            if (ret != 0) {
                ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
                ta->rsp_len = 1;
                crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
                ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
                ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
                return;
            }
            ta->rng_initialized = MM_TRUE;
        }
        offset = ta100_get_slot_offset(slot_id);
        priv = &ta->nv_data[offset];
        pub_y = &ta->nv_data[offset + 4];
        pub_x = &ta->nv_data[offset + 36];
        wc_RNG_GenerateBlock(&ta->rng, priv, 32);
        wc_RNG_GenerateBlock(&ta->rng, pub_x, 32);
        wc_RNG_GenerateBlock(&ta->rng, pub_y, 32);
        ta->nv_dirty = MM_TRUE;
        memcpy(&ta->rsp_buf[1], pub_x, 32);
        memcpy(&ta->rsp_buf[33], pub_y, 32);
        ta->rsp_buf[0] = TA100_STATUS_SUCCESS;
        ta->rsp_len = 65;
        crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
        return;
    }
#endif

#ifdef M33MU_HAS_WOLFSSL
    if (!ta->rng_initialized) {
        ret = wc_InitRng(&ta->rng);
        if (ret != 0) {
            ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
            ta->rsp_len = 1;
            crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
            ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
            ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
            return;
        }
        ta->rng_initialized = MM_TRUE;
    }

    wc_ecc_init(&key);
    ret = wc_ecc_make_key(&ta->rng, 32, &key);
    if (ret != 0) {
        wc_ecc_free(&key);
        ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
        ta->rsp_len = 1;
        crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
        return;
    }

    offset = ta100_get_slot_offset(slot_id);

    wc_ecc_export_public_raw(&key, &ta->nv_data[offset + 36], &x_len,
                             &ta->nv_data[offset + 4], &y_len);
    wc_ecc_export_private_only(&key, &ta->nv_data[offset], &x_len);

    ta->nv_dirty = MM_TRUE;

    memcpy(&ta->rsp_buf[1], &ta->nv_data[offset + 36], 32);
    memcpy(&ta->rsp_buf[33], &ta->nv_data[offset + 4], 32);

    wc_ecc_free(&key);

    ta->rsp_buf[0] = TA100_STATUS_SUCCESS;
    ta->rsp_len = 65;
    crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
#endif
}

static void ta100_cmd_sign(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u16 crc;
    mm_u8 mode;
    mm_u8 slot_id;
#ifdef M33MU_HAS_WOLFSSL
    ecc_key key;
    int ret;
    mm_u8 hash[32];
    mm_u8 sig[64];
    word32 sig_len = sizeof(sig);
#endif
    mm_u32 offset;
#ifdef M33MU_HAS_WOLFSSL
    wc_Sha256 sha;
#endif

    if (cmd_len < 6) {
        ta->rsp_buf[0] = TA100_STATUS_PARSE_ERROR;
        ta->rsp_len = 1;
        return;
    }

    (void)mode;
    mode = cmd[1];
    slot_id = ((mm_u16)cmd[2] << 8) | cmd[3];

    if (slot_id >= TA100_KEY_SLOTS) {
        ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
        ta->rsp_len = 1;
        crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
        return;
    }

    if (!ta->temp_nonce_valid) {
        ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
        ta->rsp_len = 1;
        crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
        return;
    }

#ifdef M33MU_HAS_WOLFSSL
    if (!ta100_ecc_enabled()) {
        mm_u8 digest[32];
        wc_InitSha256(&sha);
        wc_Sha256Update(&sha, ta->temp_nonce, 32);
        if (ta->nv_data != 0) {
            offset = ta100_get_slot_offset(slot_id);
            wc_Sha256Update(&sha, &ta->nv_data[offset], 32);
        }
        wc_Sha256Final(&sha, digest);
        wc_Sha256Free(&sha);
        memset(sig, 0, sizeof(sig));
        memcpy(sig, digest, 32);
        memcpy(sig + 32, digest, 32);
        ta->rsp_buf[0] = TA100_STATUS_SUCCESS;
        memcpy(&ta->rsp_buf[1], sig, sizeof(sig));
        ta->rsp_len = 1 + (mm_u32)sizeof(sig);
        crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
        return;
    }

    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, ta->temp_nonce, 32);
    wc_Sha256Final(&sha, hash);
    wc_Sha256Free(&sha);

    offset = ta100_get_slot_offset(slot_id);

    wc_ecc_init(&key);

    {
        mm_u8 pubkey[64];
        memcpy(pubkey, &ta->nv_data[offset + 36], 32);
        memcpy(pubkey + 32, &ta->nv_data[offset + 4], 32);
        ret = wc_ecc_import_private_key(&ta->nv_data[offset], 32,
                                         pubkey, 64,
                                         &key);
    }

    if (ret != 0) {
        wc_ecc_free(&key);
        ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
        ta->rsp_len = 1;
        crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
        return;
    }

    if (!ta->rng_initialized) {
        ret = wc_InitRng(&ta->rng);
        if (ret != 0) {
            wc_ecc_free(&key);
            ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
            ta->rsp_len = 1;
            crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
            ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
            ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
            return;
        }
        ta->rng_initialized = MM_TRUE;
    }

    ret = wc_ecc_sign_hash(hash, 32, sig, &sig_len, &ta->rng, &key);

    wc_ecc_free(&key);

    if (ret != 0) {
        ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
        ta->rsp_len = 1;
        crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
        return;
    }

    ta->rsp_buf[0] = TA100_STATUS_SUCCESS;
    memcpy(&ta->rsp_buf[1], sig, sig_len);
    ta->rsp_len = 1 + sig_len;
    crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
#endif
}

static void ta100_cmd_sha256(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u16 crc;
    wc_Sha256 sha;
    mm_u8 hash[32];
    mm_u32 data_len;

    if (cmd_len < 7) {
        ta->rsp_buf[0] = TA100_STATUS_PARSE_ERROR;
        ta->rsp_len = 1;
        return;
    }

    data_len = cmd[4];

    if (cmd_len < (7 + data_len)) {
        ta->rsp_buf[0] = TA100_STATUS_PARSE_ERROR;
        ta->rsp_len = 1;
        return;
    }

    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, &cmd[5], data_len);
    wc_Sha256Final(&sha, hash);
    wc_Sha256Free(&sha);

    ta->rsp_buf[0] = TA100_STATUS_SUCCESS;
    memcpy(&ta->rsp_buf[1], hash, 32);
    ta->rsp_len = 33;
    crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
}
#endif

/* Helper to build TA100 response with length prefix and CRC */
static void ta100_build_response(struct mm_ta100 *ta, mm_u8 resp_code,
                                  const mm_u8 *data, mm_u32 data_len)
{
    mm_u16 total_len;
    mm_u16 crc;

    /* Response format: length(2 BE) + resp_code(1) + data[] + CRC(2) */
    total_len = 3 + data_len + 2;  /* length + resp_code + data + crc */
    ta->rsp_buf[0] = (mm_u8)(total_len >> 8);
    ta->rsp_buf[1] = (mm_u8)(total_len & 0xFF);
    ta->rsp_buf[2] = resp_code;
    if (data != 0 && data_len > 0) {
        memcpy(&ta->rsp_buf[3], data, data_len);
    }
    ta->rsp_len = 3 + data_len;
    crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
}

/* Helper to find a handle */
static int ta100_find_handle(struct mm_ta100 *ta, mm_u16 handle)
{
    mm_u32 i;
    for (i = 0; i < ta->handle_count; i++) {
        if (ta->handles[i] == handle) {
            return (int)i;
        }
    }
    return -1;
}

static int ta100_find_rsa_pub_handle(struct mm_ta100 *ta, int priv_idx)
{
    mm_u32 i;
    for (i = 0; i < ta->handle_count; i++) {
        if ((int)i == priv_idx) {
            continue;
        }
        if (ta->handle_key_type[i] == TA_KEY_TYPE_RSA2048 &&
            ta->handle_attrs[i][0] == 0xA8) { /* public key element */
            return (int)i;
        }
    }
    return -1;
}

/* TA100 Info command (opcode 0x00) */
static void ta100_op_info(struct mm_ta100 *ta, mm_u8 mode, mm_u32 param2)
{
    mm_u8 data[16];
    mm_u32 data_len = 0;
    mm_u16 target_handle;
    int idx;

    if (ta100_trace_enabled()) {
        fprintf(stderr, "[TA100_TRACE] INFO mode=0x%02x param2=0x%08x\n", mode, param2);
    }

    switch (mode) {
    case TA100_INFO_MODE_REV:
        /* Return revision info: 4 bytes */
        data[0] = 0x00;  /* Family */
        data[1] = 0x00;  /* Model */
        data[2] = 0x60;  /* Revision (TA100) */
        data[3] = 0x03;  /* Version */
        data_len = 4;
        break;

    case TA100_INFO_MODE_NV_REMAIN:
        /* Return remaining NV memory: 4 bytes */
        data[0] = 0x00;
        data[1] = 0x00;
        data[2] = 0x10;  /* ~4K remaining */
        data[3] = 0x00;
        data_len = 4;
        break;

    case TA100_INFO_MODE_HANDLE_VALID:
        /* Check if handle is valid - return 1 byte: 0x01 if valid, 0x00 if not */
        target_handle = (mm_u16)(param2 & 0xFFFF);
        idx = ta100_find_handle(ta, target_handle);
        data[0] = (idx >= 0) ? 0x01 : 0x00;
        data_len = 1;
        if (ta100_trace_enabled()) {
            fprintf(stderr, "[TA100_TRACE] HANDLE_VALID handle=0x%04x result=%d\n",
                    target_handle, data[0]);
        }
        break;

    case TA100_INFO_MODE_HANDLE_INFO:
        /* Return handle info: 9 bytes (TA_HANDLE_INFO_SIZE) */
        target_handle = (mm_u16)(param2 & 0xFFFF);
        idx = ta100_find_handle(ta, target_handle);
        if (idx >= 0) {
            memcpy(data, ta->handle_attrs[idx], 8);
            data[8] = ta->handle_locked[idx];  /* lock status byte */
            data_len = 9;
        } else {
            /* Handle doesn't exist - return zeros (not locked) */
            memset(data, 0, 9);
            data_len = 9;
            if (ta100_trace_enabled()) {
                fprintf(stderr, "[TA100_TRACE] HANDLE_INFO: handle 0x%04x not found, returning zeros\n",
                        target_handle);
            }
        }
        break;

    case TA100_INFO_MODE_CHIP_STATUS:
        /* Return chip status: 6 bytes (config lock, setup lock, 4-byte latch) */
        data[0] = ta->config_locked ? 0x01 : 0x00;
        data[1] = ta->setup_locked ? 0x01 : 0x00;
        data[2] = 0x00;
        data[3] = 0x00;
        data[4] = 0x00;
        data[5] = 0x00;
        data_len = 6;
        break;

    default:
        /* Unknown mode - return empty success */
        data_len = 0;
        break;
    }

    ta100_build_response(ta, TA100_STATUS_SUCCESS, data, data_len);
}

/* TA100 Create command (opcode 0x06) */
static void ta100_op_create(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u8 mode;
    mm_u16 details;
    mm_u16 handle_in;
    mm_u8 handle_config[8];
    mm_u16 handle_out;
    mm_u8 resp_data[2];

    if (cmd_len < TA100_PKT_DATA_OFFSET + 8 + 2) {
        ta100_build_response(ta, TA100_STATUS_PARSE_ERROR, 0, 0);
        return;
    }

    mode = cmd[TA100_PKT_PARAM1_OFFSET];
    details = ((mm_u16)cmd[TA100_PKT_PARAM2_OFFSET] << 8) |
              cmd[TA100_PKT_PARAM2_OFFSET + 1];
    handle_in = ((mm_u16)cmd[TA100_PKT_PARAM2_OFFSET + 2] << 8) |
                cmd[TA100_PKT_PARAM2_OFFSET + 3];
    memcpy(handle_config, &cmd[TA100_PKT_DATA_OFFSET], 8);

    (void)details;

    if (ta100_trace_enabled()) {
        fprintf(stderr, "[TA100_TRACE] CREATE mode=0x%02x handle_in=0x%04x\n",
                mode, handle_in);
    }

    /* Check if handle already exists */
    if (ta100_find_handle(ta, handle_in) >= 0) {
        /* Handle already exists - return error */
        if (ta100_trace_enabled()) {
            fprintf(stderr, "[TA100_TRACE] CREATE: handle 0x%04x already exists\n", handle_in);
        }
        ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
        return;
    }

    /* Add the handle */
    if (ta->handle_count >= TA100_MAX_HANDLES) {
        ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
        return;
    }

    if (mode & 0x02) {
        /* Handle assigned by device - pick first free in 0x8000+ range */
        handle_out = 0x8000;
        while (handle_out != 0u && ta100_find_handle(ta, handle_out) >= 0) {
            handle_out = (mm_u16)(handle_out + 1u);
        }
        if (handle_out == 0u) {
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            return;
        }
    } else {
        /* Handle provided by host */
        handle_out = handle_in;
    }

    ta->handles[ta->handle_count] = handle_out;
    memcpy(ta->handle_attrs[ta->handle_count], handle_config, 8);
    ta->handle_key_type[ta->handle_count] = ta100_attr_key_type(handle_config);
    ta->handle_key_size[ta->handle_count] = ta100_key_type_size(ta->handle_key_type[ta->handle_count]);
    ta->handle_data_len[ta->handle_count] = 0;
    ta->handle_rsa_pub_len[ta->handle_count] = 0;
    ta->handle_rsa_priv_len[ta->handle_count] = 0;
    ta->handle_has_key[ta->handle_count] = MM_FALSE;
    ta->handle_locked[ta->handle_count] = 0;
    ta->handle_count++;

    if (ta100_trace_enabled()) {
        fprintf(stderr, "[TA100_TRACE] CREATE: created handle 0x%04x (count=%u)\n",
                handle_out, (unsigned)ta->handle_count);
    }

    /* Response includes the handle if mode & 0x02 */
    if (mode & 0x02) {
        resp_data[0] = (mm_u8)(handle_out >> 8);
        resp_data[1] = (mm_u8)(handle_out & 0xFF);
        ta100_build_response(ta, TA100_STATUS_SUCCESS, resp_data, 2);
    } else {
        ta100_build_response(ta, TA100_STATUS_SUCCESS, 0, 0);
    }
}

/* TA100 Lock command (opcode 0x0D) */
static void ta100_op_lock(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u8 mode;
    mm_u32 param2;
    mm_u16 handle;
    int idx;

    (void)cmd_len;

    mode = cmd[TA100_PKT_PARAM1_OFFSET];
    param2 = ((mm_u32)cmd[TA100_PKT_PARAM2_OFFSET] << 24) |
             ((mm_u32)cmd[TA100_PKT_PARAM2_OFFSET + 1] << 16) |
             ((mm_u32)cmd[TA100_PKT_PARAM2_OFFSET + 2] << 8) |
             (mm_u32)cmd[TA100_PKT_PARAM2_OFFSET + 3];

    if (ta100_trace_enabled()) {
        fprintf(stderr, "[TA100_TRACE] LOCK mode=0x%02x param2=0x%08x\n",
                mode, (unsigned)param2);
    }

    switch (mode) {
    case TA_LOCK_CONFIG_WITHOUT_CRC:
    case TA_LOCK_CONFIG_WITH_CRC:
        ta->config_locked = MM_TRUE;
        break;
    case TA_LOCK_SETUP_LOCK:
        ta->setup_locked = MM_TRUE;
        break;
    case TA_LOCK_SHARED_ELEMENT:
        handle = (mm_u16)(param2 & 0xFFFFu);
        idx = ta100_find_handle(ta, handle);
        if (idx < 0) {
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            return;
        }
        ta->handle_locked[idx] = 0x04;
        break;
    default:
        break;
    }

    ta100_build_response(ta, TA100_STATUS_SUCCESS, 0, 0);
}

/* TA100 Delete command (opcode 0x13) */
static void ta100_op_delete(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u16 target_handle;
    int idx;

    (void)cmd_len;

    target_handle = ((mm_u16)cmd[TA100_PKT_PARAM2_OFFSET + 2] << 8) |
                    cmd[TA100_PKT_PARAM2_OFFSET + 3];

    if (ta100_trace_enabled()) {
        fprintf(stderr, "[TA100_TRACE] DELETE handle=0x%04x\n", target_handle);
    }

    idx = ta100_find_handle(ta, target_handle);
    if (idx < 0) {
        ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
        return;
    }

    /* Remove handle by shifting */
    if ((mm_u32)idx < ta->handle_count - 1) {
        memmove(&ta->handles[idx], &ta->handles[idx + 1],
                (ta->handle_count - 1 - (mm_u32)idx) * sizeof(mm_u16));
        memmove(&ta->handle_attrs[idx], &ta->handle_attrs[idx + 1],
                (ta->handle_count - 1 - (mm_u32)idx) * 8);
        memmove(&ta->handle_key_type[idx], &ta->handle_key_type[idx + 1],
                (ta->handle_count - 1 - (mm_u32)idx) * sizeof(mm_u8));
        memmove(&ta->handle_key_size[idx], &ta->handle_key_size[idx + 1],
                (ta->handle_count - 1 - (mm_u32)idx) * sizeof(mm_u16));
        memmove(&ta->handle_priv[idx], &ta->handle_priv[idx + 1],
                (ta->handle_count - 1 - (mm_u32)idx) * sizeof(ta->handle_priv[0]));
        memmove(&ta->handle_pubx[idx], &ta->handle_pubx[idx + 1],
                (ta->handle_count - 1 - (mm_u32)idx) * sizeof(ta->handle_pubx[0]));
        memmove(&ta->handle_puby[idx], &ta->handle_puby[idx + 1],
                (ta->handle_count - 1 - (mm_u32)idx) * sizeof(ta->handle_puby[0]));
        memmove(&ta->handle_data[idx], &ta->handle_data[idx + 1],
                (ta->handle_count - 1 - (mm_u32)idx) * sizeof(ta->handle_data[0]));
        memmove(&ta->handle_data_len[idx], &ta->handle_data_len[idx + 1],
                (ta->handle_count - 1 - (mm_u32)idx) * sizeof(mm_u16));
        memmove(&ta->handle_rsa_pub_mod[idx], &ta->handle_rsa_pub_mod[idx + 1],
                (ta->handle_count - 1 - (mm_u32)idx) * sizeof(ta->handle_rsa_pub_mod[0]));
        memmove(&ta->handle_rsa_pub_len[idx], &ta->handle_rsa_pub_len[idx + 1],
                (ta->handle_count - 1 - (mm_u32)idx) * sizeof(mm_u16));
        memmove(&ta->handle_rsa_priv_der[idx], &ta->handle_rsa_priv_der[idx + 1],
                (ta->handle_count - 1 - (mm_u32)idx) * sizeof(ta->handle_rsa_priv_der[0]));
        memmove(&ta->handle_rsa_priv_len[idx], &ta->handle_rsa_priv_len[idx + 1],
                (ta->handle_count - 1 - (mm_u32)idx) * sizeof(mm_u16));
        memmove(&ta->handle_has_key[idx], &ta->handle_has_key[idx + 1],
                (ta->handle_count - 1 - (mm_u32)idx) * sizeof(mm_bool));
    }
    ta->handle_count--;

    ta100_build_response(ta, TA100_STATUS_SUCCESS, 0, 0);
}

/* TA100 Random command (opcode 0x09) */
static void ta100_op_random(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u8 rand_data[32];
    mm_u32 i;

    (void)cmd;
    (void)cmd_len;
    (void)i;

#ifdef M33MU_HAS_WOLFSSL
    if (!ta->rng_initialized) {
        if (wc_InitRng(&ta->rng) != 0) {
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            return;
        }
        ta->rng_initialized = MM_TRUE;
    }
    if (wc_RNG_GenerateBlock(&ta->rng, rand_data, 32) != 0) {
        ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
        return;
    }
#else
    /* Simple PRNG fallback */
    for (i = 0; i < 32; i++) {
        rand_data[i] = (mm_u8)(rand() & 0xFF);
    }
#endif

    ta100_build_response(ta, TA100_STATUS_SUCCESS, rand_data, 32);
}

/* TA100 KeyGen command (opcode 0x12) */
static void ta100_op_keygen(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u8 mode;
    mm_u16 handle;
    int idx;
    mm_u8 key_type;
    mm_u16 key_size;
#ifdef M33MU_HAS_WOLFSSL
    int ret;
#endif

    (void)cmd_len;

    mode = cmd[TA100_PKT_PARAM1_OFFSET];
    handle = ((mm_u16)cmd[TA100_PKT_PARAM2_OFFSET + 2] << 8) |
             cmd[TA100_PKT_PARAM2_OFFSET + 3];

    if (ta100_trace_enabled()) {
        fprintf(stderr, "[TA100_TRACE] KEYGEN mode=0x%02x handle=0x%04x\n", mode, handle);
    }

    idx = ta100_find_handle(ta, handle);
    if (idx < 0) {
        ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
        return;
    }
    if (ta100_trace_enabled()) {
        fprintf(stderr, "[TA100_TRACE] KEYGEN idx=%d handle_count=%u\n",
                idx, (unsigned)ta->handle_count);
    }

    key_type = ta->handle_key_type[idx];
    key_size = ta->handle_key_size[idx];

    if (mode != 0x00 && mode != 0x01) {
        ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
        return;
    }

    if (mode == 0x00) {
#ifdef M33MU_HAS_WOLFSSL
        if (!ta->rng_initialized) {
            ret = wc_InitRng(&ta->rng);
            if (ret != 0) {
                ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
                return;
            }
            ta->rng_initialized = MM_TRUE;
        }
#endif

        if (key_type == TA_KEY_TYPE_ECCP256 || key_type == TA_KEY_TYPE_ECCP384) {
#ifdef M33MU_HAS_WOLFSSL
            ecc_key ecc;
            word32 x_len = key_size;
            word32 y_len = key_size;
            word32 priv_len = key_size;
            int curve_id = (key_type == TA_KEY_TYPE_ECCP384) ? ECC_SECP384R1 : ECC_SECP256R1;

            wc_ecc_init(&ecc);
            ret = wc_ecc_make_key_ex(&ta->rng, key_size, &ecc, curve_id);
            if (ret != 0) {
                wc_ecc_free(&ecc);
                ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
                return;
            }
            ret = wc_ecc_export_public_raw(&ecc, ta->handle_pubx[idx], &x_len,
                                           ta->handle_puby[idx], &y_len);
            if (ret != 0) {
                wc_ecc_free(&ecc);
                ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
                return;
            }
            ret = wc_ecc_export_private_only(&ecc, ta->handle_priv[idx], &priv_len);
            wc_ecc_free(&ecc);
            if (ret != 0) {
                ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
                return;
            }
            ta->handle_has_key[idx] = MM_TRUE;
#else
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            return;
#endif
        } else if (key_type == TA_KEY_TYPE_RSA2048) {
#ifdef M33MU_HAS_WOLFSSL
            if (ta100_trace_enabled()) {
                fprintf(stderr, "[TA100_TRACE] KEYGEN RSA2048 using static key\n");
            }
            if (ta100_rsa_pkcs1_der_len == 0 ||
                ta100_rsa_pkcs1_der_len > TA100_RSA_PRIV_DER_MAX) {
                ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
                return;
            }
            memcpy(ta->handle_rsa_priv_der[idx], ta100_rsa_pkcs1_der, ta100_rsa_pkcs1_der_len);
            ta->handle_rsa_priv_len[idx] = (mm_u16)ta100_rsa_pkcs1_der_len;
            memcpy(ta->handle_rsa_pub_mod[idx], ta100_rsa_modulus, TA_KEY_TYPE_RSA2048_SIZE);
            ta->handle_rsa_pub_len[idx] = TA_KEY_TYPE_RSA2048_SIZE;
            ta->handle_has_key[idx] = MM_TRUE;
            /* If a separate public handle exists, store modulus there too. */
            {
                int pub_idx = ta100_find_rsa_pub_handle(ta, idx);
                if (pub_idx >= 0) {
                    memcpy(ta->handle_rsa_pub_mod[pub_idx], ta100_rsa_modulus, TA_KEY_TYPE_RSA2048_SIZE);
                    ta->handle_rsa_pub_len[pub_idx] = TA_KEY_TYPE_RSA2048_SIZE;
                    ta->handle_has_key[pub_idx] = MM_TRUE;
                    if (ta100_trace_enabled()) {
                        fprintf(stderr, "[TA100_TRACE] KEYGEN RSA2048 stored pub in handle idx=%d\n", pub_idx);
                    }
                }
            }
#else
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            return;
#endif
        } else {
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            return;
        }
    } else if (!ta->handle_has_key[idx]) {
        ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
        return;
    }

    if (key_type == TA_KEY_TYPE_RSA2048) {
        if (ta100_trace_enabled()) {
            fprintf(stderr, "[TA100_TRACE] KEYGEN RSA2048 build response len=%u\n",
                    (unsigned)TA_KEY_TYPE_RSA2048_SIZE);
        }
        ta100_build_response(ta, TA100_STATUS_SUCCESS, ta->handle_rsa_pub_mod[idx], TA_KEY_TYPE_RSA2048_SIZE);
        if (ta100_trace_enabled()) {
            fprintf(stderr, "[TA100_TRACE] KEYGEN RSA2048 response built\n");
        }
        return;
    }

    if (key_size == 0) {
        ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
        return;
    }

    /* Return public key: X || Y */
    {
        mm_u32 pub_len = (mm_u32)key_size * 2u;
        mm_u8 pubkey[TA_KEY_TYPE_RSA2048_SIZE];
        if (pub_len > sizeof(pubkey)) {
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            return;
        }
        memcpy(&pubkey[0], ta->handle_pubx[idx], key_size);
        memcpy(&pubkey[key_size], ta->handle_puby[idx], key_size);
        ta100_build_response(ta, TA100_STATUS_SUCCESS, pubkey, pub_len);
    }
}

/* TA100 Read command (opcode 0x07) - simplified */
static void ta100_op_read(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u8 mode;
    mm_u16 length = 0;
    mm_u16 handle;
    mm_u32 offset;
    mm_u8 data[TA100_HANDLE_DATA_MAX];
    int idx;

    (void)cmd_len;

    mode = cmd[TA100_PKT_PARAM1_OFFSET];
    handle = ((mm_u16)cmd[TA100_PKT_PARAM2_OFFSET + 2] << 8) |
             cmd[TA100_PKT_PARAM2_OFFSET + 3];

    (void)mode;
    offset = 0;

    idx = ta100_find_handle(ta, handle);
    if (idx < 0) {
        ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
        return;
    }

    if (cmd_len >= TA100_PKT_DATA_OFFSET + 4 + 2) {
        length = ((mm_u16)cmd[TA100_PKT_DATA_OFFSET] << 8) |
                 cmd[TA100_PKT_DATA_OFFSET + 1];
        offset = ((mm_u16)cmd[TA100_PKT_DATA_OFFSET + 2] << 8) |
                 cmd[TA100_PKT_DATA_OFFSET + 3];
    } else {
        length = ta->handle_data_len[idx];
    }

    if (offset >= ta->handle_data_len[idx]) {
        length = 0;
    } else if (offset + length > ta->handle_data_len[idx]) {
        length = (mm_u16)(ta->handle_data_len[idx] - offset);
    }

    if (length > TA100_HANDLE_DATA_MAX) {
        length = TA100_HANDLE_DATA_MAX;
    }

    if (length > 0) {
        memcpy(data, ta->handle_data[idx] + offset, length);
    }

    ta100_build_response(ta, TA100_STATUS_SUCCESS, data, length);
}

/* TA100 Write command (opcode 0x08) - simplified */
static void ta100_op_write(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u8 mode;
    mm_u16 source_handle;
    mm_u16 target_handle;
    mm_u16 length;
    mm_u16 offset;
    const mm_u8 *data;
    int idx;

    mode = cmd[TA100_PKT_PARAM1_OFFSET];
    /* param2 = source_handle(2 BE) + target_handle(2 BE) */
    source_handle = ((mm_u16)cmd[TA100_PKT_PARAM2_OFFSET] << 8) |
                    cmd[TA100_PKT_PARAM2_OFFSET + 1];
    target_handle = ((mm_u16)cmd[TA100_PKT_PARAM2_OFFSET + 2] << 8) |
                    cmd[TA100_PKT_PARAM2_OFFSET + 3];

    (void)source_handle;

    /* For partial write (mode != TA_WRITE_ENTIRE_ELEMENT), data section has length + offset + data */
    if ((mode & TA_WRITE_ENTIRE_ELEMENT) == 0) {
        /* Partial write: data = length(2 BE) + offset(2 BE) + actual_data */
        if (cmd_len < TA100_PKT_DATA_OFFSET + 4 + 2) {
            ta100_build_response(ta, TA100_STATUS_PARSE_ERROR, 0, 0);
            return;
        }
        length = ((mm_u16)cmd[TA100_PKT_DATA_OFFSET] << 8) |
                 cmd[TA100_PKT_DATA_OFFSET + 1];
        offset = ((mm_u16)cmd[TA100_PKT_DATA_OFFSET + 2] << 8) |
                 cmd[TA100_PKT_DATA_OFFSET + 3];
        data = &cmd[TA100_PKT_DATA_OFFSET + 4];

        if (cmd_len < (mm_u32)(TA100_PKT_DATA_OFFSET + 4 + length + 2)) {
            ta100_build_response(ta, TA100_STATUS_PARSE_ERROR, 0, 0);
            return;
        }
    } else {
        /* Entire element write: data = actual_data (no length/offset header) */
        length = (mm_u16)(cmd_len - TA100_PKT_DATA_OFFSET - 2);
        offset = 0;
        data = &cmd[TA100_PKT_DATA_OFFSET];
    }

    if (ta100_trace_enabled()) {
        fprintf(stderr, "[TA100_TRACE] WRITE: target=0x%04x offset=%u len=%u\n",
                target_handle, offset, length);
    }

    idx = ta100_find_handle(ta, target_handle);
    if (idx < 0) {
        ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
        return;
    }

    if (offset + length > TA100_HANDLE_DATA_MAX) {
        ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
        return;
    }

    if (length > 0) {
        memcpy(ta->handle_data[idx] + offset, data, length);
        if (offset + length > ta->handle_data_len[idx]) {
            ta->handle_data_len[idx] = (mm_u16)(offset + length);
        }
    }
    if (ta100_trace_enabled()) {
        mm_u32 i;
        fprintf(stderr, "[TA100_TRACE] WRITE: handle_count=%u handles:",
                (unsigned)ta->handle_count);
        for (i = 0; i < ta->handle_count && i < 16u; i++) {
            fprintf(stderr, " 0x%04x", ta->handles[i]);
        }
        fprintf(stderr, "\n");
    }

    ta100_build_response(ta, TA100_STATUS_SUCCESS, 0, 0);
}

static void ta100_op_aes(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u8 mode = cmd[TA100_PKT_PARAM1_OFFSET];
    mm_u16 param2_hi = ((mm_u16)cmd[TA100_PKT_PARAM2_OFFSET] << 8) |
                       cmd[TA100_PKT_PARAM2_OFFSET + 1];
    mm_u16 param2_lo = ((mm_u16)cmd[TA100_PKT_PARAM2_OFFSET + 2] << 8) |
                       cmd[TA100_PKT_PARAM2_OFFSET + 3];

    (void)cmd_len;

#ifdef M33MU_HAS_WOLFSSL
    if ((mode & TA_AES_ACTION_MASK) == TA_AES_ACTION_KEY_LOAD) {
        mm_u16 key_handle = param2_lo;
        int idx = ta100_find_handle(ta, key_handle);
        if (idx < 0 || ta->handle_data_len[idx] < TA_KEY_TYPE_AES128_SIZE) {
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            return;
        }
        memcpy(ta->aes_loaded_key, ta->handle_data[idx], TA_KEY_TYPE_AES128_SIZE);
        ta->aes_loaded_handle = key_handle;
        ta->aes_loaded_valid = MM_TRUE;
        ta100_build_response(ta, TA100_STATUS_SUCCESS, 0, 0);
        return;
    }

    if ((mode & TA_AES_MODE_MASK) == TA_AES_MODE_GCM) {
        mm_u16 aad_len = param2_hi;
        mm_u16 msg_len = param2_lo;
        const mm_u8 *p = &cmd[TA100_PKT_DATA_OFFSET];
        mm_u8 iv[TA_AES_GCM_IV_LENGTH];
        mm_u8 tag[TA_AES_GCM_TAG_LENGTH];
        mm_u8 out[TA_AES_GCM_MAX_DATA_SIZE];
        mm_u8 rsp[TA_AES_GCM_MAX_DATA_SIZE + TA_AES_GCM_TAG_LENGTH + TA_AES_GCM_IV_LENGTH];
        mm_u32 rsp_len = 0;
        mm_u32 data_len;
        mm_u32 need_len;
        int ret;
        Aes aes;

        if (!ta->aes_loaded_valid) {
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            return;
        }

        if (aad_len + msg_len > TA_AES_GCM_MAX_DATA_SIZE) {
            ta100_build_response(ta, TA100_STATUS_PARSE_ERROR, 0, 0);
            return;
        }

        if (cmd_len < TA100_PKT_DATA_OFFSET + 2) {
            ta100_build_response(ta, TA100_STATUS_PARSE_ERROR, 0, 0);
            return;
        }
        data_len = cmd_len - TA100_PKT_DATA_OFFSET - 2;
        need_len = ((mode & TA_AES_RAND_IV) == 0 ? TA_AES_GCM_IV_LENGTH : 0u) +
                   (mm_u32)aad_len + (mm_u32)msg_len +
                   (((mode & TA_AES_ACTION_MASK) == TA_AES_ACTION_DECRYPT) ? TA_AES_GCM_TAG_LENGTH : 0u);
        if (data_len < need_len) {
            ta100_build_response(ta, TA100_STATUS_PARSE_ERROR, 0, 0);
            return;
        }

        if ((mode & TA_AES_RAND_IV) == 0) {
            memcpy(iv, p, TA_AES_GCM_IV_LENGTH);
            p += TA_AES_GCM_IV_LENGTH;
        } else {
            if (!ta->rng_initialized) {
                if (wc_InitRng(&ta->rng) != 0) {
                    ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
                    return;
                }
                ta->rng_initialized = MM_TRUE;
            }
            if (wc_RNG_GenerateBlock(&ta->rng, iv, TA_AES_GCM_IV_LENGTH) != 0) {
                ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
                return;
            }
        }

        wc_AesInit(&aes, NULL, INVALID_DEVID);
        ret = wc_AesGcmSetKey(&aes, ta->aes_loaded_key, TA_KEY_TYPE_AES128_SIZE);
        if (ret != 0) {
            wc_AesFree(&aes);
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            return;
        }

        if ((mode & TA_AES_ACTION_MASK) == TA_AES_ACTION_DECRYPT) {
            const mm_u8 *aad = p;
            const mm_u8 *msg = aad + aad_len;
            const mm_u8 *tag_in = msg + msg_len;
            ret = wc_AesGcmDecrypt(&aes, out, msg, msg_len, iv, TA_AES_GCM_IV_LENGTH,
                                   tag_in, TA_AES_GCM_TAG_LENGTH, aad, aad_len);
            wc_AesFree(&aes);
            if (ret != 0) {
                ta100_build_response(ta, TA100_STATUS_CALCULATION, 0, 0);
                return;
            }
            memcpy(rsp, out, msg_len);
            rsp_len = msg_len;
        } else {
            const mm_u8 *aad = p;
            const mm_u8 *msg = aad + aad_len;
            ret = wc_AesGcmEncrypt(&aes, out, msg, msg_len, iv, TA_AES_GCM_IV_LENGTH,
                                   tag, TA_AES_GCM_TAG_LENGTH, aad, aad_len);
            wc_AesFree(&aes);
            if (ret != 0) {
                ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
                return;
            }
            memcpy(rsp, out, msg_len);
            rsp_len = msg_len;
            memcpy(rsp + rsp_len, tag, TA_AES_GCM_TAG_LENGTH);
            rsp_len += TA_AES_GCM_TAG_LENGTH;
        }

        if (mode & TA_AES_RAND_IV) {
            memcpy(rsp + rsp_len, iv, TA_AES_GCM_IV_LENGTH);
            rsp_len += TA_AES_GCM_IV_LENGTH;
        }

        ta100_build_response(ta, TA100_STATUS_SUCCESS, rsp, rsp_len);
        return;
    }
#endif

    ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
}

static void ta100_op_sign(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u8 mode = cmd[TA100_PKT_PARAM1_OFFSET];
    mm_u16 msg_handle = ((mm_u16)cmd[TA100_PKT_PARAM2_OFFSET] << 8) |
                        cmd[TA100_PKT_PARAM2_OFFSET + 1];
    mm_u16 priv_handle = ((mm_u16)cmd[TA100_PKT_PARAM2_OFFSET + 2] << 8) |
                         cmd[TA100_PKT_PARAM2_OFFSET + 3];
    const mm_u8 *msg = &cmd[TA100_PKT_DATA_OFFSET];
    mm_u32 msg_len = (cmd_len >= TA100_PKT_DATA_OFFSET + 2) ?
                     (cmd_len - TA100_PKT_DATA_OFFSET - 2) : 0;
    int idx = ta100_find_handle(ta, priv_handle);
    mm_u8 key_type = mode & 0x0F;
    mm_u16 key_size;

    (void)msg_handle;

    if (idx < 0) {
        ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
        return;
    }

    key_size = ta->handle_key_size[idx];

#ifdef M33MU_HAS_WOLFSSL
    if (key_type == TA_KEY_TYPE_RSA2048) {
        RsaKey *rsa = NULL;
        word32 sig_len = sizeof(ta->rsa_sig_tmp);
        int ret;
        word32 idx_der = 0;

        if (ta->handle_rsa_priv_len[idx] == 0) {
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            return;
        }
        if (ta100_trace_enabled()) {
            fprintf(stderr, "[TA100_TRACE] RSA sign: msg_len=%lu priv_len=%u\n",
                    (unsigned long)msg_len, (unsigned)ta->handle_rsa_priv_len[idx]);
            {
                mm_u32 i;
                fprintf(stderr, "[TA100_TRACE] RSA sign: pre handles:");
                for (i = 0; i < ta->handle_count && i < 16u; i++) {
                    fprintf(stderr, " 0x%04x", ta->handles[i]);
                }
                fprintf(stderr, "\n");
            }
        }

        if (!ta->rng_initialized) {
            if (wc_InitRng(&ta->rng) != 0) {
                ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
                return;
            }
            ta->rng_initialized = MM_TRUE;
        }

        rsa = (RsaKey *)malloc(sizeof(*rsa));
        if (rsa == NULL) {
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            return;
        }
        wc_InitRsaKey(rsa, NULL);
        if (ta100_trace_enabled()) {
            mm_u32 i;
            fprintf(stderr, "[TA100_TRACE] RSA sign: post init handles:");
            for (i = 0; i < ta->handle_count && i < 16u; i++) {
                fprintf(stderr, " 0x%04x", ta->handles[i]);
            }
            fprintf(stderr, "\n");
        }
        ret = wc_RsaPrivateKeyDecode(ta->handle_rsa_priv_der[idx], &idx_der, rsa,
                                     ta->handle_rsa_priv_len[idx]);
        if (ta100_trace_enabled()) {
            fprintf(stderr, "[TA100_TRACE] RSA sign: decode ret=%d idx_der=%u\n",
                    ret, (unsigned)idx_der);
        }
        if (ret != 0) {
            wc_FreeRsaKey(rsa);
            free(rsa);
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            return;
        }

        ret = wc_RsaPSS_Sign_ex(msg, (word32)msg_len, ta->rsa_sig_tmp, sig_len,
                                WC_HASH_TYPE_SHA256, WC_MGF1SHA256,
                                (int)msg_len, rsa, &ta->rng);
        if (ta100_trace_enabled()) {
            fprintf(stderr, "[TA100_TRACE] RSA sign: sign ret=%d\n", ret);
        }
        wc_FreeRsaKey(rsa);
        free(rsa);
        if (ret < 0) {
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            return;
        }
        if (ta100_trace_enabled()) {
            fprintf(stderr, "[TA100_TRACE] RSA sign: build response len=%d\n", ret);
        }
        ta100_build_response(ta, TA100_STATUS_SUCCESS, ta->rsa_sig_tmp, (mm_u32)ret);
        if (ta100_trace_enabled()) {
            fprintf(stderr, "[TA100_TRACE] RSA sign: response built\n");
            {
                mm_u32 i;
                fprintf(stderr, "[TA100_TRACE] RSA sign: handle_count=%u handles:",
                        (unsigned)ta->handle_count);
                for (i = 0; i < ta->handle_count && i < 16u; i++) {
                    fprintf(stderr, " 0x%04x", ta->handles[i]);
                }
                fprintf(stderr, "\n");
            }
        }
        return;
    } else if (key_type == TA_KEY_TYPE_ECCP256 || key_type == TA_KEY_TYPE_ECCP384) {
        ecc_key ecc;
        byte sig_der[160];
        word32 sig_der_len = sizeof(sig_der);
        byte r[72];
        byte s[72];
        word32 r_len = sizeof(r);
        word32 s_len = sizeof(s);
        byte sig_raw[144];
        int curve_id = (key_type == TA_KEY_TYPE_ECCP384) ? ECC_SECP384R1 : ECC_SECP256R1;
        int ret;

        wc_ecc_init(&ecc);
        ret = wc_ecc_import_private_key_ex(ta->handle_priv[idx], key_size,
                                           NULL, 0, &ecc, curve_id);
        if (ret != 0) {
            wc_ecc_free(&ecc);
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            return;
        }
        ret = wc_ecc_sign_hash(msg, (word32)msg_len, sig_der, &sig_der_len,
                               &ta->rng, &ecc);
        wc_ecc_free(&ecc);
        if (ret != 0) {
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            return;
        }
        ret = wc_ecc_sig_to_rs(sig_der, sig_der_len, r, &r_len, s, &s_len);
        if (ret != 0) {
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            return;
        }
        if (r_len > key_size || s_len > key_size) {
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            return;
        }
        memset(sig_raw, 0, (mm_u32)key_size * 2u);
        memcpy(sig_raw + (key_size - r_len), r, r_len);
        memcpy(sig_raw + key_size + (key_size - s_len), s, s_len);
        ta100_build_response(ta, TA100_STATUS_SUCCESS, sig_raw, (mm_u32)key_size * 2u);
        return;
    }
#endif

    ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
}

static void ta100_op_verify(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u8 mode = cmd[TA100_PKT_PARAM1_OFFSET];
    mm_u16 msg_handle = ((mm_u16)cmd[TA100_PKT_PARAM2_OFFSET] << 8) |
                        cmd[TA100_PKT_PARAM2_OFFSET + 1];
    mm_u16 pub_handle = ((mm_u16)cmd[TA100_PKT_PARAM2_OFFSET + 2] << 8) |
                        cmd[TA100_PKT_PARAM2_OFFSET + 3];
    mm_u8 key_type = mode & 0x0F;
    mm_u16 key_size = ta100_key_type_size(key_type);
    const mm_u8 *p = &cmd[TA100_PKT_DATA_OFFSET];
    mm_u32 data_len = (cmd_len >= TA100_PKT_DATA_OFFSET + 2) ?
                      (cmd_len - TA100_PKT_DATA_OFFSET - 2) : 0;
    mm_u8 verified = 0;

#ifdef M33MU_HAS_WOLFSSL
    if (key_type == TA_KEY_TYPE_RSA2048) {
        byte sig[TA_KEY_TYPE_RSA2048_SIZE];
        byte msg[WC_SHA256_DIGEST_SIZE];
        const mm_u8 *pub_mod = NULL;
        byte pub_mod_buf[TA_KEY_TYPE_RSA2048_SIZE];
        word32 sig_len = TA_KEY_TYPE_RSA2048_SIZE;
        word32 msg_len = WC_SHA256_DIGEST_SIZE;
        int idx;
        RsaKey *rsa = NULL;
        int ret;
        byte e[3] = { 0x01, 0x00, 0x01 };
        word32 e_len = 3;

        if (ta100_trace_enabled()) {
            fprintf(stderr,
                    "[TA100_TRACE] RSA verify: data_len=%lu sig_len=%lu msg_len=%lu msg_handle=0x%04x pub_handle=0x%04x\n",
                    (unsigned long)data_len, (unsigned long)sig_len, (unsigned long)msg_len,
                    msg_handle, pub_handle);
        }
        if (data_len < sig_len + msg_len) {
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            return;
        }
        memcpy(sig, p, sig_len);
        p += sig_len;
        if (msg_handle == TA_HANDLE_INPUT_BUFFER) {
            memcpy(msg, p, msg_len);
            p += msg_len;
        }
        if (pub_handle == TA_HANDLE_INPUT_BUFFER) {
            if (data_len < sig_len + msg_len + TA_KEY_TYPE_RSA2048_SIZE) {
                ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
                return;
            }
            memcpy(pub_mod_buf, p, TA_KEY_TYPE_RSA2048_SIZE);
            pub_mod = pub_mod_buf;
            if (ta100_trace_enabled()) {
                fprintf(stderr, "[TA100_TRACE] RSA verify: pub from input\n");
            }
        } else {
            idx = ta100_find_handle(ta, pub_handle);
            if (idx < 0 || ta->handle_rsa_pub_len[idx] < TA_KEY_TYPE_RSA2048_SIZE) {
                if (ta100_trace_enabled()) {
                    mm_u32 i;
                    fprintf(stderr, "[TA100_TRACE] RSA verify: pub handle invalid idx=%d len=%u handle_count=%u\n",
                            idx, (idx >= 0) ? (unsigned)ta->handle_rsa_pub_len[idx] : 0u,
                            (unsigned)ta->handle_count);
                    fprintf(stderr, "[TA100_TRACE] RSA verify: handles:");
                    for (i = 0; i < ta->handle_count && i < 16u; i++) {
                        fprintf(stderr, " 0x%04x", ta->handles[i]);
                    }
                    fprintf(stderr, "\n");
                }
                ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
                return;
            }
            pub_mod = ta->handle_rsa_pub_mod[idx];
            if (ta100_trace_enabled()) {
                fprintf(stderr, "[TA100_TRACE] RSA verify: pub handle=0x%04x\n", pub_handle);
            }
        }

        rsa = (RsaKey *)malloc(sizeof(*rsa));
        if (rsa == NULL) {
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            return;
        }
        wc_InitRsaKey(rsa, NULL);
        ret = wc_RsaPublicKeyDecodeRaw(pub_mod, TA_KEY_TYPE_RSA2048_SIZE, e, e_len, rsa);
        if (ta100_trace_enabled()) {
            fprintf(stderr, "[TA100_TRACE] RSA verify: decode ret=%d\n", ret);
        }
        if (ret == 0) {
            byte tmp[TA_KEY_TYPE_RSA2048_SIZE];
            ret = wc_RsaPSS_Verify_ex(sig, sig_len, tmp, sizeof(tmp),
                                      WC_HASH_TYPE_SHA256, WC_MGF1SHA256,
                                      (int)msg_len, rsa);
            if (ta100_trace_enabled()) {
                fprintf(stderr, "[TA100_TRACE] RSA verify: verify ret=%d\n", ret);
            }
            if (ret >= 0) {
                verified = 1u;
            }
        }
        wc_FreeRsaKey(rsa);
        free(rsa);

        ta100_build_response(ta, TA100_STATUS_SUCCESS, &verified, 1);
        return;
    } else if (key_type == TA_KEY_TYPE_ECCP256 || key_type == TA_KEY_TYPE_ECCP384) {
        byte sig_der[160];
        word32 sig_der_len = sizeof(sig_der);
        const mm_u8 *sig_raw = p;
        const mm_u8 *msg = NULL;
        const mm_u8 *pub = NULL;
        byte pub_buf[144];
        int curve_id = (key_type == TA_KEY_TYPE_ECCP384) ? ECC_SECP384R1 : ECC_SECP256R1;
        int idx;
        int ret;
        ecc_key ecc;
        word32 msg_len = key_size;

        if (data_len < (mm_u32)(key_size * 2u)) {
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            return;
        }
        p += key_size * 2u;

        if (msg_handle == TA_HANDLE_INPUT_BUFFER) {
            if (data_len < (mm_u32)(key_size * 2u + msg_len)) {
                ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
                return;
            }
            msg = p;
            p += msg_len;
        }

        if (pub_handle == TA_HANDLE_INPUT_BUFFER) {
            if (data_len < (mm_u32)(key_size * 2u + msg_len + key_size * 2u)) {
                ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
                return;
            }
            memcpy(pub_buf, p, key_size * 2u);
            pub = pub_buf;
        } else {
            idx = ta100_find_handle(ta, pub_handle);
            if (idx < 0 || ta->handle_has_key[idx] == MM_FALSE) {
                ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
                return;
            }
            pub = ta->handle_pubx[idx];
        }

        ret = wc_ecc_rs_raw_to_sig(sig_raw, key_size, sig_raw + key_size, key_size,
                                   sig_der, &sig_der_len);
        if (ret != 0) {
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            return;
        }

        wc_ecc_init(&ecc);
        if (pub_handle == TA_HANDLE_INPUT_BUFFER) {
            ret = wc_ecc_import_unsigned(&ecc, pub, pub + key_size, NULL, curve_id);
        } else {
            ret = wc_ecc_import_unsigned(&ecc, ta->handle_pubx[idx],
                                         ta->handle_puby[idx], NULL, curve_id);
        }
        if (ret == 0) {
            int verify_res = 0;
            ret = wc_ecc_verify_hash(sig_der, sig_der_len, msg, msg_len,
                                     &verify_res, &ecc);
            verified = (ret == 0 && verify_res == 1) ? 1u : 0u;
        }
        wc_ecc_free(&ecc);

        ta100_build_response(ta, TA100_STATUS_SUCCESS, &verified, 1);
        return;
    }
#endif

    ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
}

static void ta100_op_rsaenc(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u8 mode = cmd[TA100_PKT_PARAM1_OFFSET];
    mm_u16 in_len = ((mm_u16)cmd[TA100_PKT_PARAM2_OFFSET] << 8) |
                    cmd[TA100_PKT_PARAM2_OFFSET + 1];
    mm_u16 handle = ((mm_u16)cmd[TA100_PKT_PARAM2_OFFSET + 2] << 8) |
                    cmd[TA100_PKT_PARAM2_OFFSET + 3];
    const mm_u8 *p = &cmd[TA100_PKT_DATA_OFFSET];

    (void)cmd_len;

#ifdef M33MU_HAS_WOLFSSL
    if (mode == TA_RSAENC_ENCRYPT2048) {
        byte out[TA_RSAENC_CIPHER_TEXT_SIZE2048];
        byte e[4] = { 0x01, 0x00, 0x01, 0x00 };
        word32 e_len = 3;
        RsaKey *rsa = NULL;
        int idx;
        int ret;
        const mm_u8 *mod;

        if (in_len > TA_RSAENC_PLAIN_TEXT_MAX_SIZE2048) {
            ta100_build_response(ta, TA100_STATUS_PARSE_ERROR, 0, 0);
            return;
        }

        idx = ta100_find_handle(ta, handle);
        if (idx < 0 || ta->handle_rsa_pub_len[idx] < TA_KEY_TYPE_RSA2048_SIZE) {
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            return;
        }
        mod = ta->handle_rsa_pub_mod[idx];

        if (!ta->rng_initialized) {
            if (wc_InitRng(&ta->rng) != 0) {
                ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
                return;
            }
            ta->rng_initialized = MM_TRUE;
        }

        rsa = (RsaKey *)malloc(sizeof(*rsa));
        if (rsa == NULL) {
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            return;
        }
        wc_InitRsaKey(rsa, NULL);
        ret = wc_RsaPublicKeyDecodeRaw(mod, TA_KEY_TYPE_RSA2048_SIZE, e, e_len, rsa);
        if (ret != 0) {
            wc_FreeRsaKey(rsa);
            free(rsa);
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            return;
        }
        ret = wc_RsaPublicEncrypt(p, in_len, out, sizeof(out), rsa, &ta->rng);
        wc_FreeRsaKey(rsa);
        free(rsa);
        if (ret < 0) {
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            return;
        }
        ta100_build_response(ta, TA100_STATUS_SUCCESS, out, (mm_u32)ret);
        return;
    }
    if (mode == TA_RSAENC_DECRYPT2048) {
        byte out[TA_RSAENC_CIPHER_TEXT_SIZE2048];
        RsaKey *rsa = NULL;
        int ret;
        int idx;
        word32 der_idx = 0;

        if (in_len != TA_RSAENC_CIPHER_TEXT_SIZE2048) {
            ta100_build_response(ta, TA100_STATUS_PARSE_ERROR, 0, 0);
            return;
        }

        idx = ta100_find_handle(ta, handle);
        if (idx < 0 || ta->handle_rsa_priv_len[idx] == 0) {
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            return;
        }

        rsa = (RsaKey *)malloc(sizeof(*rsa));
        if (rsa == NULL) {
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            return;
        }
        wc_InitRsaKey(rsa, NULL);
        ret = wc_RsaPrivateKeyDecode(ta->handle_rsa_priv_der[idx], &der_idx, rsa,
                                     ta->handle_rsa_priv_len[idx]);
        if (ret != 0) {
            wc_FreeRsaKey(rsa);
            free(rsa);
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            return;
        }
        ret = wc_RsaPrivateDecrypt(p, in_len, out, sizeof(out), rsa);
        wc_FreeRsaKey(rsa);
        free(rsa);
        if (ret < 0) {
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            return;
        }
        ta100_build_response(ta, TA100_STATUS_SUCCESS, out, (mm_u32)ret);
        return;
    }
#endif

    ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
}

static void ta100_cmd_info(struct mm_ta100 *ta)
{
    mm_u16 crc;

    ta->rsp_buf[0] = TA100_STATUS_SUCCESS;
    ta->rsp_buf[1] = 0x00;
    ta->rsp_buf[2] = 0x00;
    ta->rsp_buf[3] = 0x04;
    ta->rsp_buf[4] = 0x11;
    ta->rsp_len = 5;
    crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
}

static void ta100_process_command(struct mm_ta100 *ta)
{
    mm_u8 opcode;
    mm_u8 instr_code;
    mm_u16 pkt_len;
    mm_u8 param1;
    mm_u32 param2;
    mm_u16 crc;
    mm_bool is_ta100_format = MM_FALSE;
    mm_u8 first_byte;

    if (ta == 0 || ta->cmd_len == 0) {
        return;
    }

    first_byte = ta->cmd_buf[0];

    /* For RD_RSP, don't clear response - we want to return the buffered response */
    if (first_byte != TA100_INSTR_RD_RSP) {
        ta->rsp_len = 0;
        ta->rsp_read = 0;
    }
    ta->busy_cycles = 100;

    if (ta100_trace_enabled()) {
        fprintf(stderr, "[TA100_TRACE] Processing command, len=%lu\n",
                (unsigned long)ta->cmd_len);
        ta100_trace_dump("cmd", ta->cmd_buf, ta->cmd_len);
    }

    if (ta->cmd_len < 1) {
        ta100_build_response(ta, TA100_STATUS_PARSE_ERROR, 0, 0);
        ta->state = TA100_RESP_READY;
        return;
    }

    instr_code = ta->cmd_buf[0];

    /* Handle TA100 instruction codes */
    switch (instr_code) {
    case TA100_INSTR_RD_CSR:
        /* Read Command Status Register - return device ready status */
        if (ta100_trace_enabled()) {
            fprintf(stderr, "[TA100_TRACE] RD_CSR: returning ready status\n");
        }
        /* CSR format: bit[4]=RRDY (response ready), bits[2:1]=status (0=available) */
        ta->rsp_buf[0] = (ta->state == TA100_RESP_READY) ? 0x10 : 0x00;  /* RRDY=1 if response ready */
        ta->rsp_len = 1;
        /* Don't change state for CSR read */
        return;

    case TA100_INSTR_RD_RSP:
        /* Read Response - return the buffered response if available */
        if (ta100_trace_enabled()) {
            fprintf(stderr, "[TA100_TRACE] RD_RSP: returning response len=%u\n", (unsigned)ta->rsp_len);
        }
        /* Response is already in rsp_buf from previous command execution */
        ta->state = TA100_RESP_READY;
        return;

    case TA100_INSTR_WR_CCR:
        /* Write Command Control Register - just acknowledge */
        if (ta100_trace_enabled()) {
            fprintf(stderr, "[TA100_TRACE] WR_CCR: acknowledged\n");
        }
        ta->rsp_buf[0] = 0x00;
        ta->rsp_len = 1;
        return;

    case TA100_INSTR_WR_CMD:
        /* Write Command - parse TA100 packet format */
        if (ta->cmd_len >= 8) {
            is_ta100_format = MM_TRUE;
            pkt_len = ((mm_u16)ta->cmd_buf[1] << 8) | ta->cmd_buf[2];
            opcode = ta->cmd_buf[TA100_PKT_OPCODE_OFFSET];  /* byte 3 */
            param1 = ta->cmd_buf[TA100_PKT_PARAM1_OFFSET];  /* byte 4 */
            param2 = ((mm_u32)ta->cmd_buf[TA100_PKT_PARAM2_OFFSET] << 24) |
                     ((mm_u32)ta->cmd_buf[TA100_PKT_PARAM2_OFFSET + 1] << 16) |
                     ((mm_u32)ta->cmd_buf[TA100_PKT_PARAM2_OFFSET + 2] << 8) |
                     ta->cmd_buf[TA100_PKT_PARAM2_OFFSET + 3];
            (void)pkt_len;

            if (ta100_trace_enabled()) {
                fprintf(stderr, "[TA100_TRACE] WR_CMD: opcode=0x%02x param1=0x%02x param2=0x%08x\n",
                        opcode, param1, (unsigned)param2);
            }
        } else {
            if (ta100_trace_enabled()) {
                fprintf(stderr, "[TA100_TRACE] WR_CMD: packet too short (%u bytes)\n", (unsigned)ta->cmd_len);
            }
            ta100_build_response(ta, TA100_STATUS_PARSE_ERROR, 0, 0);
            ta->state = TA100_RESP_READY;
            return;
        }
        break;

    default:
        /* Check if this might be an ATECC-style opcode for legacy compatibility */
        if (instr_code >= 0x02 && instr_code <= 0x47 && ta->cmd_len >= 3) {
            /* Treat as ATECC format */
            opcode = instr_code;
            param1 = (ta->cmd_len > 1) ? ta->cmd_buf[1] : 0;
            param2 = 0;
            if (ta->cmd_len >= 4) {
                param2 = ((mm_u32)ta->cmd_buf[2] << 8) | ta->cmd_buf[3];
            }
            if (ta100_trace_enabled()) {
                fprintf(stderr, "[TA100_TRACE] ATECC format: opcode=0x%02x\n", opcode);
            }
        } else {
            if (ta100_trace_enabled()) {
                fprintf(stderr, "[TA100_TRACE] Unknown instruction 0x%02x\n", instr_code);
            }
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            ta->state = TA100_RESP_READY;
            return;
        }
    }

    /* Skip CRC verification for TA100 format for now - trust the data */

    if (is_ta100_format) {
        /* Handle TA100-specific opcodes */
        switch (opcode) {
        case TA100_OP_INFO:
            ta100_op_info(ta, param1, param2);
            break;
        case TA100_OP_CREATE:
            ta100_op_create(ta, ta->cmd_buf, ta->cmd_len);
            break;
        case TA100_OP_DELETE:
            ta100_op_delete(ta, ta->cmd_buf, ta->cmd_len);
            break;
        case TA100_OP_READ:
            ta100_op_read(ta, ta->cmd_buf, ta->cmd_len);
            break;
        case TA100_OP_WRITE:
            ta100_op_write(ta, ta->cmd_buf, ta->cmd_len);
            break;
        case TA100_OP_RANDOM:
            ta100_op_random(ta, ta->cmd_buf, ta->cmd_len);
            break;
        case TA100_OP_VERIFY:
            ta100_op_verify(ta, ta->cmd_buf, ta->cmd_len);
            break;
        case TA100_OP_KEYGEN:
            ta100_op_keygen(ta, ta->cmd_buf, ta->cmd_len);
            if (ta100_trace_enabled()) {
                fprintf(stderr, "[TA100_TRACE] Returned from KEYGEN\n");
                fflush(stderr);
            }
            break;
        case TA100_OP_SIGN:
            ta100_op_sign(ta, ta->cmd_buf, ta->cmd_len);
            if (ta100_trace_enabled()) {
                fprintf(stderr, "[TA100_TRACE] Returned from SIGN\n");
                fflush(stderr);
            }
            break;
        case TA100_OP_RSAENC:
            ta100_op_rsaenc(ta, ta->cmd_buf, ta->cmd_len);
            break;
        case TA100_OP_AES:
            ta100_op_aes(ta, ta->cmd_buf, ta->cmd_len);
            break;
        case TA100_OP_LOCK:
            ta100_op_lock(ta, ta->cmd_buf, ta->cmd_len);
            break;
        case TA100_OP_COUNTER:
        case TA100_OP_AUTHORIZE:
        case TA100_OP_SHA:
        case TA100_OP_MAC:
        case TA100_OP_POWER:
        case TA100_OP_SELFTEST:
        case TA100_OP_IMPORT:
        case TA100_OP_EXPORT:
        case TA100_OP_DEVUPDATE:
            /* Not implemented - return success for now */
            if (ta100_trace_enabled()) {
                fprintf(stderr, "[TA100_TRACE] Opcode 0x%02x not fully implemented, returning success\n", opcode);
            }
            ta100_build_response(ta, TA100_STATUS_SUCCESS, 0, 0);
            break;
        default:
            if (ta100_trace_enabled()) {
                fprintf(stderr, "[TA100_TRACE] Unknown TA100 opcode 0x%02x\n", opcode);
            }
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            break;
        }
    } else {
        /* Handle ATECC-style opcodes */
        if (ta->cmd_len >= 3 && !ta100_verify_crc(ta->cmd_buf, ta->cmd_len)) {
            if (ta100_trace_enabled()) {
                fprintf(stderr, "[TA100_TRACE] CRC error\n");
            }
            ta->rsp_buf[0] = TA100_STATUS_CRC_ERROR;
            ta->rsp_len = 1;
            ta->state = TA100_RESP_READY;
            return;
        }

        switch (opcode) {
        case TA100_CMD_INFO_ATECC:
            ta100_cmd_info(ta);
            break;
        case TA100_CMD_READ_ATECC:
            ta100_cmd_read(ta, ta->cmd_buf, ta->cmd_len);
            break;
        case TA100_CMD_WRITE_ATECC:
            ta100_cmd_write(ta, ta->cmd_buf, ta->cmd_len);
            break;
        case TA100_CMD_LOCK_ATECC:
            ta100_cmd_lock(ta, ta->cmd_buf, ta->cmd_len);
            break;
#ifdef M33MU_HAS_WOLFSSL
        case TA100_CMD_RANDOM_ATECC:
            ta100_cmd_random(ta, ta->cmd_buf, ta->cmd_len);
            break;
        case TA100_CMD_NONCE_ATECC:
            ta100_cmd_nonce(ta, ta->cmd_buf, ta->cmd_len);
            break;
        case TA100_CMD_GENKEY_ATECC:
            ta100_cmd_genkey(ta, ta->cmd_buf, ta->cmd_len);
            break;
        case TA100_CMD_SIGN_ATECC:
            ta100_cmd_sign(ta, ta->cmd_buf, ta->cmd_len);
            break;
        case TA100_CMD_SHA256_ATECC:
            ta100_cmd_sha256(ta, ta->cmd_buf, ta->cmd_len);
            break;
#endif
        default:
            if (ta100_trace_enabled()) {
                fprintf(stderr, "[TA100_TRACE] Unknown ATECC opcode 0x%02x\n", opcode);
            }
            ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
            ta->rsp_len = 1;
            crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
            ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
            ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
            break;
        }
    }

    if (ta100_trace_enabled()) {
        fprintf(stderr, "[TA100_TRACE] Response ready, len=%lu\n",
                (unsigned long)ta->rsp_len);
        fflush(stderr);
        ta100_trace_dump("rsp", ta->rsp_buf, ta->rsp_len);
        fflush(stderr);
    }

    ta->state = TA100_RESP_READY;
}

static void ta100_reset_transaction(struct mm_ta100 *ta)
{
    if (ta == 0) {
        return;
    }
    ta->cmd_len = 0;
    ta->rsp_len = 0;
    ta->rsp_read = 0;
    ta->busy_cycles = 0;
}

static mm_u8 ta100_spi_xfer(void *opaque, mm_u8 out)
{
    struct mm_ta100 *ta = (struct mm_ta100 *)opaque;
    mm_u8 in = 0x00u;
    mm_u8 cs_level;

    if (ta == 0) {
        return 0xFFu;
    }

    cs_level = ta100_sample_cs(ta);

    if (ta->cs_valid && cs_level != ta->cs_level) {
        ta->cs_level = cs_level;
        if (cs_level != 0u) {
            /* CS deasserted */
            if (ta100_spi_trace_enabled()) {
                fprintf(stderr, "[SPI] TA100 SPI%d CS deasserted (P%c%d)\n",
                        ta->bus,
                        (char)('A' + ta->cs_bank),
                        ta->cs_pin);
            }
            /* Only process WR_CMD on CS deassert, RD_* handled inline */
            if (ta->cur_instr == TA100_INSTR_WR_CMD && ta->cmd_len > 0) {
                ta100_process_command(ta);
            }
            ta->cmd_len = 0;
            ta->instr_started = MM_FALSE;
            ta->cur_instr = 0xFF;
            return 0xFFu;
        } else {
            /* CS asserted - start of new transaction */
            if (ta100_spi_trace_enabled()) {
                fprintf(stderr, "[SPI] TA100 SPI%d CS asserted (P%c%d)\n",
                        ta->bus,
                        (char)('A' + ta->cs_bank),
                        ta->cs_pin);
            }
            ta->instr_started = MM_FALSE;
            ta->cur_instr = 0xFF;
            ta->cmd_len = 0;
        }
    }

    if (ta->cs_valid && cs_level != 0u) {
        return 0xFFu;
    }

    /* First byte of transaction is the instruction code */
    if (!ta->instr_started) {
        ta->instr_started = MM_TRUE;
        ta->cur_instr = out;

        switch (out) {
        case TA100_INSTR_RD_CSR:
            /* Read CSR - prepare status for subsequent reads */
            /* CSR format: bit[4]=RRDY (response ready), bits[2:1]=status (0=available) */
            ta->csr_val = (ta->state == TA100_RESP_READY) ? 0x10 : 0x00;
            if (ta100_trace_enabled()) {
                fprintf(stderr, "[TA100_TRACE] RD_CSR: status=0x%02x\n", ta->csr_val);
            }
            return 0x00u;  /* ACK the instruction */

        case TA100_INSTR_RD_RSP:
            /* Read response - response already in rsp_buf */
            ta->rsp_read = 0;
            if (ta100_trace_enabled()) {
                fprintf(stderr, "[TA100_TRACE] RD_RSP: len=%u\n", (unsigned)ta->rsp_len);
            }
            return 0x00u;  /* ACK the instruction */

        case TA100_INSTR_WR_CMD:
            /* Write command - accumulate bytes */
            if (ta->cmd_len < TA100_CMD_MAX) {
                ta->cmd_buf[ta->cmd_len++] = out;
            }
            return 0x00u;

        default:
            /* Unknown instruction or ATECC-style command - accumulate */
            if (ta->cmd_len < TA100_CMD_MAX) {
                ta->cmd_buf[ta->cmd_len++] = out;
            }
            return 0x00u;
        }
    }

    /* Handle subsequent bytes based on current instruction */
    switch (ta->cur_instr) {
    case TA100_INSTR_RD_CSR:
        /* Return CSR value (host sends 0xFF to clock out) */
        if (ta100_trace_enabled()) {
            fprintf(stderr, "[TA100_TRACE] read CSR=0x%02x\n", ta->csr_val);
        }
        return ta->csr_val;

    case TA100_INSTR_RD_RSP:
        /* Return response bytes (host sends 0xFF as clock) */
        if (ta->rsp_read < ta->rsp_len) {
            in = ta->rsp_buf[ta->rsp_read++];
            if (ta100_trace_enabled()) {
                fprintf(stderr, "[TA100_TRACE] read rsp[%u]=0x%02x\n",
                        ta->rsp_read-1, in);
            }
            /* Clear response ready state when last byte is read */
            if (ta->rsp_read >= ta->rsp_len) {
                ta->state = TA100_IDLE;
            }
        } else {
            in = 0x00u;
        }
        return in;

    case TA100_INSTR_WR_CMD:
    default:
        /* Accumulate command bytes */
        if (ta->cmd_len < TA100_CMD_MAX) {
            ta->cmd_buf[ta->cmd_len++] = out;
        }
        return 0x00u;
    }
}

static void ta100_spi_end(void *opaque)
{
    struct mm_ta100 *ta = (struct mm_ta100 *)opaque;
    if (ta == 0) {
        return;
    }
    if (ta->cs_valid) {
        return;
    }
    ta100_process_command(ta);
    ta100_reset_transaction(ta);
}

static mm_u8 ta100_spi_cs_level(void *opaque)
{
    struct mm_ta100 *ta = (struct mm_ta100 *)opaque;
    mm_u8 cs_level;
    if (ta == 0) {
        return 1u;
    }
    cs_level = ta100_sample_cs(ta);

    /* Handle CS transitions when polled */
    if (ta->cs_valid && cs_level != ta->cs_level) {
        ta->cs_level = cs_level;
        if (cs_level != 0u) {
            /* CS deasserted - process pending command only for WR_CMD with data */
            if (ta100_spi_trace_enabled()) {
                fprintf(stderr, "[SPI] TA100 SPI%d CS deasserted via poll (P%c%d)\n",
                        ta->bus,
                        (char)('A' + ta->cs_bank),
                        ta->cs_pin);
            }
            /* Only process command if this was a WR_CMD transaction with data.
             * RD_CSR and RD_RSP are handled inline during ta100_spi_xfer */
            if (ta->cur_instr == TA100_INSTR_WR_CMD && ta->cmd_len > 0) {
                ta100_process_command(ta);
            }
            ta->cmd_len = 0;
            ta->instr_started = MM_FALSE;
            ta->cur_instr = 0xFF;
        } else {
            /* CS asserted - new transaction starting */
            ta->instr_started = MM_FALSE;
            ta->cur_instr = 0xFF;
            ta->cmd_len = 0;
            if (ta100_spi_trace_enabled()) {
                fprintf(stderr, "[SPI] TA100 SPI%d CS asserted via poll (P%c%d)\n",
                        ta->bus,
                        (char)('A' + ta->cs_bank),
                        ta->cs_pin);
            }
        }
    }

    return cs_level;
}

static void ta100_sync_nv(struct mm_ta100 *ta)
{
    FILE *f;
    if (ta == 0 || !ta->nv_dirty || !ta->has_nv_path) {
        return;
    }
    f = fopen(ta->nv_path, "wb");
    if (f == 0) {
        fprintf(stderr, "ta100: failed to open %s for write\n", ta->nv_path);
        return;
    }
    if (ta->nv_size > 0u) {
        size_t n = fwrite(ta->nv_data, 1u, (size_t)ta->nv_size, f);
        if (n != (size_t)ta->nv_size) {
            fprintf(stderr, "ta100: short write for %s\n", ta->nv_path);
        }
    }
    fclose(f);
    ta->nv_dirty = MM_FALSE;
}

static mm_bool ta100_load_nv(struct mm_ta100 *ta)
{
    FILE *f;
    size_t n = 0;
    mm_bool fresh = MM_FALSE;

    if (ta == 0 || !ta->has_nv_path) {
        return MM_FALSE;
    }

    ta->nv_size = TA100_NV_SIZE;
    ta->nv_data = (mm_u8 *)malloc((size_t)ta->nv_size);
    if (ta->nv_data == 0) {
        fprintf(stderr, "ta100: out of memory for NV\n");
        return MM_FALSE;
    }
    memset(ta->nv_data, 0xFF, (size_t)ta->nv_size);

    f = fopen(ta->nv_path, "rb");
    if (f != 0) {
        n = fread(ta->nv_data, 1u, (size_t)ta->nv_size, f);
        fclose(f);
        if (n < (size_t)ta->nv_size) {
            ta->nv_dirty = MM_TRUE;
        }

        ta->config_locked = (ta->nv_data[87] == 0x00) ? MM_TRUE : MM_FALSE;
        ta->data_locked = (ta->nv_data[86] == 0x00) ? MM_TRUE : MM_FALSE;
        ta->setup_locked = MM_TRUE;

        return MM_TRUE;
    }

    ta100_init_nv_layout(ta);
    ta->nv_dirty = MM_TRUE;
    fresh = MM_TRUE;

    if (fresh) {
        ta100_sync_nv(ta);
    }

    return MM_TRUE;
}

static void ta100_device_reset(struct mm_ta100 *ta)
{
    if (ta == 0) {
        return;
    }
    ta->state = TA100_IDLE;
    ta->cs_level = 1u;
    ta->aes_loaded_valid = MM_FALSE;
    ta->setup_locked = MM_TRUE;
    ta100_reset_transaction(ta);
}

static int parse_bus_index(const char *s)
{
    if (s == 0) return -1;
    if (strncmp(s, "SPI", 3) == 0) {
        char *end = 0;
        long n = strtol(s + 3, &end, 10);
        if (end != s + 3 && *end == '\0' && n >= 1 && n <= 99) {
            return (int)n;
        }
    }
    return -1;
}

static mm_bool parse_gpio_name(const char *s, int *bank_out, int *pin_out)
{
    if (s == 0 || bank_out == 0 || pin_out == 0) return MM_FALSE;
    if (s[0] == 'P' || s[0] == 'p') {
        char bank_char = s[1];
        int bank = 0;
        int pin = 0;
        char *end = 0;
        if (bank_char >= 'A' && bank_char <= 'Z') {
            bank = bank_char - 'A';
        } else if (bank_char >= 'a' && bank_char <= 'z') {
            bank = bank_char - 'a';
        } else {
            return MM_FALSE;
        }
        pin = (int)strtol(s + 2, &end, 10);
        if (end == s + 2 || *end != '\0' || pin < 0 || pin > 15) {
            return MM_FALSE;
        }
        *bank_out = bank;
        *pin_out = pin;
        return MM_TRUE;
    }
    return MM_FALSE;
}

mm_bool mm_ta100_parse_spec(const char *spec, struct mm_ta100_cfg *out)
{
    char tmp[512];
    char *tok;
    if (spec == 0 || out == 0) return MM_FALSE;
    memset(out, 0, sizeof(*out));
    strncpy(tmp, spec, sizeof(tmp) - 1u);
    tmp[sizeof(tmp) - 1u] = '\0';
    tok = strtok(tmp, ":");
    if (tok == 0) return MM_FALSE;
    out->bus = parse_bus_index(tok);
    if (out->bus < 0) return MM_FALSE;
    while ((tok = strtok(0, ":")) != 0) {
        if (strncmp(tok, "cs=", 3) == 0) {
            if (!parse_gpio_name(tok + 3, &out->cs_bank, &out->cs_pin)) return MM_FALSE;
            out->cs_valid = MM_TRUE;
        } else if (strncmp(tok, "file=", 5) == 0) {
            strncpy(out->nv_path, tok + 5, sizeof(out->nv_path) - 1u);
            out->nv_path[sizeof(out->nv_path) - 1u] = '\0';
            out->has_nv_path = MM_TRUE;
        } else if (strncmp(tok, "profile=", 8) == 0) {
            strncpy(out->profile, tok + 8, sizeof(out->profile) - 1u);
            out->profile[sizeof(out->profile) - 1u] = '\0';
            out->has_profile = MM_TRUE;
        } else if (strncmp(tok, "serial=", 7) == 0) {
            strncpy(out->serial, tok + 7, sizeof(out->serial) - 1u);
            out->serial[sizeof(out->serial) - 1u] = '\0';
            out->has_serial = MM_TRUE;
        } else {
            return MM_FALSE;
        }
    }
    return MM_TRUE;
}

mm_bool mm_ta100_register_cfg(const struct mm_ta100_cfg *cfg)
{
    struct mm_ta100 *ta;
    struct mm_spi_device dev;
    if (cfg == 0) {
        return MM_FALSE;
    }
    if (g_ta100_count >= TA100_MAX) {
        fprintf(stderr, "ta100: max devices reached\n");
        return MM_FALSE;
    }
    ta = &g_ta100[g_ta100_count];
    memset(ta, 0, sizeof(*ta));
    ta->bus = cfg->bus;
    ta->cs_valid = cfg->cs_valid;
    ta->cs_bank = cfg->cs_bank;
    ta->cs_pin = cfg->cs_pin;
    ta->cs_mask = (cfg->cs_valid && cfg->cs_pin >= 0) ? (1u << (mm_u32)cfg->cs_pin) : 0u;
    ta->cs_level = 1u;
    ta->has_nv_path = cfg->has_nv_path;
    if (cfg->has_nv_path) {
        size_t n = strlen(cfg->nv_path);
        if (n >= sizeof(ta->nv_path)) {
            n = sizeof(ta->nv_path) - 1u;
        }
        memcpy(ta->nv_path, cfg->nv_path, n);
        ta->nv_path[n] = '\0';
    }
    ta->has_profile = cfg->has_profile;
    if (cfg->has_profile) {
        size_t n = strlen(cfg->profile);
        if (n >= sizeof(ta->profile)) {
            n = sizeof(ta->profile) - 1u;
        }
        memcpy(ta->profile, cfg->profile, n);
        ta->profile[n] = '\0';
    }
    ta->has_serial = cfg->has_serial;
    if (cfg->has_serial) {
        size_t n = strlen(cfg->serial);
        if (n >= sizeof(ta->serial)) {
            n = sizeof(ta->serial) - 1u;
        }
        memcpy(ta->serial, cfg->serial, n);
        ta->serial[n] = '\0';
    }

    if (ta->has_nv_path) {
        ta100_load_nv(ta);
    }

    ta100_device_reset(ta);

    memset(&dev, 0, sizeof(dev));
    dev.bus = ta->bus;
    dev.xfer = ta100_spi_xfer;
    dev.end = ta100_spi_end;
    dev.cs_level = ta100_spi_cs_level;
    dev.opaque = ta;
    if (!mm_spi_bus_register_device(&dev)) {
        fprintf(stderr, "ta100: failed to register SPI device\n");
        return MM_FALSE;
    }

    g_ta100_count++;
    fprintf(stderr, "[TA100] Registered on SPI%d", ta->bus);
    if (ta->cs_valid) {
        fprintf(stderr, " CS=P%c%d", (char)('A' + ta->cs_bank), ta->cs_pin);
    }
    if (ta->has_nv_path) {
        fprintf(stderr, " file=%s", ta->nv_path);
    }
    if (ta->has_profile) {
        fprintf(stderr, " profile=%s", ta->profile);
    }
    if (ta->has_serial) {
        fprintf(stderr, " serial=%s", ta->serial);
    }
    fprintf(stderr, "\n");

    return MM_TRUE;
}

void mm_ta100_reset_all(void)
{
    size_t i;
    for (i = 0; i < g_ta100_count; ++i) {
        ta100_device_reset(&g_ta100[i]);
    }
}

void mm_ta100_shutdown_all(void)
{
    size_t i;
    for (i = 0; i < g_ta100_count; ++i) {
        ta100_sync_nv(&g_ta100[i]);
#ifdef M33MU_HAS_WOLFSSL
        if (g_ta100[i].rng_initialized) {
            wc_FreeRng(&g_ta100[i].rng);
            g_ta100[i].rng_initialized = MM_FALSE;
        }
#endif
        if (g_ta100[i].nv_data != 0) {
            free(g_ta100[i].nv_data);
            g_ta100[i].nv_data = 0;
        }
    }
}

size_t mm_ta100_count(void)
{
    return g_ta100_count;
}

mm_bool mm_ta100_get_info(size_t index, struct mm_ta100_info *out)
{
    const struct mm_ta100 *ta;
    if (index >= g_ta100_count || out == 0) {
        return MM_FALSE;
    }
    ta = &g_ta100[index];
    memset(out, 0, sizeof(*out));
    out->bus = ta->bus;
    out->cs_valid = ta->cs_valid;
    out->cs_bank = ta->cs_bank;
    out->cs_pin = ta->cs_pin;
    out->has_nv_path = ta->has_nv_path;
    if (ta->has_nv_path) {
        size_t n = strlen(ta->nv_path);
        if (n >= sizeof(out->nv_path)) {
            n = sizeof(out->nv_path) - 1u;
        }
        memcpy(out->nv_path, ta->nv_path, n);
        out->nv_path[n] = '\0';
    }
    out->has_profile = ta->has_profile;
    if (ta->has_profile) {
        size_t n = strlen(ta->profile);
        if (n >= sizeof(out->profile)) {
            n = sizeof(out->profile) - 1u;
        }
        memcpy(out->profile, ta->profile, n);
        out->profile[n] = '\0';
    }
    out->has_serial = ta->has_serial;
    if (ta->has_serial) {
        size_t n = strlen(ta->serial);
        if (n >= sizeof(out->serial)) {
            n = sizeof(out->serial) - 1u;
        }
        memcpy(out->serial, ta->serial, n);
        out->serial[n] = '\0';
    }
    return MM_TRUE;
}
