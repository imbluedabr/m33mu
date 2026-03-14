/* m33mu -- LPC55S69 SDK CRC test
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Exercises fsl_crc.c against the emulated CRC engine.
 * Expected results (standard CRC catalogue):
 *   CRC-16/CCITT-FALSE("123456789") = 0x29b1
 *   CRC-16/ARC("123456789")         = 0xbb3d
 *   CRC-32("123456789")             = 0xcbf43926
 */
#include <stdio.h>
#include "fsl_crc.h"

static void init_crc16_ccitt(CRC_Type *base, uint32_t seed)
{
    crc_config_t cfg;
    CRC_GetDefaultConfig(&cfg);
    cfg.seed = seed;
    CRC_Init(base, &cfg);
}

static void init_crc16_arc(CRC_Type *base, uint32_t seed)
{
    crc_config_t cfg;
    cfg.polynomial    = kCRC_Polynomial_CRC_16;
    cfg.reverseIn     = true;
    cfg.complementIn  = false;
    cfg.reverseOut    = true;
    cfg.complementOut = false;
    cfg.seed          = seed;
    CRC_Init(base, &cfg);
}

static void init_crc32(CRC_Type *base, uint32_t seed)
{
    crc_config_t cfg;
    cfg.polynomial    = kCRC_Polynomial_CRC_32;
    cfg.reverseIn     = true;
    cfg.complementIn  = false;
    cfg.reverseOut    = true;
    cfg.complementOut = true;
    cfg.seed          = seed;
    CRC_Init(base, &cfg);
}

int main(void)
{
    const char data[] = "123456789";
    int pass = 1;
    uint16_t r16;
    uint32_t r32;

    printf("=== CRC test ===\n");

    /* CRC-16/CCITT-FALSE */
    init_crc16_ccitt(CRC_ENGINE, 0xFFFFu);
    CRC_WriteData(CRC_ENGINE, (const uint8_t *)data, sizeof(data) - 1u);
    r16 = CRC_Get16bitResult(CRC_ENGINE);
    printf("CRC-16/CCITT-FALSE: 0x%04x  exp 0x29b1  %s\n",
           r16, r16 == 0x29b1u ? "PASS" : "FAIL");
    if (r16 != 0x29b1u) pass = 0;

    /* CRC-16/ARC */
    init_crc16_arc(CRC_ENGINE, 0u);
    CRC_WriteData(CRC_ENGINE, (const uint8_t *)data, sizeof(data) - 1u);
    r16 = CRC_Get16bitResult(CRC_ENGINE);
    printf("CRC-16/ARC:         0x%04x  exp 0xbb3d  %s\n",
           r16, r16 == 0xbb3du ? "PASS" : "FAIL");
    if (r16 != 0xbb3du) pass = 0;

    /* CRC-32 */
    init_crc32(CRC_ENGINE, 0xFFFFFFFFu);
    CRC_WriteData(CRC_ENGINE, (const uint8_t *)data, sizeof(data) - 1u);
    r32 = CRC_Get32bitResult(CRC_ENGINE);
    printf("CRC-32:             0x%08lx  exp 0xcbf43926  %s\n",
           (unsigned long)r32, r32 == 0xcbf43926u ? "PASS" : "FAIL");
    if (r32 != 0xcbf43926u) pass = 0;

    printf("=== %s ===\n", pass ? "ALL PASS" : "SOME FAIL");
    return pass ? 0 : 1;
}
