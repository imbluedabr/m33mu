/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * PIC32CK IDAU partitioning test.
 */
#include <stdio.h>
#include <stdint.h>

#define IDAU_BASE            0x4480C000u
#define IDAU_STATUSA         (*(volatile uint32_t *)(IDAU_BASE + 0x04u))
#define IDAU_RCTRL(region)   (*(volatile uint32_t *)(IDAU_BASE + 0x1000u + (region) * 0x10u))
#define IDAU_RSTATUSA(region) (*(volatile uint32_t *)(IDAU_BASE + 0x1004u + (region) * 0x10u))
#define IDAU_RSTATUSB(region) (*(volatile uint32_t *)(IDAU_BASE + 0x1008u + (region) * 0x10u))

#define IDAU_REGION_ANSC     0x09u
#define IDAU_REGION_ANS      0x0Au
#define IDAU_REGION_RNS      0x0Eu

#define IDAU_STATUSA_ENABLE  (1u << 0)
#define IDAU_STATUSA_NBRG(v) (((v) >> 8) & 0x1FFu)

#define IDAU_RCTRL_WRSZ(sz)  (((uint32_t)0x5Cu << 24) | ((sz) & 0x00FFFFFFu))

int main(void)
{
    int all = 1;
    printf("=== PIC32CK IDAU test ===\n");

    int t1 = ((IDAU_STATUSA & IDAU_STATUSA_ENABLE) != 0u) &&
             (IDAU_STATUSA_NBRG(IDAU_STATUSA) == 24u);
    printf("IDAU enabled/default regions: %s\n", t1 ? "PASS" : "FAIL");
    all &= t1;

    int t2 = (IDAU_RSTATUSB(IDAU_REGION_ANS) == 0x00100000u) &&
             (IDAU_RSTATUSB(IDAU_REGION_ANSC) == 0x00000000u) &&
             (IDAU_RSTATUSB(IDAU_REGION_RNS) == 0x00040000u);
    printf("IDAU default sizes: %s\n", t2 ? "PASS" : "FAIL");
    all &= t2;

    IDAU_RCTRL(IDAU_REGION_ANSC) = IDAU_RCTRL_WRSZ(0x1000u);
    IDAU_RCTRL(IDAU_REGION_ANS) = IDAU_RCTRL_WRSZ(0x00080000u);
    IDAU_RCTRL(IDAU_REGION_RNS) = IDAU_RCTRL_WRSZ(0x00020000u);

    int t3 = (IDAU_RSTATUSB(IDAU_REGION_ANSC) == 0x00001000u) &&
             (IDAU_RSTATUSB(IDAU_REGION_ANS) == 0x00080000u) &&
             (IDAU_RSTATUSB(IDAU_REGION_RNS) == 0x00020000u);
    printf("IDAU watermark updates: %s\n", t3 ? "PASS" : "FAIL");
    all &= t3;

    int t4 = ((IDAU_RSTATUSA(IDAU_REGION_ANSC) & 0xFu) == 0x6u) &&
             ((IDAU_RSTATUSA(IDAU_REGION_ANS) & 0xFu) == 0x3u);
    printf("IDAU region types: %s\n", t4 ? "PASS" : "FAIL");
    all &= t4;

    printf("=== %s ===\n", all ? "ALL PASS" : "SOME FAIL");
    return all ? 0 : 1;
}
