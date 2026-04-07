/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>

#define mm_pic32ck_sercom_init mm_pic32ck_sercom_init_under_test
#define mm_pic32ck_sercom_reset mm_pic32ck_sercom_reset_under_test
#define mm_pic32ck_sercom_poll mm_pic32ck_sercom_poll_under_test
#include "../cpu/pic32ck/pic32ck_sercom.c"
#undef mm_pic32ck_sercom_init
#undef mm_pic32ck_sercom_reset
#undef mm_pic32ck_sercom_poll

static int test_usart_intflag_w1c(void)
{
    struct sercom_inst sc;
    mm_u16 flags = (mm_u16)(INTFLAG_DRE | INTFLAG_TXC | INTFLAG_RXC);

    memset(&sc, 0, sizeof(sc));
    sc.regs[SERCOM_CTRLA / 4u] = (CTRLA_MODE_USART << CTRLA_MODE_SHIFT);
    memcpy((mm_u8 *)sc.regs + SERCOM_INTFLAG, &flags, sizeof(flags));

    if (!usart_write(&sc, SERCOM_INTFLAG, 2u, INTFLAG_TXC)) return 1;
    memcpy(&flags, (mm_u8 *)sc.regs + SERCOM_INTFLAG, sizeof(flags));
    if (flags != (mm_u16)(INTFLAG_DRE | INTFLAG_RXC)) return 1;

    return 0;
}

static int test_spi_intflag_w1c(void)
{
    struct sercom_inst sc;
    mm_u16 flags = (mm_u16)(INTFLAG_DRE | INTFLAG_TXC | INTFLAG_RXC);

    memset(&sc, 0, sizeof(sc));
    sc.regs[SERCOM_CTRLA / 4u] = (CTRLA_MODE_SPI << CTRLA_MODE_SHIFT);
    memcpy((mm_u8 *)sc.regs + SERCOM_INTFLAG, &flags, sizeof(flags));

    if (!spi_write(&sc, SERCOM_INTFLAG, 2u, INTFLAG_RXC | INTFLAG_TXC)) return 1;
    memcpy(&flags, (mm_u8 *)sc.regs + SERCOM_INTFLAG, sizeof(flags));
    if (flags != (mm_u16)INTFLAG_DRE) return 1;

    return 0;
}

int main(void)
{
    if (test_usart_intflag_w1c() != 0) {
        printf("FAIL: usart_intflag_w1c\n");
        return 1;
    }
    printf("PASS: usart_intflag_w1c\n");

    if (test_spi_intflag_w1c() != 0) {
        printf("FAIL: spi_intflag_w1c\n");
        return 1;
    }
    printf("PASS: spi_intflag_w1c\n");
    return 0;
}
