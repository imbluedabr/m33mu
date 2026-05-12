/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * LPC55S69 CASPER test firmware.
 *
 * Tests RSA mod-exp via direct register programming of the CASPER peripheral.
 *
 * Test vectors (small primes for fast verification):
 *   n = 33, e = 3, d = 7, m = 4
 *   Encryption: ModExp(4, 3, 33) = 64 mod 33 = 31
 *   Decryption: ModExp(31, 7, 33) = 4 (round-trip must equal original)
 *
 * CASPER peripheral at 0x400A5000 (NS):
 *   CTRL0   0x00  - opcode (0x08 = MOD_EXP generic) and word count in [15:8]
 *   CTRL1   0x04  - reserved
 *   LOADER  0x08  - pointer to curve/modulus params (unused for RSA test)
 *   STATUS  0x0C  - BUSY=bit0, DONE=bit2, ERROR=bit3
 *   INTENSET 0x10 - interrupt enables
 *   AREG    0x20  - pointer to base (in RAM)
 *   BREG    0x24  - pointer to exponent (in RAM)
 *   CREG    0x28  - pointer to modulus (in RAM)
 *   RES0    0x30  - pointer to result (in RAM)
 *
 * On match (round-trip equals original): "CASPER TEST SUCCESSFUL" + bkpt 0x42.
 * On mismatch: error details + bkpt 0x77.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern uint32_t _sidata;
extern uint32_t _sdata;
extern uint32_t _edata;
extern uint32_t _sbss;
extern uint32_t _ebss;
extern uint32_t _estack;
extern void __libc_init_array(void);

/* -------------------------------------------------------------------------
 * FLEXCOMM0 USART for printf output
 * ------------------------------------------------------------------------- */
#define SYSCON_BASE             0x40000000u
#define AHBCLKCTRLSET1          (*(volatile uint32_t *)(SYSCON_BASE + 0x224u))
#define PRESETCTRLCLR1          (*(volatile uint32_t *)(SYSCON_BASE + 0x144u))
#define FC0_BASE                0x40086000u
#define FC0_PSELID              (*(volatile uint32_t *)(FC0_BASE + 0xFF8u))
#define FC0_CFG                 (*(volatile uint32_t *)(FC0_BASE + 0x000u))
#define FC0_FIFOCFG             (*(volatile uint32_t *)(FC0_BASE + 0xE00u))
#define FC0_FIFOSTAT            (*(volatile uint32_t *)(FC0_BASE + 0xE04u))
#define FC0_FIFOWR              (*(volatile uint32_t *)(FC0_BASE + 0xE20u))
#define FIFOSTAT_TXNOTFULL      (1u << 5)
#define CFG_ENABLE              (1u << 0)
#define CFG_DATALEN_8BIT        (1u << 2)
#define FIFOCFG_ENABLETX        (1u << 0)
#define FIFOCFG_ENABLERX        (1u << 1)
#define PSELID_PERSEL_USART     1u

/* -------------------------------------------------------------------------
 * SYSCON — clock/reset for CASPER
 * AHBCLKCTRL2 (0x40000208): bit 17 = CASPER clock  (per LPC55S69 UM)
 * PRESETCTRL2 (0x40000108): bit 17 = CASPER reset (0 = released)
 * ------------------------------------------------------------------------- */
#define AHBCLKCTRLSET2          (*(volatile uint32_t *)(SYSCON_BASE + 0x228u))
#define PRESETCTRLCLR2          (*(volatile uint32_t *)(SYSCON_BASE + 0x148u))
#define CASPER_CLK_BIT          17u

/* -------------------------------------------------------------------------
 * CASPER peripheral registers (NS alias 0x400A5000)
 * ------------------------------------------------------------------------- */
#define CASPER_BASE             0x400A5000u
#define CASPER_CTRL0            (*(volatile uint32_t *)(CASPER_BASE + 0x00u))
#define CASPER_CTRL1            (*(volatile uint32_t *)(CASPER_BASE + 0x04u))
#define CASPER_LOADER           (*(volatile uint32_t *)(CASPER_BASE + 0x08u))
#define CASPER_STATUS           (*(volatile uint32_t *)(CASPER_BASE + 0x0Cu))
#define CASPER_INTENSET         (*(volatile uint32_t *)(CASPER_BASE + 0x10u))
#define CASPER_AREG             (*(volatile uint32_t *)(CASPER_BASE + 0x20u))
#define CASPER_BREG             (*(volatile uint32_t *)(CASPER_BASE + 0x24u))
#define CASPER_CREG             (*(volatile uint32_t *)(CASPER_BASE + 0x28u))
#define CASPER_DREG             (*(volatile uint32_t *)(CASPER_BASE + 0x2Cu))
#define CASPER_RES0             (*(volatile uint32_t *)(CASPER_BASE + 0x30u))

/* STATUS bits */
#define STATUS_BUSY             (1u << 0)
#define STATUS_DONE             (1u << 2)
#define STATUS_ERROR            (1u << 3)

/* CTRL0 opcodes */
#define CASPER_OP_MODEXP_GENERIC 0x08u   /* RSA mod-exp */

/* -------------------------------------------------------------------------
 * Operand buffers in RAM (word-aligned).
 * We use 1 word (4 bytes) for the small test vectors.
 * The CASPER word count is encoded in CTRL0[15:8].
 * word_count = 1 → 32-bit operands.
 * ------------------------------------------------------------------------- */
#define CASPER_WORD_COUNT   1u   /* 1 x 32-bit word = 32-bit operands */

/* These are in RAM; CASPER reads/writes them via the pointers in AREG etc. */
static volatile uint8_t cas_base_buf[4 * CASPER_WORD_COUNT];
static volatile uint8_t cas_exp_buf[4 * CASPER_WORD_COUNT];
static volatile uint8_t cas_mod_buf[4 * CASPER_WORD_COUNT];
static volatile uint8_t cas_res_buf[4 * CASPER_WORD_COUNT];

/* -------------------------------------------------------------------------
 * UART
 * ------------------------------------------------------------------------- */
static void uart_init(void)
{
    AHBCLKCTRLSET1 = (1u << 11u);
    PRESETCTRLCLR1 = (1u << 11u);
    FC0_PSELID = (FC0_PSELID & ~0x7u) | PSELID_PERSEL_USART;
    FC0_CFG    = CFG_ENABLE | CFG_DATALEN_8BIT;
    FC0_FIFOCFG = FIFOCFG_ENABLETX | FIFOCFG_ENABLERX;
}

void fc0_putc(char c)
{
    while ((FC0_FIFOSTAT & FIFOSTAT_TXNOTFULL) == 0u) { }
    FC0_FIFOWR = (uint32_t)(uint8_t)c;
}

/* -------------------------------------------------------------------------
 * CASPER clock enable
 * ------------------------------------------------------------------------- */
static void casper_clock_enable(void)
{
    AHBCLKCTRLSET2 = (1u << CASPER_CLK_BIT);
    PRESETCTRLCLR2 = (1u << CASPER_CLK_BIT);
}

/* -------------------------------------------------------------------------
 * Write a little-endian 32-bit value into a byte buffer.
 * CASPER convention: little-endian byte arrays in RAM.
 * ------------------------------------------------------------------------- */
static void write_le32(volatile uint8_t *buf, uint32_t val)
{
    buf[0] = (uint8_t)(val & 0xFFu);
    buf[1] = (uint8_t)((val >> 8)  & 0xFFu);
    buf[2] = (uint8_t)((val >> 16) & 0xFFu);
    buf[3] = (uint8_t)((val >> 24) & 0xFFu);
}

/* -------------------------------------------------------------------------
 * Read a little-endian 32-bit value from a byte buffer.
 * ------------------------------------------------------------------------- */
static uint32_t read_le32(const volatile uint8_t *buf)
{
    return (uint32_t)buf[0]
         | ((uint32_t)buf[1] << 8)
         | ((uint32_t)buf[2] << 16)
         | ((uint32_t)buf[3] << 24);
}

/* -------------------------------------------------------------------------
 * Wait for STATUS.DONE or STATUS.ERROR with timeout.
 * Returns 1 if DONE, 0 if ERROR or timeout.
 * ------------------------------------------------------------------------- */
static int casper_wait_done(void)
{
    uint32_t timeout = 0x100000u;
    uint32_t st;
    while (--timeout != 0u) {
        st = CASPER_STATUS;
        if (st & STATUS_DONE)  return 1;
        if (st & STATUS_ERROR) return 0;
    }
    return 0; /* timeout */
}

/* -------------------------------------------------------------------------
 * Run one CASPER mod-exp: result = base^exp mod modulus
 * All values are 32-bit (word_count = 1).
 * Returns the result, or 0xFFFFFFFF on error.
 * ------------------------------------------------------------------------- */
static uint32_t casper_modexp(uint32_t base, uint32_t exp, uint32_t modulus)
{
    /* Write operands into RAM buffers (little-endian) */
    write_le32(cas_base_buf, base);
    write_le32(cas_exp_buf,  exp);
    write_le32(cas_mod_buf,  modulus);
    write_le32(cas_res_buf,  0u);  /* clear result */

    /* Point CASPER registers at the RAM buffers */
    CASPER_AREG = (uint32_t)cas_base_buf;
    CASPER_BREG = (uint32_t)cas_exp_buf;
    CASPER_CREG = (uint32_t)cas_mod_buf;
    CASPER_RES0 = (uint32_t)cas_res_buf;

    /* Clear any previous status */
    CASPER_STATUS = STATUS_DONE | STATUS_ERROR;  /* W1C */

    /* Trigger: opcode 0x08 (MODEXP_GENERIC), word_count=1 in bits[15:8] */
    CASPER_CTRL0 = CASPER_OP_MODEXP_GENERIC | (CASPER_WORD_COUNT << 8);

    /* Wait for completion */
    if (!casper_wait_done()) {
        printf("CASPER: STATUS=0x%08lx after modexp\n",
               (unsigned long)CASPER_STATUS);
        return 0xFFFFFFFFu;
    }

    return read_le32(cas_res_buf);
}

/* -------------------------------------------------------------------------
 * Main
 * ------------------------------------------------------------------------- */
int main(void)
{
    uint32_t enc, dec;
    int all_pass = 1;

    uart_init();
    casper_clock_enable();

    printf("=== LPC55S69 CASPER test ===\n");

    /*
     * RSA round-trip test:
     *   n=33, e=3, d=7, m=4
     *   Enc = ModExp(4, 3, 33) = 64 mod 33 = 31
     *   Dec = ModExp(31, 7, 33) = 27512614111 mod 33 = 4
     */
    printf("Test: ModExp(4, 3, 33) expecting 31\n");
    enc = casper_modexp(4u, 3u, 33u);
    if (enc != 31u) {
        printf("FAIL: encrypt got %lu, expected 31\n", (unsigned long)enc);
        all_pass = 0;
    } else {
        printf("Encrypt: PASS (result=%lu)\n", (unsigned long)enc);
    }

    printf("Test: ModExp(31, 7, 33) expecting 4\n");
    dec = casper_modexp(31u, 7u, 33u);
    if (dec != 4u) {
        printf("FAIL: decrypt got %lu, expected 4\n", (unsigned long)dec);
        all_pass = 0;
    } else {
        printf("Decrypt: PASS (result=%lu)\n", (unsigned long)dec);
    }

    if (all_pass) {
        printf("CASPER TEST SUCCESSFUL\n");
        __asm volatile("bkpt #0x42");
    } else {
        printf("CASPER TEST FAILED\n");
        __asm volatile("bkpt #0x77");
    }
    while (1) {
        __asm volatile("wfi");
    }
}

void Reset_Handler(void)
{
    uint32_t *src;
    uint32_t *dst;

    src = &_sidata;
    for (dst = &_sdata; dst < &_edata; ) {
        *dst++ = *src++;
    }
    for (dst = &_sbss; dst < &_ebss; ) {
        *dst++ = 0u;
    }

    __libc_init_array();
    main();
}

void HardFault_Handler(void)
{
    printf("HARDFAULT\n");
    __asm volatile("bkpt #0x7e");
    while (1) { }
}
