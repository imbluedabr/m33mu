/* m33mu -- ARMv8-M Emulator
 *
 * Directed execution tests for byte-reverse and bitfield ops:
 * REV, REV16, REVSH, RBIT, UBFX, SBFX, BFI, BFC.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <string.h>

#include "m33mu/cpu.h"
#include "m33mu/decode.h"
#include "m33mu/execute.h"
#include "m33mu/fetch.h"
#include "m33mu/memmap.h"
#include "m33mu/scs.h"

/* ---- stub callbacks ---- */

static mm_bool stub_handle_pc_write(struct mm_cpu *cpu, struct mm_memmap *map,
                                    struct mm_scs *scs, mm_u32 value,
                                    mm_u8 *itp, mm_u8 *itr, mm_u8 *itc)
{
    (void)cpu; (void)map; (void)scs; (void)value;
    (void)itp; (void)itr; (void)itc;
    return MM_TRUE;
}

static mm_bool stub_mem(struct mm_cpu *c, struct mm_memmap *m, struct mm_scs *s,
                        mm_u32 pc, mm_u32 xp, mm_u32 a, mm_bool e)
{
    (void)c; (void)m; (void)s; (void)pc; (void)xp; (void)a; (void)e;
    return MM_FALSE;
}

static mm_bool stub_uf(struct mm_cpu *c, struct mm_memmap *m, struct mm_scs *s,
                       mm_u32 pc, mm_u32 xp, mm_u32 u)
{
    (void)c; (void)m; (void)s; (void)pc; (void)xp; (void)u;
    return MM_FALSE;
}

static mm_bool stub_ret(struct mm_cpu *c, struct mm_memmap *m, struct mm_scs *s,
                        mm_u32 r)
{
    (void)c; (void)m; (void)s; (void)r;
    return MM_FALSE;
}

static mm_bool stub_enter(struct mm_cpu *c, struct mm_memmap *m, struct mm_scs *s,
                          mm_u32 n, mm_u32 rp, mm_u32 xp)
{
    (void)c; (void)m; (void)s; (void)n; (void)rp; (void)xp;
    return MM_FALSE;
}

/* ---- harness setup ---- */

struct setup {
    struct mm_cpu       cpu;
    struct mm_memmap    map;
    struct mm_scs       scs;
    struct mm_gdb_stub  gdb;
    struct mm_fetch_result fetch;
    struct mm_decoded   dec;
    struct mm_execute_ctx ctx;
    struct mmio_region  regions[1];
    mm_u8  itp, itr, itc;
    mm_bool done;
};

static void init_setup(struct setup *s)
{
    memset(s, 0, sizeof(*s));
    mm_memmap_init(&s->map, s->regions, 1u);
    s->cpu.sec_state = MM_SECURE;
    s->cpu.mode      = MM_THREAD;
    s->dec.len       = 4u;
    s->ctx.cpu              = &s->cpu;
    s->ctx.map              = &s->map;
    s->ctx.scs              = &s->scs;
    s->ctx.gdb              = &s->gdb;
    s->ctx.fetch            = &s->fetch;
    s->ctx.dec              = &s->dec;
    s->ctx.it_pattern       = &s->itp;
    s->ctx.it_remaining     = &s->itr;
    s->ctx.it_cond          = &s->itc;
    s->ctx.done             = &s->done;
    s->ctx.handle_pc_write  = stub_handle_pc_write;
    s->ctx.raise_mem_fault  = stub_mem;
    s->ctx.raise_usage_fault = stub_uf;
    s->ctx.exc_return_unstack = stub_ret;
    s->ctx.enter_exception  = stub_enter;
}

/*
 * Build the d.raw field used by UBFX/SBFX/BFI/BFC.
 *
 * For UBFX/SBFX: pass (width - 1) as width_or_msb — execute adds +1.
 * For BFI/BFC:   pass msb (= lsb + width - 1) as width_or_msb.
 */
static mm_u32 raw_bf(mm_u8 lsb, mm_u8 width_or_msb)
{
    mm_u32 imm3 = ((mm_u32)lsb >> 2) & 0x7u;
    mm_u32 imm2 = (mm_u32)lsb & 0x3u;
    return (imm3 << 12) | (imm2 << 6) | ((mm_u32)width_or_msb & 0x1Fu);
}

/* ---- per-op helpers ---- */

/*
 * REV / REV16 / REVSH / RBIT: single-register (rm -> rd).
 * Uses r[2] as rm, r[0] as rd.
 */
static int run_rev(enum mm_op_kind kind, mm_u32 rm_val,
                   mm_u32 expected, const char *name)
{
    struct setup s;
    init_setup(&s);
    s.cpu.r[2]   = rm_val;
    s.dec.kind   = kind;
    s.dec.rd     = 0u;
    s.dec.rm     = 2u;
    if (mm_execute_decoded(&s.ctx) != MM_EXEC_OK || s.done) {
        printf("%s: exec failed/faulted\n", name);
        return 1;
    }
    if (s.cpu.r[0] != expected) {
        printf("%s: got=0x%08lx expected=0x%08lx\n",
               name,
               (unsigned long)s.cpu.r[0],
               (unsigned long)expected);
        return 1;
    }
    return 0;
}

/*
 * UBFX / SBFX: rn -> rd (zero/sign-extended bitfield extract).
 * Uses r[1] as rn, r[0] as rd.
 */
static int run_bfx(enum mm_op_kind kind, mm_u32 rn_val,
                   mm_u8 lsb, mm_u8 width,
                   mm_u32 expected, const char *name)
{
    struct setup s;
    init_setup(&s);
    s.cpu.r[1]   = rn_val;
    s.dec.kind   = kind;
    s.dec.rd     = 0u;
    s.dec.rn     = 1u;
    /* UBFX/SBFX: encode (width-1) in the low 5 bits */
    s.dec.raw    = raw_bf(lsb, (mm_u8)(width - 1u));
    if (mm_execute_decoded(&s.ctx) != MM_EXEC_OK || s.done) {
        printf("%s: exec failed/faulted\n", name);
        return 1;
    }
    if (s.cpu.r[0] != expected) {
        printf("%s: got=0x%08lx expected=0x%08lx\n",
               name,
               (unsigned long)s.cpu.r[0],
               (unsigned long)expected);
        return 1;
    }
    return 0;
}

/*
 * BFI: inserts bits[width-1:0] of rn into bits[lsb+width-1:lsb] of rd.
 * Uses r[0] as rd (pre-initialised to rd_init), r[1] as rn.
 */
static int run_bfi(mm_u32 rd_init, mm_u32 rn_val,
                   mm_u8 lsb, mm_u8 width,
                   mm_u32 expected, const char *name)
{
    struct setup s;
    mm_u8 msb = (mm_u8)(lsb + width - 1u);
    init_setup(&s);
    s.cpu.r[0]   = rd_init;
    s.cpu.r[1]   = rn_val;
    s.dec.kind   = MM_OP_BFI;
    s.dec.rd     = 0u;
    s.dec.rn     = 1u;
    /* BFI: encode msb in the low 5 bits */
    s.dec.raw    = raw_bf(lsb, msb);
    if (mm_execute_decoded(&s.ctx) != MM_EXEC_OK || s.done) {
        printf("%s: exec failed/faulted\n", name);
        return 1;
    }
    if (s.cpu.r[0] != expected) {
        printf("%s: got=0x%08lx expected=0x%08lx\n",
               name,
               (unsigned long)s.cpu.r[0],
               (unsigned long)expected);
        return 1;
    }
    return 0;
}

/*
 * BFC: clears bits[lsb+width-1:lsb] of rd.
 * Uses r[0] as rd (pre-initialised to rd_init).
 */
static int run_bfc(mm_u32 rd_init, mm_u8 lsb, mm_u8 width,
                   mm_u32 expected, const char *name)
{
    struct setup s;
    mm_u8 msb = (mm_u8)(lsb + width - 1u);
    init_setup(&s);
    s.cpu.r[0]   = rd_init;
    s.dec.kind   = MM_OP_BFC;
    s.dec.rd     = 0u;
    /* BFC: encode msb in the low 5 bits */
    s.dec.raw    = raw_bf(lsb, msb);
    if (mm_execute_decoded(&s.ctx) != MM_EXEC_OK || s.done) {
        printf("%s: exec failed/faulted\n", name);
        return 1;
    }
    if (s.cpu.r[0] != expected) {
        printf("%s: got=0x%08lx expected=0x%08lx\n",
               name,
               (unsigned long)s.cpu.r[0],
               (unsigned long)expected);
        return 1;
    }
    return 0;
}

/* ---- main ---- */

int main(void)
{
    /* ---- REV (byte-reverse word) ---- */
    if (run_rev(MM_OP_REV, 0x12345678u, 0x78563412u, "rev_basic"))     return 1;
    if (run_rev(MM_OP_REV, 0x00000000u, 0x00000000u, "rev_zero"))      return 1;
    if (run_rev(MM_OP_REV, 0xFF000000u, 0x000000FFu, "rev_hi_byte"))   return 1;

    /* ---- REV16 (byte-reverse each halfword) ---- */
    if (run_rev(MM_OP_REV16, 0x12345678u, 0x34127856u, "rev16_basic")) return 1;
    if (run_rev(MM_OP_REV16, 0xAABBCCDDu, 0xBBAADDCCu, "rev16_alt"))  return 1;

    /* ---- REVSH (byte-reverse lower halfword, sign-extend to 32) ----
     *
     * REVSH swaps the two bytes of Rm[15:0], then sign-extends bit 15.
     *
     * 0x00000080: lo=0x0080, bswap16=0x8000, bit15=1 -> sext 0xFFFF8000
     * 0xAAAA0011: lo=0x0011, bswap16=0x1100, bit15=0 -> 0x00001100
     * 0x00008000: lo=0x8000, bswap16=0x0080, bit15=0 -> 0x00000080
     */
    if (run_rev(MM_OP_REVSH, 0x00000080u, 0xFFFF8000u, "revsh_neg"))   return 1;
    if (run_rev(MM_OP_REVSH, 0xAAAA0011u, 0x00001100u, "revsh_pos"))   return 1;
    if (run_rev(MM_OP_REVSH, 0x00008000u, 0x00000080u, "revsh_zero"))  return 1;

    /* ---- RBIT (reverse bit order) ---- */
    if (run_rev(MM_OP_RBIT, 0x00000001u, 0x80000000u, "rbit_lsb"))     return 1;
    if (run_rev(MM_OP_RBIT, 0x80000000u, 0x00000001u, "rbit_msb"))     return 1;
    if (run_rev(MM_OP_RBIT, 0x12345678u, 0x1E6A2C48u, "rbit_pattern")) return 1;
    if (run_rev(MM_OP_RBIT, 0xFFFFFFFFu, 0xFFFFFFFFu, "rbit_all1"))    return 1;
    if (run_rev(MM_OP_RBIT, 0x00000000u, 0x00000000u, "rbit_zero"))    return 1;

    /* ---- UBFX (unsigned bitfield extract) ----
     *
     * 0xDEADBEEF bits[11:4]:
     *   0xDEADBEEF = ...1011_1110_1110_1111
     *   bits[11:4] = 0xEE
     *
     * 0xDEADBEEF bits[31:0] (width=32, lsb=0): full word
     * 0xFFFFFFFF bits[23:16] (lsb=16, width=8): 0xFF
     */
    if (run_bfx(MM_OP_UBFX, 0xDEADBEEFu, 4u,  8u,  0x000000EEu, "ubfx_mid"))  return 1;
    if (run_bfx(MM_OP_UBFX, 0xDEADBEEFu, 0u, 32u,  0xDEADBEEFu, "ubfx_full")) return 1;
    if (run_bfx(MM_OP_UBFX, 0xFFFFFFFFu, 16u, 8u,  0x000000FFu, "ubfx_hi"))   return 1;

    /* ---- SBFX (signed bitfield extract) ----
     *
     * 0xDEADBEEF bits[11:4] = 0xEE, bit7=1 -> sign-extend -> 0xFFFFFFEE
     * 0x00000050 bits[7:0]  = 0x50, bit7=0 -> no extension -> 0x00000050
     * 0xF0000000 bits[31:28]= 0xF,  bit3=1 -> sign-extend -> 0xFFFFFFFF
     */
    if (run_bfx(MM_OP_SBFX, 0xDEADBEEFu, 4u,  8u,  0xFFFFFFEEu, "sbfx_neg"))  return 1;
    if (run_bfx(MM_OP_SBFX, 0x00000050u, 0u,  8u,  0x00000050u, "sbfx_pos"))  return 1;
    if (run_bfx(MM_OP_SBFX, 0xF0000000u, 28u, 4u,  0xFFFFFFFFu, "sbfx_top"))  return 1;

    /* ---- BFI (bitfield insert) ----
     *
     * Insert 0xA5 into bits[11:4] of 0xFFFFFFFF:
     *   clear mask = ~(0xFF<<4) = 0xFFFFF00F
     *   OR (0xA5<<4)=0xA50 -> 0xFFFFFA5F
     *
     * Insert 0xFF into bits[31:24] of 0x00000000: 0xFF000000
     *
     * Insert 0x7 into bits[2:0] of 0xAABBCCDD:
     *   clear mask = 0xFFFFFFF8, OR 7 -> 0xAABBCCDF
     */
    if (run_bfi(0xFFFFFFFFu, 0x000000A5u,  4u, 8u,  0xFFFFFA5Fu, "bfi_mid"))   return 1;
    if (run_bfi(0x00000000u, 0x000000FFu, 24u, 8u,  0xFF000000u, "bfi_top"))   return 1;
    if (run_bfi(0xAABBCCDDu, 0x00000007u,  0u, 3u,  0xAABBCCDFu, "bfi_lsb"))  return 1;

    /* ---- BFC (bitfield clear) ----
     *
     * Clear bits[11:4] of 0xFFFFFFFF: 0xFFFFF00F
     * Clear bits[31:0]  of 0xFFFFFFFF: 0x00000000
     * Clear bits[23:16] of 0xAABBCCDD: 0xAA00CCDD
     */
    if (run_bfc(0xFFFFFFFFu,  4u,  8u, 0xFFFFF00Fu, "bfc_mid"))  return 1;
    if (run_bfc(0xFFFFFFFFu,  0u, 32u, 0x00000000u, "bfc_all"))  return 1;
    if (run_bfc(0xAABBCCDDu, 16u,  8u, 0xAA00CCDDu, "bfc_byte")) return 1;

    printf("exec_misc_thumb2_test: OK\n");
    return 0;
}
