/* m33mu -- ARMv8-M Emulator
 *
 * Tests for DSP parallel arithmetic instructions added for fidelity update:
 * SADD8/16, SSUB8/16, UADD8/16, USUB8/16, QADD8/16, QSUB8/16, UQADD8/16,
 * UQSUB8/16, SHADD8/16, SHSUB8/16, UHADD8/16, UHSUB8/16, SASX/SSAX/UASX/USAX
 * and the saturating/halving cross variants, SSAT16/USAT16, SEL, USAD8,
 * USADA8, SMUAD(X), SMUSD(X), SMLSLD(X).
 *
 * Both decode-side (against real assembler-emitted encodings) and execute-side
 * semantics are checked.  GE-flag updates verified for normal parallel adds.
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

static mm_bool stub_handle_pc_write(struct mm_cpu *cpu, struct mm_memmap *map,
                                    struct mm_scs *scs, mm_u32 value,
                                    mm_u8 *itp, mm_u8 *itr, mm_u8 *itc)
{ (void)cpu;(void)map;(void)scs;(void)value;(void)itp;(void)itr;(void)itc; return MM_TRUE; }
static mm_bool stub_mem(struct mm_cpu *c, struct mm_memmap *m, struct mm_scs *s,
                        mm_u32 pc, mm_u32 xp, mm_u32 a, mm_bool e)
{ (void)c;(void)m;(void)s;(void)pc;(void)xp;(void)a;(void)e; return MM_FALSE; }
static mm_bool stub_uf(struct mm_cpu *c, struct mm_memmap *m, struct mm_scs *s,
                       mm_u32 pc, mm_u32 xp, mm_u32 u)
{ (void)c;(void)m;(void)s;(void)pc;(void)xp;(void)u; return MM_FALSE; }
static mm_bool stub_ret(struct mm_cpu *c, struct mm_memmap *m, struct mm_scs *s, mm_u32 r)
{ (void)c;(void)m;(void)s;(void)r; return MM_FALSE; }
static mm_bool stub_enter(struct mm_cpu *c, struct mm_memmap *m, struct mm_scs *s,
                          mm_u32 n, mm_u32 rp, mm_u32 xp)
{ (void)c;(void)m;(void)s;(void)n;(void)rp;(void)xp; return MM_FALSE; }

struct setup {
    struct mm_cpu cpu;
    struct mm_memmap map;
    struct mm_scs scs;
    struct mm_gdb_stub gdb;
    struct mm_fetch_result fetch;
    struct mm_decoded dec;
    struct mm_execute_ctx ctx;
    struct mmio_region regions[1];
    mm_u8 itp, itr, itc;
    mm_bool done;
};

static void init_setup(struct setup *s)
{
    memset(s, 0, sizeof(*s));
    mm_memmap_init(&s->map, s->regions, 1u);
    s->cpu.sec_state = MM_SECURE;
    s->cpu.mode = MM_THREAD;
    s->dec.len = 4u;
    s->ctx.cpu = &s->cpu;
    s->ctx.map = &s->map;
    s->ctx.scs = &s->scs;
    s->ctx.gdb = &s->gdb;
    s->ctx.fetch = &s->fetch;
    s->ctx.dec = &s->dec;
    s->ctx.it_pattern = &s->itp;
    s->ctx.it_remaining = &s->itr;
    s->ctx.it_cond = &s->itc;
    s->ctx.done = &s->done;
    s->ctx.handle_pc_write = stub_handle_pc_write;
    s->ctx.raise_mem_fault = stub_mem;
    s->ctx.raise_usage_fault = stub_uf;
    s->ctx.exc_return_unstack = stub_ret;
    s->ctx.enter_exception = stub_enter;
}

/* Run a Rn/Rm two-operand DSP op; checks both rd and (optionally) GE flags. */
static int run_dsp(enum mm_op_kind kind, mm_u32 rn_val, mm_u32 rm_val,
                   mm_u32 expected, int check_ge, mm_u8 expected_ge,
                   const char *name)
{
    struct setup s;
    init_setup(&s);
    s.cpu.r[1] = rn_val;
    s.cpu.r[2] = rm_val;
    s.dec.kind = kind;
    s.dec.rd = 0u;
    s.dec.rn = 1u;
    s.dec.rm = 2u;
    if (mm_execute_decoded(&s.ctx) != MM_EXEC_OK || s.done) {
        printf("%s: exec failed\n", name);
        return 1;
    }
    if (s.cpu.r[0] != expected) {
        printf("%s: r0=0x%08lx expected=0x%08lx\n",
               name, (unsigned long)s.cpu.r[0], (unsigned long)expected);
        return 1;
    }
    if (check_ge && s.cpu.ge_flags != expected_ge) {
        printf("%s: ge=0x%x expected=0x%x\n",
               name, (unsigned)s.cpu.ge_flags, (unsigned)expected_ge);
        return 1;
    }
    return 0;
}

static int run_decode_check(mm_u32 insn, enum mm_op_kind expected,
                            const char *name)
{
    struct mm_fetch_result fetch;
    struct mm_decoded dec;
    memset(&fetch, 0, sizeof(fetch));
    fetch.insn = insn;
    fetch.len = 4u;
    dec = mm_decode_t32(&fetch);
    if (dec.kind != expected || dec.undefined) {
        printf("%s: kind=%d expected=%d undef=%d\n",
               name, (int)dec.kind, (int)expected, (int)dec.undefined);
        return 1;
    }
    return 0;
}

int main(void)
{
    /* ---- Decode: assembler-emitted encodings (r0,r1,r2) ---- */
    if (run_decode_check(0xfa81f002u, MM_OP_SADD8, "dec_sadd8")) return 1;
    if (run_decode_check(0xfac1f002u, MM_OP_SSUB8, "dec_ssub8")) return 1;
    if (run_decode_check(0xfa81f042u, MM_OP_UADD8, "dec_uadd8")) return 1;
    if (run_decode_check(0xfa81f012u, MM_OP_QADD8, "dec_qadd8")) return 1;
    if (run_decode_check(0xfa81f022u, MM_OP_SHADD8, "dec_shadd8")) return 1;
    if (run_decode_check(0xfa81f052u, MM_OP_UQADD8, "dec_uqadd8")) return 1;
    if (run_decode_check(0xfa81f062u, MM_OP_UHADD8, "dec_uhadd8")) return 1;
    if (run_decode_check(0xfa91f002u, MM_OP_SADD16, "dec_sadd16")) return 1;
    if (run_decode_check(0xfa91f042u, MM_OP_UADD16, "dec_uadd16")) return 1;
    if (run_decode_check(0xfaa1f002u, MM_OP_SASX, "dec_sasx")) return 1;
    if (run_decode_check(0xfae1f042u, MM_OP_USAX, "dec_usax")) return 1;
    if (run_decode_check(0xfaa1f082u, MM_OP_SEL, "dec_sel")) return 1;
    if (run_decode_check(0xf3210000u, MM_OP_SSAT16, "dec_ssat16")) return 1;
    if (run_decode_check(0xf3a10002u, MM_OP_USAT16, "dec_usat16")) return 1;
    if (run_decode_check(0xfb71f002u, MM_OP_USAD8, "dec_usad8")) return 1;
    if (run_decode_check(0xfb713002u, MM_OP_USADA8, "dec_usada8")) return 1;
    if (run_decode_check(0xfb21f002u, MM_OP_SMUAD, "dec_smuad")) return 1;
    if (run_decode_check(0xfb21f012u, MM_OP_SMUADX, "dec_smuadx")) return 1;
    if (run_decode_check(0xfb41f002u, MM_OP_SMUSD, "dec_smusd")) return 1;
    if (run_decode_check(0xfb41f012u, MM_OP_SMUSDX, "dec_smusdx")) return 1;
    if (run_decode_check(0xfbd201c3u, MM_OP_SMLSLD, "dec_smlsld")) return 1;
    if (run_decode_check(0xfbd201d3u, MM_OP_SMLSLDX, "dec_smlsldx")) return 1;

    /* ---- SADD8 / UADD8 + GE flags ----
     * Rn=0x01020304, Rm=0x10203040
     * Lane sums: 0x04+0x40=0x44, 0x03+0x30=0x33, 0x02+0x20=0x22, 0x01+0x10=0x11
     * All four >=0 → GE=0xF
     */
    if (run_dsp(MM_OP_SADD8, 0x01020304u, 0x10203040u, 0x11223344u, 1, 0xfu,
                "sadd8_pos_ge")) return 1;
    /* Lane underflow: -1 + 1 = 0 (still ≥0), -128 + -1 = -129 wraps to 0x7F lane,
     * but signed result is -129<0 → GE bit for that lane = 0.
     * Use Rn=0x80808080 (-128 each lane), Rm=0x01010101 → result 0x81818181, all negative
     */
    if (run_dsp(MM_OP_SADD8, 0x80808080u, 0x01010101u, 0x81818181u, 1, 0x0u,
                "sadd8_neg_ge")) return 1;

    /* UADD8: 0xC0+0x80 = 0x140 → carry; lane = 0x40, GE bit = 1 */
    if (run_dsp(MM_OP_UADD8, 0xc0c0c0c0u, 0x80808080u, 0x40404040u, 1, 0xfu,
                "uadd8_carry_ge")) return 1;
    /* 0x10+0x20=0x30 no carry → GE=0 */
    if (run_dsp(MM_OP_UADD8, 0x10101010u, 0x20202020u, 0x30303030u, 1, 0x0u,
                "uadd8_nocarry_ge")) return 1;

    /* ---- QADD8 / QSUB8 saturation ---- */
    /* 0x40+0x40=0x80 sat to +127 (0x7F); -128+(-128) sat to -128 (0x80) */
    if (run_dsp(MM_OP_QADD8, 0x40808040u, 0x40808040u, 0x7f80807fu, 0, 0,
                "qadd8_sat")) return 1;
    /* UQADD8: 0xFF+0x01=0x100 sat to 0xFF */
    if (run_dsp(MM_OP_UQADD8, 0xff010101u, 0x01ff0202u, 0xffff0303u, 0, 0,
                "uqadd8_sat")) return 1;
    /* UQSUB8: 0x10-0x20 sat to 0 */
    if (run_dsp(MM_OP_UQSUB8, 0x10101010u, 0x20202020u, 0x00000000u, 0, 0,
                "uqsub8_sat")) return 1;

    /* ---- SHADD8 halving signed ---- */
    /* 0x40+0x60=0xA0; >>1 (signed) = 0x50 */
    if (run_dsp(MM_OP_SHADD8, 0x40404040u, 0x60606060u, 0x50505050u, 0, 0,
                "shadd8_basic")) return 1;
    /* UHADD8: 0x80+0x80=0x100; >>1 = 0x80 */
    if (run_dsp(MM_OP_UHADD8, 0x80808080u, 0x80808080u, 0x80808080u, 0, 0,
                "uhadd8_basic")) return 1;

    /* ---- 16-bit parallel ---- */
    /* SADD16: GE flag is set per the unbounded signed sum (not the
     * 16-bit truncated result).  Use one positive lane sum and one
     * negative lane sum so GE shows the difference.
     * Rn=0xC0000100 (-16384, 256), Rm=0xC0000300 (-16384, 768)
     * lo: 256 + 768 = 1024 ≥0 → GE[1:0]=11
     * hi: -16384 + -16384 = -32768 <0 → GE[3:2]=00
     * Result: lo=0x0400, hi=0x8000 → 0x80000400
     */
    if (run_dsp(MM_OP_SADD16, 0xc0000100u, 0xc0000300u, 0x80000400u, 1, 0x3u,
                "sadd16_mixed_ge")) return 1;
    /* UADD16: 0x8000+0x9000=0x11000 carry → lo lane 0x1000, GE 0,1 set
     * 0x1000+0x2000=0x3000 no carry → GE 2,3 = 0  → GE = 0x3
     */
    if (run_dsp(MM_OP_UADD16, 0x10008000u, 0x20009000u, 0x30001000u, 1, 0x3u,
                "uadd16_lo_carry_ge")) return 1;

    /* QADD16 saturate: 0x7FFF + 0x7FFF = saturates to 0x7FFF (signed max) */
    if (run_dsp(MM_OP_QADD16, 0x7fff7fffu, 0x7fff7fffu, 0x7fff7fffu, 0, 0,
                "qadd16_sat_pos")) return 1;
    /* QSUB16: 0x8000 - 0x7FFF = -65535 saturates to -32768 (0x8000) */
    if (run_dsp(MM_OP_QSUB16, 0x80008000u, 0x7fff7fffu, 0x80008000u, 0, 0,
                "qsub16_sat_neg")) return 1;

    /* ---- Cross add-sub ----
     * SASX: Rd[hi] = Rn[hi] + Rm[lo]; Rd[lo] = Rn[lo] - Rm[hi]
     * Rn=0x00010002, Rm=0x00030004 → hi = 1+4=5; lo = 2-3 = -1 (0xFFFF)
     */
    if (run_dsp(MM_OP_SASX, 0x00010002u, 0x00030004u, 0x0005ffffu, 1, 0xcu,
                "sasx_basic")) return 1;
    /* SSAX: hi = Rn[hi] - Rm[lo]; lo = Rn[lo] + Rm[hi]
     * Rn=0x00040002, Rm=0x00030001 → hi = 4-1=3; lo = 2+3 = 5
     */
    if (run_dsp(MM_OP_SSAX, 0x00040002u, 0x00030001u, 0x00030005u, 1, 0xfu,
                "ssax_basic")) return 1;

    /* ---- SSAT16 ----
     * Sat to 8 bits signed: range -128..127.
     * Rn = 0x00ff0050 → lo=0x0050=80 (in range), hi=0x00ff=255 (>127, sat to 127=0x7F)
     * Wait: lo lane is bits[15:0]=0x0050; hi lane bits[31:16]=0x00ff.
     * Result: lo=0x0050, hi=0x007F → 0x007f0050
     */
    {
        struct setup s;
        init_setup(&s);
        s.cpu.r[1] = 0x00ff0050u;
        s.dec.kind = MM_OP_SSAT16;
        s.dec.rd = 0u; s.dec.rn = 1u;
        s.dec.imm = 8u;  /* 8 bits signed (-128..127) */
        if (mm_execute_decoded(&s.ctx) != MM_EXEC_OK) {
            printf("ssat16_basic: exec failed\n");
            return 1;
        }
        if (s.cpu.r[0] != 0x007f0050u) {
            printf("ssat16_basic: got=0x%08lx expected=0x007f0050\n",
                   (unsigned long)s.cpu.r[0]);
            return 1;
        }
        if (!s.cpu.q_flag) {
            printf("ssat16_basic: Q flag not set on saturation\n");
            return 1;
        }
    }

    /* USAT16: sat to 8 bits unsigned (0..255).
     * Rn = 0xffff0050 → lo=0x0050=80 in range; hi=0xffff=-1 signed → sat to 0
     * Expected: 0x00000050
     */
    {
        struct setup s;
        init_setup(&s);
        s.cpu.r[1] = 0xffff0050u;
        s.dec.kind = MM_OP_USAT16;
        s.dec.rd = 0u; s.dec.rn = 1u;
        s.dec.imm = 8u;  /* 8 bits unsigned (0..255) */
        if (mm_execute_decoded(&s.ctx) != MM_EXEC_OK) {
            printf("usat16_basic: exec failed\n");
            return 1;
        }
        if (s.cpu.r[0] != 0x00000050u) {
            printf("usat16_basic: got=0x%08lx expected=0x00000050\n",
                   (unsigned long)s.cpu.r[0]);
            return 1;
        }
    }

    /* ---- SEL: pick bytes based on GE flags ----
     * GE=0b1010 → byte 0 from Rm, byte 1 from Rn, byte 2 from Rm, byte 3 from Rn
     * Rn=0x11223344, Rm=0xAABBCCDD
     * → byte 0 = 0xDD (Rm), 1 = 0x33 (Rn), 2 = 0xBB (Rm), 3 = 0x11 (Rn)
     * = 0x11BB33DD
     */
    {
        struct setup s;
        init_setup(&s);
        s.cpu.ge_flags = 0xau;  /* 0b1010 */
        s.cpu.r[1] = 0x11223344u;
        s.cpu.r[2] = 0xaabbccddu;
        s.dec.kind = MM_OP_SEL;
        s.dec.rd = 0u; s.dec.rn = 1u; s.dec.rm = 2u;
        if (mm_execute_decoded(&s.ctx) != MM_EXEC_OK) {
            printf("sel_basic: exec failed\n");
            return 1;
        }
        if (s.cpu.r[0] != 0x11bb33ddu) {
            printf("sel_basic: got=0x%08lx expected=0x11bb33dd\n",
                   (unsigned long)s.cpu.r[0]);
            return 1;
        }
    }

    /* ---- USAD8 ----
     * Rn = 0x0a0b0c0d, Rm = 0x01020304
     * lane diffs: |13-4|=9, |12-3|=9, |11-2|=9, |10-1|=9 → sum = 36 (0x24)
     */
    if (run_dsp(MM_OP_USAD8, 0x0a0b0c0du, 0x01020304u, 0x24u, 0, 0,
                "usad8_basic")) return 1;

    /* USADA8 with Ra = 100 (0x64): sum + 0x64 = 0x88 */
    {
        struct setup s;
        init_setup(&s);
        s.cpu.r[1] = 0x0a0b0c0du;
        s.cpu.r[2] = 0x01020304u;
        s.cpu.r[3] = 0x64u;
        s.dec.kind = MM_OP_USADA8;
        s.dec.rd = 0u; s.dec.rn = 1u; s.dec.rm = 2u; s.dec.ra = 3u;
        if (mm_execute_decoded(&s.ctx) != MM_EXEC_OK) {
            printf("usada8_basic: exec failed\n");
            return 1;
        }
        if (s.cpu.r[0] != 0x88u) {
            printf("usada8_basic: got=0x%08lx expected=0x88\n",
                   (unsigned long)s.cpu.r[0]);
            return 1;
        }
    }

    /* ---- SMUAD ----
     * Rn = 0x00020003 (hi=2, lo=3), Rm = 0x00040005 (hi=4, lo=5)
     * SMUAD: 3*5 + 2*4 = 15 + 8 = 23
     */
    if (run_dsp(MM_OP_SMUAD, 0x00020003u, 0x00040005u, 23u, 0, 0,
                "smuad_basic")) return 1;
    /* SMUADX: 3*4 + 2*5 = 12 + 10 = 22 (cross) */
    if (run_dsp(MM_OP_SMUADX, 0x00020003u, 0x00040005u, 22u, 0, 0,
                "smuadx_basic")) return 1;
    /* SMUSD: 3*5 - 2*4 = 15 - 8 = 7 */
    if (run_dsp(MM_OP_SMUSD, 0x00020003u, 0x00040005u, 7u, 0, 0,
                "smusd_basic")) return 1;
    /* SMUSDX: 3*4 - 2*5 = 12 - 10 = 2 */
    if (run_dsp(MM_OP_SMUSDX, 0x00020003u, 0x00040005u, 2u, 0, 0,
                "smusdx_basic")) return 1;

    /* ---- SMLSLD ----
     * RdHi:RdLo + (Rn[lo]*Rm[lo] - Rn[hi]*Rm[hi])
     * Init RdHi=0, RdLo=100, Rn=0x00020003, Rm=0x00040005
     * Add (3*5 - 2*4) = 7. Result: 107.
     */
    {
        struct setup s;
        init_setup(&s);
        s.cpu.r[1] = 0x00020003u;
        s.cpu.r[2] = 0x00040005u;
        s.cpu.r[0] = 100u;  /* RdLo */
        s.cpu.r[3] = 0u;    /* RdHi */
        s.dec.kind = MM_OP_SMLSLD;
        s.dec.rd = 0u; s.dec.ra = 3u; s.dec.rn = 1u; s.dec.rm = 2u;
        if (mm_execute_decoded(&s.ctx) != MM_EXEC_OK) {
            printf("smlsld_basic: exec failed\n");
            return 1;
        }
        if (s.cpu.r[0] != 107u || s.cpu.r[3] != 0u) {
            printf("smlsld_basic: RdLo=0x%08lx RdHi=0x%08lx expected 107/0\n",
                   (unsigned long)s.cpu.r[0], (unsigned long)s.cpu.r[3]);
            return 1;
        }
    }

    printf("exec_dsp_parallel_test: OK\n");
    return 0;
}
