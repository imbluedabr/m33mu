/* m33mu -- ARMv8-M Emulator
 *
 * Tests for FPv5 half-precision and fixed-point VCVT instructions:
 *   VCVTB/VCVTT.F32.F16, VCVTB/VCVTT.F16.F32
 *   VCVT.F32.{S16,U16,S32,U32} #fbits
 *   VCVT.{S16,U16,S32,U32}.F32 #fbits
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <string.h>
#include <math.h>

#include "m33mu/cpu.h"
#include "m33mu/decode.h"
#include "m33mu/execute.h"
#include "m33mu/fetch.h"
#include "m33mu/memmap.h"
#include "m33mu/scs.h"

static mm_u32 f32_to_u32(float f)
{
    union { float f; mm_u32 u; } v;
    v.f = f;
    return v.u;
}

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
    s->scs.fpu_present = MM_TRUE;
    s->scs.cpacr_s = 0x00f00000u;
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

/* Run VCVTB/T.F32.F16: extract half from src, expand to single. */
static int run_half_to_single(enum mm_op_kind kind, mm_u32 src_word,
                              mm_u32 expected_single, const char *name)
{
    struct setup s;
    init_setup(&s);
    s.cpu.s[1] = src_word;
    s.dec.kind = kind;
    s.dec.rd = 0u; s.dec.rm = 1u;
    if (mm_execute_decoded(&s.ctx) != MM_EXEC_OK || s.done) {
        printf("%s: exec failed\n", name);
        return 1;
    }
    if (s.cpu.s[0] != expected_single) {
        printf("%s: got=0x%08lx expected=0x%08lx\n",
               name, (unsigned long)s.cpu.s[0], (unsigned long)expected_single);
        return 1;
    }
    return 0;
}

/* Run VCVTB/T.F16.F32: pack half result into top/bottom of Sd. */
static int run_single_to_half(enum mm_op_kind kind, mm_u32 sd_init,
                              mm_u32 sm_value, mm_u32 expected_word,
                              const char *name)
{
    struct setup s;
    init_setup(&s);
    s.cpu.s[0] = sd_init;
    s.cpu.s[1] = sm_value;
    s.dec.kind = kind;
    s.dec.rd = 0u; s.dec.rm = 1u;
    if (mm_execute_decoded(&s.ctx) != MM_EXEC_OK || s.done) {
        printf("%s: exec failed\n", name);
        return 1;
    }
    if (s.cpu.s[0] != expected_word) {
        printf("%s: got=0x%08lx expected=0x%08lx\n",
               name, (unsigned long)s.cpu.s[0], (unsigned long)expected_word);
        return 1;
    }
    return 0;
}

static int run_vcvt_fixed(mm_u32 imm_packed, mm_u32 src_word,
                          mm_u32 expected, const char *name)
{
    struct setup s;
    init_setup(&s);
    s.cpu.s[0] = src_word;
    s.dec.kind = MM_OP_VCVT_FIXED;
    s.dec.rd = 0u; s.dec.rm = 0u;
    s.dec.imm = imm_packed;
    if (mm_execute_decoded(&s.ctx) != MM_EXEC_OK || s.done) {
        printf("%s: exec failed\n", name);
        return 1;
    }
    if (s.cpu.s[0] != expected) {
        printf("%s: got=0x%08lx expected=0x%08lx\n",
               name, (unsigned long)s.cpu.s[0], (unsigned long)expected);
        return 1;
    }
    return 0;
}

int main(void)
{
    /* ---- Decode patterns (assembler-emitted) ---- */
    if (run_decode_check(0xeeb20a60u, MM_OP_VCVTB_F32_F16, "dec_vcvtb_f32_f16")) return 1;
    if (run_decode_check(0xeeb20ae0u, MM_OP_VCVTT_F32_F16, "dec_vcvtt_f32_f16")) return 1;
    if (run_decode_check(0xeeb30a60u, MM_OP_VCVTB_F16_F32, "dec_vcvtb_f16_f32")) return 1;
    if (run_decode_check(0xeeb30ae0u, MM_OP_VCVTT_F16_F32, "dec_vcvtt_f16_f32")) return 1;
    /* Fixed-point */
    if (run_decode_check(0xeeba0acfu, MM_OP_VCVT_FIXED, "dec_vcvt_fx_f32_s32_2")) return 1;
    if (run_decode_check(0xeebb0aedu, MM_OP_VCVT_FIXED, "dec_vcvt_fx_f32_u32_5")) return 1;
    if (run_decode_check(0xeebe0acfu, MM_OP_VCVT_FIXED, "dec_vcvt_fx_s32_f32_2")) return 1;
    if (run_decode_check(0xeebf0aedu, MM_OP_VCVT_FIXED, "dec_vcvt_fx_u32_f32_5")) return 1;
    if (run_decode_check(0xeeba0a47u, MM_OP_VCVT_FIXED, "dec_vcvt_fx_f32_s16_2")) return 1;

    /* ---- VCVTB.F32.F16: half 0x3C00 (1.0) -> single 0x3F800000 (1.0) ---- */
    if (run_half_to_single(MM_OP_VCVTB_F32_F16, 0x00003c00u, 0x3f800000u,
                           "vcvtb_f32_f16_one")) return 1;
    /* VCVTT.F32.F16: extract top half 0x3C00 from 0x3C000000 */
    if (run_half_to_single(MM_OP_VCVTT_F32_F16, 0x3c000000u, 0x3f800000u,
                           "vcvtt_f32_f16_one_top")) return 1;
    /* Half +inf (0x7C00) -> single +inf (0x7F800000) */
    if (run_half_to_single(MM_OP_VCVTB_F32_F16, 0x00007c00u, 0x7f800000u,
                           "vcvtb_f32_f16_inf")) return 1;
    /* Half -1.0 (0xBC00) -> single -1.0 (0xBF800000) */
    if (run_half_to_single(MM_OP_VCVTB_F32_F16, 0x0000bc00u, 0xbf800000u,
                           "vcvtb_f32_f16_minus_one")) return 1;
    /* Half +0 (0x0000) -> single +0 (0x00000000) */
    if (run_half_to_single(MM_OP_VCVTB_F32_F16, 0x00000000u, 0x00000000u,
                           "vcvtb_f32_f16_pos_zero")) return 1;
    /* Half -0 (0x8000) -> single -0 (0x80000000) */
    if (run_half_to_single(MM_OP_VCVTB_F32_F16, 0x00008000u, 0x80000000u,
                           "vcvtb_f32_f16_neg_zero")) return 1;

    /* ---- VCVTB.F16.F32: single 1.0 -> half 0x3C00 in bottom ----
     * Sd init = 0xDEAD0000 → result keeps top half, bottom = 0x3C00
     */
    if (run_single_to_half(MM_OP_VCVTB_F16_F32, 0xdead0000u, 0x3f800000u,
                           0xdead3c00u, "vcvtb_f16_f32_one_bot")) return 1;
    /* VCVTT.F16.F32: result in top half, bottom preserved */
    if (run_single_to_half(MM_OP_VCVTT_F16_F32, 0x0000dead, 0x3f800000u,
                           0x3c00dead, "vcvtt_f16_f32_one_top")) return 1;
    /* Overflow: single 1e20 -> +inf (0x7C00) */
    if (run_single_to_half(MM_OP_VCVTB_F16_F32, 0u, f32_to_u32(1e20f), 0x7c00u,
                           "vcvtb_f16_f32_overflow_inf")) return 1;

    /* ---- Round-trip: half -> single -> half preserves common values ---- */
    {
        mm_u16 vals[] = {0x3c00, 0x4000, 0xc000, 0x3555, 0x7c00, 0xfc00, 0x0000};
        size_t i;
        for (i = 0; i < sizeof(vals)/sizeof(vals[0]); ++i) {
            struct setup s;
            init_setup(&s);
            s.cpu.s[0] = 0u;
            s.cpu.s[1] = vals[i];
            s.dec.kind = MM_OP_VCVTB_F32_F16;
            s.dec.rd = 2u; s.dec.rm = 1u;
            if (mm_execute_decoded(&s.ctx) != MM_EXEC_OK) {
                printf("roundtrip_h2f_%zu: exec failed\n", i); return 1;
            }
            s.dec.kind = MM_OP_VCVTB_F16_F32;
            s.dec.rd = 3u; s.dec.rm = 2u;
            s.cpu.s[3] = 0u;
            if (mm_execute_decoded(&s.ctx) != MM_EXEC_OK) {
                printf("roundtrip_f2h_%zu: exec failed\n", i); return 1;
            }
            if ((s.cpu.s[3] & 0xffffu) != (mm_u32)vals[i]) {
                printf("roundtrip_%zu: 0x%04x -> 0x%08lx -> 0x%04lx\n",
                       i, vals[i], (unsigned long)s.cpu.s[2],
                       (unsigned long)(s.cpu.s[3] & 0xffffu));
                return 1;
            }
        }
    }

    /* ---- Fixed-point: F32 -> S32 with #fbits=2 ----
     * Input 1.5 → fixed = 1.5 * 4 = 6
     */
    {
        mm_u32 imm = 0u                  /* to-fixed */
                   | 0u                  /* signed */
                   | 4u                  /* 32-bit */
                   | (2u << 3);          /* frac_bits = 2 */
        if (run_vcvt_fixed(imm, f32_to_u32(1.5f), 6u, "fx_s32_f32_1.5_2")) return 1;
        /* Negative: -1.5 → -6 */
        if (run_vcvt_fixed(imm, f32_to_u32(-1.5f), (mm_u32)(-6), "fx_s32_f32_-1.5_2")) return 1;
        /* Saturation: huge value clamps to INT32_MAX */
        if (run_vcvt_fixed(imm, f32_to_u32(1e30f), 0x7fffffffu, "fx_s32_f32_sat")) return 1;
    }

    /* F32 -> U32 fixed #fbits=5: 1.5 → 1.5 * 32 = 48 */
    {
        mm_u32 imm = 0u | 2u | 4u | (5u << 3);
        if (run_vcvt_fixed(imm, f32_to_u32(1.5f), 48u, "fx_u32_f32_1.5_5")) return 1;
        /* Negative input saturates to 0 */
        if (run_vcvt_fixed(imm, f32_to_u32(-1.0f), 0u, "fx_u32_f32_neg_sat")) return 1;
    }

    /* S32 fixed -> F32 #fbits=2: 6 / 4 = 1.5 */
    {
        mm_u32 imm = 1u | 0u | 4u | (2u << 3);
        if (run_vcvt_fixed(imm, 6u, f32_to_u32(1.5f), "fx_f32_s32_6_2")) return 1;
        /* Negative: -6 → -1.5 */
        if (run_vcvt_fixed(imm, (mm_u32)(-6), f32_to_u32(-1.5f), "fx_f32_s32_-6_2")) return 1;
    }

    /* U32 fixed -> F32 #fbits=5: 48 / 32 = 1.5 */
    {
        mm_u32 imm = 1u | 2u | 4u | (5u << 3);
        if (run_vcvt_fixed(imm, 48u, f32_to_u32(1.5f), "fx_f32_u32_48_5")) return 1;
    }

    /* S16 fixed -> F32: low 16 bits of Sd interpreted as fixed s16.
     * Input lane = 0x0006 (=6), frac=2 → 1.5
     */
    {
        mm_u32 imm = 1u | 0u | 0u | (2u << 3);  /* to-float, signed, 16-bit, frac=2 */
        if (run_vcvt_fixed(imm, 0x00000006u, f32_to_u32(1.5f), "fx_f32_s16_6_2")) return 1;
        /* Negative: 0xFFFFFFFA (-6 as s16) → -1.5 */
        if (run_vcvt_fixed(imm, 0xfffffffau, f32_to_u32(-1.5f), "fx_f32_s16_-6_2")) return 1;
    }

    /* F32 -> S16 fixed: 1.5 * 4 = 6, packed into low 16 bits of Sd
     * Sd init = 0xdead0000, expected low half = 0x0006 → 0xdead0006
     */
    {
        struct setup s;
        mm_u32 imm = 0u | 0u | 0u | (2u << 3);
        init_setup(&s);
        s.cpu.s[0] = 0xdead0000u | f32_to_u32(1.5f); /* low 16 contains source */
        /* Need Sd to hold the f32 source AND the top half preserved.
         * Workaround: just verify saturation/result without preserving top half. */
        s.cpu.s[0] = f32_to_u32(1.5f);
        s.dec.kind = MM_OP_VCVT_FIXED;
        s.dec.rd = 0u; s.dec.imm = imm;
        if (mm_execute_decoded(&s.ctx) != MM_EXEC_OK) {
            printf("fx_s16_f32_1.5_2: exec failed\n"); return 1;
        }
        if ((s.cpu.s[0] & 0xffffu) != 6u) {
            printf("fx_s16_f32_1.5_2: low=0x%04lx expected=0x0006\n",
                   (unsigned long)(s.cpu.s[0] & 0xffffu));
            return 1;
        }
    }

    printf("exec_fpu_vcvt_half_fixed_test: OK\n");
    return 0;
}
