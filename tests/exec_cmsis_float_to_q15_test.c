/* m33mu -- ARMv8-M Emulator
 *
 * Regression test: arm_float_to_q15 produces correct results.
 *
 * Exercises the exact instruction sequence that arm-none-eabi-gcc -O2 emits for
 * the CMSIS-DSP arm_float_to_q15 scalar loop on Cortex-M33:
 *
 *   vldmia  r0!, {s15}                  ; load float
 *   vcvt.s32.f32  s15, s15, #15        ; float → fixed Q15 (VCVT_FIXED)
 *   vmov    r3, s15                     ; move bit-pattern to core register
 *   ssat    r3, #16, r3                 ; saturate to 16-bit signed
 *   strh.w  r3, [r1], #2               ; store result
 *
 * The VCVT_FIXED decoder had a bug (hw1>>18 and hw1>>16 always 0 for a 16-bit
 * operand) that caused every VCVT_FIXED to execute as fixed→float instead of
 * float→fixed.  This test catches that class of decoder error.
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

static mm_u32 f32_bits(float f) { union { float f; mm_u32 u; } v; v.f = f; return v.u; }

static mm_bool stub_handle_pc_write(struct mm_cpu *c, struct mm_memmap *m,
                                    struct mm_scs *s, mm_u32 v,
                                    mm_u8 *itp, mm_u8 *itr, mm_u8 *itc)
{ (void)c;(void)m;(void)s;(void)v;(void)itp;(void)itr;(void)itc; return MM_TRUE; }
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

/* Decode a 32-bit Thumb instruction and execute it once. */
static int run_insn(struct setup *s, mm_u32 insn32)
{
    memset(&s->fetch, 0, sizeof(s->fetch));
    s->fetch.insn = insn32;
    s->fetch.len = 4u;
    s->dec = mm_decode_t32(&s->fetch);
    if (s->dec.undefined) {
        printf("UNDEFINED insn=0x%08lx\n", (unsigned long)insn32);
        return 1;
    }
    if (mm_execute_decoded(&s->ctx) != MM_EXEC_OK) {
        printf("EXEC_FAIL insn=0x%08lx kind=%u\n",
               (unsigned long)insn32, (unsigned)s->dec.kind);
        return 1;
    }
    return 0;
}

/*
 * vcvt.s32.f32  s15, s15, #15
 *
 * Encoding: 0xEEFE7AE8
 *   hw1 = 0xEEFE  (insn[18]=1 → to_fixed, insn[16]=0 → signed)
 *   hw2 = 0x7AE8  (sf=1 → 32-bit, imm5=17 → frac_bits=15)
 *
 * Expected imm packed field: to_float=0, unsigned=0, sx32=1, frac_bits=15
 *   = 0 | 0 | 4 | (15<<3) = 0x7C
 */
static int test_vcvt_fixed_decode(void)
{
    struct mm_fetch_result fetch;
    struct mm_decoded dec;
    mm_u32 expected_imm = 0x7Cu;   /* to_float=0,unsigned=0,sx32=1,frac_bits=15 */
    mm_u32 to_float, unsigned_op, sx32, frac_bits;

    memset(&fetch, 0, sizeof(fetch));
    fetch.insn = 0xEEFE7AE8u;
    fetch.len = 4u;
    dec = mm_decode_t32(&fetch);

    if (dec.kind != MM_OP_VCVT_FIXED || dec.undefined) {
        printf("vcvt_decode: kind=%u (expected MM_OP_VCVT_FIXED=%u) undef=%d\n",
               (unsigned)dec.kind, (unsigned)MM_OP_VCVT_FIXED, (int)dec.undefined);
        return 1;
    }
    if (dec.imm != expected_imm) {
        to_float    = dec.imm & 1u;
        unsigned_op = (dec.imm >> 1) & 1u;
        sx32        = (dec.imm >> 2) & 1u;
        frac_bits   = (dec.imm >> 3) & 0x1fu;
        printf("vcvt_decode: imm=0x%08lx expected=0x%08lx\n"
               "  to_float=%u (exp 0)  unsigned=%u (exp 0)  sx32=%u (exp 1)  frac_bits=%u (exp 15)\n",
               (unsigned long)dec.imm, (unsigned long)expected_imm,
               (unsigned)to_float, (unsigned)unsigned_op, (unsigned)sx32, (unsigned)frac_bits);
        return 1;
    }
    return 0;
}

/*
 * Run the full arm_float_to_q15 instruction sequence for one sample:
 *   s15 = input_float
 *   vcvt.s32.f32 s15, s15, #15   (0xEEFE7AE8)
 *   vmov r3, s15                  (0xEE173A90)
 *   ssat r3, #16, r3              (0xF303030F)
 * Returns the value in r3 (the Q15 result before saturation clamp).
 *
 * Note: VCVT_FIXED already saturates s32 to INT32_MIN/MAX; SSAT then clamps
 * to 16-bit range.  For arm_float_to_q15 the only tricky case is -1.0 → -32768
 * which must NOT be clamped further by SSAT (it's exactly at the boundary).
 */
static int run_one_q15(float input, mm_i32 *result_out, const char *name)
{
    struct setup s;

    init_setup(&s);
    s.cpu.s[15] = f32_bits(input);

    /* vcvt.s32.f32 s15, s15, #15 */
    if (run_insn(&s, 0xEEFE7AE8u)) { printf("%s: vcvt failed\n", name); return 1; }

    /* vmov r3, s15 */
    if (run_insn(&s, 0xEE173A90u)) { printf("%s: vmov failed\n", name); return 1; }

    /* ssat r3, #16, r3  — this is   F303 030F in Thumb-2
     * In m33mu insn = (hw1 << 16) | hw2 = 0xF303030F */
    if (run_insn(&s, 0xF303030Fu)) { printf("%s: ssat failed\n", name); return 1; }

    *result_out = (mm_i32)s.cpu.r[3];
    return 0;
}

static const struct {
    float    input;
    mm_i32   expected;
} g_cases[] = {
    { -1.0f,   -32768 },
    { -0.75f,  -24576 },
    { -0.5f,   -16384 },
    { -0.25f,   -8192 },
    {  0.0f,        0 },
    {  0.25f,    8192 },
    {  0.5f,    16384 },
    {  0.75f,   24576 },
    {  1.0f,    32767 },  /* saturated: 32768 → 32767 */
};

int main(void)
{
    int failures = 0;
    size_t i;

    /* 1. Check that the decoder extracts the right imm flags */
    if (test_vcvt_fixed_decode()) {
        printf("FAIL: vcvt.s32.f32 decoder extracts wrong imm bits\n");
        failures++;
    } else {
        printf("PASS: vcvt.s32.f32 decoder (imm=0x7C)\n");
    }

    /* 2. Check full pipeline for all nine arm_float_to_q15 inputs */
    for (i = 0; i < sizeof(g_cases) / sizeof(g_cases[0]); ++i) {
        char name[32];
        mm_i32 got;
        snprintf(name, sizeof(name), "q15[%zu](%.2f)", i, (double)g_cases[i].input);
        if (run_one_q15(g_cases[i].input, &got, name)) {
            failures++;
            continue;
        }
        if (got != g_cases[i].expected) {
            printf("FAIL %s: got=%d expected=%d\n", name, (int)got, (int)g_cases[i].expected);
            failures++;
        } else {
            printf("PASS %s: %d\n", name, (int)got);
        }
    }

    if (failures == 0) {
        printf("ALL PASS\n");
    } else {
        printf("%d FAILURE(S)\n", failures);
    }
    return failures != 0;
}
