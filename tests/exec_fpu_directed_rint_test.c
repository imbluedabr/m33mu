/* m33mu -- ARMv8-M Emulator
 *
 * Tests for FPv5 directed-rounding VCVT (VCVTA/N/P/M) and VRINT
 * (VRINTA/N/P/M/Z/R/X) added for fidelity update.
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
{
    (void)cpu; (void)map; (void)scs; (void)value;
    (void)itp; (void)itr; (void)itc;
    return MM_TRUE;
}

static mm_bool stub_raise_mem_fault(struct mm_cpu *c, struct mm_memmap *m,
                                    struct mm_scs *s, mm_u32 pc, mm_u32 xp,
                                    mm_u32 a, mm_bool e)
{ (void)c;(void)m;(void)s;(void)pc;(void)xp;(void)a;(void)e; return MM_FALSE; }

static mm_bool stub_raise_usage_fault(struct mm_cpu *c, struct mm_memmap *m,
                                      struct mm_scs *s, mm_u32 pc, mm_u32 xp,
                                      mm_u32 ub)
{ (void)c;(void)m;(void)s;(void)pc;(void)xp;(void)ub; return MM_FALSE; }

static mm_bool stub_exc_return_unstack(struct mm_cpu *c, struct mm_memmap *m,
                                       struct mm_scs *s, mm_u32 r)
{ (void)c;(void)m;(void)s;(void)r; return MM_FALSE; }

static mm_bool stub_enter_exception(struct mm_cpu *c, struct mm_memmap *m,
                                    struct mm_scs *s, mm_u32 n, mm_u32 rp,
                                    mm_u32 xp)
{ (void)c;(void)m;(void)s;(void)n;(void)rp;(void)xp; return MM_FALSE; }

static int run_unary_fpu(enum mm_op_kind kind, float input, mm_u32 expected,
                         const char *name)
{
    struct mm_cpu cpu;
    struct mm_memmap map;
    struct mm_scs scs;
    struct mm_gdb_stub gdb;
    struct mm_fetch_result fetch;
    struct mm_decoded dec;
    struct mm_execute_ctx ctx;
    struct mmio_region regions[1];
    mm_u8 itp = 0, itr = 0, itc = 0;
    mm_bool done = MM_FALSE;

    memset(&cpu, 0, sizeof(cpu));
    memset(&map, 0, sizeof(map));
    memset(&scs, 0, sizeof(scs));
    memset(&gdb, 0, sizeof(gdb));
    memset(&fetch, 0, sizeof(fetch));
    memset(&dec, 0, sizeof(dec));
    memset(&ctx, 0, sizeof(ctx));
    memset(regions, 0, sizeof(regions));
    mm_memmap_init(&map, regions, 1u);

    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.s[1] = f32_to_u32(input);

    scs.fpu_present = MM_TRUE;
    scs.cpacr_s = 0x00f00000u;

    dec.kind = kind;
    dec.rd = 0u;
    dec.rm = 1u;
    dec.len = 4u;

    ctx.cpu = &cpu; ctx.map = &map; ctx.scs = &scs; ctx.gdb = &gdb;
    ctx.fetch = &fetch; ctx.dec = &dec;
    ctx.it_pattern = &itp; ctx.it_remaining = &itr; ctx.it_cond = &itc;
    ctx.done = &done;
    ctx.handle_pc_write = stub_handle_pc_write;
    ctx.raise_mem_fault = stub_raise_mem_fault;
    ctx.raise_usage_fault = stub_raise_usage_fault;
    ctx.exc_return_unstack = stub_exc_return_unstack;
    ctx.enter_exception = stub_enter_exception;

    if (mm_execute_decoded(&ctx) != MM_EXEC_OK) {
        printf("%s: execution failed\n", name);
        return 1;
    }
    if (done) {
        printf("%s: unexpected fault\n", name);
        return 1;
    }
    if (cpu.s[0] != expected) {
        printf("%s: got=0x%08lx expected=0x%08lx (input=%f)\n",
               name, (unsigned long)cpu.s[0], (unsigned long)expected,
               (double)input);
        return 1;
    }
    return 0;
}

/* Decode-side sanity: ensure the new patterns route to the new kinds. */
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
        printf("%s: decoded kind=%d (expected=%d) undef=%d\n",
               name, (int)dec.kind, (int)expected, (int)dec.undefined);
        return 1;
    }
    return 0;
}

int main(void)
{
    /* ---- Decode patterns wired up (real encodings from arm-none-eabi-as) ---- */
    /* vcvta.s32.f32 s0, s1 */
    if (run_decode_check(0xfebc0ae0u, MM_OP_VCVTA_S32_F32, "dec_vcvta_s32")) return 1;
    /* vcvta.u32.f32 s0, s1 */
    if (run_decode_check(0xfebc0a60u, MM_OP_VCVTA_U32_F32, "dec_vcvta_u32")) return 1;
    /* vcvtn.s32.f32 s0, s1 */
    if (run_decode_check(0xfebd0ae0u, MM_OP_VCVTN_S32_F32, "dec_vcvtn_s32")) return 1;
    /* vcvtp.s32.f32 s0, s1 */
    if (run_decode_check(0xfebe0ae0u, MM_OP_VCVTP_S32_F32, "dec_vcvtp_s32")) return 1;
    /* vcvtm.s32.f32 s0, s1 */
    if (run_decode_check(0xfebf0ae0u, MM_OP_VCVTM_S32_F32, "dec_vcvtm_s32")) return 1;
    /* vrinta.f32 s0, s1 */
    if (run_decode_check(0xfeb80a60u, MM_OP_VRINTA_F32, "dec_vrinta")) return 1;
    /* vrintn.f32 s0, s1 */
    if (run_decode_check(0xfeb90a60u, MM_OP_VRINTN_F32, "dec_vrintn")) return 1;
    /* vrintp.f32 s0, s1 */
    if (run_decode_check(0xfeba0a60u, MM_OP_VRINTP_F32, "dec_vrintp")) return 1;
    /* vrintm.f32 s0, s1 */
    if (run_decode_check(0xfebb0a60u, MM_OP_VRINTM_F32, "dec_vrintm")) return 1;
    /* vrintz.f32 s0, s1 */
    if (run_decode_check(0xeeb60ae0u, MM_OP_VRINTZ_F32, "dec_vrintz")) return 1;
    /* vrintr.f32 s0, s1 */
    if (run_decode_check(0xeeb60a60u, MM_OP_VRINTR_F32, "dec_vrintr")) return 1;
    /* vrintx.f32 s0, s1 */
    if (run_decode_check(0xeeb70a60u, MM_OP_VRINTX_F32, "dec_vrintx")) return 1;

    /* ---- VCVTA: round-to-nearest, ties away from zero ---- */
    if (run_unary_fpu(MM_OP_VCVTA_S32_F32, 0.5f, 1u, "vcvta_s32_0.5")) return 1;
    if (run_unary_fpu(MM_OP_VCVTA_S32_F32, -0.5f, 0xffffffffu, "vcvta_s32_-0.5")) return 1;
    if (run_unary_fpu(MM_OP_VCVTA_S32_F32, 1.5f, 2u, "vcvta_s32_1.5")) return 1;
    if (run_unary_fpu(MM_OP_VCVTA_S32_F32, -2.5f, 0xfffffffdu, "vcvta_s32_-2.5")) return 1;
    if (run_unary_fpu(MM_OP_VCVTA_U32_F32, 0.5f, 1u, "vcvta_u32_0.5")) return 1;
    if (run_unary_fpu(MM_OP_VCVTA_U32_F32, -0.5f, 0u, "vcvta_u32_-0.5_sat")) return 1;

    /* ---- VCVTN: round-to-nearest, ties to even ---- */
    if (run_unary_fpu(MM_OP_VCVTN_S32_F32, 0.5f, 0u, "vcvtn_s32_0.5_even")) return 1;
    if (run_unary_fpu(MM_OP_VCVTN_S32_F32, 1.5f, 2u, "vcvtn_s32_1.5_even")) return 1;
    if (run_unary_fpu(MM_OP_VCVTN_S32_F32, 2.5f, 2u, "vcvtn_s32_2.5_even")) return 1;
    if (run_unary_fpu(MM_OP_VCVTN_S32_F32, -1.5f, 0xfffffffeu, "vcvtn_s32_-1.5_even")) return 1;

    /* ---- VCVTP: round toward +infinity ---- */
    if (run_unary_fpu(MM_OP_VCVTP_S32_F32, 0.1f, 1u, "vcvtp_s32_0.1")) return 1;
    if (run_unary_fpu(MM_OP_VCVTP_S32_F32, -0.9f, 0u, "vcvtp_s32_-0.9")) return 1;
    if (run_unary_fpu(MM_OP_VCVTP_S32_F32, -1.5f, 0xffffffffu, "vcvtp_s32_-1.5")) return 1;
    if (run_unary_fpu(MM_OP_VCVTP_U32_F32, 0.001f, 1u, "vcvtp_u32_tiny")) return 1;

    /* ---- VCVTM: round toward -infinity ---- */
    if (run_unary_fpu(MM_OP_VCVTM_S32_F32, 0.9f, 0u, "vcvtm_s32_0.9")) return 1;
    if (run_unary_fpu(MM_OP_VCVTM_S32_F32, -0.1f, 0xffffffffu, "vcvtm_s32_-0.1")) return 1;
    if (run_unary_fpu(MM_OP_VCVTM_S32_F32, 2.99f, 2u, "vcvtm_s32_2.99")) return 1;
    if (run_unary_fpu(MM_OP_VCVTM_U32_F32, -0.5f, 0u, "vcvtm_u32_-0.5_sat")) return 1;

    /* ---- Saturation at int32 limits ---- */
    if (run_unary_fpu(MM_OP_VCVTA_S32_F32, 2147483648.0f, 0x7fffffffu,
                      "vcvta_s32_sat_max")) return 1;
    if (run_unary_fpu(MM_OP_VCVTM_S32_F32, -2147483904.0f, 0x80000000u,
                      "vcvtm_s32_sat_min")) return 1;
    if (run_unary_fpu(MM_OP_VCVTA_U32_F32, 4294967296.0f, 0xffffffffu,
                      "vcvta_u32_sat_max")) return 1;

    /* ---- NaN: VCVT family must return 0 ---- */
    if (run_unary_fpu(MM_OP_VCVTA_S32_F32, NAN, 0u, "vcvta_s32_nan")) return 1;
    if (run_unary_fpu(MM_OP_VCVTN_U32_F32, NAN, 0u, "vcvtn_u32_nan")) return 1;

    /* ---- VRINT: result is float-typed ---- */
    if (run_unary_fpu(MM_OP_VRINTA_F32, 0.5f, f32_to_u32(1.0f), "vrinta_0.5")) return 1;
    if (run_unary_fpu(MM_OP_VRINTA_F32, -0.5f, f32_to_u32(-1.0f), "vrinta_-0.5")) return 1;
    if (run_unary_fpu(MM_OP_VRINTN_F32, 0.5f, f32_to_u32(0.0f), "vrintn_0.5_even")) return 1;
    if (run_unary_fpu(MM_OP_VRINTN_F32, 2.5f, f32_to_u32(2.0f), "vrintn_2.5_even")) return 1;
    if (run_unary_fpu(MM_OP_VRINTP_F32, 0.1f, f32_to_u32(1.0f), "vrintp_0.1")) return 1;
    if (run_unary_fpu(MM_OP_VRINTM_F32, -0.1f, f32_to_u32(-1.0f), "vrintm_-0.1")) return 1;
    if (run_unary_fpu(MM_OP_VRINTZ_F32, 1.9f, f32_to_u32(1.0f), "vrintz_1.9")) return 1;
    if (run_unary_fpu(MM_OP_VRINTZ_F32, -1.9f, f32_to_u32(-1.0f), "vrintz_-1.9")) return 1;

    /* ---- VRINT preserves -0.0 sign correctly (float, not int) ---- */
    if (run_unary_fpu(MM_OP_VRINTZ_F32, -0.5f, f32_to_u32(-0.0f), "vrintz_-0.5_negzero")) return 1;

    printf("exec_fpu_directed_rint_test: OK\n");
    return 0;
}
