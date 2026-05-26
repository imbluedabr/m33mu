/* m33mu -- ARMv8-M Emulator
 *
 * Tests for FPv5 binary ops: VMAXNM/VMINNM/VSEL/VFMA/VFMS/VFNMA/VFNMS,
 * VNMUL/VNMLA/VNMLS.  Verifies both decode (against real assembler-emitted
 * encodings) and execution semantics.
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

static int run_binop(enum mm_op_kind kind, float a, float b, float dest_init,
                     mm_u32 expected, const char *name)
{
    struct setup s;
    init_setup(&s);
    s.cpu.s[1] = f32_to_u32(a);
    s.cpu.s[2] = f32_to_u32(b);
    s.cpu.s[0] = f32_to_u32(dest_init);
    s.dec.kind = kind;
    s.dec.rd = 0u;
    s.dec.rn = 1u;
    s.dec.rm = 2u;
    if (mm_execute_decoded(&s.ctx) != MM_EXEC_OK || s.done) {
        printf("%s: exec failed/faulted\n", name);
        return 1;
    }
    if (s.cpu.s[0] != expected) {
        union { float f; mm_u32 u; } e, g;
        e.u = expected; g.u = s.cpu.s[0];
        printf("%s: got=0x%08lx (%g) expected=0x%08lx (%g)\n",
               name,
               (unsigned long)g.u, (double)g.f,
               (unsigned long)e.u, (double)e.f);
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
        printf("%s: decoded kind=%d expected=%d undef=%d\n",
               name, (int)dec.kind, (int)expected, (int)dec.undefined);
        return 1;
    }
    return 0;
}

static int run_vsel(mm_u8 cond_sel, mm_u32 apsr_nzcv, float a, float b,
                    float expected, const char *name)
{
    struct setup s;
    init_setup(&s);
    s.cpu.xpsr = apsr_nzcv << 28;
    s.cpu.s[1] = f32_to_u32(a);
    s.cpu.s[2] = f32_to_u32(b);
    s.dec.kind = MM_OP_VSEL_F32;
    s.dec.rd = 0u;
    s.dec.rn = 1u;
    s.dec.rm = 2u;
    s.dec.imm = cond_sel;
    if (mm_execute_decoded(&s.ctx) != MM_EXEC_OK || s.done) {
        printf("%s: exec failed\n", name);
        return 1;
    }
    if (s.cpu.s[0] != f32_to_u32(expected)) {
        printf("%s: got=0x%08lx expected=%g\n",
               name, (unsigned long)s.cpu.s[0], (double)expected);
        return 1;
    }
    return 0;
}

int main(void)
{
    /* ---- Decode side: real encodings from arm-none-eabi-as ---- */
    if (run_decode_check(0xfe800a81u, MM_OP_VMAXNM_F32, "dec_vmaxnm")) return 1;
    if (run_decode_check(0xfe800ac1u, MM_OP_VMINNM_F32, "dec_vminnm")) return 1;
    if (run_decode_check(0xfe000a81u, MM_OP_VSEL_F32, "dec_vseleq")) return 1;
    if (run_decode_check(0xfe100a81u, MM_OP_VSEL_F32, "dec_vselvs")) return 1;
    if (run_decode_check(0xfe200a81u, MM_OP_VSEL_F32, "dec_vselge")) return 1;
    if (run_decode_check(0xfe300a81u, MM_OP_VSEL_F32, "dec_vselgt")) return 1;
    if (run_decode_check(0xeea00a81u, MM_OP_VFMA_F32, "dec_vfma")) return 1;
    if (run_decode_check(0xeea00ac1u, MM_OP_VFMS_F32, "dec_vfms")) return 1;
    if (run_decode_check(0xee900ac1u, MM_OP_VFNMA_F32, "dec_vfnma")) return 1;
    if (run_decode_check(0xee900a81u, MM_OP_VFNMS_F32, "dec_vfnms")) return 1;
    if (run_decode_check(0xee200ac1u, MM_OP_VNMUL_F32, "dec_vnmul")) return 1;
    if (run_decode_check(0xee100ac1u, MM_OP_VNMLA_F32, "dec_vnmla")) return 1;
    if (run_decode_check(0xee100a81u, MM_OP_VNMLS_F32, "dec_vnmls")) return 1;

    /* ---- VMAXNM / VMINNM ---- */
    if (run_binop(MM_OP_VMAXNM_F32, 1.5f, 2.5f, 0.0f, f32_to_u32(2.5f), "vmaxnm_2.5")) return 1;
    if (run_binop(MM_OP_VMAXNM_F32, NAN, 3.0f, 0.0f, f32_to_u32(3.0f), "vmaxnm_nan_a")) return 1;
    if (run_binop(MM_OP_VMAXNM_F32, 3.0f, NAN, 0.0f, f32_to_u32(3.0f), "vmaxnm_nan_b")) return 1;
    if (run_binop(MM_OP_VMINNM_F32, 1.5f, 2.5f, 0.0f, f32_to_u32(1.5f), "vminnm_1.5")) return 1;
    if (run_binop(MM_OP_VMINNM_F32, NAN, -3.0f, 0.0f, f32_to_u32(-3.0f), "vminnm_nan_a")) return 1;

    /* ---- VSEL: cond encoding 00=EQ, 01=VS, 10=GE, 11=GT ----
     * APSR NZCV: bit 3=N, 2=Z, 1=C, 0=V.
     */
    /* EQ: Z=1 → pick Sn */
    if (run_vsel(0u, 0x4u /*Z=1*/, 1.0f, 2.0f, 1.0f, "vsel_eq_z1")) return 1;
    if (run_vsel(0u, 0x0u /*Z=0*/, 1.0f, 2.0f, 2.0f, "vsel_eq_z0")) return 1;
    /* VS: V=1 → pick Sn */
    if (run_vsel(1u, 0x1u /*V=1*/, 1.0f, 2.0f, 1.0f, "vsel_vs_v1")) return 1;
    if (run_vsel(1u, 0x0u /*V=0*/, 1.0f, 2.0f, 2.0f, "vsel_vs_v0")) return 1;
    /* GE: N==V → pick Sn */
    if (run_vsel(2u, 0x0u /*N=0,V=0*/, 1.0f, 2.0f, 1.0f, "vsel_ge_eq")) return 1;
    if (run_vsel(2u, 0x9u /*N=1,V=1*/, 1.0f, 2.0f, 1.0f, "vsel_ge_neg")) return 1;
    if (run_vsel(2u, 0x8u /*N=1,V=0*/, 1.0f, 2.0f, 2.0f, "vsel_ge_ne")) return 1;
    /* GT: Z=0 && N==V */
    if (run_vsel(3u, 0x0u, 1.0f, 2.0f, 1.0f, "vsel_gt_0000")) return 1;
    if (run_vsel(3u, 0x4u, 1.0f, 2.0f, 2.0f, "vsel_gt_z1")) return 1;

    /* ---- VFMA/VFMS/VFNMA/VFNMS ---- */
    /* VFMA: Sd = Sd + (Sn * Sm).  Init Sd=10, Sn=2, Sm=3 → 16 */
    if (run_binop(MM_OP_VFMA_F32, 2.0f, 3.0f, 10.0f, f32_to_u32(16.0f), "vfma_basic")) return 1;
    /* VFMS: Sd = Sd + (-Sn * Sm).  10 + (-2*3) = 4 */
    if (run_binop(MM_OP_VFMS_F32, 2.0f, 3.0f, 10.0f, f32_to_u32(4.0f), "vfms_basic")) return 1;
    /* VFNMA: Sd = -Sd + (-Sn * Sm).  -10 + (-6) = -16 */
    if (run_binop(MM_OP_VFNMA_F32, 2.0f, 3.0f, 10.0f, f32_to_u32(-16.0f), "vfnma_basic")) return 1;
    /* VFNMS: Sd = -Sd + (Sn * Sm).  -10 + 6 = -4 */
    if (run_binop(MM_OP_VFNMS_F32, 2.0f, 3.0f, 10.0f, f32_to_u32(-4.0f), "vfnms_basic")) return 1;

    /* Fused multiply: tiny + (large * inverse-large) should preserve precision
     * unlike non-fused.  Here just check magnitude. */
    {
        struct setup s;
        float epsilon = 1e-30f;
        union { float f; mm_u32 u; } r;
        init_setup(&s);
        s.cpu.s[1] = f32_to_u32(1e15f);
        s.cpu.s[2] = f32_to_u32(1e15f);
        s.cpu.s[0] = f32_to_u32(epsilon);
        s.dec.kind = MM_OP_VFMA_F32;
        s.dec.rd = 0u; s.dec.rn = 1u; s.dec.rm = 2u;
        if (mm_execute_decoded(&s.ctx) != MM_EXEC_OK) {
            printf("vfma_precision: exec failed\n");
            return 1;
        }
        r.u = s.cpu.s[0];
        if (!(r.f > 9e29f && r.f < 1.1e30f)) {
            printf("vfma_precision: got=%g (expected ~1e30)\n", (double)r.f);
            return 1;
        }
    }

    /* ---- VNMUL/VNMLA/VNMLS ---- */
    /* VNMUL: -(Sn * Sm) = -6 */
    if (run_binop(MM_OP_VNMUL_F32, 2.0f, 3.0f, 0.0f, f32_to_u32(-6.0f), "vnmul_basic")) return 1;
    /* VNMLA: -Sd - (Sn * Sm) = -10 - 6 = -16 */
    if (run_binop(MM_OP_VNMLA_F32, 2.0f, 3.0f, 10.0f, f32_to_u32(-16.0f), "vnmla_basic")) return 1;
    /* VNMLS: -Sd + (Sn * Sm) = -10 + 6 = -4 */
    if (run_binop(MM_OP_VNMLS_F32, 2.0f, 3.0f, 10.0f, f32_to_u32(-4.0f), "vnmls_basic")) return 1;

    printf("exec_fpu_fpv5_binops_test: OK\n");
    return 0;
}
