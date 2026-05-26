/* m33mu -- ARMv8-M Emulator
 *
 * Tests for basic FPv5 single-precision ops: VADD, VSUB, VMUL, VDIV, VMLA,
 * VMLS, VABS, VNEG, VSQRT, VCMP, VCMPE, VMOV_IMM, VMOV_SR, VMOV_RS.
 * Exercises execution semantics only (no decode/encoding checks).
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

/* Run a 3-register op: Sd = Sn op Sm.  rd=0, rn=1, rm=2. */
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

/* Run a unary op: Sd = op(Sm).  rd=0, rm=2. */
static int run_unary(enum mm_op_kind kind, float src, mm_u32 expected,
                     const char *name)
{
    struct setup s;
    init_setup(&s);
    s.cpu.s[2] = f32_to_u32(src);
    s.dec.kind = kind;
    s.dec.rd = 0u;
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

/* VCMP/VCMPE: compare Sd (rd=0) vs Sm (rm=2) or 0.0 (imm!=0).
 * Result in fpscr top 4 bits. */
static int run_vcmp(enum mm_op_kind kind, float sd_val, float sm_val,
                    mm_u32 imm, mm_u32 expected_nzcv, const char *name)
{
    struct setup s;
    init_setup(&s);
    s.cpu.s[0] = f32_to_u32(sd_val);
    s.cpu.s[2] = f32_to_u32(sm_val);
    s.dec.kind = kind;
    s.dec.rd = 0u;
    s.dec.rm = 2u;
    s.dec.imm = imm;
    if (mm_execute_decoded(&s.ctx) != MM_EXEC_OK || s.done) {
        printf("%s: exec failed/faulted\n", name);
        return 1;
    }
    if ((s.cpu.fpscr & 0xF0000000u) != expected_nzcv) {
        printf("%s: fpscr_nzcv=0x%08lx expected=0x%08lx\n",
               name,
               (unsigned long)(s.cpu.fpscr & 0xF0000000u),
               (unsigned long)expected_nzcv);
        return 1;
    }
    return 0;
}

int main(void)
{
    /* ---- VADD ---- */
    if (run_binop(MM_OP_VADD, 1.5f, 2.5f, 0.0f, f32_to_u32(4.0f), "vadd_basic")) return 1;
    if (run_binop(MM_OP_VADD, -1.0f, 1.0f, 0.0f, f32_to_u32(0.0f), "vadd_cancel")) return 1;

    /* ---- VSUB ---- */
    if (run_binop(MM_OP_VSUB, 5.0f, 3.0f, 0.0f, f32_to_u32(2.0f), "vsub_basic")) return 1;
    if (run_binop(MM_OP_VSUB, 1.0f, 1.0f, 0.0f, f32_to_u32(0.0f), "vsub_zero")) return 1;

    /* ---- VMUL ---- */
    if (run_binop(MM_OP_VMUL, 3.0f, 4.0f, 0.0f, f32_to_u32(12.0f), "vmul_basic")) return 1;
    if (run_binop(MM_OP_VMUL, -2.0f, 3.0f, 0.0f, f32_to_u32(-6.0f), "vmul_neg")) return 1;

    /* ---- VDIV ---- */
    if (run_binop(MM_OP_VDIV, 10.0f, 4.0f, 0.0f, f32_to_u32(2.5f), "vdiv_basic")) return 1;
    if (run_binop(MM_OP_VDIV, -6.0f, 2.0f, 0.0f, f32_to_u32(-3.0f), "vdiv_neg")) return 1;

    /* ---- VMLA: Sd = Sd + (Sn * Sm) ---- */
    /* 10 + (2 * 3) = 16 */
    if (run_binop(MM_OP_VMLA, 2.0f, 3.0f, 10.0f, f32_to_u32(16.0f), "vmla_basic")) return 1;
    /* 0 + (2 * 3) = 6 */
    if (run_binop(MM_OP_VMLA, 2.0f, 3.0f, 0.0f, f32_to_u32(6.0f), "vmla_zero_acc")) return 1;

    /* ---- VMLS: Sd = Sd - (Sn * Sm) ---- */
    /* 10 - (2 * 3) = 4 */
    if (run_binop(MM_OP_VMLS, 2.0f, 3.0f, 10.0f, f32_to_u32(4.0f), "vmls_basic")) return 1;
    /* 0 - (2 * 3) = -6 */
    if (run_binop(MM_OP_VMLS, 2.0f, 3.0f, 0.0f, f32_to_u32(-6.0f), "vmls_neg")) return 1;

    /* ---- VABS: Sd = |Sm| (clears sign bit) ---- */
    if (run_unary(MM_OP_VABS, -4.0f, f32_to_u32(4.0f), "vabs_neg")) return 1;
    if (run_unary(MM_OP_VABS, 4.0f, f32_to_u32(4.0f), "vabs_pos")) return 1;
    /* NaN: sign bit cleared, rest preserved */
    {
        mm_u32 nan_neg = f32_to_u32(NAN) | 0x80000000u;
        mm_u32 nan_pos = nan_neg & ~0x80000000u;
        struct setup s;
        init_setup(&s);
        s.cpu.s[2] = nan_neg;
        s.dec.kind = MM_OP_VABS;
        s.dec.rd = 0u;
        s.dec.rm = 2u;
        if (mm_execute_decoded(&s.ctx) != MM_EXEC_OK || s.done) {
            printf("vabs_nan: exec failed\n");
            return 1;
        }
        if (s.cpu.s[0] != nan_pos) {
            printf("vabs_nan: got=0x%08lx expected=0x%08lx\n",
                   (unsigned long)s.cpu.s[0], (unsigned long)nan_pos);
            return 1;
        }
    }

    /* ---- VNEG: Sd = -Sm ---- */
    if (run_unary(MM_OP_VNEG, 3.0f, f32_to_u32(-3.0f), "vneg_pos")) return 1;
    if (run_unary(MM_OP_VNEG, -3.0f, f32_to_u32(3.0f), "vneg_neg")) return 1;
    if (run_unary(MM_OP_VNEG, 0.0f, f32_to_u32(-0.0f), "vneg_zero")) return 1;

    /* ---- VSQRT: Sd = sqrt(Sm) ---- */
    if (run_unary(MM_OP_VSQRT, 9.0f, f32_to_u32(3.0f), "vsqrt_9")) return 1;
    if (run_unary(MM_OP_VSQRT, 0.0f, f32_to_u32(0.0f), "vsqrt_zero")) return 1;
    if (run_unary(MM_OP_VSQRT, 2.0f, f32_to_u32(sqrtf(2.0f)), "vsqrt_2")) return 1;

    /* ---- VCMP / VCMPE: result in fpscr top 4 bits.
     * equal:   Z=1,C=1 → 0x60000000
     * less:    N=1      → 0x80000000
     * greater: C=1      → 0x20000000
     * unorder: C=1,V=1  → 0x30000000
     */
    /* Sd == Sm */
    if (run_vcmp(MM_OP_VCMP, 1.0f, 1.0f, 0u, 0x60000000u, "vcmp_eq")) return 1;
    /* Sd < Sm */
    if (run_vcmp(MM_OP_VCMP, 1.0f, 2.0f, 0u, 0x80000000u, "vcmp_lt")) return 1;
    /* Sd > Sm */
    if (run_vcmp(MM_OP_VCMP, 3.0f, 2.0f, 0u, 0x20000000u, "vcmp_gt")) return 1;
    /* NaN involved → unordered */
    if (run_vcmp(MM_OP_VCMP, NAN, 1.0f, 0u, 0x30000000u, "vcmp_nan_sd")) return 1;
    if (run_vcmp(MM_OP_VCMP, 1.0f, NAN, 0u, 0x30000000u, "vcmp_nan_sm")) return 1;

    /* VCMPE with same semantics */
    if (run_vcmp(MM_OP_VCMPE, 5.0f, 5.0f, 0u, 0x60000000u, "vcmpe_eq")) return 1;
    if (run_vcmp(MM_OP_VCMPE, 1.0f, 5.0f, 0u, 0x80000000u, "vcmpe_lt")) return 1;

    /* VCMP Sd vs 0.0 (imm != 0) */
    if (run_vcmp(MM_OP_VCMP, 0.0f, 999.0f, 1u, 0x60000000u, "vcmp_vs0_eq")) return 1;
    if (run_vcmp(MM_OP_VCMP, -1.0f, 999.0f, 1u, 0x80000000u, "vcmp_vs0_lt")) return 1;
    if (run_vcmp(MM_OP_VCMP, 1.0f, 999.0f, 1u, 0x20000000u, "vcmp_vs0_gt")) return 1;

    /* ---- VMOV_IMM: Sd = fpu_vmov_imm_to_u32(imm8)
     * imm8=0x70: sign=0 exp=((7^4)+124)=127 mant=0 → 0x3f800000 = 1.0f
     * imm8=0xF0: sign=1 exp=127 mant=0 → 0xbf800000 = -1.0f
     * imm8=0x00: sign=0 exp=((0^4)+124)=128 mant=0 → 0x40000000 = 2.0f
     */
    {
        struct setup s;
        init_setup(&s);
        s.dec.kind = MM_OP_VMOV_IMM;
        s.dec.rd = 0u;
        s.dec.imm = 0x70u;
        if (mm_execute_decoded(&s.ctx) != MM_EXEC_OK || s.done) {
            printf("vmov_imm_1.0: exec failed\n");
            return 1;
        }
        if (s.cpu.s[0] != 0x3f800000u) {
            printf("vmov_imm_1.0: got=0x%08lx expected=0x3f800000\n",
                   (unsigned long)s.cpu.s[0]);
            return 1;
        }
    }
    {
        struct setup s;
        init_setup(&s);
        s.dec.kind = MM_OP_VMOV_IMM;
        s.dec.rd = 0u;
        s.dec.imm = 0xF0u;
        if (mm_execute_decoded(&s.ctx) != MM_EXEC_OK || s.done) {
            printf("vmov_imm_-1.0: exec failed\n");
            return 1;
        }
        if (s.cpu.s[0] != 0xbf800000u) {
            printf("vmov_imm_-1.0: got=0x%08lx expected=0xbf800000\n",
                   (unsigned long)s.cpu.s[0]);
            return 1;
        }
    }
    {
        struct setup s;
        init_setup(&s);
        s.dec.kind = MM_OP_VMOV_IMM;
        s.dec.rd = 0u;
        s.dec.imm = 0x00u;
        if (mm_execute_decoded(&s.ctx) != MM_EXEC_OK || s.done) {
            printf("vmov_imm_2.0: exec failed\n");
            return 1;
        }
        if (s.cpu.s[0] != 0x40000000u) {
            printf("vmov_imm_2.0: got=0x%08lx expected=0x40000000\n",
                   (unsigned long)s.cpu.s[0]);
            return 1;
        }
    }

    /* ---- VMOV_SR: Sd = Rn (VFP rd, ARM rn) ---- */
    {
        struct setup s;
        init_setup(&s);
        s.cpu.r[3] = 0xDEADBEEFu;
        s.dec.kind = MM_OP_VMOV_SR;
        s.dec.rd = 5u;
        s.dec.rn = 3u;
        if (mm_execute_decoded(&s.ctx) != MM_EXEC_OK || s.done) {
            printf("vmov_sr: exec failed\n");
            return 1;
        }
        if (s.cpu.s[5] != 0xDEADBEEFu) {
            printf("vmov_sr: got=0x%08lx expected=0xDEADBEEF\n",
                   (unsigned long)s.cpu.s[5]);
            return 1;
        }
    }

    /* ---- VMOV_RS: Rd = Sn (ARM rd, VFP rn) ---- */
    {
        struct setup s;
        init_setup(&s);
        s.cpu.s[7] = 0x12345678u;
        s.dec.kind = MM_OP_VMOV_RS;
        s.dec.rd = 2u;
        s.dec.rn = 7u;
        if (mm_execute_decoded(&s.ctx) != MM_EXEC_OK || s.done) {
            printf("vmov_rs: exec failed\n");
            return 1;
        }
        if (s.cpu.r[2] != 0x12345678u) {
            printf("vmov_rs: got=0x%08lx expected=0x12345678\n",
                   (unsigned long)s.cpu.r[2]);
            return 1;
        }
    }

    printf("exec_fpu_basic_test: OK\n");
    return 0;
}
