/* m33mu -- ARMv8-M Emulator
 *
 * Directed execution tests for scalar signed multiply instructions:
 *   SMULBB/BT/TB/TT, SMULWB/WT, SMLAWB/WT, SMMUL, SMMLA, SMMLS, SMMLSR.
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

/* ---------- stub callbacks -------------------------------------------- */

static mm_bool stub_handle_pc_write(struct mm_cpu *cpu, struct mm_memmap *map,
                                    struct mm_scs *scs, mm_u32 value,
                                    mm_u8 *itp, mm_u8 *itr, mm_u8 *itc)
{
    (void)cpu; (void)map; (void)scs; (void)value;
    (void)itp; (void)itr; (void)itc;
    return MM_TRUE;
}

static mm_bool stub_raise_mem_fault(struct mm_cpu *cpu, struct mm_memmap *map,
                                    struct mm_scs *scs, mm_u32 fault_pc,
                                    mm_u32 fault_xpsr, mm_u32 addr,
                                    mm_bool is_exec)
{
    (void)cpu; (void)map; (void)scs; (void)fault_pc;
    (void)fault_xpsr; (void)addr; (void)is_exec;
    return MM_FALSE;
}

static mm_bool stub_raise_usage_fault(struct mm_cpu *cpu, struct mm_memmap *map,
                                      struct mm_scs *scs, mm_u32 fault_pc,
                                      mm_u32 fault_xpsr, mm_u32 ufsr_bits)
{
    (void)cpu; (void)map; (void)scs; (void)fault_pc;
    (void)fault_xpsr; (void)ufsr_bits;
    return MM_FALSE;
}

static mm_bool stub_exc_return_unstack(struct mm_cpu *cpu, struct mm_memmap *map,
                                       struct mm_scs *scs, mm_u32 exc_ret)
{
    (void)cpu; (void)map; (void)scs; (void)exc_ret;
    return MM_FALSE;
}

static mm_bool stub_enter_exception(struct mm_cpu *cpu, struct mm_memmap *map,
                                    struct mm_scs *scs, mm_u32 exc_num,
                                    mm_u32 return_pc, mm_u32 xpsr_in)
{
    (void)cpu; (void)map; (void)scs; (void)exc_num;
    (void)return_pc; (void)xpsr_in;
    return MM_FALSE;
}

/* ---------- harness ---------------------------------------------------- */

struct setup {
    struct mm_cpu     cpu;
    struct mm_memmap  map;
    struct mm_scs     scs;
    struct mm_gdb_stub gdb;
    struct mm_fetch_result fetch;
    struct mm_decoded dec;
    struct mm_execute_ctx ctx;
    struct mmio_region regions[1];
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
    s->ctx.cpu             = &s->cpu;
    s->ctx.map             = &s->map;
    s->ctx.scs             = &s->scs;
    s->ctx.gdb             = &s->gdb;
    s->ctx.fetch           = &s->fetch;
    s->ctx.dec             = &s->dec;
    s->ctx.it_pattern      = &s->itp;
    s->ctx.it_remaining    = &s->itr;
    s->ctx.it_cond         = &s->itc;
    s->ctx.done            = &s->done;
    s->ctx.handle_pc_write    = stub_handle_pc_write;
    s->ctx.raise_mem_fault    = stub_raise_mem_fault;
    s->ctx.raise_usage_fault  = stub_raise_usage_fault;
    s->ctx.exc_return_unstack = stub_exc_return_unstack;
    s->ctx.enter_exception    = stub_enter_exception;
}

/* ---------- SMULBB helper --------------------------------------------- */
/*
 * Runs MM_OP_SMULBB with the given halfword-select imm (0=BB,1=BT,2=TB,3=TT).
 * Rd=r0, Rn=r1, Rm=r2.
 */
static int run_smulbb(mm_u8 xy, mm_u32 rn, mm_u32 rm, mm_u32 expected,
                      const char *name)
{
    struct setup s;
    init_setup(&s);
    s.cpu.q_flag = MM_FALSE;
    s.cpu.r[1]  = rn;
    s.cpu.r[2]  = rm;
    s.dec.kind  = MM_OP_SMULBB;
    s.dec.rd    = 0u;
    s.dec.rn    = 1u;
    s.dec.rm    = 2u;
    s.dec.imm   = xy;
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

/* ---------- SMULWB/WT / SMLAWB/WT helper ------------------------------ */
/*
 * For SMULWB/WT: ra is ignored (set 0).
 * For SMLAWB/WT: ra contributes to the accumulate and may set q_flag.
 * Rd=r0, Rn=r1, Rm=r2, Ra=r3.
 */
static int run_smulw(enum mm_op_kind kind, mm_u32 rn, mm_u32 rm, mm_u32 ra,
                     mm_u32 expected_rd, mm_bool expected_q,
                     const char *name)
{
    struct setup s;
    init_setup(&s);
    s.cpu.q_flag = MM_FALSE;
    s.cpu.r[1]  = rn;
    s.cpu.r[2]  = rm;
    s.cpu.r[3]  = ra;
    s.dec.kind  = kind;
    s.dec.rd    = 0u;
    s.dec.rn    = 1u;
    s.dec.rm    = 2u;
    s.dec.ra    = 3u;
    if (mm_execute_decoded(&s.ctx) != MM_EXEC_OK || s.done) {
        printf("%s: exec failed/faulted\n", name);
        return 1;
    }
    if (s.cpu.r[0] != expected_rd) {
        printf("%s: Rd got=0x%08lx expected=0x%08lx\n",
               name,
               (unsigned long)s.cpu.r[0],
               (unsigned long)expected_rd);
        return 1;
    }
    if (s.cpu.q_flag != expected_q) {
        printf("%s: q_flag got=%d expected=%d\n",
               name, (int)s.cpu.q_flag, (int)expected_q);
        return 1;
    }
    return 0;
}

/* ---------- SMMUL/SMMLA/SMMLS/SMMLSR helper --------------------------- */
/*
 * imm: used for SMMUL rounded (imm=1) vs unrounded (imm=0).
 *      For SMMLA/SMMLS/SMMLSR, imm is 0 (SMMLSR ignores imm; always rounds).
 * Rd=r0, Rn=r1, Rm=r2, Ra=r3.
 */
static int run_smm(enum mm_op_kind kind, mm_u32 rn, mm_u32 rm, mm_u32 ra,
                   mm_u32 imm, mm_u32 expected, const char *name)
{
    struct setup s;
    init_setup(&s);
    s.cpu.q_flag = MM_FALSE;
    s.cpu.r[1]  = rn;
    s.cpu.r[2]  = rm;
    s.cpu.r[3]  = ra;
    s.dec.kind  = kind;
    s.dec.rd    = 0u;
    s.dec.rn    = 1u;
    s.dec.rm    = 2u;
    s.dec.ra    = 3u;
    s.dec.imm   = imm;
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

/* ======================================================================= */

int main(void)
{
    /* ------------------------------------------------------------------ */
    /* SMULBB -- four halfword-select variants                             */
    /* Rn=0x00050003 (hi=5, lo=3), Rm=0x00070002 (hi=7, lo=2)            */
    /* ------------------------------------------------------------------ */
    /* imm=0 (BB): lo(Rn)*lo(Rm) = 3*2 = 6 */
    if (run_smulbb(0u, 0x00050003u, 0x00070002u, 0x00000006u, "smulbb_BB")) return 1;
    /* imm=1 (BT): lo(Rn)*hi(Rm) = 3*7 = 21 = 0x15 */
    if (run_smulbb(1u, 0x00050003u, 0x00070002u, 0x00000015u, "smulbb_BT")) return 1;
    /* imm=2 (TB): hi(Rn)*lo(Rm) = 5*2 = 10 = 0x0A */
    if (run_smulbb(2u, 0x00050003u, 0x00070002u, 0x0000000au, "smulbb_TB")) return 1;
    /* imm=3 (TT): hi(Rn)*hi(Rm) = 5*7 = 35 = 0x23 */
    if (run_smulbb(3u, 0x00050003u, 0x00070002u, 0x00000023u, "smulbb_TT")) return 1;

    /* Negative halfword: Rn=0x0000FFFF (lo=-1 signed), Rm=0x00000002 (lo=2)
     * BB: -1 * 2 = -2 = 0xFFFFFFFE */
    if (run_smulbb(0u, 0x0000FFFFu, 0x00000002u, 0xFFFFFFFEu, "smulbb_BB_neg")) return 1;

    /* ------------------------------------------------------------------ */
    /* SMULWB / SMULWT                                                     */
    /* product = sint32(Rn) * sint16(Rm.half); Rd = product >> 16          */
    /* ------------------------------------------------------------------ */
    /* SMULWB: Rn=0x10000000, Rm lo=4.  0x10000000*4=0x40000000 >>16=0x4000 */
    if (run_smulw(MM_OP_SMULWB, 0x10000000u, 0x00000004u, 0u,
                  0x00004000u, MM_FALSE, "smulwb_basic")) return 1;
    /* SMULWT: Rn=0x10000000, Rm hi=8.  0x10000000*8=0x80000000 >>16=0x8000 */
    if (run_smulw(MM_OP_SMULWT, 0x10000000u, 0x00080000u, 0u,
                  0x00008000u, MM_FALSE, "smulwt_basic")) return 1;

    /* ------------------------------------------------------------------ */
    /* SMLAWB / SMLAWT                                                     */
    /* ------------------------------------------------------------------ */
    /* SMLAWB no-overflow: same SMULWB result (0x4000) + Ra=10 = 0x400A    */
    if (run_smulw(MM_OP_SMLAWB, 0x10000000u, 0x00000004u, 10u,
                  0x0000400au, MM_FALSE, "smlawb_no_overflow")) return 1;

    /* SMLAWT overflow: Rn=0x40000000, Rm hi=4, Ra=0x7FFFFFFF
     * product = 0x40000000*4 = 0x100000000; >>16 = 0x10000
     * sum = 0x10000 + 0x7FFFFFFF = 0x8000FFFF  (overflows int32 → q_flag) */
    if (run_smulw(MM_OP_SMLAWT, 0x40000000u, 0x00040000u, 0x7FFFFFFFu,
                  0x8000FFFFu, MM_TRUE, "smlawt_overflow")) return 1;

    /* ------------------------------------------------------------------ */
    /* SMMUL / SMMULR                                                      */
    /* prod = sint32(Rn)*sint32(Rm); Rd = prod >> 32 [+ 0x80000000]        */
    /* ------------------------------------------------------------------ */
    /* SMMUL: Rn=0x10000000, Rm=0x10000000.
     * prod = 0x100000000000000; >>32 = 0x01000000 */
    if (run_smm(MM_OP_SMMUL, 0x10000000u, 0x10000000u, 0u, 0u,
                0x01000000u, "smmul_basic")) return 1;

    /* SMMULR (imm=1): Rn=0x00010000, Rm=0xFFFF8000 (-32768 signed).
     * prod = 0x10000 * -32768 = -2147483648 = 0xFFFFFFFF80000000 (int64).
     * Unrounded >>32 = 0xFFFFFFFF.
     * Rounded: 0xFFFFFFFF80000000 + 0x80000000 = 0x0000000000000000 >>32 = 0. */
    if (run_smm(MM_OP_SMMUL, 0x00010000u, 0xFFFF8000u, 0u, 1u,
                0x00000000u, "smmulr_rounding")) return 1;

    /* ------------------------------------------------------------------ */
    /* SMMLA                                                               */
    /* result = (Ra:00 + prod) >> 32                                       */
    /* ------------------------------------------------------------------ */
    /* SMMLA: Rn=2, Rm=3, Ra=1.
     * prod=6; (1<<32)+6 = 0x100000006; >>32 = 1 */
    if (run_smm(MM_OP_SMMLA, 2u, 3u, 1u, 0u,
                0x00000001u, "smmla_basic")) return 1;

    /* ------------------------------------------------------------------ */
    /* SMMLS                                                               */
    /* result = (Ra:00 - prod) >> 32                                       */
    /* ------------------------------------------------------------------ */
    /* SMMLS: Rn=2, Rm=3, Ra=1.
     * prod=6; (1<<32)-6 = 0x00000000FFFFFFFA (positive int64); >>32 = 0 */
    if (run_smm(MM_OP_SMMLS, 2u, 3u, 1u, 0u,
                0x00000000u, "smmls_basic")) return 1;

    /* ------------------------------------------------------------------ */
    /* SMMLSR                                                              */
    /* result = (Ra:00 - prod + 0x80000000) >> 32                         */
    /* ------------------------------------------------------------------ */
    /* SMMLSR: Rn=2, Rm=3, Ra=1.
     * 0xFFFFFFFA + 0x80000000 = 0x17FFFFFFA; >>32 = 1 */
    if (run_smm(MM_OP_SMMLSR, 2u, 3u, 1u, 0u,
                0x00000001u, "smmlsr_basic")) return 1;

    printf("exec_dsp_smul_test: OK\n");
    return 0;
}
