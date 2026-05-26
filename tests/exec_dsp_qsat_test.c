/* m33mu -- an ARMv8-M Emulator
 *
 * Copyright (C) 2026
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

#define INT32_MAX_U 0x7FFFFFFFu
#define INT32_MIN_U 0x80000000u

static mm_bool stub_handle_pc_write(struct mm_cpu *cpu,
                                    struct mm_memmap *map,
                                    struct mm_scs *scs,
                                    mm_u32 value,
                                    mm_u8 *it_pattern,
                                    mm_u8 *it_remaining,
                                    mm_u8 *it_cond)
{
    (void)cpu; (void)map; (void)scs; (void)value;
    (void)it_pattern; (void)it_remaining; (void)it_cond;
    return MM_TRUE;
}

static mm_bool stub_raise_mem_fault(struct mm_cpu *cpu,
                                    struct mm_memmap *map,
                                    struct mm_scs *scs,
                                    mm_u32 fault_pc,
                                    mm_u32 fault_xpsr,
                                    mm_u32 addr,
                                    mm_bool is_exec)
{
    (void)cpu; (void)map; (void)scs; (void)fault_pc;
    (void)fault_xpsr; (void)addr; (void)is_exec;
    return MM_FALSE;
}

static mm_bool stub_raise_usage_fault(struct mm_cpu *cpu,
                                      struct mm_memmap *map,
                                      struct mm_scs *scs,
                                      mm_u32 fault_pc,
                                      mm_u32 fault_xpsr,
                                      mm_u32 ufsr_bits)
{
    (void)cpu; (void)map; (void)scs; (void)fault_pc;
    (void)fault_xpsr; (void)ufsr_bits;
    return MM_FALSE;
}

static mm_bool stub_exc_return_unstack(struct mm_cpu *cpu,
                                       struct mm_memmap *map,
                                       struct mm_scs *scs,
                                       mm_u32 exc_ret)
{
    (void)cpu; (void)map; (void)scs; (void)exc_ret;
    return MM_FALSE;
}

static mm_bool stub_enter_exception(struct mm_cpu *cpu,
                                    struct mm_memmap *map,
                                    struct mm_scs *scs,
                                    mm_u32 exc_num,
                                    mm_u32 return_pc,
                                    mm_u32 xpsr_in)
{
    (void)cpu; (void)map; (void)scs; (void)exc_num;
    (void)return_pc; (void)xpsr_in;
    return MM_FALSE;
}

/* Shared state for all test cases. */
struct test_state {
    struct mm_cpu       cpu;
    struct mm_memmap    map;
    struct mm_scs       scs;
    struct mm_gdb_stub  gdb;
    struct mm_fetch_result fetch;
    struct mm_decoded   dec;
    struct mm_execute_ctx ctx;
    struct mmio_region  regions[1];
    mm_u8 it_pattern;
    mm_u8 it_remaining;
    mm_u8 it_cond;
    mm_bool done;
};

static void init_setup(struct test_state *s)
{
    memset(s, 0, sizeof(*s));
    mm_memmap_init(&s->map, s->regions, 1u);

    s->cpu.sec_state = MM_SECURE;
    s->cpu.mode      = MM_THREAD;
    s->dec.len       = 4u;
    s->dec.undefined = MM_FALSE;

    s->ctx.cpu             = &s->cpu;
    s->ctx.map             = &s->map;
    s->ctx.scs             = &s->scs;
    s->ctx.gdb             = &s->gdb;
    s->ctx.fetch           = &s->fetch;
    s->ctx.dec             = &s->dec;
    s->ctx.it_pattern      = &s->it_pattern;
    s->ctx.it_remaining    = &s->it_remaining;
    s->ctx.it_cond         = &s->it_cond;
    s->ctx.done            = &s->done;
    s->ctx.handle_pc_write     = stub_handle_pc_write;
    s->ctx.raise_mem_fault     = stub_raise_mem_fault;
    s->ctx.raise_usage_fault   = stub_raise_usage_fault;
    s->ctx.exc_return_unstack  = stub_exc_return_unstack;
    s->ctx.enter_exception     = stub_enter_exception;
}

/*
 * Run one saturating op: Rd=r0, Rn=r1 (value a), Rm=r2 (value b).
 * q_flag is preserved across calls unless the caller clears it.
 * Returns 0 on pass, 1 on failure.
 */
static int run_q(struct test_state *s,
                 enum mm_op_kind kind,
                 mm_u32 a, mm_u32 b,
                 mm_u32 expected_result,
                 mm_bool expected_q,
                 const char *name)
{
    s->cpu.r[1]  = a;
    s->cpu.r[2]  = b;
    s->dec.kind  = kind;
    s->dec.rd    = 0u;
    s->dec.rn    = 1u;
    s->dec.rm    = 2u;
    s->done      = MM_FALSE;

    if (mm_execute_decoded(&s->ctx) != MM_EXEC_OK) {
        printf("exec_dsp_qsat_test: %s: execution failed\n", name);
        return 1;
    }
    if (s->cpu.r[0] != expected_result) {
        printf("exec_dsp_qsat_test: %s: result mismatch got=0x%08lx want=0x%08lx\n",
               name,
               (unsigned long)s->cpu.r[0],
               (unsigned long)expected_result);
        return 1;
    }
    if (s->cpu.q_flag != expected_q) {
        printf("exec_dsp_qsat_test: %s: q_flag mismatch got=%d want=%d\n",
               name, (int)s->cpu.q_flag, (int)expected_q);
        return 1;
    }
    return 0;
}

int main(void)
{
    struct test_state s;
    init_setup(&s);

    /* --- QADD ---------------------------------------------------------------- */

    /* Case 1: 0x3FFFFFFF + 0x3FFFFFFF = 0x7FFFFFFE (1073741823+1073741823), no saturation */
    s.cpu.q_flag = MM_FALSE;
    if (run_q(&s, MM_OP_QADD, 0x3FFFFFFFu, 0x3FFFFFFFu,
              0x7FFFFFFEu, MM_FALSE, "QADD no-sat")) return 1;

    /* Case 2: 0x70000000 + 0x70000000 -> saturates to INT32_MAX */
    s.cpu.q_flag = MM_FALSE;
    if (run_q(&s, MM_OP_QADD, 0x70000000u, 0x70000000u,
              INT32_MAX_U, MM_TRUE, "QADD pos-sat")) return 1;

    /* Case 3: 0x80000000 + 0x80000000 (INT32_MIN + INT32_MIN) -> saturates to INT32_MIN */
    s.cpu.q_flag = MM_FALSE;
    if (run_q(&s, MM_OP_QADD, INT32_MIN_U, INT32_MIN_U,
              INT32_MIN_U, MM_TRUE, "QADD neg-sat")) return 1;

    /* --- QSUB ---------------------------------------------------------------- */

    /* Case 4: 0x7FFFFFFF - 0x80000000 (INT32_MAX - INT32_MIN) -> saturates to INT32_MAX */
    s.cpu.q_flag = MM_FALSE;
    if (run_q(&s, MM_OP_QSUB, INT32_MAX_U, INT32_MIN_U,
              INT32_MAX_U, MM_TRUE, "QSUB pos-sat")) return 1;

    /* Case 5: 0x80000000 - 0x00000001 (INT32_MIN - 1) -> saturates to INT32_MIN */
    s.cpu.q_flag = MM_FALSE;
    if (run_q(&s, MM_OP_QSUB, INT32_MIN_U, 0x00000001u,
              INT32_MIN_U, MM_TRUE, "QSUB neg-sat")) return 1;

    /* Case 6: 5 - 3 = 2, no saturation */
    s.cpu.q_flag = MM_FALSE;
    if (run_q(&s, MM_OP_QSUB, 5u, 3u,
              2u, MM_FALSE, "QSUB no-sat")) return 1;

    /* --- QDADD --------------------------------------------------------------- */

    /* Case 7: Rn=10, Rm=5 -> sat(10) = 10, 10+10 = 20, no sat */
    s.cpu.q_flag = MM_FALSE;
    if (run_q(&s, MM_OP_QDADD, 10u, 5u,
              20u, MM_FALSE, "QDADD no-sat")) return 1;

    /* Case 8: Rn=0, Rm=0x40000001 -> 2*Rm overflows to INT32_MAX (sat), 0+INT32_MAX=INT32_MAX */
    s.cpu.q_flag = MM_FALSE;
    if (run_q(&s, MM_OP_QDADD, 0u, 0x40000001u,
              INT32_MAX_U, MM_TRUE, "QDADD double-sat")) return 1;

    /* --- QDSUB --------------------------------------------------------------- */

    /* Case 9: Rn=20, Rm=5 -> sat(10) = 10, 20-10 = 10, no sat */
    s.cpu.q_flag = MM_FALSE;
    if (run_q(&s, MM_OP_QDSUB, 20u, 5u,
              10u, MM_FALSE, "QDSUB no-sat")) return 1;

    /* Case 10: Rn=0, Rm=0xC0000000 (=-1073741824)
     * doubled = -2147483648 = INT32_MIN (fits, no sat in doubling step)
     * 0 - INT32_MIN = +2147483648 -> saturates to INT32_MAX, q_flag=true */
    s.cpu.q_flag = MM_FALSE;
    if (run_q(&s, MM_OP_QDSUB, 0u, 0xC0000000u,
              INT32_MAX_U, MM_TRUE, "QDSUB sub-sat")) return 1;

    /* --- Q flag stickiness --------------------------------------------------- */

    /* Case 11: After a saturating op, run a non-saturating op; q_flag stays true */
    s.cpu.q_flag = MM_FALSE;
    /* First, trigger saturation */
    if (run_q(&s, MM_OP_QADD, 0x70000000u, 0x70000000u,
              INT32_MAX_U, MM_TRUE, "sticky: saturating op")) return 1;
    /* Now run non-saturating op without resetting q_flag */
    if (run_q(&s, MM_OP_QADD, 1u, 1u,
              2u, MM_TRUE, "sticky: q_flag persists")) return 1;

    printf("exec_dsp_qsat_test: OK\n");
    return 0;
}
