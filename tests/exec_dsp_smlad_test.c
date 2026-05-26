/* m33mu -- ARMv8-M Emulator
 *
 * Tests for dual signed multiply families:
 * SMLAD/SMLADX  -- 32-bit accumulator, Q flag on overflow
 * SMLSD/SMLSDX  -- 32-bit accumulator (subtract second product), Q flag
 * SMLALD/SMLALDX -- 64-bit accumulator (RdHi:RdLo), no Q flag
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

/*
 * Run SMLAD or SMLSD (32-bit accumulator variants).
 * Registers: rd=0, rn=1, rm=2, ra=3.
 * q_flag is reset to MM_FALSE before execution unless reset_q is false.
 */
static int run_smlad(enum mm_op_kind kind, mm_u32 rn, mm_u32 rm, mm_u32 ra,
                     mm_u32 expected, mm_bool expected_q, int reset_q,
                     const char *name)
{
    struct setup s;
    init_setup(&s);
    if (!reset_q) {
        s.cpu.q_flag = MM_TRUE;  /* preserve sticky state */
    }
    s.cpu.r[1] = rn;
    s.cpu.r[2] = rm;
    s.cpu.r[3] = ra;
    s.dec.kind = kind;
    s.dec.rd = 0u;
    s.dec.rn = 1u;
    s.dec.rm = 2u;
    s.dec.ra = 3u;
    if (mm_execute_decoded(&s.ctx) != MM_EXEC_OK || s.done) {
        printf("%s: exec failed\n", name);
        return 1;
    }
    if (s.cpu.r[0] != expected) {
        printf("%s: rd=0x%08lx expected=0x%08lx\n",
               name, (unsigned long)s.cpu.r[0], (unsigned long)expected);
        return 1;
    }
    if (s.cpu.q_flag != expected_q) {
        printf("%s: q_flag=%d expected=%d\n",
               name, (int)s.cpu.q_flag, (int)expected_q);
        return 1;
    }
    return 0;
}

/*
 * Run SMLALD or SMLALDX (64-bit accumulator).
 * Registers: rd=0 (RdLo), ra=3 (RdHi), rn=1, rm=2.
 * No Q flag is set by these instructions.
 */
static int run_smlald(enum mm_op_kind kind, mm_u32 rn, mm_u32 rm,
                      mm_u32 rdlo_in, mm_u32 rdhi_in,
                      mm_u32 expected_lo, mm_u32 expected_hi,
                      const char *name)
{
    struct setup s;
    init_setup(&s);
    s.cpu.r[1] = rn;
    s.cpu.r[2] = rm;
    s.cpu.r[0] = rdlo_in;   /* RdLo */
    s.cpu.r[3] = rdhi_in;   /* RdHi */
    s.dec.kind = kind;
    s.dec.rd = 0u;   /* RdLo */
    s.dec.ra = 3u;   /* RdHi */
    s.dec.rn = 1u;
    s.dec.rm = 2u;
    if (mm_execute_decoded(&s.ctx) != MM_EXEC_OK || s.done) {
        printf("%s: exec failed\n", name);
        return 1;
    }
    if (s.cpu.r[0] != expected_lo || s.cpu.r[3] != expected_hi) {
        printf("%s: RdLo=0x%08lx RdHi=0x%08lx expected lo=0x%08lx hi=0x%08lx\n",
               name,
               (unsigned long)s.cpu.r[0], (unsigned long)s.cpu.r[3],
               (unsigned long)expected_lo, (unsigned long)expected_hi);
        return 1;
    }
    return 0;
}

int main(void)
{
    /* ================================================================
     * SMLAD -- prod1 = Rn.lo * Rm.lo, prod2 = Rn.hi * Rm.hi, +Ra
     * Rn=0x00020003 (hi=2, lo=3), Rm=0x00040005 (hi=4, lo=5)
     * prod1=3*5=15, prod2=2*4=8, sum=23
     * ================================================================ */
    if (run_smlad(MM_OP_SMLAD, 0x00020003u, 0x00040005u, 0u,
                  23u, MM_FALSE, 1, "smlad_basic")) return 1;

    /* Ra=1000: sum = 23 + 1000 = 1023 */
    if (run_smlad(MM_OP_SMLAD, 0x00020003u, 0x00040005u, 1000u,
                  1023u, MM_FALSE, 1, "smlad_with_ra")) return 1;

    /* ================================================================
     * SMLADX -- prod1 = Rn.lo * Rm.hi, prod2 = Rn.hi * Rm.lo (X = exchange Rm)
     * prod1=3*4=12, prod2=2*5=10, sum=22
     * ================================================================ */
    if (run_smlad(MM_OP_SMLADX, 0x00020003u, 0x00040005u, 0u,
                  22u, MM_FALSE, 1, "smladx_basic")) return 1;

    /* ================================================================
     * SMLAD overflow -> Q flag set
     * Rn=0x7FFF7FFF (hi=32767, lo=32767), Rm=0x7FFF7FFF (hi=32767, lo=32767)
     * prod1 = 32767*32767 = 1073676289
     * prod2 = 32767*32767 = 1073676289
     * prods_sum = 2147352578 (fits in i32, max is 2147483647)
     * Add Ra=0x7FFFFFFF (2147483647):
     * sum_i64 = 2147352578 + 2147483647 = 4294836225
     * 4294836225 > 2147483647 → overflow → Q=true
     * Rd = (mm_u32)4294836225 = 0xFFFE0001
     * ================================================================ */
    if (run_smlad(MM_OP_SMLAD, 0x7fff7fffu, 0x7fff7fffu, 0x7fffffffu,
                  0xfffe0001u, MM_TRUE, 1, "smlad_overflow_q")) return 1;

    /* Q flag stickiness: do a non-overflowing op WITHOUT resetting q_flag;
     * q_flag must remain MM_TRUE from the previous case.
     * (reset_q=0 means we start with q_flag=MM_TRUE and don't reset it) */
    if (run_smlad(MM_OP_SMLAD, 0x00020003u, 0x00040005u, 0u,
                  23u, MM_TRUE, 0, "smlad_q_sticky")) return 1;

    /* ================================================================
     * SMLSD -- diff = prod1 - prod2 + Ra
     * Rn=0x00020003, Rm=0x00040005
     * prod1=3*5=15, prod2=2*4=8, diff=15-8+0=7
     * ================================================================ */
    if (run_smlad(MM_OP_SMLSD, 0x00020003u, 0x00040005u, 0u,
                  7u, MM_FALSE, 1, "smlsd_basic")) return 1;

    /* ================================================================
     * SMLSDX -- prod1 = Rn.lo * Rm.hi, prod2 = Rn.hi * Rm.lo (exchange Rm)
     * prod1=3*4=12, prod2=2*5=10, diff=12-10=2
     * ================================================================ */
    if (run_smlad(MM_OP_SMLSDX, 0x00020003u, 0x00040005u, 0u,
                  2u, MM_FALSE, 1, "smlsdx_basic")) return 1;

    /* ================================================================
     * SMLSD overflow -> Q flag set
     * Rn=0x80000001 (hi=-32768 as i16, lo=1)
     * Rm=0x80007FFF (hi=-32768 as i16, lo=32767)
     * prod1 = (i32)1 * (i32)32767 = 32767
     * prod2 = (i32)(-32768) * (i32)(-32768) = 1073741824
     * Ra=0x80000000 = -2147483648 as i32
     * diff = 32767 - 1073741824 + (-2147483648)
     *      = 32767 - 1073741824 - 2147483648
     *      = -3221192705
     * -3221192705 < -2147483648 → overflow → Q=true
     * Rd = (mm_u32)(-3221192705LL & 0xFFFFFFFF) = (mm_u32)(0x40010FFFF) & 0xFFFF = ...
     * -3221192705 in hex:
     *   -3221192705 two's comp 64-bit = 0xFFFFFFFF_40007FFF
     *   low 32 bits = 0x40007FFF
     * ================================================================ */
    if (run_smlad(MM_OP_SMLSD, 0x80000001u, 0x80007fffu, 0x80000000u,
                  0x40007fffu, MM_TRUE, 1, "smlsd_overflow_q")) return 1;

    /* ================================================================
     * SMLALD -- 64-bit accumulator, no Q flag
     * Rn=0x00020003, Rm=0x00040005: prod1+prod2 = 23
     * Init: RdHi=0, RdLo=100 → sum = 100 + 23 = 123
     * ================================================================ */
    if (run_smlald(MM_OP_SMLALD, 0x00020003u, 0x00040005u,
                   100u, 0u, 123u, 0u, "smlald_basic")) return 1;

    /* ================================================================
     * SMLALD 64-bit carry across RdLo→RdHi boundary
     * RdLo=0xFFFFFFFF, RdHi=0, add 23
     * accum = 0x00000000_FFFFFFFF
     * sum   = 0x00000001_00000016  (0xFFFFFFFF + 23 = 0x100000016)
     * RdLo=0x00000016=22, RdHi=0x00000001=1
     * Wait: 0xFFFFFFFF = 4294967295, + 23 = 4294967318 = 0x100000016
     * low32 = 0x00000016 = 22, hi32 = 1
     * ================================================================ */
    if (run_smlald(MM_OP_SMLALD, 0x00020003u, 0x00040005u,
                   0xffffffffu, 0u, 0x00000016u, 1u, "smlald_carry")) return 1;

    /* ================================================================
     * SMLALDX -- exchange Rm halves
     * prod1 = Rn.lo * Rm.hi = 3*4 = 12
     * prod2 = Rn.hi * Rm.lo = 2*5 = 10
     * sum = 12 + 10 = 22
     * Init: RdHi=0, RdLo=0 → result: RdLo=22, RdHi=0
     * ================================================================ */
    if (run_smlald(MM_OP_SMLALDX, 0x00020003u, 0x00040005u,
                   0u, 0u, 22u, 0u, "smlaldx_basic")) return 1;

    printf("exec_dsp_smlad_test: OK\n");
    return 0;
}
