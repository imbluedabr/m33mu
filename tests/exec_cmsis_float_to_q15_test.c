/* m33mu -- ARMv8-M Emulator
 *
 * Regression test: arm_float_to_q15 produces correct results.
 *
 * Exercises the exact instruction sequence that arm-none-eabi-gcc -O2 emits for
 * the CMSIS-DSP arm_float_to_q15 scalar loop on Cortex-M33:
 *
 *   vldmia  r0!, {s15}                  ; load float, r0 += 4
 *   vcvt.s32.f32  s15, s15, #15        ; float → fixed Q15 (VCVT_FIXED)
 *   vmov    r3, s15                     ; move bit-pattern to core register
 *   ssat    r3, #16, r3                 ; saturate to 16-bit signed
 *   subs    r2, #1                      ; decrement loop counter
 *   strh.w  r3, [r1], #2               ; store result, r1 += 2
 *   bne.n   (back to vldmia)
 *
 * Tests:
 *  1. VCVT_FIXED decoder extracts correct to_float/unsigned_op bits.
 *  2. Per-sample computation: all 9 Q15 values correct (no memory).
 *  3. Full loop: 9 iterations with real RAM, verifies pointer advancement
 *     (r0 += 4 per VLDMIA, r1 += 2 per STRH) and correct output buffer.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <string.h>

#include "m33mu/cpu.h"
#include "m33mu/decode.h"
#include "m33mu/execute.h"
#include "m33mu/fetch.h"
#include "m33mu/mem.h"
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

/* Run a 16-bit Thumb instruction. */
static int run_insn16(struct setup *s, mm_u16 hw1_val)
{
    memset(&s->fetch, 0, sizeof(s->fetch));
    s->fetch.insn = (mm_u32)hw1_val;
    s->fetch.len = 2u;
    s->dec = mm_decode_t32(&s->fetch);
    if (s->dec.undefined) {
        printf("UNDEFINED insn16=0x%04x\n", (unsigned)hw1_val);
        return 1;
    }
    if (mm_execute_decoded(&s->ctx) != MM_EXEC_OK) {
        printf("EXEC_FAIL insn16=0x%04x kind=%u\n", (unsigned)hw1_val, (unsigned)s->dec.kind);
        return 1;
    }
    return 0;
}

static void write_le32(mm_u8 *buf, mm_u32 val)
{
    buf[0] = (mm_u8)(val & 0xffu);
    buf[1] = (mm_u8)((val >> 8) & 0xffu);
    buf[2] = (mm_u8)((val >> 16) & 0xffu);
    buf[3] = (mm_u8)((val >> 24) & 0xffu);
}

static mm_i16 read_le16(const mm_u8 *buf)
{
    mm_u16 v = (mm_u16)buf[0] | (mm_u16)((mm_u16)buf[1] << 8);
    return (mm_i16)v;
}

/*
 * Simulate the full arm_float_to_q15 loop (9 iterations) with real RAM.
 *
 * Loop body:
 *   0xECF07A01  vldmia r0!, {s15}         -- loads float, r0 += 4
 *   0xEEFE7AE8  vcvt.s32.f32 s15,s15,#15
 *   0xEE173A90  vmov r3, s15
 *   0xF303030F  ssat r3, #16, r3
 *   0x3A01      subs r2, #1              (16-bit)
 *   0xF8213B02  strh.w r3, [r1], #2       -- stores q15, r1 += 2
 *
 * Verifies: pointer advancement (r0 += 4, r1 += 2 each iteration) and
 * correct output buffer contents.
 */
static int test_float_to_q15_loop(void)
{
    mm_u8 ram_backing[512];
    const mm_u32 RAM_BASE   = 0x20000000u;
    const mm_u32 RAM_SIZE   = (mm_u32)sizeof(ram_backing);
    const mm_u32 INPUT_OFF  = 0u;   /* 9 x float32 = 36 bytes */
    const mm_u32 OUTPUT_OFF = 64u;  /* 9 x q15_t = 18 bytes */

    static const float inputs[9] =
        { -1.0f, -0.75f, -0.5f, -0.25f, 0.0f, 0.25f, 0.5f, 0.75f, 1.0f };
    static const mm_i16 expected[9] =
        { -32768, -24576, -16384, -8192, 0, 8192, 16384, 24576, 32767 };

    struct setup s;
    int failures = 0;
    int i;

    memset(ram_backing, 0, sizeof(ram_backing));
    for (i = 0; i < 9; i++)
        write_le32(ram_backing + INPUT_OFF + (mm_u32)(i * 4), f32_bits(inputs[i]));

    init_setup(&s);

    /* Map RAM at 0x20000000 */
    s.map.ram.buffer  = ram_backing;
    s.map.ram.base    = RAM_BASE;
    s.map.ram.length  = (size_t)RAM_SIZE;
    s.map.ram_base_s  = RAM_BASE;
    s.map.ram_size_s  = RAM_SIZE;
    s.map.ram_base_ns = RAM_BASE;
    s.map.ram_size_ns = RAM_SIZE;

    s.cpu.r[0] = RAM_BASE + INPUT_OFF;
    s.cpu.r[1] = RAM_BASE + OUTPUT_OFF;
    s.cpu.r[2] = 9u;

    for (i = 0; i < 9; i++) {
        mm_u32 r0_exp = s.cpu.r[0] + 4u;
        mm_u32 r1_exp = s.cpu.r[1] + 2u;

        if (run_insn(&s, 0xECF07A01u)) {
            printf("FAIL loop[%d]: vldmia exec error\n", i); return 1;
        }
        if (s.cpu.r[0] != r0_exp) {
            printf("FAIL loop[%d] r0: after vldmia got=0x%08lx expected=0x%08lx\n",
                   i, (unsigned long)s.cpu.r[0], (unsigned long)r0_exp);
            failures++;
        }

        if (run_insn(&s, 0xEEFE7AE8u)) {
            printf("FAIL loop[%d]: vcvt exec error\n", i); return 1;
        }
        if (run_insn(&s, 0xEE173A90u)) {
            printf("FAIL loop[%d]: vmov exec error\n", i); return 1;
        }
        if (run_insn(&s, 0xF303030Fu)) {
            printf("FAIL loop[%d]: ssat exec error\n", i); return 1;
        }
        if (run_insn16(&s, 0x3A01u)) {
            printf("FAIL loop[%d]: subs exec error\n", i); return 1;
        }

        if (run_insn(&s, 0xF8213B02u)) {
            printf("FAIL loop[%d]: strh exec error\n", i); return 1;
        }
        if (s.cpu.r[1] != r1_exp) {
            printf("FAIL loop[%d] r1: after strh.w got=0x%08lx expected=0x%08lx\n",
                   i, (unsigned long)s.cpu.r[1], (unsigned long)r1_exp);
            failures++;
        }
    }

    for (i = 0; i < 9; i++) {
        mm_i16 got = read_le16(ram_backing + OUTPUT_OFF + (mm_u32)(i * 2));
        if (got != expected[i]) {
            printf("FAIL loop_output[%d](%.2f): got=%d expected=%d\n",
                   i, (double)inputs[i], (int)got, (int)expected[i]);
            failures++;
        }
    }

    if (failures == 0)
        printf("PASS: arm_float_to_q15 loop (9 iterations, r0/r1 advancement, output values)\n");
    return failures;
}

/*
 * Test the GCC-unrolled loop body from arm_float_to_q15 with ARM_MATH_LOOPUNROLL.
 *
 * For blockSize=9 the compiler emits a 4-at-a-time loop using:
 *   vldr    s15, [r3, #-N]          (ED53 7A0N)
 *   vcvt.s32.f32 s15, s15, #15     (EEFE 7AE8)
 *   vmov    lr, s15                 (EE17 EA90)  ← uses lr not r3!
 *   ssat    lr, #16, lr             (F30E 0E0F)
 *   ... load next element into s15 ...
 *   strh.w  lr, [ip, #-N]           (F82C ECNN)  ← ip=r12, negative offset
 *
 * This function verifies each step for one iteration (4 elements).
 */
static int test_float_to_q15_unrolled_body(void)
{
    mm_u8 ram_backing[512];
    const mm_u32 RAM_BASE   = 0x20000000u;
    const mm_u32 RAM_SIZE   = (mm_u32)sizeof(ram_backing);
    const mm_u32 INPUT_OFF  = 16u;   /* r3 starts at INPUT_OFF+16 */
    const mm_u32 OUTPUT_OFF = 128u;  /* ip starts at OUTPUT_OFF+8 */

    static const float inputs[4] =
        { -1.0f, -0.75f, -0.5f, -0.25f };
    static const mm_i16 expected[4] =
        { -32768, -24576, -16384, -8192 };

    struct setup s;
    int failures = 0;

    memset(ram_backing, 0, sizeof(ram_backing));
    /* Place inputs at RAM_BASE+INPUT_OFF (r3 starts at INPUT_OFF+16) */
    {
        int i;
        for (i = 0; i < 4; i++)
            write_le32(ram_backing + INPUT_OFF + (mm_u32)(i * 4), f32_bits(inputs[i]));
    }

    init_setup(&s);
    s.map.ram.buffer  = ram_backing;
    s.map.ram.base    = RAM_BASE;
    s.map.ram.length  = (size_t)RAM_SIZE;
    s.map.ram_base_s  = RAM_BASE;
    s.map.ram_size_s  = RAM_SIZE;
    s.map.ram_base_ns = RAM_BASE;
    s.map.ram_size_ns = RAM_SIZE;

    /* r3 = pSrc + 16 (loop uses [r3,#-16..#-4]) */
    s.cpu.r[3]  = RAM_BASE + INPUT_OFF + 16u;
    /* ip (r12) = pDst + 8 (loop uses [ip,#-8..#-2]) */
    s.cpu.r[12] = RAM_BASE + OUTPUT_OFF + 8u;

    /* --- Element 0: vldr s15,[r3,#-16]; vcvt; vmov lr,s15; ssat lr --- */
    if (run_insn(&s, 0xED537A04u)) { printf("FAIL unrolled: vldr e0\n"); return 1; }
    if (run_insn(&s, 0xEEFE7AE8u)) { printf("FAIL unrolled: vcvt e0\n"); return 1; }
    if (run_insn(&s, 0xEE17EA90u)) { printf("FAIL unrolled: vmov lr,s15 e0\n"); return 1; }
    {
        mm_i32 got_lr = (mm_i32)s.cpu.r[14];
        if (got_lr != (mm_i32)expected[0]) {
            printf("FAIL unrolled[0] after vmov lr,s15: lr=%d expected=%d\n",
                   (int)got_lr, (int)expected[0]);
            failures++;
        }
    }
    if (run_insn(&s, 0xF30E0E0Fu)) { printf("FAIL unrolled: ssat lr e0\n"); return 1; }
    {
        mm_i32 got_lr = (mm_i32)s.cpu.r[14];
        if (got_lr != (mm_i32)expected[0]) {
            printf("FAIL unrolled[0] after ssat lr: lr=%d expected=%d\n",
                   (int)got_lr, (int)expected[0]);
            failures++;
        }
    }

    /* --- Element 1: vldr s15,[r3,#-12]; vcvt; strh lr,[ip,#-8]; vmov lr,s15; ssat lr --- */
    if (run_insn(&s, 0xED537A03u)) { printf("FAIL unrolled: vldr e1\n"); return 1; }
    if (run_insn(&s, 0xEEFE7AE8u)) { printf("FAIL unrolled: vcvt e1\n"); return 1; }
    {
        /* lr should still have element[0] value; s15 now has element[1] value */
        mm_i32 got_lr = (mm_i32)s.cpu.r[14];
        if (got_lr != (mm_i32)expected[0]) {
            printf("FAIL unrolled[1] before strh: lr=%d expected=%d (should still be e0)\n",
                   (int)got_lr, (int)expected[0]);
            failures++;
        }
    }
    if (run_insn(&s, 0xF82CEC08u)) { printf("FAIL unrolled: strh e0->out[0]\n"); return 1; }
    {
        mm_i16 got = read_le16(ram_backing + OUTPUT_OFF + 0u);
        if (got != expected[0]) {
            printf("FAIL unrolled output[0]: got=%d expected=%d\n",
                   (int)got, (int)expected[0]);
            failures++;
        }
    }
    if (run_insn(&s, 0xEE17EA90u)) { printf("FAIL unrolled: vmov lr,s15 e1\n"); return 1; }
    if (run_insn(&s, 0xF30E0E0Fu)) { printf("FAIL unrolled: ssat lr e1\n"); return 1; }

    /* --- Element 2: vldr s15,[r3,#-8]; vcvt; strh lr,[ip,#-6]; vmov lr,s15; ssat lr --- */
    if (run_insn(&s, 0xED537A02u)) { printf("FAIL unrolled: vldr e2\n"); return 1; }
    if (run_insn(&s, 0xEEFE7AE8u)) { printf("FAIL unrolled: vcvt e2\n"); return 1; }
    if (run_insn(&s, 0xF82CEC06u)) { printf("FAIL unrolled: strh e1->out[1]\n"); return 1; }
    {
        mm_i16 got = read_le16(ram_backing + OUTPUT_OFF + 2u);
        if (got != expected[1]) {
            printf("FAIL unrolled output[1]: got=%d expected=%d\n",
                   (int)got, (int)expected[1]);
            failures++;
        }
    }
    if (run_insn(&s, 0xEE17EA90u)) { printf("FAIL unrolled: vmov lr,s15 e2\n"); return 1; }
    if (run_insn(&s, 0xF30E0E0Fu)) { printf("FAIL unrolled: ssat lr e2\n"); return 1; }

    /* --- Element 3: vldr s15,[r3,#-4]; vcvt; strh lr,[ip,#-4]; vmov lr,s15; ssat lr --- */
    if (run_insn(&s, 0xED537A01u)) { printf("FAIL unrolled: vldr e3\n"); return 1; }
    if (run_insn(&s, 0xEEFE7AE8u)) { printf("FAIL unrolled: vcvt e3\n"); return 1; }
    if (run_insn(&s, 0xF82CEC04u)) { printf("FAIL unrolled: strh e2->out[2]\n"); return 1; }
    {
        mm_i16 got = read_le16(ram_backing + OUTPUT_OFF + 4u);
        if (got != expected[2]) {
            printf("FAIL unrolled output[2]: got=%d expected=%d\n",
                   (int)got, (int)expected[2]);
            failures++;
        }
    }
    if (run_insn(&s, 0xEE17EA90u)) { printf("FAIL unrolled: vmov lr,s15 e3\n"); return 1; }
    if (run_insn(&s, 0xF30E0E0Fu)) { printf("FAIL unrolled: ssat lr e3\n"); return 1; }
    if (run_insn(&s, 0xF82CEC02u)) { printf("FAIL unrolled: strh e3->out[3]\n"); return 1; }
    {
        mm_i16 got = read_le16(ram_backing + OUTPUT_OFF + 6u);
        if (got != expected[3]) {
            printf("FAIL unrolled output[3]: got=%d expected=%d\n",
                   (int)got, (int)expected[3]);
            failures++;
        }
    }

    if (failures == 0)
        printf("PASS: arm_float_to_q15 unrolled body (4 elements via lr/ip path)\n");
    return failures;
}

/* Write a 32-bit Thumb-2 instruction (hw1<<16|hw2) into a code buffer at offset `off`. */
static void put_insn32(mm_u8 *buf, size_t off, mm_u32 insn)
{
    buf[off + 0u] = (mm_u8)((insn >> 16) & 0xFFu);
    buf[off + 1u] = (mm_u8)((insn >> 24) & 0xFFu);
    buf[off + 2u] = (mm_u8)((insn >>  0) & 0xFFu);
    buf[off + 3u] = (mm_u8)((insn >>  8) & 0xFFu);
}

/* Write a 16-bit Thumb instruction into a code buffer at offset `off`. */
static void put_insn16(mm_u8 *buf, size_t off, mm_u16 insn16)
{
    buf[off + 0u] = (mm_u8)((insn16 >> 0) & 0xFFu);
    buf[off + 1u] = (mm_u8)((insn16 >> 8) & 0xFFu);
}

/*
 * Full run-loop test for the GCC ARM_MATH_LOOPUNROLL unrolled path of
 * arm_float_to_q15 with blockSize=9.
 *
 * Places the exact instruction bytes (from arm-none-eabi-gcc -O2 disassembly)
 * into a code buffer and runs them through the real fetch/decode/execute loop,
 * including the BNE branch-back.  Verifies all 8 outputs produced by the
 * unrolled 4-at-a-time loop (2 iterations × 4 elements).
 *
 * Code layout (matching disassembly offsets):
 *   0x16..0x71  — two-iteration unrolled loop body + BNE
 */
static int test_float_to_q15_runloop(void)
{
    /* Code buffer: large enough for offsets 0x00..0x71 */
    static mm_u8 code_buf[0x80];
    /* RAM: input floats and output halfwords */
    static mm_u8 ram_backing[512];

    const mm_u32 RAM_BASE   = 0x20000000u;
    const mm_u32 RAM_SIZE   = (mm_u32)sizeof(ram_backing);
    /* pSrc starts at RAM_BASE+0; pDst at RAM_BASE+128 */
    const mm_u32 INPUT_BASE = RAM_BASE;
    const mm_u32 OUTPUT_BASE = RAM_BASE + 128u;

    static const float inputs[8] =
        { -1.0f, -0.75f, -0.5f, -0.25f, 0.0f, 0.25f, 0.5f, 0.75f };
    static const mm_i16 expected[8] =
        { -32768, -24576, -16384, -8192, 0, 8192, 16384, 24576 };

    struct mm_cpu cpu;
    struct mm_memmap map;
    struct mm_scs scs;
    struct mm_gdb_stub gdb;
    struct mmio_region regions[1];
    mm_u8 it_pattern = 0, it_remaining = 0, it_cond = 0;
    mm_bool done = MM_FALSE;
    struct mm_mem code_mem;
    int failures = 0;
    int i;

    /* --- Build code buffer at offsets matching the disassembly --- */
    memset(code_buf, 0, sizeof(code_buf));

    /* 0x16: vldr s15, [r3, #-16]           ED53 7A04 */
    put_insn32(code_buf, 0x16u, 0xED537A04u);
    /* 0x1a: vcvt.s32.f32 s15, s15, #15     EEFE 7AE8 */
    put_insn32(code_buf, 0x1au, 0xEEFE7AE8u);
    /* 0x1e: vmov lr, s15                   EE17 EA90 */
    put_insn32(code_buf, 0x1eu, 0xEE17EA90u);
    /* 0x22: ssat lr, #16, lr               F30E 0E0F */
    put_insn32(code_buf, 0x22u, 0xF30E0E0Fu);
    /* 0x26: vldr s15, [r3, #-12]           ED53 7A03 */
    put_insn32(code_buf, 0x26u, 0xED537A03u);
    /* 0x2a: vcvt.s32.f32 s15, s15, #15     EEFE 7AE8 */
    put_insn32(code_buf, 0x2au, 0xEEFE7AE8u);
    /* 0x2e: strh.w lr, [ip, #-8]           F82C EC08 */
    put_insn32(code_buf, 0x2eu, 0xF82CEC08u);
    /* 0x32: vmov lr, s15                   EE17 EA90 */
    put_insn32(code_buf, 0x32u, 0xEE17EA90u);
    /* 0x36: ssat lr, #16, lr               F30E 0E0F */
    put_insn32(code_buf, 0x36u, 0xF30E0E0Fu);
    /* 0x3a: vldr s15, [r3, #-8]            ED53 7A02 */
    put_insn32(code_buf, 0x3au, 0xED537A02u);
    /* 0x3e: vcvt.s32.f32 s15, s15, #15     EEFE 7AE8 */
    put_insn32(code_buf, 0x3eu, 0xEEFE7AE8u);
    /* 0x42: strh.w lr, [ip, #-6]           F82C EC06 */
    put_insn32(code_buf, 0x42u, 0xF82CEC06u);
    /* 0x46: vmov lr, s15                   EE17 EA90 */
    put_insn32(code_buf, 0x46u, 0xEE17EA90u);
    /* 0x4a: ssat lr, #16, lr               F30E 0E0F */
    put_insn32(code_buf, 0x4au, 0xF30E0E0Fu);
    /* 0x4e: vldr s15, [r3, #-4]            ED53 7A01 */
    put_insn32(code_buf, 0x4eu, 0xED537A01u);
    /* 0x52: vcvt.s32.f32 s15, s15, #15     EEFE 7AE8 */
    put_insn32(code_buf, 0x52u, 0xEEFE7AE8u);
    /* 0x56: strh.w lr, [ip, #-4]           F82C EC04 */
    put_insn32(code_buf, 0x56u, 0xF82CEC04u);
    /* 0x5a: vmov lr, s15                   EE17 EA90 */
    put_insn32(code_buf, 0x5au, 0xEE17EA90u);
    /* 0x5e: ssat lr, #16, lr               F30E 0E0F */
    put_insn32(code_buf, 0x5eu, 0xF30E0E0Fu);
    /* 0x62: subs r1, #1                    3901  (16-bit) */
    put_insn16(code_buf, 0x62u, 0x3901u);
    /* 0x64: strh.w lr, [ip, #-2]           F82C EC02 */
    put_insn32(code_buf, 0x64u, 0xF82CEC02u);
    /* 0x68: add.w r3, r3, #16              F103 0310 */
    put_insn32(code_buf, 0x68u, 0xF1030310u);
    /* 0x6c: add.w ip, ip, #8              F10C 0C08 */
    put_insn32(code_buf, 0x6cu, 0xF10C0C08u);
    /* 0x70: bne.n 0x16                     D1D1  (16-bit) */
    put_insn16(code_buf, 0x70u, 0xD1D1u);

    /* Code memory: base=0, length=0x72 (loop stops when PC reaches 0x72) */
    code_mem.buffer = code_buf;
    code_mem.length = 0x72u;
    code_mem.base   = 0u;

    /* --- Set up RAM with input floats --- */
    memset(ram_backing, 0, sizeof(ram_backing));
    for (i = 0; i < 8; i++)
        write_le32(ram_backing + (mm_u32)(i * 4), f32_bits(inputs[i]));

    /* --- Set up CPU and memory map --- */
    memset(&cpu,  0, sizeof(cpu));
    memset(&scs,  0, sizeof(scs));
    memset(&gdb,  0, sizeof(gdb));
    memset(&map,  0, sizeof(map));
    memset(regions, 0, sizeof(regions));
    mm_memmap_init(&map, regions, 1u);
    cpu.sec_state = MM_SECURE;
    cpu.mode      = MM_THREAD;
    scs.fpu_present = MM_TRUE;
    scs.cpacr_s     = 0x00f00000u;

    map.ram.buffer  = ram_backing;
    map.ram.base    = RAM_BASE;
    map.ram.length  = (size_t)RAM_SIZE;
    map.ram_base_s  = RAM_BASE;
    map.ram_size_s  = RAM_SIZE;
    map.ram_base_ns = RAM_BASE;
    map.ram_size_ns = RAM_SIZE;

    /*
     * Registers after the function prologue for blockSize=9:
     *   r1  = 2           (loop counter = blockSize/4)
     *   r3  = pSrc + 16   (vldr uses [r3,#-16..#-4])
     *   r12 = pDst + 8    (strh uses [ip,#-8..#-2])
     */
    cpu.r[1]  = 2u;
    cpu.r[3]  = INPUT_BASE + 16u;
    cpu.r[12] = OUTPUT_BASE + 8u;
    /* Thumb bit set, PC pointing at first vldr at 0x16 */
    cpu.r[15] = 0x16u | 1u;

    /* --- Run the fetch/decode/execute loop --- */
    while ((cpu.r[15] & ~1u) < code_mem.length) {
        struct mm_fetch_result fetch;
        struct mm_decoded dec;
        struct mm_execute_ctx ctx;

        fetch = mm_fetch_t32(&cpu, &code_mem);
        if (fetch.fault) {
            printf("FAIL runloop: fetch fault at PC=0x%08lx\n",
                   (unsigned long)(cpu.r[15] & ~1u));
            return 1;
        }
        dec = mm_decode_t32(&fetch);
        if (dec.undefined) {
            printf("FAIL runloop: undefined insn=0x%08lx at PC=0x%08lx\n",
                   (unsigned long)fetch.insn,
                   (unsigned long)fetch.pc_fetch);
            return 1;
        }

        memset(&ctx, 0, sizeof(ctx));
        ctx.cpu          = &cpu;
        ctx.map          = &map;
        ctx.scs          = &scs;
        ctx.gdb          = &gdb;
        ctx.fetch        = &fetch;
        ctx.dec          = &dec;
        ctx.it_pattern   = &it_pattern;
        ctx.it_remaining = &it_remaining;
        ctx.it_cond      = &it_cond;
        ctx.done         = &done;
        ctx.handle_pc_write   = stub_handle_pc_write;
        ctx.raise_mem_fault   = stub_mem;
        ctx.raise_usage_fault = stub_uf;
        ctx.exc_return_unstack = stub_ret;
        ctx.enter_exception    = stub_enter;

        if (mm_execute_decoded(&ctx) != MM_EXEC_OK) {
            printf("FAIL runloop: exec error insn=0x%08lx kind=%u at PC=0x%08lx\n",
                   (unsigned long)fetch.insn, (unsigned)dec.kind,
                   (unsigned long)fetch.pc_fetch);
            return 1;
        }
        if (done) break;
    }

    /* --- Verify outputs --- */
    for (i = 0; i < 8; i++) {
        mm_i16 got = read_le16(ram_backing + 128u + (mm_u32)(i * 2));
        if (got != expected[i]) {
            printf("FAIL runloop output[%d](%.2f): got=%d expected=%d\n",
                   i, (double)inputs[i], (int)got, (int)expected[i]);
            failures++;
        }
    }
    if (failures == 0)
        printf("PASS: arm_float_to_q15 unrolled run-loop (8 elements, 2 BNE iterations)\n");
    return failures;
}

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

    /* 3. Full loop with real memory: pointer advancement + output buffer */
    {
        int loop_failures = test_float_to_q15_loop();
        if (loop_failures != 0) {
            printf("FAIL: arm_float_to_q15 loop (%d failure(s))\n", loop_failures);
            failures += loop_failures;
        }
    }

    /* 4. Unrolled loop body (lr/ip register path, GCC -O2 with LOOPUNROLL) */
    {
        int ub_failures = test_float_to_q15_unrolled_body();
        if (ub_failures != 0) {
            printf("FAIL: arm_float_to_q15 unrolled body (%d failure(s))\n", ub_failures);
            failures += ub_failures;
        }
    }

    /* 5. Full run-loop with BNE branch-back (reproduces blockSize=9 bug) */
    {
        int rl_failures = test_float_to_q15_runloop();
        if (rl_failures != 0) {
            printf("FAIL: arm_float_to_q15 run-loop (%d failure(s))\n", rl_failures);
            failures += rl_failures;
        }
    }

    if (failures == 0) {
        printf("ALL PASS\n");
    } else {
        printf("%d FAILURE(S)\n", failures);
    }
    return failures != 0;
}
