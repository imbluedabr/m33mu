/* m33mu -- an ARMv8-M Emulator
 *
 * Copyright (C) 2026
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>

#define main m33mu_cli_main
#include "../src/main.c"
#undef main

static void write32(mm_u8 *buf, mm_u32 off, mm_u32 v)
{
    buf[off + 0] = (mm_u8)(v & 0xffu);
    buf[off + 1] = (mm_u8)((v >> 8) & 0xffu);
    buf[off + 2] = (mm_u8)((v >> 16) & 0xffu);
    buf[off + 3] = (mm_u8)((v >> 24) & 0xffu);
}

static void setup_basic_map(struct mm_memmap *map,
                            struct mm_scs *scs,
                            struct mm_target_cfg *cfg,
                            struct mmio_region *regions,
                            mm_u8 *flash,
                            size_t flash_len,
                            mm_u8 *ram,
                            size_t ram_len)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->flash_base_s = 0u;
    cfg->flash_size_s = (mm_u32)flash_len;
    cfg->flash_base_ns = 0u;
    cfg->flash_size_ns = (mm_u32)flash_len;
    cfg->ram_base_s = 0x20000000u;
    cfg->ram_size_s = (mm_u32)ram_len;
    cfg->ram_base_ns = 0x20000000u;
    cfg->ram_size_ns = (mm_u32)ram_len;

    mm_memmap_init(map, regions, 4u);
    (void)mm_memmap_configure_flash(map, cfg, flash, MM_TRUE);
    (void)mm_memmap_configure_flash(map, cfg, flash, MM_FALSE);
    (void)mm_memmap_configure_ram(map, cfg, ram, MM_TRUE);
    mm_scs_init(scs, 0u);
}

static int test_extended_fp_frame_layout(void)
{
    struct mm_cpu cpu;
    struct mm_memmap map;
    struct mm_scs scs;
    struct mmio_region regions[4];
    struct mm_target_cfg cfg;
    mm_u8 flash[0x200];
    mm_u8 ram[0x400];
    mm_u32 val = 0;
    mm_u32 sp;
    int i;

    memset(&cpu, 0, sizeof(cpu));
    memset(&map, 0, sizeof(map));
    memset(&scs, 0, sizeof(scs));
    memset(regions, 0, sizeof(regions));
    memset(flash, 0, sizeof(flash));
    memset(ram, 0, sizeof(ram));
    setup_basic_map(&map, &scs, &cfg, regions, flash, sizeof(flash), ram, sizeof(ram));

    write32(flash, 20u * 4u, 0x00000181u);

    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.msp_s = 0x20000180u;
    cpu.r[0] = 0x01020304u;
    cpu.r[1] = 0x11121314u;
    cpu.r[2] = 0x21222324u;
    cpu.r[3] = 0x31323334u;
    cpu.r[12] = 0xccccccccu;
    cpu.r[14] = 0xeeeeeeeeu;
    cpu.r[15] = 0x00000041u;
    cpu.xpsr = 0x61000000u;
    cpu.control_s = (1u << 2);
    cpu.fp_active = MM_TRUE;
    cpu.fpscr = 0xfeed1234u;
    for (i = 0; i < 16; ++i) {
        cpu.s[i] = 0xa0a00000u + (mm_u32)i;
    }
    scs.fpu_present = MM_TRUE;
    scs.cpacr_s = 0x00f00000u;
    scs.fpccr = FPCCR_ASPEN;

    if (!enter_exception_ex(&cpu, &map, &scs, 20u, 0x00000040u, cpu.xpsr, MM_SECURE)) {
        printf("extended_fp_frame_layout: enter_exception_ex failed\n");
        return 1;
    }
    sp = cpu.msp_s;
    if (sp != 0x20000118u) {
        printf("extended_fp_frame_layout: bad sp got=0x%08lx\n", (unsigned long)sp);
        return 1;
    }
    if (scs.fpcar != sp + 32u) {
        printf("extended_fp_frame_layout: bad fpcar got=0x%08lx want=0x%08lx\n",
               (unsigned long)scs.fpcar, (unsigned long)(sp + 32u));
        return 1;
    }
    if (!mm_memmap_read(&map, MM_SECURE, sp + 0u, 4u, &val) || val != cpu.r[0]) {
        printf("extended_fp_frame_layout: bad stacked r0 got=0x%08lx\n", (unsigned long)val);
        return 1;
    }
    if (!mm_memmap_read(&map, MM_SECURE, sp + 32u, 4u, &val) || val != 0xa0a00000u) {
        printf("extended_fp_frame_layout: bad stacked s0 got=0x%08lx\n", (unsigned long)val);
        return 1;
    }
    if (!mm_memmap_read(&map, MM_SECURE, sp + 96u, 4u, &val) || val != cpu.fpscr) {
        printf("extended_fp_frame_layout: bad stacked fpscr got=0x%08lx\n", (unsigned long)val);
        return 1;
    }
    if (!mm_memmap_read(&map, MM_SECURE, sp + 4u, 4u, &val) || val != cpu.r[1]) return 1;
    if (!mm_memmap_read(&map, MM_SECURE, sp + 28u, 4u, &val) || val != 0x61000000u) {
        printf("extended_fp_frame_layout: bad stacked xpsr got=0x%08lx\n", (unsigned long)val);
        return 1;
    }
    if (!exc_return_unstack(&cpu, &map, &scs, cpu.r[14])) {
        printf("extended_fp_frame_layout: exc_return_unstack failed\n");
        return 1;
    }
    if (cpu.r[0] != 0x01020304u || cpu.s[0] != 0xa0a00000u || cpu.mode != MM_THREAD) {
        printf("extended_fp_frame_layout: restore mismatch\n");
        return 1;
    }
    return 0;
}

static int test_lazy_fp_reserved_frame_unstacks_from_fp_slot(void)
{
    struct mm_cpu cpu;
    struct mm_memmap map;
    struct mm_scs scs;
    struct mmio_region regions[4];
    struct mm_target_cfg cfg;
    mm_u8 flash[0x200];
    mm_u8 ram[0x400];
    mm_u32 sp;
    mm_u32 val;
    int i;

    memset(&cpu, 0, sizeof(cpu));
    memset(&map, 0, sizeof(map));
    memset(&scs, 0, sizeof(scs));
    memset(&cfg, 0, sizeof(cfg));
    memset(flash, 0, sizeof(flash));
    memset(ram, 0, sizeof(ram));
    setup_basic_map(&map, &scs, &cfg, regions, flash, sizeof(flash), ram, sizeof(ram));

    write32(flash, 20u * 4u, 0x00000181u);

    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.msp_s = 0x20000180u;
    cpu.r[0] = 0x01020304u;
    cpu.r[1] = 0x11121314u;
    cpu.r[2] = 0x21222324u;
    cpu.r[3] = 0x31323334u;
    cpu.r[12] = 0xccccccccu;
    cpu.r[14] = 0xeeeeeeeeu;
    cpu.r[15] = 0x00000041u;
    cpu.xpsr = 0x61000000u;
    cpu.control_s = (1u << 2);
    cpu.fp_active = MM_TRUE;
    cpu.fpscr = 0xfeed1234u;
    for (i = 0; i < 16; ++i) {
        cpu.s[i] = 0x5a5a0000u + (mm_u32)i;
    }
    scs.fpu_present = MM_TRUE;
    scs.cpacr_s = 0x00f00000u;
    scs.fpccr = FPCCR_ASPEN | FPCCR_LSPACT;

    if (!enter_exception_ex(&cpu, &map, &scs, 20u, 0x00000040u, cpu.xpsr, MM_SECURE)) {
        printf("lazy_fp_reserved_frame: enter_exception_ex failed\n");
        return 1;
    }
    sp = cpu.msp_s;
    if (scs.fpcar != sp + 32u) {
        printf("lazy_fp_reserved_frame: bad fpcar got=0x%08lx want=0x%08lx\n",
               (unsigned long)scs.fpcar, (unsigned long)(sp + 32u));
        return 1;
    }
    if (!mm_memmap_read(&map, MM_SECURE, sp + 0u, 4u, &val) || val != 0x01020304u) {
        printf("lazy_fp_reserved_frame: bad basic frame base got=0x%08lx\n", (unsigned long)val);
        return 1;
    }
    for (i = 0; i < 16; ++i) {
        if (!mm_memmap_write(&map, MM_SECURE, sp + 32u + (mm_u32)(i * 4u), 4u, 0x5a5a0000u + (mm_u32)i)) return 1;
    }
    if (!mm_memmap_write(&map, MM_SECURE, sp + 32u + (16u * 4u), 4u, cpu.fpscr)) return 1;
    if (!mm_memmap_write(&map, MM_SECURE, sp + 32u + (17u * 4u), 4u, 0u)) return 1;
    cpu.exc_fp_saved[0] = MM_TRUE;
    scs.fpccr &= ~FPCCR_LSPACT;

    if (!exc_return_unstack(&cpu, &map, &scs, cpu.r[14])) {
        printf("lazy_fp_reserved_frame: exc_return_unstack failed\n");
        return 1;
    }
    if (cpu.r[0] != 0x01020304u || cpu.r[15] != 0x00000041u || cpu.s[0] != 0x5a5a0000u) {
        printf("lazy_fp_reserved_frame: restore mismatch r0=0x%08lx pc=0x%08lx s0=0x%08lx\n",
               (unsigned long)cpu.r[0],
               (unsigned long)cpu.r[15],
               (unsigned long)cpu.s[0]);
        return 1;
    }
    return 0;
}

static int test_secure_to_nonsecure_exception_sanitizes_and_restores_callee_regs(void)
{
    struct mm_cpu cpu;
    struct mm_memmap map;
    struct mm_scs scs;
    struct mmio_region regions[4];
    struct mm_target_cfg cfg;
    mm_u8 flash[0x200];
    mm_u8 ram[0x400];
    mm_u32 ret;
    int i;

    memset(&cpu, 0, sizeof(cpu));
    memset(&map, 0, sizeof(map));
    memset(&scs, 0, sizeof(scs));
    memset(&cfg, 0, sizeof(cfg));
    memset(flash, 0, sizeof(flash));
    memset(ram, 0, sizeof(ram));

    cfg.flash_base_s = 0u;
    cfg.flash_size_s = sizeof(flash);
    cfg.flash_base_ns = 0u;
    cfg.flash_size_ns = sizeof(flash);
    cfg.ram_base_s = 0x20000000u;
    cfg.ram_size_s = sizeof(ram);
    cfg.ram_base_ns = 0x20000000u;
    cfg.ram_size_ns = sizeof(ram);

    write32(flash, 0x100u + (20u * 4u), 0x00000181u);

    mm_memmap_init(&map, regions, 4u);
    if (!mm_memmap_configure_flash(&map, &cfg, flash, MM_TRUE)) return 1;
    if (!mm_memmap_configure_flash(&map, &cfg, flash, MM_FALSE)) return 1;
    if (!mm_memmap_configure_ram(&map, &cfg, ram, MM_TRUE)) return 1;

    mm_scs_init(&scs, 0u);
    scs.vtor_ns = 0x100u;

    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.msp_s = 0x20000100u;
    cpu.r[15] = 0x00000041u;
    cpu.xpsr = 0x01000000u;
    for (i = 0; i < 8; ++i) {
        cpu.r[4 + i] = 0x11111111u * (mm_u32)(i + 1);
    }

    if (!enter_exception_ex(&cpu, &map, &scs, 20u, 0x00000040u, cpu.xpsr, MM_NONSECURE)) {
        printf("enter_exception_ex failed\n");
        return 1;
    }
    if (cpu.sec_state != MM_NONSECURE || cpu.mode != MM_HANDLER) {
        printf("wrong handler state sec=%d mode=%d\n", (int)cpu.sec_state, (int)cpu.mode);
        return 1;
    }
    for (i = 0; i < 8; ++i) {
        if (cpu.r[4 + i] != 0u) {
            printf("callee reg r%d leaked into NS handler: 0x%08lx\n",
                   4 + i, (unsigned long)cpu.r[4 + i]);
            return 1;
        }
    }
    if (cpu.exc_depth != 1 || !cpu.exc_cross_domain[0]) {
        printf("cross-domain frame metadata missing depth=%d flag=%d\n",
               cpu.exc_depth,
               (int)cpu.exc_cross_domain[0]);
        return 1;
    }
    if ((cpu.r[14] & (1u << 5)) != 0u) {
        printf("cross-domain frame should clear DCRS lr=0x%08lx\n",
               (unsigned long)cpu.r[14]);
        return 1;
    }
    if (cpu.msp_s != 0x200000bcu) {
        printf("cross-domain frame should consume additional secure stack got=0x%08lx\n",
               (unsigned long)cpu.msp_s);
        return 1;
    }
    for (i = 0; i < 8; ++i) {
        mm_u32 val = 0;
        mm_u32 want = 0x11111111u * (mm_u32)(i + 1);
        if (!mm_memmap_read(&map, MM_SECURE, cpu.msp_s + 32u + (mm_u32)(i * 4u), 4u, &val) || val != want) {
            printf("cross-domain stacked callee reg mismatch idx=%d got=0x%08lx want=0x%08lx\n",
                   i, (unsigned long)val, (unsigned long)want);
            return 1;
        }
    }

    for (i = 0; i < 8; ++i) {
        cpu.r[4 + i] = 0xdead0000u + (mm_u32)i;
    }
    ret = cpu.r[14];
    if (!exc_return_unstack(&cpu, &map, &scs, ret)) {
        printf("exc_return_unstack failed\n");
        return 1;
    }
    if (cpu.sec_state != MM_SECURE || cpu.mode != MM_THREAD || cpu.exc_depth != 0) {
        printf("wrong restored state sec=%d mode=%d depth=%d\n",
               (int)cpu.sec_state, (int)cpu.mode, cpu.exc_depth);
        return 1;
    }
    for (i = 0; i < 8; ++i) {
        mm_u32 want = 0x11111111u * (mm_u32)(i + 1);
        if (cpu.r[4 + i] != want) {
            printf("callee reg r%d restore mismatch got=0x%08lx want=0x%08lx\n",
                   4 + i,
                   (unsigned long)cpu.r[4 + i],
                   (unsigned long)want);
            return 1;
        }
    }

    return 0;
}

static int test_usagefault_metadata_and_spsel_clear(void)
{
    struct mm_cpu cpu;
    struct mm_memmap map;
    struct mm_scs scs;
    struct mmio_region regions[4];
    struct mm_target_cfg cfg;
    mm_u8 flash[0x200];
    mm_u8 ram[0x400];

    memset(&cpu, 0, sizeof(cpu));
    memset(&map, 0, sizeof(map));
    memset(&scs, 0, sizeof(scs));
    memset(regions, 0, sizeof(regions));
    memset(flash, 0, sizeof(flash));
    memset(ram, 0, sizeof(ram));
    setup_basic_map(&map, &scs, &cfg, regions, flash, sizeof(flash), ram, sizeof(ram));

    write32(flash, 6u * 4u, 0x00000101u);
    scs.shcsr_s = (1u << 18);

    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.psp_s = 0x20000140u;
    cpu.control_s = 0x2u;
    cpu.r[15] = 0x00000041u;
    cpu.xpsr = 0x01000000u;
    cpu.exc_fp_reserved[0] = MM_TRUE;
    cpu.exc_fp_saved[0] = MM_FALSE;
    cpu.exc_cross_domain[0] = MM_TRUE;

    if (!raise_usage_fault(&cpu, &map, &scs, 0x00000040u, cpu.xpsr, UFSR_UNDEFINSTR)) {
        printf("usagefault_metadata: raise_usage_fault failed\n");
        return 1;
    }
    if (cpu.mode != MM_HANDLER || (cpu.control_s & 0x2u) != 0u) {
        printf("usagefault_metadata: mode/control mismatch mode=%d ctrl=0x%08lx\n",
               (int)cpu.mode, (unsigned long)cpu.control_s);
        return 1;
    }
    if (cpu.exc_depth != 1 ||
        cpu.exc_fp_reserved[0] != MM_FALSE ||
        cpu.exc_fp_saved[0] != MM_FALSE ||
        cpu.exc_cross_domain[0] != MM_FALSE) {
        printf("usagefault_metadata: stale metadata depth=%d reserved=%d saved=%d cross=%d\n",
               cpu.exc_depth,
               (int)cpu.exc_fp_reserved[0],
               (int)cpu.exc_fp_saved[0],
               (int)cpu.exc_cross_domain[0]);
        return 1;
    }
    return 0;
}

static int test_hardfault_respects_aspen_and_clears_control(void)
{
    struct mm_cpu cpu;
    struct mm_memmap map;
    struct mm_scs scs;
    struct mmio_region regions[4];
    struct mm_target_cfg cfg;
    mm_u8 flash[0x200];
    mm_u8 ram[0x400];

    memset(&cpu, 0, sizeof(cpu));
    memset(&map, 0, sizeof(map));
    memset(&scs, 0, sizeof(scs));
    memset(regions, 0, sizeof(regions));
    memset(flash, 0, sizeof(flash));
    memset(ram, 0, sizeof(ram));
    setup_basic_map(&map, &scs, &cfg, regions, flash, sizeof(flash), ram, sizeof(ram));

    write32(flash, 3u * 4u, 0x00000101u);

    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.psp_s = 0x20000140u;
    cpu.control_s = 0x6u;
    cpu.fp_active = MM_TRUE;
    cpu.r[15] = 0x00000041u;
    cpu.xpsr = 0x01000000u;
    scs.fpu_present = MM_TRUE;
    scs.cpacr_s = 0x00f00000u;
    scs.fpccr = 0u;

    if (!raise_hard_fault(&cpu, &map, &scs, 0x00000040u, cpu.xpsr)) {
        printf("hardfault_aspen: raise_hard_fault failed\n");
        return 1;
    }
    if (cpu.psp_s != 0x20000120u || cpu.r[14] != 0xfffffffdu || (cpu.control_s & 0x2u) != 0u) {
        printf("hardfault_aspen: sp/lr/control mismatch psp=0x%08lx lr=0x%08lx ctrl=0x%08lx\n",
               (unsigned long)cpu.psp_s,
               (unsigned long)cpu.r[14],
               (unsigned long)cpu.control_s);
        return 1;
    }
    return 0;
}

static int test_cross_domain_return_clears_handler_faultmask_bank(void)
{
    struct mm_cpu cpu;
    struct mm_memmap map;
    struct mm_scs scs;
    struct mmio_region regions[4];
    struct mm_target_cfg cfg;
    mm_u8 flash[0x200];
    mm_u8 ram[0x400];

    memset(&cpu, 0, sizeof(cpu));
    memset(&map, 0, sizeof(map));
    memset(&scs, 0, sizeof(scs));
    memset(regions, 0, sizeof(regions));
    memset(flash, 0, sizeof(flash));
    memset(ram, 0, sizeof(ram));
    setup_basic_map(&map, &scs, &cfg, regions, flash, sizeof(flash), ram, sizeof(ram));

    write32(flash, 7u * 4u, 0x00000101u);

    cpu.sec_state = MM_NONSECURE;
    cpu.mode = MM_THREAD;
    cpu.msp_ns = 0x20000100u;
    cpu.faultmask_s = 1u;
    cpu.faultmask_ns = 1u;
    cpu.r[15] = 0x00000041u;
    cpu.xpsr = 0x01000000u;

    if (!enter_exception_ex(&cpu, &map, &scs, MM_VECT_SECUREFAULT, 0x00000040u, cpu.xpsr, MM_SECURE)) {
        return 1;
    }
    if (!exc_return_unstack(&cpu, &map, &scs, cpu.r[14])) {
        return 1;
    }
    if (cpu.faultmask_s != 0u || cpu.faultmask_ns != 1u) {
        printf("cross_domain_faultmask: s=%lu ns=%lu\n",
               (unsigned long)cpu.faultmask_s,
               (unsigned long)cpu.faultmask_ns);
        return 1;
    }
    return 0;
}

static int test_securefault_active_bit_uses_secure_bank(void)
{
    struct mm_cpu cpu;
    struct mm_memmap map;
    struct mm_scs scs;
    struct mmio_region regions[4];
    struct mm_target_cfg cfg;
    mm_u8 flash[0x200];
    mm_u8 ram[0x400];

    memset(&cpu, 0, sizeof(cpu));
    memset(&map, 0, sizeof(map));
    memset(&scs, 0, sizeof(scs));
    memset(regions, 0, sizeof(regions));
    memset(flash, 0, sizeof(flash));
    memset(ram, 0, sizeof(ram));
    setup_basic_map(&map, &scs, &cfg, regions, flash, sizeof(flash), ram, sizeof(ram));

    write32(flash, 7u * 4u, 0x00000101u);

    cpu.sec_state = MM_NONSECURE;
    cpu.mode = MM_THREAD;
    cpu.msp_ns = 0x20000100u;
    cpu.r[15] = 0x00000041u;
    cpu.xpsr = 0x01000000u;

    if (!enter_exception_ex(&cpu, &map, &scs, MM_VECT_SECUREFAULT, 0x00000040u, cpu.xpsr, MM_SECURE)) {
        return 1;
    }
    if ((scs.shcsr_s & (1u << 4)) == 0u || (scs.shcsr_ns & (1u << 4)) != 0u) {
        printf("securefault_active_bank: shcsr_s=0x%08lx shcsr_ns=0x%08lx\n",
               (unsigned long)scs.shcsr_s,
               (unsigned long)scs.shcsr_ns);
        return 1;
    }
    return 0;
}

int main(void)
{
    if (test_extended_fp_frame_layout() != 0) {
        return 1;
    }
    if (test_lazy_fp_reserved_frame_unstacks_from_fp_slot() != 0) {
        return 1;
    }
    if (test_secure_to_nonsecure_exception_sanitizes_and_restores_callee_regs() != 0) {
        return 1;
    }
    if (test_usagefault_metadata_and_spsel_clear() != 0) {
        return 1;
    }
    if (test_hardfault_respects_aspen_and_clears_control() != 0) {
        return 1;
    }
    if (test_cross_domain_return_clears_handler_faultmask_bank() != 0) {
        return 1;
    }
    if (test_securefault_active_bit_uses_secure_bank() != 0) {
        return 1;
    }
    return 0;
}
