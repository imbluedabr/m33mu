/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include <string.h>
#include "rp2350/rp2350_bootrom.h"
#include "rp2350/rp2350_mmio.h"

#define RP2350_BOOTROM_TABLE_LOOKUP_OFFSET 0x16u

#define RP2350_ROM_TABLE_LOOKUP_ADDR 0x00000100u
#define RP2350_ROM_FLASH_RANGE_ERASE_ADDR 0x00000180u
#define RP2350_ROM_FLASH_RANGE_PROGRAM_ADDR 0x000001a0u
#define RP2350_ROM_FLASH_FLUSH_CACHE_ADDR 0x000001c0u
#define RP2350_ROM_CONNECT_INTERNAL_FLASH_ADDR 0x000001e0u
#define RP2350_ROM_FLASH_EXIT_XIP_ADDR 0x00000200u
#define RP2350_ROM_FLASH_ENTER_CMD_XIP_ADDR 0x00000220u
#define RP2350_ROM_BOOTROM_STATE_RESET_ADDR 0x00000240u
#define RP2350_ROM_MEMSET_ADDR 0x00000260u
#define RP2350_ROM_MEMCPY_ADDR 0x00000280u
#define RP2350_ROM_MEMSET4_ADDR 0x000002a0u
#define RP2350_ROM_MEMCPY44_ADDR 0x000002c0u
#define RP2350_ROM_CLZ32_ADDR 0x000002e0u
#define RP2350_ROM_CTZ32_ADDR 0x00000300u
#define RP2350_ROM_REVERSE32_ADDR 0x00000320u
#define RP2350_ROM_POPCOUNT32_ADDR 0x00000340u
#define RP2350_ROM_UNIMPL_ADDR 0x00000360u

#define ROM_TABLE_CODE(c1, c2) ((mm_u32)(c1) | ((mm_u32)(c2) << 8))
#define ROM_FUNC_FLASH_ENTER_CMD_XIP  ROM_TABLE_CODE('C', 'X')
#define ROM_FUNC_FLASH_EXIT_XIP       ROM_TABLE_CODE('E', 'X')
#define ROM_FUNC_FLASH_FLUSH_CACHE    ROM_TABLE_CODE('F', 'C')
#define ROM_FUNC_CONNECT_INTERNAL_FLASH ROM_TABLE_CODE('I', 'F')
#define ROM_FUNC_FLASH_RANGE_ERASE    ROM_TABLE_CODE('R', 'E')
#define ROM_FUNC_FLASH_RANGE_PROGRAM  ROM_TABLE_CODE('R', 'P')
#define ROM_FUNC_BOOTROM_STATE_RESET  ROM_TABLE_CODE('S', 'R')
#define ROM_FUNC_MEMSET               ROM_TABLE_CODE('M', 'S')
#define ROM_FUNC_MEMCPY               ROM_TABLE_CODE('M', 'C')
#define ROM_FUNC_MEMSET4              ROM_TABLE_CODE('S', '4')
#define ROM_FUNC_MEMCPY44             ROM_TABLE_CODE('C', '4')
#define ROM_FUNC_CLZ32                ROM_TABLE_CODE('L', '3')
#define ROM_FUNC_CTZ32                ROM_TABLE_CODE('T', '3')
#define ROM_FUNC_REVERSE32            ROM_TABLE_CODE('R', '3')
#define ROM_FUNC_POPCOUNT32           ROM_TABLE_CODE('P', '3')

static mm_u32 rp2350_bootrom_lookup(mm_u32 code)
{
    switch (code) {
    case ROM_FUNC_FLASH_RANGE_ERASE: return RP2350_ROM_FLASH_RANGE_ERASE_ADDR | 1u;
    case ROM_FUNC_FLASH_RANGE_PROGRAM: return RP2350_ROM_FLASH_RANGE_PROGRAM_ADDR | 1u;
    case ROM_FUNC_FLASH_FLUSH_CACHE: return RP2350_ROM_FLASH_FLUSH_CACHE_ADDR | 1u;
    case ROM_FUNC_CONNECT_INTERNAL_FLASH: return RP2350_ROM_CONNECT_INTERNAL_FLASH_ADDR | 1u;
    case ROM_FUNC_FLASH_EXIT_XIP: return RP2350_ROM_FLASH_EXIT_XIP_ADDR | 1u;
    case ROM_FUNC_FLASH_ENTER_CMD_XIP: return RP2350_ROM_FLASH_ENTER_CMD_XIP_ADDR | 1u;
    case ROM_FUNC_BOOTROM_STATE_RESET: return RP2350_ROM_BOOTROM_STATE_RESET_ADDR | 1u;
    case ROM_FUNC_MEMSET: return RP2350_ROM_MEMSET_ADDR | 1u;
    case ROM_FUNC_MEMCPY: return RP2350_ROM_MEMCPY_ADDR | 1u;
    case ROM_FUNC_MEMSET4: return RP2350_ROM_MEMSET4_ADDR | 1u;
    case ROM_FUNC_MEMCPY44: return RP2350_ROM_MEMCPY44_ADDR | 1u;
    case ROM_FUNC_CLZ32: return RP2350_ROM_CLZ32_ADDR | 1u;
    case ROM_FUNC_CTZ32: return RP2350_ROM_CTZ32_ADDR | 1u;
    case ROM_FUNC_REVERSE32: return RP2350_ROM_REVERSE32_ADDR | 1u;
    case ROM_FUNC_POPCOUNT32: return RP2350_ROM_POPCOUNT32_ADDR | 1u;
    default:
        break;
    }
    return RP2350_ROM_UNIMPL_ADDR | 1u;
}

mm_bool mm_rp2350_bootrom_read(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 *value_out)
{
    mm_u32 v = 0u;
    (void)opaque;
    if (value_out == 0 || size_bytes == 0u || size_bytes > 4u) return MM_FALSE;
    if (offset == RP2350_BOOTROM_TABLE_LOOKUP_OFFSET) {
        v = RP2350_ROM_TABLE_LOOKUP_ADDR | 1u;
    }
    if (offset == RP2350_BOOTROM_TABLE_LOOKUP_OFFSET && size_bytes == 2u) {
        *value_out = v & 0xffffu;
        return MM_TRUE;
    }
    if (offset == RP2350_BOOTROM_TABLE_LOOKUP_OFFSET && size_bytes == 1u) {
        *value_out = v & 0xffu;
        return MM_TRUE;
    }
    if (offset == RP2350_BOOTROM_TABLE_LOOKUP_OFFSET + 1u && size_bytes == 1u) {
        *value_out = (v >> 8) & 0xffu;
        return MM_TRUE;
    }
    *value_out = 0u;
    return MM_TRUE;
}

mm_bool mm_rp2350_bootrom_write(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 value)
{
    (void)opaque;
    (void)offset;
    (void)size_bytes;
    (void)value;
    return MM_TRUE;
}

static void rp2350_bootrom_return(struct mm_cpu *cpu)
{
    if (cpu == 0) return;
    cpu->r[15] = cpu->r[14];
}

static mm_u32 bit_reverse32(mm_u32 v)
{
    mm_u32 r = 0u;
    mm_u32 i;
    for (i = 0; i < 32u; ++i) {
        r = (r << 1) | (v & 1u);
        v >>= 1;
    }
    return r;
}

static mm_u32 popcount32(mm_u32 v)
{
    mm_u32 c = 0u;
    while (v != 0u) {
        c += v & 1u;
        v >>= 1;
    }
    return c;
}

static mm_bool rom_memset(struct mm_memmap *map, enum mm_sec_state sec, mm_u32 dst, mm_u8 value, mm_u32 len)
{
    mm_u32 i;
    if (map == 0) return MM_FALSE;
    for (i = 0; i < len; ++i) {
        if (!mm_memmap_write8(map, sec, dst + i, value)) return MM_FALSE;
    }
    return MM_TRUE;
}

static mm_bool rom_memcpy(struct mm_memmap *map, enum mm_sec_state sec, mm_u32 dst, mm_u32 src, mm_u32 len)
{
    mm_u32 i;
    mm_u8 b;
    if (map == 0) return MM_FALSE;
    for (i = 0; i < len; ++i) {
        if (!mm_memmap_read8(map, sec, src + i, &b)) return MM_FALSE;
        if (!mm_memmap_write8(map, sec, dst + i, b)) return MM_FALSE;
    }
    return MM_TRUE;
}

mm_bool mm_rp2350_bootrom_handle(struct mm_cpu *cpu, struct mm_memmap *map)
{
    mm_u32 pc;
    if (cpu == 0 || map == 0) return MM_FALSE;
    if (!mm_rp2350_active()) return MM_FALSE;

    pc = cpu->r[15] & ~1u;
    switch (pc) {
    case RP2350_ROM_TABLE_LOOKUP_ADDR:
        cpu->r[0] = rp2350_bootrom_lookup(cpu->r[0]);
        rp2350_bootrom_return(cpu);
        return MM_TRUE;
    case RP2350_ROM_FLASH_RANGE_ERASE_ADDR:
        (void)mm_rp2350_flash_erase(cpu->r[0], cpu->r[1]);
        rp2350_bootrom_return(cpu);
        return MM_TRUE;
    case RP2350_ROM_FLASH_RANGE_PROGRAM_ADDR:
        (void)mm_rp2350_flash_program(map, cpu->sec_state, cpu->r[0], cpu->r[1], cpu->r[2]);
        rp2350_bootrom_return(cpu);
        return MM_TRUE;
    case RP2350_ROM_FLASH_FLUSH_CACHE_ADDR:
    case RP2350_ROM_CONNECT_INTERNAL_FLASH_ADDR:
    case RP2350_ROM_FLASH_EXIT_XIP_ADDR:
    case RP2350_ROM_FLASH_ENTER_CMD_XIP_ADDR:
    case RP2350_ROM_BOOTROM_STATE_RESET_ADDR:
        rp2350_bootrom_return(cpu);
        return MM_TRUE;
    case RP2350_ROM_MEMSET_ADDR:
        (void)rom_memset(map, cpu->sec_state, cpu->r[0], (mm_u8)cpu->r[1], cpu->r[2]);
        rp2350_bootrom_return(cpu);
        return MM_TRUE;
    case RP2350_ROM_MEMCPY_ADDR:
        (void)rom_memcpy(map, cpu->sec_state, cpu->r[0], cpu->r[1], cpu->r[2]);
        rp2350_bootrom_return(cpu);
        return MM_TRUE;
    case RP2350_ROM_MEMSET4_ADDR:
        (void)rom_memset(map, cpu->sec_state, cpu->r[0], (mm_u8)cpu->r[1], cpu->r[2]);
        rp2350_bootrom_return(cpu);
        return MM_TRUE;
    case RP2350_ROM_MEMCPY44_ADDR:
        (void)rom_memcpy(map, cpu->sec_state, cpu->r[0], cpu->r[1], cpu->r[2]);
        rp2350_bootrom_return(cpu);
        return MM_TRUE;
    case RP2350_ROM_CLZ32_ADDR:
        cpu->r[0] = (cpu->r[0] == 0u) ? 32u : (mm_u32)__builtin_clz(cpu->r[0]);
        rp2350_bootrom_return(cpu);
        return MM_TRUE;
    case RP2350_ROM_CTZ32_ADDR:
        cpu->r[0] = (cpu->r[0] == 0u) ? 32u : (mm_u32)__builtin_ctz(cpu->r[0]);
        rp2350_bootrom_return(cpu);
        return MM_TRUE;
    case RP2350_ROM_REVERSE32_ADDR:
        cpu->r[0] = bit_reverse32(cpu->r[0]);
        rp2350_bootrom_return(cpu);
        return MM_TRUE;
    case RP2350_ROM_POPCOUNT32_ADDR:
        cpu->r[0] = popcount32(cpu->r[0]);
        rp2350_bootrom_return(cpu);
        return MM_TRUE;
    case RP2350_ROM_UNIMPL_ADDR:
        cpu->r[0] = 0u;
        rp2350_bootrom_return(cpu);
        return MM_TRUE;
    default:
        break;
    }
    return MM_FALSE;
}
