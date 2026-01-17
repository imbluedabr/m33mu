/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include <string.h>
#include <stdlib.h>
#include "rp2350/rp2350_bootrom.h"
#include "rp2350/rp2350_mmio.h"

#define RP2350_BOOTROM_MAGIC_OFFSET 0x10u
#define RP2350_BOOTROM_FUNC_TABLE_OFFSET 0x14u
#define RP2350_BOOTROM_TABLE_LOOKUP_OFFSET 0x16u
#define RP2350_BOOTROM_TABLE_LOOKUP_ENTRY_OFFSET 0x18u

#define RP2350_BOOTROM_MAGIC0 'M'
#define RP2350_BOOTROM_MAGIC1 'u'
#define RP2350_BOOTROM_MAJOR 2u
#define RP2350_BOOTROM_MINOR 4u

#define RP2350_ROM_TABLE_LOOKUP_ADDR 0x00000100u
#define RP2350_ROM_TABLE_LOOKUP_ENTRY_ADDR 0x00000120u
#define RP2350_ROMTABLE_START_ADDR 0x00000400u
#define RP2350_ROM_FLASH_RANGE_ERASE_ADDR 0x00000180u
#define RP2350_ROM_FLASH_RANGE_PROGRAM_ADDR 0x000001a0u
#define RP2350_ROM_FLASH_FLUSH_CACHE_ADDR 0x000001c0u
#define RP2350_ROM_CONNECT_INTERNAL_FLASH_ADDR 0x000001e0u
#define RP2350_ROM_FLASH_EXIT_XIP_ADDR 0x00000200u
#define RP2350_ROM_FLASH_ENTER_CMD_XIP_ADDR 0x00000220u
#define RP2350_ROM_BOOTROM_STATE_RESET_ADDR 0x00000240u
#define RP2350_ROM_DATA_FLASH_DEVINFO_PTR_ADDR 0x00000250u
#define RP2350_ROM_DATA_PARTITION_TABLE_PTR_ADDR 0x00000270u
#define RP2350_ROM_FLASH_OP_ADDR 0x00000380u
#define RP2350_ROM_MEMSET_ADDR 0x00000260u
#define RP2350_ROM_MEMCPY_ADDR 0x00000280u
#define RP2350_ROM_MEMSET4_ADDR 0x000002a0u
#define RP2350_ROM_MEMCPY44_ADDR 0x000002c0u
#define RP2350_ROM_CLZ32_ADDR 0x000002e0u
#define RP2350_ROM_CTZ32_ADDR 0x00000300u
#define RP2350_ROM_REVERSE32_ADDR 0x00000320u
#define RP2350_ROM_POPCOUNT32_ADDR 0x00000340u
#define RP2350_ROM_UNIMPL_ADDR 0x00000360u
#define RP2350_ROM_REBOOT_ADDR 0x000003a0u
#define RP2350_ROM_GET_PARTITION_TABLE_INFO_ADDR 0x000003c0u
#define RP2350_ROM_GET_SYS_INFO_ADDR 0x000003e0u
#define RP2350_ROM_OTP_ACCESS_ADDR 0x00000400u
#define RP2350_ROM_LOAD_PARTITION_TABLE_ADDR 0x00000420u
#define RP2350_ROM_PICK_AB_PARTITION_ADDR 0x00000440u
#define RP2350_ROM_CHAIN_IMAGE_ADDR 0x00000460u
#define RP2350_ROM_GET_B_PARTITION_ADDR 0x00000480u

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
#define ROM_FUNC_FLASH_OP             ROM_TABLE_CODE('F', 'O')
#define ROM_FUNC_REBOOT               ROM_TABLE_CODE('R', 'B')
#define ROM_FUNC_GET_PARTITION_TABLE_INFO ROM_TABLE_CODE('G', 'P')
#define ROM_FUNC_GET_SYS_INFO         ROM_TABLE_CODE('G', 'S')
#define ROM_FUNC_OTP_ACCESS           ROM_TABLE_CODE('O', 'A')
#define ROM_FUNC_LOAD_PARTITION_TABLE ROM_TABLE_CODE('L', 'P')
#define ROM_FUNC_PICK_AB_PARTITION    ROM_TABLE_CODE('A', 'B')
#define ROM_FUNC_CHAIN_IMAGE          ROM_TABLE_CODE('C', 'I')
#define ROM_FUNC_GET_B_PARTITION      ROM_TABLE_CODE('G', 'B')
#define ROM_DATA_FLASH_DEVINFO16_PTR  ROM_TABLE_CODE('F', 'D')
#define ROM_DATA_PARTITION_TABLE_PTR  ROM_TABLE_CODE('P', 'T')

#define RP2350_RT_FLAG_FUNC_ARM_SEC    0x0004u
#define RP2350_RT_FLAG_FUNC_ARM_NONSEC 0x0010u
#define RP2350_RT_FLAG_DATA            0x0040u

#define RP2350_FLASH_XIP_BASE 0x10000000u
#define RP2350_BOOTRAM_BASE 0x400e0000u
#define RP2350_BOOTRAM_FLASH_DEVINFO_OFFSET 0x200u
#define RP2350_BOOTRAM_PARTITION_TABLE_OFFSET 0x0f60u
#define RP2350_CFLASH_OP_BITS 0x00070000u
#define RP2350_CFLASH_OP_LSB  16u
#define RP2350_CFLASH_OP_ERASE 0u
#define RP2350_CFLASH_OP_PROGRAM 1u
#define RP2350_CFLASH_OP_READ 2u
#define RP2350_CFLASH_FLAGS_BITS 0x00070301u
#define RP2350_CFLASH_SECLEVEL_BITS 0x00000300u
#define RP2350_CFLASH_SECLEVEL_LSB 8u
#define RP2350_CFLASH_SECLEVEL_VALUE_SECURE 1u
#define RP2350_CFLASH_OP_MAX 2u

#define RP2350_PICOBIN_PARTITION_PERMISSIONS_BITS 0xfc000000u
#define RP2350_PICOBIN_PARTITION_PERMISSION_S_R_BITS 0x04000000u
#define RP2350_PICOBIN_PARTITION_PERMISSION_S_W_BITS 0x08000000u
#define RP2350_PICOBIN_PARTITION_PERMISSION_NS_R_BITS 0x10000000u
#define RP2350_PICOBIN_PARTITION_PERMISSION_NS_W_BITS 0x20000000u
#define RP2350_PICOBIN_PARTITION_PERMISSION_NSBOOT_R_BITS 0x40000000u
#define RP2350_PICOBIN_PARTITION_PERMISSION_NSBOOT_W_BITS 0x80000000u
#define RP2350_PICOBIN_PARTITION_LOCATION_FIRST_SECTOR_LSB 0u
#define RP2350_PICOBIN_PARTITION_LOCATION_FIRST_SECTOR_BITS 0x00001fffu
#define RP2350_PICOBIN_PARTITION_LOCATION_LAST_SECTOR_LSB 13u
#define RP2350_PICOBIN_PARTITION_LOCATION_LAST_SECTOR_BITS 0x03ffe000u
#define RP2350_PARTITION_TABLE_NO_PARTITION_INDEX 0xffu
#define RP2350_FLASH_SECTOR_SIZE 4096u
#define RP2350_FLASH_PAGE_SIZE 256u

#define RP2350_PT_INFO_PT_INFO 0x0001u
#define RP2350_PT_INFO_SINGLE_PARTITION 0x8000u
#define RP2350_PT_INFO_PARTITION_LOCATION_AND_FLAGS 0x0010u
#define RP2350_PT_INFO_PARTITION_ID 0x0020u
#define RP2350_PT_INFO_PARTITION_FAMILY_IDS 0x0040u
#define RP2350_PT_INFO_PARTITION_NAME 0x0080u

#define RP2350_BOOTROM_OK 0u
#define RP2350_BOOTROM_ERROR_NOT_PERMITTED ((mm_u32)0u - 4u)
#define RP2350_BOOTROM_ERROR_INVALID_ARG ((mm_u32)0u - 5u)
#define RP2350_BOOTROM_ERROR_INVALID_ADDRESS ((mm_u32)0u - 10u)
#define RP2350_BOOTROM_ERROR_BAD_ALIGNMENT ((mm_u32)0u - 11u)
#define RP2350_BOOTROM_ERROR_BUFFER_TOO_SMALL ((mm_u32)0u - 13u)
#define RP2350_BOOTROM_ERROR_PRECONDITION_NOT_MET ((mm_u32)0u - 14u)
#define RP2350_BOOTROM_ERROR_NOT_FOUND ((mm_u32)0u - 17u)

#define RP2350_SYS_INFO_BOOT_INFO 0x0040u

#define RP2350_OTP_CMD_WRITE_BITS 0x00010000u

extern void mm_system_request_reset_boot(int mode);

static mm_u32 rp2350_bootrom_lookup(mm_u32 code, mm_u32 mask)
{
    if ((mask & RP2350_RT_FLAG_DATA) != 0u) {
        switch (code) {
        case ROM_DATA_FLASH_DEVINFO16_PTR: return RP2350_ROM_DATA_FLASH_DEVINFO_PTR_ADDR;
        case ROM_DATA_PARTITION_TABLE_PTR: return RP2350_ROM_DATA_PARTITION_TABLE_PTR_ADDR;
        default:
            break;
        }
        return 0u;
    }
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
    case ROM_FUNC_FLASH_OP: return RP2350_ROM_FLASH_OP_ADDR | 1u;
    case ROM_FUNC_REBOOT: return RP2350_ROM_REBOOT_ADDR | 1u;
    case ROM_FUNC_GET_PARTITION_TABLE_INFO: return RP2350_ROM_GET_PARTITION_TABLE_INFO_ADDR | 1u;
    case ROM_FUNC_GET_SYS_INFO: return RP2350_ROM_GET_SYS_INFO_ADDR | 1u;
    case ROM_FUNC_OTP_ACCESS: return RP2350_ROM_OTP_ACCESS_ADDR | 1u;
    case ROM_FUNC_LOAD_PARTITION_TABLE: return RP2350_ROM_LOAD_PARTITION_TABLE_ADDR | 1u;
    case ROM_FUNC_PICK_AB_PARTITION: return RP2350_ROM_PICK_AB_PARTITION_ADDR | 1u;
    case ROM_FUNC_CHAIN_IMAGE: return RP2350_ROM_CHAIN_IMAGE_ADDR | 1u;
    case ROM_FUNC_GET_B_PARTITION: return RP2350_ROM_GET_B_PARTITION_ADDR | 1u;
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
    if (offset == RP2350_BOOTROM_MAGIC_OFFSET && size_bytes == 1u) {
        *value_out = RP2350_BOOTROM_MAGIC0;
        return MM_TRUE;
    }
    if (offset == RP2350_BOOTROM_MAGIC_OFFSET + 1u && size_bytes == 1u) {
        *value_out = RP2350_BOOTROM_MAGIC1;
        return MM_TRUE;
    }
    if (offset == RP2350_BOOTROM_MAGIC_OFFSET + 2u && size_bytes == 1u) {
        *value_out = RP2350_BOOTROM_MAJOR;
        return MM_TRUE;
    }
    if (offset == RP2350_BOOTROM_MAGIC_OFFSET + 3u && size_bytes == 1u) {
        *value_out = RP2350_BOOTROM_MINOR;
        return MM_TRUE;
    }
    if (offset == RP2350_BOOTROM_FUNC_TABLE_OFFSET) {
        v = RP2350_ROMTABLE_START_ADDR;
    }
    if (offset == RP2350_BOOTROM_TABLE_LOOKUP_OFFSET) {
        v = RP2350_ROM_TABLE_LOOKUP_ADDR | 1u;
    }
    if (offset == RP2350_BOOTROM_TABLE_LOOKUP_ENTRY_OFFSET) {
        v = RP2350_ROM_TABLE_LOOKUP_ENTRY_ADDR | 1u;
    }
    if ((offset == RP2350_BOOTROM_FUNC_TABLE_OFFSET
        || offset == RP2350_BOOTROM_TABLE_LOOKUP_OFFSET
        || offset == RP2350_BOOTROM_TABLE_LOOKUP_ENTRY_OFFSET) && size_bytes == 2u) {
        *value_out = v & 0xffffu;
        return MM_TRUE;
    }
    if ((offset == RP2350_BOOTROM_FUNC_TABLE_OFFSET
        || offset == RP2350_BOOTROM_TABLE_LOOKUP_OFFSET
        || offset == RP2350_BOOTROM_TABLE_LOOKUP_ENTRY_OFFSET) && size_bytes == 1u) {
        *value_out = v & 0xffu;
        return MM_TRUE;
    }
    if ((offset == RP2350_BOOTROM_FUNC_TABLE_OFFSET + 1u
        || offset == RP2350_BOOTROM_TABLE_LOOKUP_OFFSET + 1u
        || offset == RP2350_BOOTROM_TABLE_LOOKUP_ENTRY_OFFSET + 1u) && size_bytes == 1u) {
        *value_out = (v >> 8) & 0xffu;
        return MM_TRUE;
    }
    if (offset == RP2350_ROM_DATA_FLASH_DEVINFO_PTR_ADDR && size_bytes == 4u) {
        *value_out = RP2350_BOOTRAM_BASE + RP2350_BOOTRAM_FLASH_DEVINFO_OFFSET;
        return MM_TRUE;
    }
    if (offset == RP2350_ROM_DATA_PARTITION_TABLE_PTR_ADDR && size_bytes == 4u) {
        *value_out = RP2350_BOOTRAM_BASE + RP2350_BOOTRAM_PARTITION_TABLE_OFFSET;
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

static mm_u32 rp2350_flash_permission_mask(mm_u32 seclevel, mm_bool permission_w)
{
    if (seclevel < RP2350_CFLASH_SECLEVEL_VALUE_SECURE) return 0u;
    return RP2350_PICOBIN_PARTITION_PERMISSION_S_R_BITS <<
           ((permission_w ? 1u : 0u) + 2u * (seclevel - RP2350_CFLASH_SECLEVEL_VALUE_SECURE));
}

static mm_bool rp2350_partition_has_permissions(mm_u32 perm_loc, mm_u32 perm_flags, mm_u32 required)
{
    mm_u32 perms = (perm_loc & perm_flags & RP2350_PICOBIN_PARTITION_PERMISSIONS_BITS);
    return (perms & required) == required ? MM_TRUE : MM_FALSE;
}

static int rp2350_partition_num_for_addr(const struct rp2350_partition_table *pt, mm_u32 addr, mm_u32 flash_size)
{
    mm_u32 sector;
    mm_u32 count;
    mm_u32 i;
    if (pt == 0 || flash_size == 0u) return -1;
    if (addr < RP2350_FLASH_XIP_BASE || addr >= RP2350_FLASH_XIP_BASE + flash_size) return -1;
    sector = (addr - RP2350_FLASH_XIP_BASE) / RP2350_FLASH_SECTOR_SIZE;
    count = pt->permission_partition_count;
    if (count == 0u) {
        count = pt->partition_count;
    }
    if (count > RP2350_PARTITION_TABLE_MAX_PARTITIONS) {
        count = RP2350_PARTITION_TABLE_MAX_PARTITIONS;
    }
    for (i = 0; i < count; ++i) {
        mm_u32 loc = pt->partitions[i].permissions_and_location;
        mm_u32 first = (loc & RP2350_PICOBIN_PARTITION_LOCATION_FIRST_SECTOR_BITS) >>
                       RP2350_PICOBIN_PARTITION_LOCATION_FIRST_SECTOR_LSB;
        mm_u32 last = (loc & RP2350_PICOBIN_PARTITION_LOCATION_LAST_SECTOR_BITS) >>
                      RP2350_PICOBIN_PARTITION_LOCATION_LAST_SECTOR_LSB;
        if (sector >= first && sector <= last) {
            return (int)i;
        }
    }
    return (int)RP2350_PARTITION_TABLE_NO_PARTITION_INDEX;
}

static mm_bool rp2350_flash_span_has_permissions(mm_u32 addr, mm_u32 size_bytes, mm_u32 required)
{
    const struct rp2350_partition_table *pt = mm_rp2350_partition_table_get();
    mm_u32 flash_size = mm_rp2350_flash_size();
    int p_start;
    int p_end;
    if (size_bytes == 0u) return MM_TRUE;
    if (addr < RP2350_FLASH_XIP_BASE || flash_size == 0u) return MM_FALSE;
    if (addr + size_bytes < addr) return MM_FALSE;
    if (addr + size_bytes > RP2350_FLASH_XIP_BASE + flash_size) return MM_FALSE;
    p_start = rp2350_partition_num_for_addr(pt, addr, flash_size);
    p_end = rp2350_partition_num_for_addr(pt, addr + size_bytes - 1u, flash_size);
    if (p_start < 0 || p_end < 0 || p_start != p_end) return MM_FALSE;
    if (p_start == (int)RP2350_PARTITION_TABLE_NO_PARTITION_INDEX) {
        mm_u32 perm_flags = pt ? pt->unpartitioned_space_permissions_and_flags : 0u;
        mm_u32 perm_loc = (perm_flags & RP2350_PICOBIN_PARTITION_PERMISSIONS_BITS) |
                          RP2350_PICOBIN_PARTITION_LOCATION_LAST_SECTOR_BITS;
        return rp2350_partition_has_permissions(perm_loc, perm_flags, required);
    }
    if (pt == 0) return MM_FALSE;
    return rp2350_partition_has_permissions(pt->partitions[p_start].permissions_and_location,
                                           pt->partitions[p_start].permissions_and_flags,
                                           required);
}

static mm_u32 rp2350_flash_op(struct mm_cpu *cpu,
                              struct mm_memmap *map,
                              mm_u32 flags,
                              mm_u32 addr,
                              mm_u32 size_bytes,
                              mm_u32 buf_addr)
{
    mm_u32 op;
    mm_u32 seclevel;
    mm_u32 offs;
    mm_u32 permission_mask;
    mm_bool permission_w;
    if (cpu == 0 || map == 0) return RP2350_BOOTROM_ERROR_INVALID_ARG;
    if (flags & ~RP2350_CFLASH_FLAGS_BITS) return RP2350_BOOTROM_ERROR_INVALID_ARG;
    seclevel = (flags & RP2350_CFLASH_SECLEVEL_BITS) >> RP2350_CFLASH_SECLEVEL_LSB;
    if (seclevel == 0u) return RP2350_BOOTROM_ERROR_INVALID_ARG;
    op = (flags & RP2350_CFLASH_OP_BITS) >> RP2350_CFLASH_OP_LSB;
    if (op > RP2350_CFLASH_OP_MAX) return RP2350_BOOTROM_ERROR_INVALID_ARG;
    if (addr < RP2350_FLASH_XIP_BASE) return RP2350_BOOTROM_ERROR_INVALID_ADDRESS;
    offs = addr - RP2350_FLASH_XIP_BASE;
    permission_w = (op == RP2350_CFLASH_OP_ERASE || op == RP2350_CFLASH_OP_PROGRAM) ? MM_TRUE : MM_FALSE;
    permission_mask = rp2350_flash_permission_mask(seclevel, permission_w);
    if (permission_mask == 0u) return RP2350_BOOTROM_ERROR_INVALID_ARG;
    if (!rp2350_flash_span_has_permissions(addr, size_bytes, permission_mask)) {
        return RP2350_BOOTROM_ERROR_NOT_PERMITTED;
    }
    if (op == RP2350_CFLASH_OP_ERASE) {
        if ((addr & (RP2350_FLASH_SECTOR_SIZE - 1u)) != 0u ||
            (size_bytes & (RP2350_FLASH_SECTOR_SIZE - 1u)) != 0u) {
            return RP2350_BOOTROM_ERROR_BAD_ALIGNMENT;
        }
    } else if (op == RP2350_CFLASH_OP_PROGRAM) {
        if ((addr & (RP2350_FLASH_PAGE_SIZE - 1u)) != 0u ||
            (size_bytes & (RP2350_FLASH_PAGE_SIZE - 1u)) != 0u) {
            return RP2350_BOOTROM_ERROR_BAD_ALIGNMENT;
        }
    }
    switch (op) {
    case RP2350_CFLASH_OP_ERASE:
        if (!mm_rp2350_flash_erase(offs, size_bytes)) return RP2350_BOOTROM_ERROR_INVALID_ARG;
        return RP2350_BOOTROM_OK;
    case RP2350_CFLASH_OP_PROGRAM:
        if (!mm_rp2350_flash_program(map, cpu->sec_state, offs, buf_addr, size_bytes)) {
            return RP2350_BOOTROM_ERROR_INVALID_ARG;
        }
        return RP2350_BOOTROM_OK;
    case RP2350_CFLASH_OP_READ:
    {
        mm_u32 i;
        mm_u8 b = 0xffu;
        for (i = 0; i < size_bytes; ++i) {
            if (!mm_memmap_read8(map, cpu->sec_state, RP2350_FLASH_XIP_BASE + offs + i, &b)) {
                return RP2350_BOOTROM_ERROR_INVALID_ARG;
            }
            if (!mm_memmap_write8(map, cpu->sec_state, buf_addr + i, b)) {
                return RP2350_BOOTROM_ERROR_INVALID_ARG;
            }
        }
        return RP2350_BOOTROM_OK;
    }
    default:
        break;
    }
    return RP2350_BOOTROM_ERROR_INVALID_ARG;
}

static mm_u32 rp2350_partition_table_info(struct mm_memmap *map,
                                          enum mm_sec_state sec,
                                          mm_u32 out_addr,
                                          mm_u32 out_words,
                                          mm_u32 flags_and_partition)
{
    const struct rp2350_partition_table *pt = mm_rp2350_partition_table_get();
    mm_u32 flags = flags_and_partition & 0xffffu;
    mm_u32 partition_index = (flags_and_partition >> 24u) & 0xffu;
    mm_u32 supported = flags & (RP2350_PT_INFO_PT_INFO |
                                RP2350_PT_INFO_PARTITION_LOCATION_AND_FLAGS |
                                RP2350_PT_INFO_PARTITION_ID |
                                RP2350_PT_INFO_PARTITION_FAMILY_IDS |
                                RP2350_PT_INFO_PARTITION_NAME |
                                RP2350_PT_INFO_SINGLE_PARTITION);
    mm_u32 needed = 1u;
    mm_u32 write_idx = 0u;
    mm_u32 flash_size;
    mm_u32 last_sector;
    if (map == 0) return RP2350_BOOTROM_ERROR_INVALID_ARG;
    if ((out_addr & 3u) != 0u) return RP2350_BOOTROM_ERROR_BAD_ALIGNMENT;
    if (pt == 0 || pt->loaded == 0u) return RP2350_BOOTROM_ERROR_PRECONDITION_NOT_MET;
    if ((flags & RP2350_PT_INFO_SINGLE_PARTITION) != 0u) {
        if (partition_index >= pt->partition_count) {
            return RP2350_BOOTROM_ERROR_NOT_FOUND;
        }
    }
    if ((flags & RP2350_PT_INFO_PT_INFO) != 0u) {
        needed += 3u;
    }
    if (out_words < needed) return RP2350_BOOTROM_ERROR_BUFFER_TOO_SMALL;
    (void)mm_memmap_write(map, sec, out_addr + write_idx * 4u, 4u, supported);
    write_idx++;
    if ((flags & RP2350_PT_INFO_PT_INFO) != 0u) {
        mm_u32 count_word = pt->partition_count & 0xffu;
        (void)mm_memmap_write(map, sec, out_addr + write_idx * 4u, 4u, count_word);
        write_idx++;
        flash_size = mm_rp2350_flash_size();
        last_sector = flash_size ? (flash_size / RP2350_FLASH_SECTOR_SIZE) - 1u : 0u;
        (void)mm_memmap_write(map, sec, out_addr + write_idx * 4u, 4u,
                              ((0u << RP2350_PICOBIN_PARTITION_LOCATION_FIRST_SECTOR_LSB) &
                               RP2350_PICOBIN_PARTITION_LOCATION_FIRST_SECTOR_BITS) |
                              ((last_sector << RP2350_PICOBIN_PARTITION_LOCATION_LAST_SECTOR_LSB) &
                               RP2350_PICOBIN_PARTITION_LOCATION_LAST_SECTOR_BITS));
        write_idx++;
        (void)mm_memmap_write(map, sec, out_addr + write_idx * 4u, 4u,
                              pt->unpartitioned_space_permissions_and_flags);
        write_idx++;
    }
    return write_idx;
}

static mm_u32 rp2350_sys_info(struct mm_memmap *map,
                              enum mm_sec_state sec,
                              mm_u32 out_addr,
                              mm_u32 out_words,
                              mm_u32 flags)
{
    const struct rp2350_boot_info *info = mm_rp2350_boot_info_get();
    if (map == 0) return RP2350_BOOTROM_ERROR_INVALID_ARG;
    if ((out_addr & 3u) != 0u) return RP2350_BOOTROM_ERROR_BAD_ALIGNMENT;
    if (flags != RP2350_SYS_INFO_BOOT_INFO) return RP2350_BOOTROM_ERROR_INVALID_ARG;
    if (out_words < 5u) return RP2350_BOOTROM_ERROR_BUFFER_TOO_SMALL;

    (void)mm_memmap_write(map, sec, out_addr + 0u, 4u, RP2350_SYS_INFO_BOOT_INFO);
    (void)mm_memmap_write(map, sec, out_addr + 4u, 4u, (info != 0) ? info->boot_word : 0u);
    (void)mm_memmap_write(map, sec, out_addr + 8u, 4u, (info != 0) ? info->boot_diagnostic : 0u);
    (void)mm_memmap_write(map, sec, out_addr + 12u, 4u, (info != 0) ? info->reboot_params[0] : 0u);
    (void)mm_memmap_write(map, sec, out_addr + 16u, 4u, (info != 0) ? info->reboot_params[1] : 0u);
    return 5u;
}

static mm_u32 rp2350_otp_access(struct mm_cpu *cpu,
                                struct mm_memmap *map,
                                mm_u32 buf_addr,
                                mm_u32 len,
                                mm_u32 flags)
{
    mm_u8 *buf;
    mm_u32 rc;
    mm_u32 i;
    mm_bool write = (flags & RP2350_OTP_CMD_WRITE_BITS) != 0u;
    if (cpu == 0 || map == 0 || len == 0u) return RP2350_BOOTROM_ERROR_INVALID_ARG;
    buf = (mm_u8 *)malloc(len);
    if (buf == 0) return RP2350_BOOTROM_ERROR_INVALID_ARG;
    if (write) {
        for (i = 0; i < len; ++i) {
            if (!mm_memmap_read8(map, cpu->sec_state, buf_addr + i, &buf[i])) {
                free(buf);
                return RP2350_BOOTROM_ERROR_INVALID_ADDRESS;
            }
        }
    } else {
        memset(buf, 0, len);
    }
    rc = mm_rp2350_otp_access(cpu->sec_state, flags, buf, len);
    if (rc == 0u && !write) {
        for (i = 0; i < len; ++i) {
            if (!mm_memmap_write8(map, cpu->sec_state, buf_addr + i, buf[i])) {
                rc = RP2350_BOOTROM_ERROR_INVALID_ADDRESS;
                break;
            }
        }
    }
    free(buf);
    return rc;
}

static mm_u32 rp2350_load_partition_table(mm_u32 workarea_addr, mm_u32 workarea_size, mm_u32 force_reload)
{
    struct rp2350_partition_table *pt = mm_rp2350_partition_table_get_mut();
    (void)workarea_addr;
    (void)workarea_size;
    (void)force_reload;
    if (pt != 0) {
        pt->loaded = 1u;
    }
    return RP2350_BOOTROM_OK;
}

static mm_u32 rp2350_pick_ab_partition(mm_u32 partition_a_num)
{
    return partition_a_num;
}

static mm_u32 rp2350_get_b_partition(mm_u32 partition_a_num)
{
    return partition_a_num;
}

static mm_u32 rp2350_chain_image(mm_u32 image_base, mm_u32 image_size)
{
    (void)image_base;
    (void)image_size;
    mm_system_request_reset_boot(1);
    return RP2350_BOOTROM_OK;
}

mm_bool mm_rp2350_bootrom_handle(struct mm_cpu *cpu, struct mm_memmap *map)
{
    mm_u32 pc;
    if (cpu == 0 || map == 0) return MM_FALSE;
    if (!mm_rp2350_active()) return MM_FALSE;

    pc = cpu->r[15] & ~1u;
    switch (pc) {
    case RP2350_ROM_TABLE_LOOKUP_ADDR:
        cpu->r[0] = rp2350_bootrom_lookup(cpu->r[0], cpu->r[1]);
        rp2350_bootrom_return(cpu);
        return MM_TRUE;
    case RP2350_ROM_TABLE_LOOKUP_ENTRY_ADDR:
        cpu->r[0] = rp2350_bootrom_lookup(cpu->r[0], cpu->r[1]);
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
    case RP2350_ROM_REBOOT_ADDR:
        (void)mm_rp2350_flash_erase_all();
        mm_system_request_reset_boot(0);
        rp2350_bootrom_return(cpu);
        return MM_TRUE;
    case RP2350_ROM_FLASH_OP_ADDR:
        cpu->r[0] = rp2350_flash_op(cpu, map, cpu->r[0], cpu->r[1], cpu->r[2], cpu->r[3]);
        rp2350_bootrom_return(cpu);
        return MM_TRUE;
    case RP2350_ROM_GET_PARTITION_TABLE_INFO_ADDR:
        cpu->r[0] = rp2350_partition_table_info(map, cpu->sec_state, cpu->r[0], cpu->r[1], cpu->r[2]);
        rp2350_bootrom_return(cpu);
        return MM_TRUE;
    case RP2350_ROM_GET_SYS_INFO_ADDR:
        cpu->r[0] = rp2350_sys_info(map, cpu->sec_state, cpu->r[0], cpu->r[1], cpu->r[2]);
        rp2350_bootrom_return(cpu);
        return MM_TRUE;
    case RP2350_ROM_OTP_ACCESS_ADDR:
        cpu->r[0] = rp2350_otp_access(cpu, map, cpu->r[0], cpu->r[1], cpu->r[2]);
        rp2350_bootrom_return(cpu);
        return MM_TRUE;
    case RP2350_ROM_LOAD_PARTITION_TABLE_ADDR:
        cpu->r[0] = rp2350_load_partition_table(cpu->r[0], cpu->r[1], cpu->r[2]);
        rp2350_bootrom_return(cpu);
        return MM_TRUE;
    case RP2350_ROM_PICK_AB_PARTITION_ADDR:
        cpu->r[0] = rp2350_pick_ab_partition(cpu->r[2]);
        rp2350_bootrom_return(cpu);
        return MM_TRUE;
    case RP2350_ROM_GET_B_PARTITION_ADDR:
        cpu->r[0] = rp2350_get_b_partition(cpu->r[0]);
        rp2350_bootrom_return(cpu);
        return MM_TRUE;
    case RP2350_ROM_CHAIN_IMAGE_ADDR:
        cpu->r[0] = rp2350_chain_image(cpu->r[2], cpu->r[3]);
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
