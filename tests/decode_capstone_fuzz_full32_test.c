/* m33mu -- an ARMv8-M Emulator
 *
 * Copyright (C) 2026  Daniele Lacamera <root@danielinux.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include "m33mu/capstone.h"
#include "m33mu/cpu.h"
#include "m33mu/decode.h"
#include "m33mu/fetch.h"
#include "m33mu/mem.h"

static volatile sig_atomic_t g_alarm_fired = 0;

static void on_alarm(int sig)
{
    (void)sig;
    g_alarm_fired = 1;
    (void)signal(SIGALRM, on_alarm);
    (void)alarm(5);
}

static int parse_u32(const char *s, mm_u32 *out)
{
    char *end = 0;
    unsigned long val;

    if (s == 0 || s[0] == '\0') return 1;
    val = strtoul(s, &end, 0);
    if (end == s || *end != '\0') return 1;
    if (val > 0xfffffffful) return 1;
    *out = (mm_u32)val;
    return 0;
}

static void maybe_print_progress(mm_u64 tested, mm_u64 total, unsigned long hits)
{
    if (!g_alarm_fired) {
        return;
    }
    g_alarm_fired = 0;
    fprintf(stderr, "progress: tested=%llu total=%llu hits=%lu (%.2f%%)\n",
            (unsigned long long)tested,
            (unsigned long long)total,
            hits,
            total ? (100.0 * (double)tested / (double)total) : 0.0);
}

static int capstone_should_skip(const char *mnemonic, const char *op_str)
{
    static const char *const msr_allowed[] = {
        "apsr", "iapsr", "eapsr", "xpsr",
        "msp", "psp",
        "primask", "basepri", "faultmask", "control"
    };

    if (mnemonic == 0 || op_str == 0) {
        return 0;
    }
    if (mnemonic[0] == 'v') {
        const char *p = op_str;
        while (*p != '\0') {
            if (*p == 'd' || *p == 'D') {
                char *end = 0;
                long dnum = strtol(p + 1, &end, 10);
                if (end != p + 1 && dnum >= 16) {
                    return 1;
                }
                p = end;
                continue;
            }
            p++;
        }
        p = op_str;
        while (*p != '\0') {
            if (*p == 'q' || *p == 'Q') {
                return 1;
            }
            p++;
        }
        if (strchr(mnemonic, '.') != 0 && strstr(mnemonic, ".f32") == 0) {
            return 1;
        }
    }
    if (strncmp(mnemonic, "vmov.", 5) == 0) {
        return 1;
    }
    if (strncmp(mnemonic, "vcvt", 4) == 0) {
        if (strstr(mnemonic, ".s16") != 0 || strstr(mnemonic, ".u16") != 0) {
            return 1;
        }
        if (strstr(op_str, "#") != 0) {
            return 1;
        }
    }
    if (strstr(mnemonic, ".f32") != 0) {
        if (strstr(op_str, "d") != 0 || strstr(op_str, "D") != 0) {
            return 1;
        }
    }
    if (strstr(mnemonic, ".i") != 0) {
        return 1;
    }
    if (strcmp(mnemonic, "vmsr") == 0 || strcmp(mnemonic, "vmrs") == 0) {
        if (strstr(op_str, "fpscr") == 0 && strstr(op_str, "FPSCR") == 0) {
            return 1;
        }
    }
    if (strstr(mnemonic, ".16") != 0 || strstr(mnemonic, ".f16") != 0 || strstr(mnemonic, ".f64") != 0) {
        return 1;
    }
    if (strcmp(mnemonic, "mvn") == 0 || strcmp(mnemonic, "mvn.w") == 0 ||
        strcmp(mnemonic, "mvns") == 0 || strcmp(mnemonic, "mvns.w") == 0) {
        if (strstr(op_str, "pc") != 0 || strstr(op_str, "PC") != 0) {
            return 1;
        }
    }
    if (strcmp(mnemonic, "msr") == 0 || strcmp(mnemonic, "mrs") == 0) {
        size_t i;
        for (i = 0; i < (sizeof(msr_allowed) / sizeof(msr_allowed[0])); ++i) {
            if (strstr(op_str, msr_allowed[i]) != 0) {
                return 0;
            }
        }
        return 1;
    }
    if (strncmp(mnemonic, "cps", 3) == 0) {
        if (strstr(op_str, "#") != 0 || strstr(op_str, "none") != 0 || strstr(mnemonic, ".w") != 0) {
            return 1;
        }
    }
    if (strcmp(mnemonic, "blx") == 0 || strcmp(mnemonic, "blx.w") == 0) {
        if (strstr(op_str, "#") != 0) {
            return 1;
        }
    }
    if (strcmp(mnemonic, "ubfx") == 0 || strcmp(mnemonic, "sbfx") == 0 ||
        strcmp(mnemonic, "bfi") == 0 || strcmp(mnemonic, "bfc") == 0) {
        if (strstr(op_str, "pc") != 0 || strstr(op_str, "PC") != 0) {
            return 1;
        }
    }
    if (strncmp(mnemonic, "ldrb", 4) == 0 || strncmp(mnemonic, "strb", 4) == 0) {
        if (strstr(op_str, "pc") != 0 || strstr(op_str, "PC") != 0) {
            return 1;
        }
    }
    if (strncmp(mnemonic, "strh", 4) == 0) {
        if (strstr(op_str, "sp") != 0 || strstr(op_str, "SP") != 0 ||
            strstr(op_str, "pc") != 0 || strstr(op_str, "PC") != 0) {
            return 1;
        }
    }
    if (strncmp(mnemonic, "ldrh", 4) == 0) {
        if (strstr(op_str, "pc") != 0 || strstr(op_str, "PC") != 0) {
            return 1;
        }
    }
    if (strncmp(mnemonic, "ldrsh", 5) == 0) {
        if (strstr(op_str, "],") != 0 || strstr(op_str, "!") != 0 ||
            strstr(op_str, "pc") != 0 || strstr(op_str, "PC") != 0) {
            return 1;
        }
    }
    if (strncmp(mnemonic, "sxth", 4) == 0 || strncmp(mnemonic, "sxtb", 4) == 0 ||
        strncmp(mnemonic, "uxth", 4) == 0 || strncmp(mnemonic, "uxtb", 4) == 0) {
        if (strstr(op_str, "pc") != 0 || strstr(op_str, "PC") != 0) {
            return 1;
        }
    }
    if (strcmp(mnemonic, "mla") == 0 || strcmp(mnemonic, "mls") == 0) {
        if (strstr(op_str, "pc") != 0 || strstr(op_str, "PC") != 0) {
            return 1;
        }
    }
    if (strcmp(mnemonic, "mul") == 0 || strcmp(mnemonic, "mul.w") == 0) {
        if (strstr(op_str, "pc") != 0 || strstr(op_str, "PC") != 0) {
            return 1;
        }
    }
    if (strncmp(mnemonic, "sml", 3) == 0) {
        if (strstr(op_str, "pc") != 0 || strstr(op_str, "PC") != 0) {
            return 1;
        }
    }
    if (strcmp(mnemonic, "smull") == 0 || strcmp(mnemonic, "umull") == 0 ||
        strcmp(mnemonic, "smlal") == 0 || strcmp(mnemonic, "umlal") == 0) {
        if (strstr(op_str, "pc") != 0 || strstr(op_str, "PC") != 0) {
            return 1;
        }
    }
    if (strcmp(mnemonic, "umaal") == 0) {
        if (strstr(op_str, "pc") != 0 || strstr(op_str, "PC") != 0) {
            return 1;
        }
    }
    if (strcmp(mnemonic, "sdiv") == 0 || strcmp(mnemonic, "udiv") == 0) {
        if (strstr(op_str, "pc") != 0 || strstr(op_str, "PC") != 0) {
            return 1;
        }
    }
    if (strncmp(mnemonic, "ldrsb", 5) == 0) {
        if (strstr(op_str, "],") != 0 || strstr(op_str, "!") != 0 ||
            strstr(op_str, "pc") != 0 || strstr(op_str, "PC") != 0) {
            return 1;
        }
    }
    return 0;
}

static int run_range(mm_u32 start, mm_u32 end)
{
    struct mm_mem mem;
    struct mm_cpu cpu;
    struct mm_fetch_result fetch;
    struct mm_decoded dec;
    mm_u8 bytes[4];
    mm_u32 insn;
    mm_u32 low;
    mm_u32 high;
    mm_u32 start_low;
    mm_u32 start_high;
    mm_u32 end_low;
    mm_u32 end_high;
    int failures = 0;
    unsigned long hits = 0;
    char mnemonic[64];
    char op_str[160];
    int cap_id = 0;
    int cap_ok;
    mm_u64 tested = 0;
    mm_u64 total = 0;

    mem.base = 0;
    mem.length = 4;
    mem.buffer = bytes;
    cpu.xpsr = 0;

    for (mm_u32 r = 0; r < 16u; ++r) {
        cpu.r[r] = 0u;
    }

    start_low = start & 0xffffu;
    start_high = (start >> 16) & 0xffffu;
    end_low = end & 0xffffu;
    end_high = (end >> 16) & 0xffffu;
    total = (mm_u64)end - (mm_u64)start + 1ull;
    for (low = 0u; low <= 0xffffu; ++low) {
        mm_u32 min_high;
        mm_u32 max_high;
        mm_u32 first_high;
        mm_u64 skip;

        min_high = start_high + ((low < start_low) ? 1u : 0u);
        max_high = end_high - ((low > end_low) ? 1u : 0u);
        if (min_high > max_high) {
            continue;
        }
        first_high = min_high;

        bytes[0] = (mm_u8)(low & 0xffu);
        bytes[1] = (mm_u8)((low >> 8) & 0xffu);
        bytes[2] = (mm_u8)(first_high & 0xffu);
        bytes[3] = (mm_u8)((first_high >> 8) & 0xffu);

        cpu.r[15] = 1u;
        fetch = mm_fetch_t32(&cpu, &mem);
        if (fetch.fault) {
            continue;
        }

        if (fetch.len == 2u) {
            skip = (mm_u64)max_high - (mm_u64)min_high + 1ull;
            insn = (first_high << 16) | low;
            tested += skip;
            maybe_print_progress(tested, total, hits);
            cap_ok = capstone_decode_one(&fetch, &cap_id, mnemonic, sizeof(mnemonic), op_str, sizeof(op_str));
            if (!cap_ok) {
                continue;
            }
            if (capstone_should_skip(mnemonic, op_str)) {
                continue;
            }

            hits++;
            /* printf("HIT insn=0x%08lx raw=0x%08lx len=%u capstone=%s %s\n",
                   (unsigned long)insn,
                   (unsigned long)fetch.insn,
                   (unsigned)fetch.len,
                   mnemonic,
                   op_str); */

            dec = mm_decode_t32(&fetch);
            if (!capstone_cross_check(&fetch, &dec)) {
                const char *reason = (dec.kind == MM_OP_UNDEFINED) ? "unknown decode" : "misdecode";
                printf("MISS insn=0x%08lx raw=0x%08lx len=%u capstone=%s %s reason=%s mm_kind=%u rd=%u rn=%u rm=%u imm=0x%08lx\n",
                       (unsigned long)insn,
                       (unsigned long)fetch.insn,
                       (unsigned)fetch.len,
                       mnemonic,
                       op_str,
                       reason,
                       (unsigned)dec.kind,
                       (unsigned)dec.rd,
                       (unsigned)dec.rn,
                       (unsigned)dec.rm,
                       (unsigned long)dec.imm);
                failures = 1;
                break;
            }
            continue;
        }

        for (high = first_high; high <= max_high; ++high) {
            insn = (high << 16) | low;
            bytes[2] = (mm_u8)((insn >> 16) & 0xffu);
            bytes[3] = (mm_u8)((insn >> 24) & 0xffu);

            cpu.r[15] = 1u;
            fetch = mm_fetch_t32(&cpu, &mem);
            if (fetch.fault) {
                tested++;
                maybe_print_progress(tested, total, hits);
                continue;
            }

            tested++;
            maybe_print_progress(tested, total, hits);

            cap_ok = capstone_decode_one(&fetch, &cap_id, mnemonic, sizeof(mnemonic), op_str, sizeof(op_str));
            if (!cap_ok) {
                continue;
            }
            if (capstone_should_skip(mnemonic, op_str)) {
                continue;
            }

            hits++;
            /* printf("HIT insn=0x%08lx raw=0x%08lx len=%u capstone=%s %s\n",
                   (unsigned long)insn,
                   (unsigned long)fetch.insn,
                   (unsigned)fetch.len,
                   mnemonic,
                   op_str); */

            dec = mm_decode_t32(&fetch);
            if (!capstone_cross_check(&fetch, &dec)) {
                const char *reason = (dec.kind == MM_OP_UNDEFINED) ? "unknown decode" : "misdecode";
                printf("MISS insn=0x%08lx raw=0x%08lx len=%u capstone=%s %s reason=%s mm_kind=%u rd=%u rn=%u rm=%u imm=0x%08lx\n",
                       (unsigned long)insn,
                       (unsigned long)fetch.insn,
                       (unsigned)fetch.len,
                       mnemonic,
                       op_str,
                       reason,
                       (unsigned)dec.kind,
                       (unsigned)dec.rd,
                       (unsigned)dec.rn,
                       (unsigned)dec.rm,
                       (unsigned long)dec.imm);
                failures = 1;
                break;
            }
        }

        if (failures != 0) {
            break;
        }
    }

    return failures;
}

int main(int argc, char **argv)
{
    int res;
    int i;
    mm_u32 start = 0u;
    mm_u32 end = 0xffffffffu;

    if (!capstone_available() || !capstone_init()) {
        printf("decode_capstone_fuzz_full32_test: capstone not available\n");
        return 0;
    }
    (void)capstone_set_enabled(MM_TRUE);

    if (signal(SIGALRM, on_alarm) == SIG_ERR) {
        fprintf(stderr, "decode_capstone_fuzz_full32_test: failed to set alarm handler\n");
    } else {
        (void)alarm(5);
    }

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--start") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "decode_capstone_fuzz_full32_test: --start requires a value\n");
                return 1;
            }
            if (parse_u32(argv[i + 1], &start) != 0) {
                fprintf(stderr, "decode_capstone_fuzz_full32_test: invalid --start value '%s'\n", argv[i + 1]);
                return 1;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--end") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "decode_capstone_fuzz_full32_test: --end requires a value\n");
                return 1;
            }
            if (parse_u32(argv[i + 1], &end) != 0) {
                fprintf(stderr, "decode_capstone_fuzz_full32_test: invalid --end value '%s'\n", argv[i + 1]);
                return 1;
            }
            i++;
            continue;
        }
        fprintf(stderr, "decode_capstone_fuzz_full32_test: unknown arg '%s'\n", argv[i]);
        return 1;
    }

    if (start > end) {
        fprintf(stderr, "decode_capstone_fuzz_full32_test: --start must be <= --end\n");
        capstone_shutdown();
        return 1;
    }

    printf("decode_capstone_fuzz_full32_test: start=0x%08x end=0x%08x\n",
           (unsigned)start, (unsigned)end);
    res = run_range(start, end);
    capstone_shutdown();
    return res;
}
