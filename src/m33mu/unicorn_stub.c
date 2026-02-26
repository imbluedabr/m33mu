/* m33mu -- an ARMv8-M Emulator
 *
 * Unicorn integration stub (when libunicorn is unavailable).
 */

#include "m33mu/unicorn.h"
#include <stdio.h>

mm_bool mm_unicorn_available(void)
{
    return MM_FALSE;
}

mm_bool mm_unicorn_active(void)
{
    return MM_FALSE;
}

mm_bool mm_unicorn_configure(mm_u32 entry_pc, mm_u32 stack_window, mm_u32 max_steps)
{
    (void)entry_pc;
    (void)stack_window;
    (void)max_steps;
    return MM_FALSE;
}

mm_bool mm_unicorn_maybe_start(struct mm_cpu *cpu, struct mm_memmap *map)
{
    (void)cpu;
    (void)map;
    fprintf(stderr, "Unicorn support not available (built without libunicorn)\n");
    return MM_FALSE;
}

mm_unicorn_step_result mm_unicorn_step_compare(struct mm_cpu *cpu,
                                               struct mm_memmap *map,
                                               const struct mm_fetch_result *fetch,
                                               const struct mm_decoded *dec,
                                               mm_bool execute_it)
{
    (void)cpu;
    (void)map;
    (void)fetch;
    (void)dec;
    (void)execute_it;
    return MM_UNICORN_STEP_OK;
}

void mm_unicorn_stop(void)
{
}

void mm_unicorn_clear_m33mu_write(void)
{
}

void mm_unicorn_record_m33mu_write(enum mm_sec_state sec, mm_u32 addr,
                                   mm_u32 size_bytes, mm_u32 value)
{
    (void)sec;
    (void)addr;
    (void)size_bytes;
    (void)value;
}

void mm_unicorn_snapshot_pre(const struct mm_cpu *cpu)
{
    (void)cpu;
}
