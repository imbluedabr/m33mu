#!/usr/bin/env python3
"""Compare m33mu [TRACE_LIVE] windows against Unicorn execution.

This script parses an m33mu log that contains one or more [RECORD_START] blocks
and [TRACE_LIVE] windows (emitted by --record-start + --record-window). For each
recorded segment it replays the recorded state in Unicorn and compares per-step
PC and register values against m33mu's trace.
"""

import argparse
import re
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_LITTLE_ENDIAN, UcError
from unicorn.arm_const import *

IT_MASK_PATTERN_EVEN = {
    0x8: [1],
    0x4: [1, 1],
    0xC: [1, 0],
    0x2: [1, 1, 1],
    0x6: [1, 1, 0],
    0xA: [1, 0, 1],
    0xE: [1, 0, 0],
    0x1: [1, 1, 1, 1],
    0x3: [1, 1, 1, 0],
    0x5: [1, 1, 0, 1],
    0x7: [1, 1, 0, 0],
    0x9: [1, 0, 1, 1],
    0xB: [1, 0, 1, 0],
    0xD: [1, 0, 0, 1],
    0xF: [1, 0, 0, 0],
}

IT_MASK_PATTERN_ODD = {
    0x8: [1],
    0xC: [1, 1],
    0x4: [1, 0],
    0xE: [1, 1, 1],
    0xA: [1, 1, 0],
    0x6: [1, 0, 1],
    0x2: [1, 0, 0],
    0xF: [1, 1, 1, 1],
    0xD: [1, 1, 1, 0],
    0xB: [1, 1, 0, 1],
    0x9: [1, 1, 0, 0],
    0x7: [1, 0, 1, 1],
    0x5: [1, 0, 1, 0],
    0x3: [1, 0, 0, 1],
    0x1: [1, 0, 0, 0],
}


def cond_pass(cond, cpsr):
    n = 1 if (cpsr & (1 << 31)) else 0
    z = 1 if (cpsr & (1 << 30)) else 0
    c = 1 if (cpsr & (1 << 29)) else 0
    v = 1 if (cpsr & (1 << 28)) else 0

    if cond == 0x0:  # EQ
        return z == 1
    if cond == 0x1:  # NE
        return z == 0
    if cond == 0x2:  # CS/HS
        return c == 1
    if cond == 0x3:  # CC/LO
        return c == 0
    if cond == 0x4:  # MI
        return n == 1
    if cond == 0x5:  # PL
        return n == 0
    if cond == 0x6:  # VS
        return v == 1
    if cond == 0x7:  # VC
        return v == 0
    if cond == 0x8:  # HI
        return c == 1 and z == 0
    if cond == 0x9:  # LS
        return c == 0 or z == 1
    if cond == 0xA:  # GE
        return n == v
    if cond == 0xB:  # LT
        return n != v
    if cond == 0xC:  # GT
        return z == 0 and n == v
    if cond == 0xD:  # LE
        return z == 1 or n != v
    if cond == 0xE:  # AL
        return True
    return False


def parse_segments(log_path: Path):
    segments = []
    cur = None
    cur_addr = None
    cur_buf = bytearray()

    capture_mode = 'start'
    end_capture_ok = False
    with log_path.open('r', errors='ignore') as f:
        for line in f:
            m = re.search(r"\[RECORD_START\] pc=0x([0-9a-fA-F]+)", line)
            if m:
                if cur is not None:
                    if cur_addr is not None and cur_buf:
                        cur['mem'][cur_addr] = bytes(cur_buf)
                    segments.append(cur)
                cur = {'pc': int(m.group(1), 16), 'regs': None, 'mem': {}, 'mem_end': {}, 'trace': [], 'window_steps': None}
                cur_addr = None
                cur_buf = bytearray()
                capture_mode = 'start'
                end_capture_ok = False
                continue
            if cur is None:
                continue
            m = re.search(r"\[RECORD_START_REGS\] (.*)", line)
            if m:
                regs = {}
                for part in m.group(1).split():
                    if '=' in part:
                        k, v = part.split('=')
                        regs[k] = int(v, 16)
                cur['regs'] = regs
                continue
            if line.startswith('[RECORD_WINDOW]'):
                m = re.search(r"steps=(\d+)", line)
                if m and cur is not None:
                    try:
                        cur['window_steps'] = int(m.group(1))
                    except ValueError:
                        cur['window_steps'] = None
                if cur_addr is not None and cur_buf:
                    if capture_mode == 'start':
                        cur['mem'][cur_addr] = bytes(cur_buf)
                    elif capture_mode == 'end':
                        if end_capture_ok:
                            cur['mem_end'][cur_addr] = bytes(cur_buf)
                cur_addr = None
                cur_buf = bytearray()
                capture_mode = 'end'
                end_capture_ok = False
                continue
            if line.startswith('[BKPT_DUMP]') and capture_mode in ('start', 'end'):
                if 'addr=' in line and 'len=' in line:
                    if cur_addr is not None and cur_buf:
                        if capture_mode == 'start':
                            cur['mem'][cur_addr] = bytes(cur_buf)
                        else:
                            if end_capture_ok:
                                cur['mem_end'][cur_addr] = bytes(cur_buf)
                    cur_buf = bytearray()
                    m = re.search(r"addr=0x([0-9a-fA-F]+) len=(\d+)", line)
                    if m:
                        cur_addr = int(m.group(1), 16)
                    else:
                        cur_addr = None
                    if capture_mode == 'end':
                        end_capture_ok = ('record_ram_ns_end' in line or 'record_ram_s_end' in line)
                elif 'read fault' in line:
                    cur_addr = None
                    cur_buf = bytearray()
                elif cur_addr is not None:
                    m = re.search(r"0x[0-9a-fA-F]+: (.*)", line)
                    if m:
                        for b in m.group(1).strip().split():
                            try:
                                cur_buf.append(int(b, 16))
                            except ValueError:
                                # Ignore malformed tokens from interleaved output.
                                continue
                continue
            if line.startswith('[TRACE_LIVE]'):
                m = re.search(r"pc=0x([0-9a-fA-F]+) len=(\d+) insn=0x([0-9a-fA-F]+) (.*) exec=(\d+)", line)
                if m:
                    pc = int(m.group(1), 16)
                    insn_len = int(m.group(2))
                    insn = int(m.group(3), 16)
                    rest = m.group(4)
                    exec_flag = int(m.group(5))
                    regs_map = {}
                    for part in rest.split():
                        if '=' in part:
                            k, v = part.split('=')
                            if k in ('sp', 'lr', 'xpsr') or k.startswith('r'):
                                regs_map[k] = int(v, 16)
                    cur['trace'].append({'pc': pc, 'len': insn_len, 'insn': insn, 'regs': regs_map, 'exec': exec_flag})
                    capture_mode = 'none'

    if cur is not None:
        if cur_addr is not None and cur_buf:
            if capture_mode == 'start':
                cur['mem'][cur_addr] = bytes(cur_buf)
            elif capture_mode == 'end':
                cur['mem_end'][cur_addr] = bytes(cur_buf)
        segments.append(cur)
    return segments


def setup_unicorn(app_bin: Path, mem_blocks, regs, pc):
    blob = app_bin.read_bytes()
    flash_base = 0x08000000
    flash_size = (len(blob) + 0xFFF) & ~0xFFF

    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_LITTLE_ENDIAN)
    uc.mem_map(flash_base, flash_size)
    uc.mem_write(flash_base, blob)

    mapped = [(flash_base, flash_base + flash_size)]

    def map_region(base, size):
        start = base & ~0xFFF
        end = (base + size + 0xFFF) & ~0xFFF
        for mstart, mend in mapped:
            if start < mend and end > mstart:
                return
        uc.mem_map(start, end - start)
        mapped.append((start, end))

    # Default RAM map for common cases; additional ranges are mapped on demand.
    map_region(0x20000000, 0x00100000)

    for addr, data in mem_blocks.items():
        map_region(addr, len(data))
        uc.mem_write(addr, data)

    for r in range(13):
        uc.reg_write(UC_ARM_REG_R0 + r, regs[f'r{r}'])
    uc.reg_write(UC_ARM_REG_SP, regs['sp'])
    uc.reg_write(UC_ARM_REG_LR, regs['lr'])
    uc.reg_write(UC_ARM_REG_PC, pc | 1)

    # Seed CPSR with APSR (NZCV) + ITSTATE bits; Unicorn uses ARM CPSR layout.
    cpsr = (regs['xpsr'] & 0xF8000000) | (regs['xpsr'] & 0x0600FC00) | 0x20
    uc.reg_write(UC_ARM_REG_CPSR, cpsr)

    debug_mem = None
    debug_len = 16
    env = __import__('os').environ
    if 'UNICORN_DEBUG_MEM' in env:
        parts = env['UNICORN_DEBUG_MEM'].split(',')
        try:
            debug_mem = int(parts[0], 16)
            if len(parts) > 1:
                debug_len = int(parts[1], 0)
        except ValueError:
            debug_mem = None
    if debug_mem is not None:
        try:
            data = uc.mem_read(debug_mem, debug_len)
            print(f'[DEBUG_MEM] addr=0x{debug_mem:08x} len={debug_len} data={data.hex()}')
        except UcError as e:
            print(f'[DEBUG_MEM] addr=0x{debug_mem:08x} len={debug_len} error={e}')

    return uc


def compare_segment(uc, trace, mem_end=None, max_steps=None, step_count=None):
    mismatch = None
    steps = 0
    it_cond = None
    it_pattern = None
    it_index = 0
    prev_ipsr_nonzero = False

    def resync_from_trace(entry):
        regs = entry['regs']
        for r in range(13):
            key = f'r{r}'
            if key in regs:
                uc.reg_write(UC_ARM_REG_R0 + r, regs[key])
        if 'sp' in regs:
            uc.reg_write(UC_ARM_REG_SP, regs['sp'])
        if 'lr' in regs:
            uc.reg_write(UC_ARM_REG_LR, regs['lr'])
        uc.reg_write(UC_ARM_REG_PC, entry['pc'] | 1)
        if 'xpsr' in regs:
            cpsr = (regs['xpsr'] & 0xF8000000) | (regs['xpsr'] & 0x0600FC00) | 0x20
            uc.reg_write(UC_ARM_REG_CPSR, cpsr)

    if trace:
        for i, entry in enumerate(trace):
            if max_steps is not None and steps >= max_steps:
                break

            mpc = entry['pc']
            mregs = entry['regs']
            cur_ipsr_nonzero = False
            if 'xpsr' in mregs and (mregs['xpsr'] & 0x1ff):
                cur_ipsr_nonzero = True
            if cur_ipsr_nonzero:
                resync_from_trace(entry)
                it_pattern = None
                it_cond = None
                it_index = 0
                steps += 1
                prev_ipsr_nonzero = True
                continue
            if prev_ipsr_nonzero:
                resync_from_trace(entry)
                it_pattern = None
                it_cond = None
                it_index = 0
                prev_ipsr_nonzero = False
            prev_ipsr_nonzero = False
            upc = uc.reg_read(UC_ARM_REG_PC) & ~1
            if upc != mpc:
                if 'xpsr' in mregs and (mregs['xpsr'] & 0x1ff):
                    resync_from_trace(entry)
                    steps += 1
                    continue
                mismatch = ('pc', i, hex(mpc), hex(upc))
                break

            for r in range(13):
                name = f'r{r}'
                uval = uc.reg_read(UC_ARM_REG_R0 + r)
                if name in mregs and mregs[name] != uval:
                    mismatch = (name, i, hex(mregs[name]), hex(uval), hex(mpc))
                    break
            if mismatch:
                break

            if 'sp' in mregs and mregs['sp'] != uc.reg_read(UC_ARM_REG_SP):
                mismatch = ('sp', i, hex(mregs['sp']), hex(uc.reg_read(UC_ARM_REG_SP)), hex(mpc))
                break
            if 'lr' in mregs and mregs['lr'] != uc.reg_read(UC_ARM_REG_LR):
                mismatch = ('lr', i, hex(mregs['lr']), hex(uc.reg_read(UC_ARM_REG_LR)), hex(mpc))
                break

            # Handle IT instruction manually (Unicorn does not model IT state).
            if (entry['insn'] & 0xff00) == 0xbf00 and (entry['insn'] & 0x000f) != 0x0:
                mask = entry['insn'] & 0x000f
                it_cond = (entry['insn'] >> 4) & 0x0f
                it_map = IT_MASK_PATTERN_ODD if (it_cond & 1) else IT_MASK_PATTERN_EVEN
                it_pattern = it_map.get(mask)
                it_index = 0
                if it_pattern is None:
                    mismatch = ('it_mask', i, hex(mask), hex(mpc))
                    break
                upc = uc.reg_read(UC_ARM_REG_PC) & ~1
                uc.reg_write(UC_ARM_REG_PC, (upc + entry['len']) | 1)
                steps += 1
                continue

            expected_exec = True
            if it_pattern is not None and it_index < len(it_pattern):
                cpsr = uc.reg_read(UC_ARM_REG_CPSR)
                cond = it_cond if it_pattern[it_index] else (it_cond ^ 1)
                expected_exec = cond_pass(cond, cpsr)
                it_index += 1
                if it_index >= len(it_pattern):
                    it_pattern = None
                    it_cond = None
                    it_index = 0

            if entry['exec'] != (1 if expected_exec else 0):
                mismatch = ('it_exec', i, expected_exec, entry['exec'], hex(mpc))
                break

            try:
                if expected_exec:
                    uc.emu_start((upc | 1), 0, count=1)
                else:
                    uc.reg_write(UC_ARM_REG_PC, (upc + entry['len']) | 1)
            except UcError as e:
                # Treat BKPT as expected stop (Unicorn reports as exception).
                if (entry['insn'] & 0xff00) == 0xbe00:
                    return None
                mismatch = ('uc_error', i, str(e), hex(mpc))
                break

            steps += 1
    elif step_count is not None:
        try:
            uc.emu_start(uc.reg_read(UC_ARM_REG_PC) | 1, 0, count=step_count)
        except UcError as e:
            mismatch = ('uc_error', 0, str(e))

    if mismatch is None and mem_end:
        for addr, data in mem_end.items():
            try:
                got = uc.mem_read(addr, len(data))
            except UcError as e:
                if 'READ_UNMAPPED' in str(e) or 'UC_ERR_READ_UNMAPPED' in str(e):
                    continue
                return ('mem_read', hex(addr), str(e))
            if got != data:
                for i, (a, b) in enumerate(zip(data, got)):
                    if a != b:
                        return ('mem_diff', hex(addr + i), hex(a), hex(b))
                return ('mem_diff', hex(addr), 'mismatch', 'unknown')

    return mismatch


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--log', required=True, help='m33mu log with RECORD_START/TRACE_LIVE')
    ap.add_argument('--bin', required=True, help='firmware app.bin path')
    ap.add_argument('--segment', type=int, default=0, help='segment index to compare (default: 0)')
    ap.add_argument('--max-steps', type=int, default=50, help='limit compare steps per segment (default: 50)')
    ap.add_argument('--steps', type=int, default=None, help='execute this many steps when no trace is present')
    ap.add_argument('--ignore-secure-ram', action='store_true', help='ignore 0x30000000 RAM blocks in mem compares')
    args = ap.parse_args()

    segments = parse_segments(Path(args.log))
    if args.segment is not None:
        if args.segment < 0 or args.segment >= len(segments):
            raise SystemExit(f'segment index out of range: {args.segment} (segments={len(segments)})')
        segments = [segments[args.segment]]

    for idx, seg in enumerate(segments):
        if not seg['regs']:
            print(f'segment {idx}: skipped (missing regs)')
            continue
        mem_blocks = seg['mem']
        mem_end = seg.get('mem_end')
        if args.ignore_secure_ram:
            mem_blocks = {addr: data for addr, data in mem_blocks.items() if not (0x30000000 <= addr < 0x40000000)}
            if mem_end:
                mem_end = {addr: data for addr, data in mem_end.items() if not (0x30000000 <= addr < 0x40000000)}
        uc = setup_unicorn(Path(args.bin), mem_blocks, seg['regs'], seg['pc'])
        step_count = args.steps if args.steps is not None else seg.get('window_steps')
        mismatch = compare_segment(uc, seg['trace'], mem_end, max_steps=args.max_steps, step_count=step_count)
        print(f'segment {idx}: trace {len(seg["trace"])} mismatch {mismatch}')


if __name__ == '__main__':
    main()
