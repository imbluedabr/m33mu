# python-unicorn trace compare

This directory contains a small Python helper to compare m33mu trace windows against Unicorn.

## What it does
- Parses an m33mu log containing `--record-start` + `--record-window` output.
- Reconstructs memory/regs at each `RECORD_START` block.
- Replays the window in Unicorn (Thumb, little‑endian) and compares PC + registers per step.

## How to use
1. Run the target with record window enabled. Example:

```bash
m33mu/build/m33mu m33mu-examples/test-wolfcrypt/app.bin --no-tz \
  --record --record-start 0x0801511c --record-start-dump --record-window 200 \
  --timeout 60 --uart-stdout > ecc_record_window_1511c.log 2>&1
```

2. Compare against Unicorn:

```bash
m33mu/scripts/python-unicorn/compare_trace.py \
  --log ecc_record_window_1511c.log \
  --bin m33mu-examples/test-wolfcrypt/app.bin
```

3. Optional: compare a single segment and/or cap the number of steps:

```bash
m33mu/scripts/python-unicorn/compare_trace.py \
  --log ecc_record_window_1511c.log \
  --bin m33mu-examples/test-wolfcrypt/app.bin \
  --segment 0 \
  --max-steps 50
```

Defaults:
- `--segment 0`
- `--max-steps 50`

## Notes
- The script skips IT instructions and any trace lines with `exec=0` to keep alignment with Unicorn.
- For CPSR it only applies APSR (NZCV) bits; Unicorn does not track ITSTATE like m33mu.
- If your log contains many RECORD_START blocks, the script will iterate them in order.
