# CI And Automated Testing

`m33mu` works well as a non-interactive firmware test runner. The most useful options for CI are:

- `--expect-bkpt`
- `--uart-stdout`
- `--timeout`

## Recommended Pattern

Use firmware to signal success or failure with a `BKPT` instruction, route UART logs to stdout, and enforce a host-side timeout.

Example:

```sh
build/m33mu \
  --uart-stdout \
  --expect-bkpt 0x42 \
  --timeout 10 \
  tests/firmware/test-stm32h563/app.bin
```

## `--expect-bkpt`

`--expect-bkpt <imm>` changes the process exit status so the run passes only if a `BKPT` with the requested immediate value is reached.

Behavior:

- exit `0` if the expected BKPT is hit
- exit `1` if execution ends without hitting that BKPT

This is useful for firmware that intentionally reports “test passed” by executing a known breakpoint.

Example:

```sh
build/m33mu --expect-bkpt 0x7f tests/firmware/my-test.bin
```

## `--uart-stdout`

`--uart-stdout` sends UART output to stdout instead of exposing PTYs. This is usually what you want in CI because it makes logs visible in job output and easy to assert on.

Example:

```sh
build/m33mu --uart-stdout tests/firmware/my-test.bin | tee test.log
```

Notes:

- this is intended for non-TUI usage
- when TUI is active, stdout UART routing is disabled

## `--timeout`

`--timeout <seconds>` installs a host-side execution timeout. If the timeout elapses, `m33mu` exits with code `127`.

This protects CI jobs from hanging forever due to firmware deadlocks, infinite loops, or waiting for events that never arrive.

Example:

```sh
build/m33mu --timeout 15 tests/firmware/my-test.bin
```

## Typical CI One-Liners

Pass/fail by BKPT and capture UART logs:

```sh
build/m33mu --uart-stdout --expect-bkpt 0x23 --timeout 20 firmware.bin
```

TrustZone split-image firmware test:

```sh
build/m33mu \
  --uart-stdout \
  --expect-bkpt 0x33 \
  --timeout 20 \
  secure.bin nonsecure.bin:0x2000
```

Debug a failing CI case by enabling decode output:

```sh
build/m33mu --uart-stdout --timeout 20 --dump firmware.bin
```

## Exit-Code Guidance

- `0`: normal success, including the expected BKPT case
- `1`: argument or validation failure, or expected BKPT not hit when `--expect-bkpt` is used
- `127`: timeout elapsed

## Good Practices

- Prefer `--uart-stdout` in CI to avoid PTY handling.
- Always set `--timeout` for unattended jobs.
- Reserve a dedicated BKPT immediate for “test passed” so your CI harness can detect success deterministically.
- When diagnosing failures, add `--gdb`, `--dump`, `--record`, or `--call-trace` as needed.
