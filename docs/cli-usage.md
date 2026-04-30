# Command-Line Usage

## Basic Form

```sh
build/m33mu [options] <image.bin[:offset]|image.elf|image.hex|image.uf2> [more images...]
```

`m33mu` can run as a straightforward CLI process, as an interactive TUI with `--tui`, or as a debug target with `--gdb`.

## Core Modes

- Pure CLI:

```sh
build/m33mu tests/firmware/test-stm32h563/app.bin
```

- Interactive TUI:

```sh
build/m33mu --tui tests/firmware/test-stm32h563/app.bin
```

- GDB remote debugging:

```sh
build/m33mu --gdb --gdb-symbols firmware.elf firmware.bin
```

## Frequently Used Options

- `--cpu <cpu>`: select the MCU/SoC profile
- `--tui`: start the interactive ncurses UI
- `--gdb`: expose a GDB remote server on port `1234`
- `--port <n>`: override the GDB port
- `--gdb-symbols <elf>`: load debug symbols from one or more ELFs
- `--uart-stdout`: send UART output to stdout instead of PTYs
- `--dump`: print instruction/decode tracing
- `--record`: keep an in-memory execution trace for reverse/debug workflows
- `--call-trace`: log calls, returns, interrupts, and TrustZone SG transitions
- `--quit-on-faults`: terminate when the first fault is raised
- `--timeout <seconds>`: force a host-side timeout
- `--expect-bkpt <imm>`: turn a firmware BKPT into a pass/fail test signal

## Recording And Debug-Oriented Options

The trace/record options are useful when debugging difficult firmware behavior:

- `--record`
- `--record-start <pc>`
- `--record-start-dump`
- `--record-start-dump-ram`
- `--record-end-dump-ram`
- `--record-window <n>`
- `--record-dump <n>`
- `--record-trace <path>`
- `--record-quiet`

These let you capture a bounded execution window, dump machine state around a specific PC, and export traces for offline inspection.

## Peripheral / Backend Options

`m33mu` can attach optional emulated or host-backed peripherals:

- `--spiflash:SPIx:file=<path>:size=<n>[:mmap=0xaddr][:cs=GPIONAME]`
- `--usb`
- `--usb:udc=<name>`
- `--usb:path=/dev/gadget/<name>`
- `--tap[:name]`
- `--vde[:/path/to/vde.ctl]`
- `--tpm:SPIx:cs=GPIONAME[:file=<path>]`
- `--ta100:SPIx:cs=GPIONAME[:file=<path>][:profile=<name>][:serial=<hex>]`

Only one Ethernet backend can be selected at a time.

## TrustZone / Memory / Flash Options

- `--no-tz`: run without TrustZone protections for the session
- `--dualbank`: enable STM32 dual-bank flash behavior
- `--persist`: write modified flash contents back to the original input BINs when supported
- `--puf-seed <value>`: fill initial RAM deterministically from a fixed PRNG seed
- `--puf-cold-boot <n>`: select the deterministic cold-boot index used for PUF noise derivation
- `--puf-noise <n>`: with `--puf-seed`, flip exactly `n` pseudo-random bits per 127-bit block
- `--meminfo`: print SAU/MPU layout and related logs
- `--boot flash|ram|spiflash`
- `--boot-offset=0x...`

## Environment Variables

- `CAPSTONE_PC=<hex>`
- `M33MU_MEMWATCH=<addr:size>`
- `M33MU_NVIC_TRACE=1`
- `M33MU_SYSTICK_TRACE=1`
- `M33MU_SLEEP_TRACE=1`
- `M33MU_PROT_TRACE=1..3`

See [m33mu.1](/home/dan/src/m33mu/m33mu.1) for full descriptions and examples.
