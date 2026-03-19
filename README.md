![m33mu logo](png/m33mu.png)

# m33mu

`m33mu` is an embedded microcontroller emulator for ARMv8-M Cortex-M33 targets.
It is used to test, debug, and demonstrate firmware without any physical hardware.

It can run as:

- an interactive terminal UI with `--tui`
- a pure command-line emulator
- a tool inside automated tests and CI jobs

## What It Does

- Emulates Cortex-M33 / ARMv8-M firmware with TrustZone awareness
- Runs firmware images directly from your host machine
- Supports debugging through a built-in GDB remote server
- Can load multiple images, including Secure and Non-secure firmware combinations
- Exposes UART, SPI flash, TPM, USB, Ethernet, and other target-specific peripherals

## Documentation Index

- [Getting started](docs/getting-started.md)
- [Supported CPUs](docs/supported-cpus.md)
- [Loading images](docs/loading-images.md)
- [Command-line usage](docs/cli-usage.md)
- [CI and automated testing](docs/ci-testing.md)

## Screenshots for TUI mode

#### m33mu TUI, stopped, stepping with GDB:

![m33mu TUI, stopped, stepping with GDB](png/screen01.png)

#### m33mu TUI, running in secure domain:

![m33mu TUI, running in secure domain (green bar)](png/screen02.png)

#### m33mu TUI, running in non-secure domain:

![m33mu TUI, running in non-secure domain (blue bar)](png/screen03.png)

## Reporting Issues

Please report issues to the [GitHub issue tracker](https://github.com/danielinux/m33mu/issues).

Include, if possible, a full capture using `--capstone`, a reproducer firmware image, and a clear explanation of how to reproduce the problem.

## Copyright / License

Copyright (c) Daniele Lacamera 2025.

Released under AGPLv3. See [LICENSE](/home/dan/src/m33mu/LICENSE).
