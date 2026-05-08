# wolfSSL Simulators — vendored source

This directory contains Rust source from [wolfssl/simulators](https://github.com/wolfssl/simulators)
(commit 7149e6fd), vendored for use as static libraries in m33mu.

## Contents

- `atecc608-sim/` — Microchip ATECC608A secure element simulator (SPI, word_addr protocol)
- `se050-sim/` — NXP SE050 secure element simulator (I2C, T=1/ISO 7816-3 protocol)
- `stsafe-a120-sim/` — STMicroelectronics STSAFE-A120 secure element simulator (I2C)

## Copyright

Copyright (C) 2026 wolfSSL Inc. — original simulator implementations.
Licensed under the GNU General Public License version 3 or later.

The `src/ffi.rs` files in each crate are m33mu additions:
Copyright (C) 2026 Daniele Lacamera — FFI export layer for m33mu integration.

## Building

These libraries are built automatically by CMake when `cargo` is detected:

```
cmake -S . -B build
cmake --build build
```

To build manually:

```
cd third_party/wolfssl-simulators
cargo build --release
```

Each crate produces a static library (e.g. `target/release/libatecc608_sim.a`)
that is linked into the m33mu binary.
