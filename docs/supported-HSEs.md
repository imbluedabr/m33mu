# Supported HSE (Hardware Security Element) Simulators

m33mu can attach a set of emulated **Hardware Security Elements** (HSEs) to
the running firmware so that wolfSSL and other crypto stacks can be exercised
end-to-end without any physical secure element on the host. Each simulator
plugs into the appropriate emulated bus (I2C, SPI, or UART), so the firmware
talks to the device exactly as it would on real silicon — the same APDUs,
opcodes, frames, AT commands, CRCs, and chip-select edges.

This document describes every HSE simulator currently shipped, how to attach
it from the command line, what protocol surface it implements, what
cryptographic operations are supported, and the relevant limitations.

## Table of contents

- [Overview](#overview)
- [Common CLI conventions](#common-cli-conventions)
- [NV persistence](#nv-persistence)
- [Build-time prerequisites](#build-time-prerequisites)
- [STSAFE-A120](#stsafe-a120) — ST Microelectronics, I2C
- [SE050](#se050) — NXP, I2C
- [ATECC608A](#atecc608a) — Microchip, SPI
- [TA-100](#ta-100) — Microchip Trust Anchor, SPI
- [TPM 2.0 (TIS)](#tpm-20-tis) — TCG TIS over SPI
- [IoT SAFE modem + SIM](#iot-safe-modem--sim) — GSMA IoT SAFE over UART
- [Troubleshooting / tracing](#troubleshooting--tracing)
- [References](#references)

## Overview

| Device          | Bus  | Default address / locator        | NV persistence | Backend             | Build flag                                |
|-----------------|------|----------------------------------|----------------|---------------------|-------------------------------------------|
| STSAFE-A120     | I2C  | `addr=0x20`                      | `file=<path>`  | Rust crate (FFI)    | `M33MU_HAS_RUST_PLUGINS` (cargo at build) |
| SE050           | I2C  | `addr=0x48`                      | `file=<path>`  | Rust crate (FFI)    | `M33MU_HAS_RUST_PLUGINS` (cargo at build) |
| ATECC608A       | SPI  | `cs=GPIONAME` (e.g. `PA4`)       | `file=<path>`  | Rust crate (FFI)    | `M33MU_HAS_RUST_PLUGINS` (cargo at build) |
| TA-100          | SPI  | `cs=GPIONAME` (e.g. `PB5`)       | `file=<path>`  | C-native + wolfSSL  | `M33MU_HAS_WOLFSSL`                       |
| TPM 2.0 (TIS)   | SPI  | `cs=GPIONAME`                    | `file=<path>`  | C-native + libtpms  | `M33MU_HAS_LIBTPMS`                       |
| IoT SAFE        | UART | `<uart-base-hex>` (e.g. `0x40004800`) | `file=<path>` | C-native + wolfSSL | `M33MU_HAS_WOLFSSL`                       |

Up to **four** instances of each device type can be registered concurrently.
Multiple device types may be present on the same emulated SoC at the same
time — for instance an ATECC608A on SPI1 plus an SE050 on I2C1 plus an
STSAFE-A120 on I2C2 (this is exactly the configuration exercised by
`tests/firmware/test-se-suite/`).

## Common CLI conventions

Every HSE option uses the same general shape:

```
--<device>:<bus>[:key=value[:key=value...]]
```

- `<bus>` is one of:
  - `I2Cx` — I2C controller index (1-based), e.g. `I2C1`, `I2C2`
  - `SPIx` — SPI controller index (1-based), e.g. `SPI1`, `SPI2`
  - `<uart-base-hex>` — raw memory-mapped UART base address (e.g. `0x40004800`)
- `addr=HEX` — I2C 7-bit address (only for I2C devices)
- `cs=GPIONAME` — chip-select GPIO for SPI devices, written `P<bank><pin>`
  with `<bank>` = `A..Z` and `<pin>` = `0..15` (e.g. `PA4`, `PB13`)
- `file=PATH` — host file used for NV persistence (see below)
- TA-100 also accepts `profile=<name>` and `serial=<hex>`

Order of `key=value` parameters after the bus token is free; unknown keys
are rejected.

## NV persistence

Most simulators accept an optional `file=PATH`. If the path is provided:

- On startup the simulator loads the file (or initialises a fresh image if
  the file does not exist or is too small).
- During execution the simulator updates the file whenever a NV-affecting
  command runs (write zones, key generation, lock bits, IoT SAFE file/key
  slots, libtpms NV indices, etc.).
- Across reboots of the firmware (or across multiple m33mu invocations
  pointed at the same file) the device retains its state.

If `file=` is omitted the device is **volatile**: keys, lock bits, and
NV writes only live as long as the m33mu process. This is usually the
right choice for quick CI runs; the file form is the right choice when
testing provisioning workflows or anything that must survive a reboot.

## Build-time prerequisites

- **Rust plugins** (ATECC608A, SE050, STSAFE-A120): m33mu's CMake autodetects
  `cargo`; if present, the three Rust crates under
  `third_party/wolfssl-simulators/` are built as static libraries and linked
  into the binary. The CPP macro `M33MU_HAS_RUST_PLUGINS` is defined and the
  three CLI options become available.
- **wolfSSL** (TA-100, IoT SAFE): the m33mu binary must be linked against
  wolfSSL (`M33MU_HAS_WOLFSSL`). Without it the IoT SAFE option exits with
  *"wolfSSL support not built in"* and the TA-100 simulator's crypto paths
  are unavailable.
- **libtpms** (TPM 2.0 TIS): m33mu's CMake autodetects libtpms; if found,
  `M33MU_HAS_LIBTPMS` is defined and the `--tpm:` option becomes available.

Run `build/m33mu` without any image to see whether each option is listed in
the printed usage banner — that is the easiest way to confirm a given HSE
was compiled in.

---

## STSAFE-A120

ST Microelectronics' STSAFE-A120 is an authentication + secure key storage
chip used in IoT and industrial applications.

### CLI

```
--stsafe:I2Cx[:addr=HEX][:file=PATH]
```

- Default I2C address: **`0x20`** (`MM_STSAFE_DEFAULT_ADDR`).
- Maximum simultaneous instances: 4.

### Examples

```sh
# Volatile STSAFE-A120 on I2C1 at the default address (0x20)
build/m33mu --stsafe:I2C1 firmware.bin

# Persistent STSAFE-A120 on I2C2 at a custom address with NV file
build/m33mu --stsafe:I2C2:addr=21:file=/tmp/stsafe.bin firmware.bin
```

### Protocol surface

The device wraps the
[wolfSSL/simulators stsafe-a120-sim](https://github.com/wolfssl/simulators)
Rust crate (vendored under `third_party/wolfssl-simulators/stsafe-a120-sim/`).
The simulator implements the STSELib framing layer (CRC-16/X-25, big-endian
on wire) and the following commands:

| Opcode | Name                | Behaviour                                                     |
|--------|---------------------|---------------------------------------------------------------|
| `0x00` | `ECHO`              | Echoes the request body                                       |
| `0x01` | `RESET`             | Resets session state                                          |
| `0x02` | `GENERATE_RANDOM`   | RNG, length per request                                       |
| `0x05` | `READ`              | Reads a data zone / certificate slot                          |
| `0x0D` | `HIBERNATE`         | Acknowledged; resets session                                  |
| `0x11` | `GENERATE_KEY`      | ECC P-256 key generation                                      |
| `0x14` | `QUERY`             | Static device-info query                                      |
| `0x16` | `GENERATE_SIGNATURE`| ECDSA P-256 sign                                              |
| `0x17` | `VERIFY_SIGNATURE`  | ECDSA P-256 verify                                            |
| `0x18` | `ESTABLISH_KEY`     | ECDH                                                          |
| `0x19` | `STANDBY`           | Acknowledged; resets session                                  |

Extended commands (prefix `0x1F` — start-volatile-KEK-session, generate
ECDHE, hash, etc.) return `COMMAND_CODE_NOT_SUPPORTED` because plain-mode
wolfSSL does not exercise them on this part. STSELib treats this as a
clean error rather than a transport failure.

CRC and length errors are reported via status-code-only response frames so
that retries work; the I2C bus is never desynchronised.

### Limitations

- No host-side reset line; the firmware must issue the soft-reset command
  itself when it wants to resynchronise the session.
- Extended (`0x1F`-prefixed) commands are stubs.

---

## SE050

The NXP SE050 is an EdgeLock secure element that talks the GP T=1 protocol
over I2C (ISO 7816-3) and exposes the SE050 proprietary APDU command set.

### CLI

```
--se050:I2Cx[:addr=HEX][:file=PATH]
```

- Default I2C address: **`0x48`** (`MM_SE050_DEFAULT_ADDR`).
- Maximum simultaneous instances: 4.

### Examples

```sh
# Volatile SE050 on I2C1 at the default address (0x48)
build/m33mu --se050:I2C1 firmware.bin

# Persistent SE050 on I2C1 at a custom address with NV file
build/m33mu --se050:I2C1:addr=48:file=/tmp/se050_nv.bin firmware.bin
```

### Protocol surface

The simulator (wolfssl/simulators `se050-sim` crate) implements the SE050
T=1 framing layer (CRC-16/X-25, little-endian on wire) plus a meaningful
subset of the proprietary command set, dispatched by CLA / INS / P1 / P2:

- **Session**: SELECT (ISO 7816-4), open session, get version, get memory,
  scp03 transport (skeleton).
- **Object management**: write/read/delete/list of every object type below;
  size and exists queries; delete-all.
- **EC keys**: write EC key pair / public key, EC key generation, sign,
  verify, ECDH compute, get curve ID.
- **RSA keys**: write RSA key, read modulus / public exponent, sign,
  verify.
- **AES keys**: write key, ECB / CBC / GCM encrypt and decrypt, both
  one-shot and init/update/final.
- **Crypto objects** (digest, MAC, signature, cipher): create, list, init,
  update, final, oneshot.
- **HMAC, binary files, user IDs, counters, PCRs**: write/read/delete.
- **Symmetric one-shot helpers**: digest, HMAC, AES, RSA, EC.
- **Random**: RNG of requested length.

Status words mirror the SE050 spec: `SW_NO_ERROR=0x9000`, `SW_WRONG_DATA=0x6A80`,
`SW_INS_NOT_SUPPORTED=0x6D00`, `SW_FILE_NOT_FOUND=0x6A82`, etc.

### NV format

When `file=` is provided the SE050 object store is serialised into that
file. EC keys are stored as raw P-256 scalars / X9.63 public points; RSA
keys as PKCS#1 DER; AES/HMAC keys as raw bytes; binary files / user IDs
/ counters as opaque blobs. The Rust crate manages the file directly via
its own FFI helpers — no separate on-disk schema is exposed to firmware.

### Limitations

- The T=1 state is preserved across emulated bus resets; the host driver
  is expected to drive the protocol-level soft reset itself when it
  wants to resync.
- No secure messaging (SCP03) over the full session: skeleton handling
  only — pass-through if the firmware does not require channel security.

---

## ATECC608A

The Microchip ATECC608A (and its A/B/TFLXTLS variants) is an ECC secure
element commonly used with TLS stacks. m33mu emulates the SPI variant.

### CLI

```
--atecc608:SPIx:cs=GPIONAME[:file=PATH]
```

- `cs=` is **mandatory** — the ATECC608A SPI protocol requires the host to
  signal start/end of transaction with the chip-select line.
- Maximum simultaneous instances: 4.

### Example

```sh
build/m33mu --atecc608:SPI1:cs=PA4:file=/tmp/atecc608.bin firmware.bin
```

### Protocol surface

The simulator (wolfssl/simulators `atecc608-sim` crate) implements the
word-address framing used by the SPI variant of the part:

| Word address | Meaning                                       |
|--------------|-----------------------------------------------|
| `0x00`       | Wake (no response on the wire)                |
| `0x01`       | Sleep                                         |
| `0x02`       | Idle                                          |
| `0x03`       | Command (followed by `count` byte + payload)  |

Commands implemented:

| Opcode | Name      | Notes                                                   |
|--------|-----------|---------------------------------------------------------|
| `0x02` | `READ`    | Config / OTP / Data zone read                           |
| `0x12` | `WRITE`   | Config / OTP / Data zone write                          |
| `0x17` | `LOCK`    | Config-zone and data-zone lock bits                     |
| `0x16` | `NONCE`   | TempKey nonce generation                                |
| `0x1B` | `RANDOM`  | RNG (32 bytes per call, padded as on real silicon)     |
| `0x30` | `INFO`    | Revision / state                                        |
| `0x40` | `GENKEY`  | ECC P-256 key generation                                |
| `0x41` | `SIGN`    | ECDSA P-256 (internal or external message via TempKey)  |
| `0x43` | `ECDH`    | ECDH against a configured slot or external pubkey       |
| `0x45` | `VERIFY`  | ECDSA P-256 verify                                      |
| `0x47` | `SHA`     | SHA-256 (oneshot, init/update/end)                      |

Frame CRC is the Microchip 16-bit polynomial (`poly=0x8005`, `init=0`,
LSB-first per byte). Frames that fail CRC return the standard
`PARSE_ERROR` status word; the firmware can retry.

### Chip-select handling

The chip-select GPIO is **sampled live** from the emulated GPIO bank — the
simulator detects rising and falling edges and uses them to delimit
transactions:

- CS falling → start of a new transaction. The next byte on MOSI is the
  word-address byte.
- CS rising → end of transaction. If the simulator was mid-command, the
  buffered payload is dispatched.

If the firmware never deasserts CS the simulator falls back to
length-based framing (the `count` byte tells it how many payload bytes
to expect).

### Limitations

- The ATECC608A has no out-of-band reset line; resync is done with the
  `SLEEP` word-address — the host driver must send it when it wants to
  reset.
- Some less-common opcodes (KDF, AES, secure-boot signature
  verification) are not implemented yet. The dispatch returns
  `PARSE_ERROR` for unknown opcodes.

---

## TA-100

The Microchip TA-100 is a Trust Anchor (TA) secure element. Unlike the
ATECC family it speaks a more general TA command set with element handles,
class/type/algorithm metadata, and explicit AES / RSA / ECC operations.

The m33mu TA-100 simulator is **C-native** (under `src/m33mu/ta100.c`) and
uses wolfSSL for all crypto primitives.

### CLI

```
--ta100:SPIx:cs=GPIONAME[:file=PATH][:profile=NAME][:serial=HEX]
```

- `cs=` is **mandatory**.
- `profile=NAME` selects a configuration profile baked into the simulator
  (e.g. `wolfssl-default`, `aescmac-only`, etc. — firmware-driven).
- `serial=HEX` overrides the reported device serial number (used by
  `INFO`-style queries).
- Maximum simultaneous instances: 4.

### Example

```sh
build/m33mu --ta100:SPI2:cs=PB5:file=/tmp/ta100.bin firmware.bin
```

### NV layout

- 4 KB total NV blob.
- 128 B configuration zone.
- 1 KB data zone.
- 16 key slots × 72 B each.
- Up to 64 generic handles (max 2 KB each).

Persisted to the host file in a single binary image; the simulator marks
the file dirty after every state change and flushes on shutdown.

### Cryptographic capabilities

The simulator implements a meaningful subset of the TA-100 command set:

- **RNG**: hardware-style random, requested length.
- **ECC**:
  - P-224, P-256, P-384 keypair generation.
  - ECDSA sign/verify, both internal-message (with TempKey-style staging
    buffer `0x4800`) and external-message modes.
- **RSA-2048**:
  - Key generation (uses a fixed test vector unless slot is provisioned).
  - PKCS#1 v1.5 encrypt/decrypt (`TA_RSAENC_*` opcodes).
- **AES** (key load / encrypt / decrypt):
  - ECB (block-aligned, 16-byte data path).
  - GCM with up to 996 B per call, random or supplied IV (12 B), 16 B tag.
- **SHA-256**: oneshot and incremental.
- **HMAC**, **HKDF-Extract**.
- **Handle / element management**: class (public, private, symmetric),
  key-type, alg-mode metadata.

### Limitations

- Only operations exercised by `tests/firmware/test-ta100/` and the wolfSSL
  TA-100 integration are fully validated; rarely-used opcodes may return
  generic error frames.
- RSA key generation falls back to a fixed embedded test keypair to keep
  emulation deterministic; if you need a fresh keypair, generate it on the
  host and provision it into the simulator's NV file directly.

---

## TPM 2.0 (TIS)

m33mu can emulate a discrete TPM 2.0 chip behind the TCG TIS interface
over SPI. The crypto / state engine is provided by **libtpms**; the m33mu
side implements the TIS register file and SPI command framing.

### CLI

```
--tpm:SPIx:cs=GPIONAME[:file=PATH]
```

- `cs=` is **mandatory** (TIS-over-SPI requires CS-framed transactions).
- `file=PATH` selects the NV blob root used by libtpms; multiple NV
  entries (permanent state, platform state, etc.) are namespaced under
  the path.
- Maximum simultaneous instances: 4.

### Example

```sh
build/m33mu --tpm:SPI1:cs=PA15:file=/tmp/tpm-nv firmware.bin
```

### TIS register map

The simulator exposes the standard TCG-TIS register set on the SPI wire:

| Address  | Register            | Notes                                  |
|----------|---------------------|----------------------------------------|
| `0x0000` | `TPM_ACCESS`        | Locality request / active / valid bits |
| `0x0018` | `TPM_STS`           | `VALID`, `COMMAND_READY`, `GO`, `DATA_AVAIL`, `EXPECT` |
| `0x0024` | `TPM_DATA_FIFO`     | Command / response payload FIFO        |
| `0x0F00` | `TPM_DID_VID`       | Device / vendor ID                     |
| `0x0F04` | `TPM_RID`           | Revision                               |

The 4-byte SPI header is decoded into read/write + register address +
length; a single `wait_phase` byte is supported when the firmware uses
flow-control reads; burst counts up to 64 B per FIFO transaction.

### Supported TPM operations

Anything libtpms supports — that includes the full TPM 2.0 command set
(startup, NV indices, primary keys, sign / verify, encrypt / decrypt,
PCR ops, sessions, etc.). The crypto and persistence is libtpms-native;
m33mu only routes raw command buffers in and response buffers out.

### Tracing

Two environment variables are honoured:

- `M33MU_SPI_TRACE=1` — dump raw SPI bytes that hit the TPM.
- `M33MU_TPM_TRACE=1` — dump TIS register reads/writes and
  command/response payloads (truncated to 256 B per direction).

These are independent of `--dump` and can be enabled per-run.

### Limitations

- Only a single locality (locality 0) is exposed.
- The simulator runs synchronously: `TPM_STS.GO` triggers libtpms in the
  same call, so there is no concept of TPM background processing time.
- libtpms must be present at build time; otherwise the `--tpm:` option
  is not compiled in.

---

## IoT SAFE modem + SIM

This simulator emulates a **cellular modem + UICC** pair speaking the
**GSMA IoT SAFE** applet over an AT-command-driven UART link. It is the
component used by `tests/firmware/test-stm32h563-wolfssl-iotsafe/` to
exercise wolfSSL's IoT SAFE TLS integration with no real modem.

### CLI

```
--iotsafe-uart:<uart-base-hex>[:file=PATH]
```

- `<uart-base-hex>` is the memory-mapped base address of the emulated
  UART (e.g. `0x40004800` for STM32H5 USART3 in the bundled demo). The simulator attaches
  to the UART backend at that base; the firmware then drives it as it
  would a real modem.
- Maximum simultaneous instances: 4.

### Example

```sh
build/m33mu \
    --cpu stm32h563 \
    --iotsafe-uart:0x40004800:file=/tmp/iotsafe.bin \
    tests/firmware/test-stm32h563-wolfssl-iotsafe/app.bin
```

### Modem AT surface

- `AT` → `OK` (used for liveness polling).
- `ATE0` / `ATE1` → echo off / on (`OK`).
- `AT+CSIM=<len>,"<hex-apdu>"` → transports a single APDU to the IoT
  SAFE applet. The response is returned as `+CSIM: <len>,"<hex-resp>"`
  followed by `OK`. This is the standard 3GPP TS 27.007 channel used
  by GSMA IoT SAFE.

Other AT commands return `ERROR` so the firmware can detect that the
modem is in a known minimal state.

### IoT SAFE applet surface

The applet implements the relevant IoT SAFE INS codes (CLA `0x81`):

| INS    | Name                       | Notes                                  |
|--------|----------------------------|----------------------------------------|
| `0x24` | `PUT PUBLIC INIT`          | Begin import of a peer public key       |
| `0xD8` | `PUT PUBLIC UPDATE`        | Continue peer-pubkey import            |
| `0x2A` | `SIGN INIT`                | Begin ECDSA signing                    |
| `0x2B` | `SIGN UPDATE`              | Continue / finalise signing            |
| `0x2C` | `VERIFY INIT`              | Begin ECDSA verify                     |
| `0x2D` | `VERIFY UPDATE`            | Continue / finalise verify             |
| `0x46` | `COMPUTE DH`               | ECDH with stored / imported pubkey     |
| `0x4A` | `HKDF EXTRACT`             | HKDF-Extract (SHA-256/384/512)         |
| `0x84` | `GET RANDOM`               | RNG                                    |
| `0xB0` | `READ FILE`                | Read a SIM file slot                   |
| `0xB9` | `GEN KEYPAIR`              | ECC P-256 key generation                |
| `0xC0` | `GET RESPONSE`             | Chained response retrieval             |
| `0xCB` | `GET DATA`                 | Read tag-encoded data (e.g. files)     |
| `0xCD` | `READ KEY`                 | Read an export-allowed public key      |

Tag encoding follows the IoT SAFE TLV definitions (`0x33` signature,
`0x34` ECC key field, `0x49` ECC key type, `0x86` ECC key XY, `0x83`
file ID, `0x84` private-key ID, `0x85` public-key ID, `0x91` hash algo,
`0x92` sign algo, `0xA1` mode-of-operation, `0xD1` secret, `0xD5` salt,
`0x9E` hash value). Slot and file identifiers are **16-bit** so that
wolfSSL's `_ex` IoT SAFE APIs (`wolfSSL_CTX_iotsafe_on_*_ex`) can be
exercised in full.

### Default provisioning

On startup, in the absence of a usable NV file, the simulator pre-loads
the SIM with the wolfSSL `certs_test.h` material so that TLS handshakes
work out-of-the-box:

| ID       | Slot                                              | Content                                  |
|----------|---------------------------------------------------|------------------------------------------|
| `0x0001` | Default private key slot                          | P-256 client private key (`ecc_clikey_der_256`) |
| `0x0002` | Default client cert file                          | ECC client cert (`cliecc_cert_der_256`)         |
| `0x0003` | Default server cert file                          | ECC server cert (`serv_ecc_der_256`)            |
| `0x0004` | Default ECDH slot                                 | Empty (filled on demand)                  |
| `0x0005` | Default peer-public-key slot                      | Empty (filled by `PUT PUBLIC`)            |

When `file=PATH` is given, the NV image is loaded from / written back to
that file. The on-disk format starts with an 8-byte magic (`"IOTSAFE1"`),
a 32-bit version, then a fixed-size struct of up to 16 file slots
(2 KB each) and 16 key slots; loading is forgiving — corrupt or
mismatched files are replaced with the default provisioning.

### Asynchronous-style commands

The IoT SAFE applet allows certain INS codes to deliberately answer
*"OK, retry GET RESPONSE"* (mode `MM_IOTSAFE_APDU_OK_ASYNC`) instead of
returning a full response on the first `AT+CSIM=`. The modem implements
the polling state expected by GSMA IoT SAFE — a follow-up `GET
RESPONSE` (`INS 0xC0`) returns the accumulated data.

### Limitations

- Only a minimal AT command set is implemented; SMS, GPRS, sockets, etc.
  are out of scope — this simulator is a *transport* to the SIM, not a
  full cellular modem.
- The applet is implemented for the use cases wolfSSL exercises; less
  common IoT SAFE operations (key derivation chains beyond HKDF-Extract,
  symmetric AES on the SIM, etc.) are not present.
- Requires `M33MU_HAS_WOLFSSL`; without wolfSSL the option exits with
  *"wolfSSL support not built in"*.

---

## Troubleshooting / tracing

| Symptom                                            | Where to look                                  |
|----------------------------------------------------|------------------------------------------------|
| Device does not respond                            | Look for `[ATECC608] Registered ...`, `[SE050] Registered ...`, etc. on startup. If missing, the option failed to parse or wasn't compiled in. |
| Wrong I2C address                                  | Double-check `addr=` matches what firmware drives; default is `0x20` for STSAFE-A120, `0x48` for SE050. |
| Wrong CS pin                                       | The SPI HAL samples GPIO output state — make sure firmware drives the CS GPIO low for transactions and that you pass the same GPIO name to `cs=`. |
| TPM commands hang                                  | Enable `M33MU_TPM_TRACE=1` and `M33MU_SPI_TRACE=1` to see TIS register traffic and SPI bytes; check that `--tpm:` actually appeared in usage (libtpms must be available at build time). |
| Stale NV state across runs                         | Either omit `file=` to make the device volatile, or delete the file. |
| IoT SAFE: `wolfSSL support not built in`           | Build m33mu with `M33MU_HAS_WOLFSSL`; the IoT SAFE simulator is a wolfSSL-only feature. |
| Rust HSEs missing from usage                       | `cargo` was not detected at build time. Install Rust toolchain and re-run CMake. |

The combination of `--call-trace`, `--dump`, and `M33MU_SPI_TRACE=1` /
`M33MU_TPM_TRACE=1` is usually enough to localise any HSE-side problem
to a single command frame.

## References

- `src/main.c` — CLI option parsing (`--stsafe`, `--se050`, `--atecc608`,
  `--ta100`, `--tpm`, `--iotsafe-uart`)
- `src/m33mu/stsafe.c`, `src/m33mu/se050.c`, `src/m33mu/atecc608.c` —
  m33mu integration over the Rust simulator FFI
- `src/m33mu/ta100.c`, `src/m33mu/tpm_tis.c`, `src/m33mu/iotsafe_uart.c` —
  native C simulators
- `third_party/wolfssl-simulators/` — vendored Rust crates for the three
  off-the-shelf secure elements (upstream:
  [github.com/wolfssl/simulators](https://github.com/wolfssl/simulators))
- `tests/firmware/test-se-suite/` — end-to-end ATECC608A + SE050 +
  STSAFE-A120 smoke test on STM32H563
- `tests/firmware/test-ta100/` — end-to-end TA-100 test on STM32U585
- `tests/firmware/test-stm32h563-wolfssl-iotsafe/` — end-to-end wolfSSL
  IoT SAFE TLS test using `--iotsafe-uart`
- [m33mu(1)](../m33mu.1) — concise CLI manpage
- [docs/cli-usage.md](cli-usage.md) — broader CLI usage guide
