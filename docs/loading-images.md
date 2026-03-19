# Loading Images

`m33mu` can load one or more firmware images into the emulated target memory map.

## Supported Input Forms

- Raw binary: `image.bin`
- Raw binary with flash offset: `image.bin:0x2000`
- ELF image: `image.elf`
- Intel HEX image: `image.hex`
- UF2 image: `image.uf2`

## Raw Binaries

Raw binaries are loaded relative to the current boot target. They may include a byte offset suffix:

```sh
build/m33mu firmware.bin:0x2000
```

The suffix is interpreted as a byte offset and accepts hexadecimal values.

## ELF / HEX / UF2

- ELF and Intel HEX files are auto-detected and placed by their encoded load addresses.
- UF2 images are also accepted by the CLI and are handled according to their encoded target addresses and payload layout.

These formats are generally the right choice when the firmware already includes link/load addresses and should not be manually offset.

## Loading Multiple Images

`m33mu` accepts multiple image arguments in one invocation. This is useful for Secure / Non-secure pairs or other split-image layouts.

Example: Secure firmware at offset `0`, Non-secure firmware at offset `0x2000`:

```sh
build/m33mu \
  tests/firmware/test-tz-bxns-cmse-sau-mpu/build/secure.bin \
  tests/firmware/test-tz-bxns-cmse-sau-mpu/build/nonsecure.bin:0x2000
```

## Boot Modes

The executable supports selecting a boot source with `--boot`:

- `--boot flash`
- `--boot ram`
- `--boot spiflash`

Optional `--boot-offset=0x...` can move the entry point within the selected boot source.

Example: boot from RAM instead of flash:

```sh
build/m33mu --boot ram firmware.bin
```

Example: boot from memory-mapped SPI flash:

```sh
build/m33mu \
  --boot spiflash \
  --spiflash:SPI1:file=flash.img:size=0x200000:mmap=0x90000000 \
  firmware.bin
```

## Related Documents

- [Getting started](getting-started.md)
- [Command-line usage](cli-usage.md)
- [CI and automated testing](ci-testing.md)
