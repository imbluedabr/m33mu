/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include <stdio.h>
#include <string.h>
#include "m33mu/mmio.h"
#include "m33mu/nvic.h"
#include "m33mu/spi_bus.h"
#include "m33mu/snapshot.h"
#include "stm32_spi.h"

struct fake_spi_dev {
    mm_u8 response;
    int xfer_count;
    int end_count;
    int poll_count;
};

static mm_u8 fake_xfer(void *opaque, mm_u8 out)
{
    struct fake_spi_dev *dev = (struct fake_spi_dev *)opaque;
    dev->xfer_count++;
    dev->response = (mm_u8)(out ^ 0xFFu);
    return dev->response;
}

static void fake_end(void *opaque)
{
    struct fake_spi_dev *dev = (struct fake_spi_dev *)opaque;
    dev->end_count++;
}

static mm_u8 fake_cs_level(void *opaque)
{
    struct fake_spi_dev *dev = (struct fake_spi_dev *)opaque;
    dev->poll_count++;
    return 0u;
}

static int test_u585_cs_polling(void)
{
    static const mm_u32 bases[] = { 0x40013000u };
    static const mm_u32 bases_sec[] = { 0x50013000u };
    static const int irq_map[] = { 59 };
    struct stm32_spi_config cfg;
    struct stm32_spi_state state;
    struct mmio_bus bus;
    struct mmio_region regions[4];
    struct mm_nvic nvic;
    struct fake_spi_dev dev;
    struct mm_spi_device spi_dev;

    memset(&cfg, 0, sizeof(cfg));
    memset(&state, 0, sizeof(state));
    memset(&dev, 0, sizeof(dev));
    memset(&spi_dev, 0, sizeof(spi_dev));
    mm_nvic_init(&nvic);
    mmio_bus_init(&bus, regions, 4);

    cfg.bases = bases;
    cfg.bases_sec = bases_sec;
    cfg.irq_map = irq_map;
    cfg.count = 1u;
    cfg.poll_cs = MM_TRUE;

    spi_dev.bus = 1;
    spi_dev.xfer = fake_xfer;
    spi_dev.end = fake_end;
    spi_dev.cs_level = fake_cs_level;
    spi_dev.opaque = &dev;
    if (!mm_spi_bus_register_device(&spi_dev)) return 1;

    stm32_spi_init(&state, &cfg, &bus, &nvic);
    if (!mmio_bus_write(&bus, bases[0] + 0x04u, 4, 1u)) return 1;
    if (!mmio_bus_write(&bus, bases[0] + 0x00u, 4, (1u << 0) | (1u << 9))) return 1;
    if (!mmio_bus_write(&bus, bases[0] + 0x20u, 1, 0x12u)) return 1;
    if (dev.xfer_count != 1) return 1;
    if (dev.end_count == 0) return 1;
    if (dev.poll_count < 3) return 1;
    return 0;
}

static int test_h5_snapshot_roundtrip(void)
{
    static const mm_u32 bases[] = { 0x40013000u };
    static const mm_u32 bases_sec[] = { 0x50013000u };
    static const int irq_map[] = { 55 };
    static const char *const names[] = { "SPI1" };
    struct stm32_spi_config cfg;
    struct stm32_spi_state src_state;
    struct stm32_spi_state dst_state;
    struct mmio_bus src_bus;
    struct mmio_bus dst_bus;
    struct mmio_region src_regions[4];
    struct mmio_region dst_regions[4];
    struct mm_nvic src_nvic;
    struct mm_nvic dst_nvic;
    struct fake_spi_dev dev;
    struct mm_spi_device spi_dev;
    mm_u8 snap_buf[512];
    struct mm_snapshot_writer w;
    struct mm_snapshot_reader r;
    mm_u32 value = 0;

    memset(&cfg, 0, sizeof(cfg));
    memset(&src_state, 0, sizeof(src_state));
    memset(&dst_state, 0, sizeof(dst_state));
    memset(&dev, 0, sizeof(dev));
    memset(&spi_dev, 0, sizeof(spi_dev));
    memset(snap_buf, 0, sizeof(snap_buf));
    mm_nvic_init(&src_nvic);
    mm_nvic_init(&dst_nvic);
    mmio_bus_init(&src_bus, src_regions, 4);
    mmio_bus_init(&dst_bus, dst_regions, 4);

    cfg.bases = bases;
    cfg.bases_sec = bases_sec;
    cfg.irq_map = irq_map;
    cfg.names = names;
    cfg.count = 1u;
    cfg.enable_snapshot = MM_TRUE;

    spi_dev.bus = 1;
    spi_dev.xfer = fake_xfer;
    spi_dev.end = fake_end;
    spi_dev.opaque = &dev;
    if (!mm_spi_bus_register_device(&spi_dev)) return 1;

    stm32_spi_init(&src_state, &cfg, &src_bus, &src_nvic);
    if (!mmio_bus_write(&src_bus, bases[0] + 0x04u, 4, 1u)) return 1;
    if (!mmio_bus_write(&src_bus, bases[0] + 0x00u, 4, (1u << 0) | (1u << 9))) return 1;
    if (!mmio_bus_write(&src_bus, bases[0] + 0x20u, 1, 0x22u)) return 1;

    mm_snapshot_writer_init(&w, snap_buf, (mm_u32)sizeof(snap_buf));
    if (!mmio_bus_save(&src_bus, &w)) return 1;

    stm32_spi_init(&dst_state, &cfg, &dst_bus, &dst_nvic);
    mm_snapshot_reader_init(&r, snap_buf, mm_snapshot_bytes_used(&w));
    if (!mmio_bus_load(&dst_bus, &r)) return 1;
    if (!mmio_bus_read(&dst_bus, bases[0] + 0x30u, 1, &value)) return 1;
    if ((value & 0xFFu) != 0xDDu) return 1;
    return 0;
}

int main(void)
{
    struct { const char *name; int (*fn)(void); } tests[] = {
        { "u585_cs_polling", test_u585_cs_polling },
        { "h5_snapshot_roundtrip", test_h5_snapshot_roundtrip },
    };
    int failures = 0;
    int i;
    const int count = (int)(sizeof(tests) / sizeof(tests[0]));
    for (i = 0; i < count; ++i) {
        if (tests[i].fn() != 0) {
            ++failures;
            printf("FAIL: %s\n", tests[i].name);
        } else {
            printf("PASS: %s\n", tests[i].name);
        }
    }
    if (failures != 0) {
        printf("stm32_spi_test: %d failure(s)\n", failures);
        return 1;
    }
    return 0;
}
