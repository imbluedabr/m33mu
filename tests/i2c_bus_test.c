/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include <stdio.h>
#include <string.h>

#include "m33mu/i2c_bus.h"

struct fake_i2c {
    mm_u8 last_write[8];
    size_t last_write_len;
    unsigned writes;
    unsigned reads;
    unsigned shutdowns;
};

static mm_bool fake_write(void *opaque, mm_u8 addr,
                          const mm_u8 *data, size_t len)
{
    struct fake_i2c *f = (struct fake_i2c *)opaque;
    (void)addr;
    if (len > sizeof(f->last_write)) {
        return MM_FALSE;
    }
    memcpy(f->last_write, data, len);
    f->last_write_len = len;
    f->writes++;
    return MM_TRUE;
}

static mm_bool fake_read(void *opaque, mm_u8 addr, mm_u8 *data, size_t len)
{
    struct fake_i2c *f = (struct fake_i2c *)opaque;
    size_t i;
    (void)addr;
    for (i = 0; i < len; ++i) {
        data[i] = (mm_u8)(0xa0u + i);
    }
    f->reads++;
    return MM_TRUE;
}

static void fake_shutdown(void *opaque)
{
    struct fake_i2c *f = (struct fake_i2c *)opaque;
    f->shutdowns++;
}

int main(void)
{
    struct fake_i2c f;
    struct mm_i2c_device dev;
    mm_u8 tx[3] = { 1u, 2u, 3u };
    mm_u8 rx[3] = { 0u, 0u, 0u };
    int failures = 0;

    memset(&f, 0, sizeof(f));
    memset(&dev, 0, sizeof(dev));
    dev.bus = 1;
    dev.addr = 0x48u;
    dev.write = fake_write;
    dev.read = fake_read;
    dev.shutdown = fake_shutdown;
    dev.opaque = &f;

    if (!mm_i2c_bus_register_device(&dev)) {
        printf("i2c_bus_test: failed to register device\n");
        return 1;
    }
    if (!mm_i2c_bus_write(1, 0x48u, tx, sizeof(tx))) {
        printf("i2c_bus_test: matching write failed\n");
        failures++;
    }
    if (f.writes != 1u || f.last_write_len != sizeof(tx) ||
        memcmp(f.last_write, tx, sizeof(tx)) != 0) {
        printf("i2c_bus_test: write data mismatch\n");
        failures++;
    }
    if (mm_i2c_bus_write(2, 0x48u, tx, sizeof(tx))) {
        printf("i2c_bus_test: wrong bus matched\n");
        failures++;
    }
    if (mm_i2c_bus_read(1, 0x49u, rx, sizeof(rx))) {
        printf("i2c_bus_test: wrong address matched\n");
        failures++;
    }
    if (!mm_i2c_bus_read(1, 0x48u, rx, sizeof(rx)) ||
        rx[0] != 0xa0u || rx[1] != 0xa1u || rx[2] != 0xa2u) {
        printf("i2c_bus_test: read mismatch\n");
        failures++;
    }
    mm_i2c_bus_shutdown_all();
    if (f.shutdowns != 1u) {
        printf("i2c_bus_test: shutdown not called\n");
        failures++;
    }

    if (failures != 0) {
        printf("i2c_bus_test: %d failure(s)\n", failures);
        return 1;
    }
    return 0;
}
