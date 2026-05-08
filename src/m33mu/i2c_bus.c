/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include <string.h>
#include "m33mu/i2c_bus.h"

#define MM_I2C_BUS_DEVICE_MAX 16

static struct mm_i2c_device g_i2c_devices[MM_I2C_BUS_DEVICE_MAX];
static size_t g_i2c_device_count;

mm_bool mm_i2c_bus_register_device(const struct mm_i2c_device *dev)
{
    if (dev == 0 || (dev->write == 0 && dev->read == 0)) {
        return MM_FALSE;
    }
    if (dev->bus < 0 || dev->addr > 0x7fu) {
        return MM_FALSE;
    }
    if (g_i2c_device_count >= MM_I2C_BUS_DEVICE_MAX) {
        return MM_FALSE;
    }
    memcpy(&g_i2c_devices[g_i2c_device_count], dev, sizeof(*dev));
    g_i2c_device_count++;
    return MM_TRUE;
}

static struct mm_i2c_device *i2c_bus_find(int bus, mm_u8 addr)
{
    size_t i;
    for (i = 0; i < g_i2c_device_count; ++i) {
        struct mm_i2c_device *dev = &g_i2c_devices[i];
        if (dev->bus == bus && dev->addr == addr) {
            return dev;
        }
    }
    return 0;
}

mm_bool mm_i2c_bus_write(int bus, mm_u8 addr, const mm_u8 *data, size_t len)
{
    struct mm_i2c_device *dev = i2c_bus_find(bus, addr);
    if (dev == 0 || dev->write == 0) {
        return MM_FALSE;
    }
    return dev->write(dev->opaque, addr, data, len);
}

mm_bool mm_i2c_bus_read(int bus, mm_u8 addr, mm_u8 *data, size_t len)
{
    struct mm_i2c_device *dev = i2c_bus_find(bus, addr);
    if (dev == 0 || dev->read == 0) {
        return MM_FALSE;
    }
    return dev->read(dev->opaque, addr, data, len);
}

void mm_i2c_bus_reset_all(void)
{
    size_t i;
    for (i = 0; i < g_i2c_device_count; ++i) {
        if (g_i2c_devices[i].reset != 0) {
            g_i2c_devices[i].reset(g_i2c_devices[i].opaque);
        }
    }
}

void mm_i2c_bus_shutdown_all(void)
{
    size_t i;
    for (i = 0; i < g_i2c_device_count; ++i) {
        if (g_i2c_devices[i].shutdown != 0) {
            g_i2c_devices[i].shutdown(g_i2c_devices[i].opaque);
        }
    }
    g_i2c_device_count = 0;
}

mm_bool mm_i2c_bus_probe(int bus, mm_u8 addr)
{
    return i2c_bus_find(bus, addr) != 0 ? MM_TRUE : MM_FALSE;
}

void mm_i2c_bus_reset(int bus)
{
    size_t i;
    for (i = 0; i < g_i2c_device_count; ++i) {
        if (g_i2c_devices[i].bus == bus && g_i2c_devices[i].reset != 0) {
            g_i2c_devices[i].reset(g_i2c_devices[i].opaque);
        }
    }
}
