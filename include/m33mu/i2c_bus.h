/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef M33MU_I2C_BUS_H
#define M33MU_I2C_BUS_H

#include "m33mu/types.h"

typedef mm_bool (*mm_i2c_write_fn)(void *opaque, mm_u8 addr,
                                  const mm_u8 *data, size_t len);
typedef mm_bool (*mm_i2c_read_fn)(void *opaque, mm_u8 addr,
                                 mm_u8 *data, size_t len);
typedef void (*mm_i2c_reset_fn)(void *opaque);
typedef void (*mm_i2c_shutdown_fn)(void *opaque);

struct mm_i2c_device {
    int bus;
    mm_u8 addr;
    mm_i2c_write_fn write;
    mm_i2c_read_fn read;
    mm_i2c_reset_fn reset;
    mm_i2c_shutdown_fn shutdown;
    void *opaque;
};

mm_bool mm_i2c_bus_register_device(const struct mm_i2c_device *dev);
mm_bool mm_i2c_bus_write(int bus, mm_u8 addr, const mm_u8 *data, size_t len);
mm_bool mm_i2c_bus_read(int bus, mm_u8 addr, mm_u8 *data, size_t len);
void mm_i2c_bus_reset_all(void);
void mm_i2c_bus_shutdown_all(void);

#endif /* M33MU_I2C_BUS_H */
