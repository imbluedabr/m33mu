/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include <stdio.h>
#include <string.h>

#include "m33mu/se050.h"

static int expect_parse(const char *spec, int bus, unsigned char addr)
{
    struct mm_se050_cfg cfg;
    if (!mm_se050_parse_spec(spec, &cfg)) {
        printf("se050_parse_test: parse failed for %s\n", spec);
        return 1;
    }
    if (cfg.bus != bus || cfg.addr != addr) {
        printf("se050_parse_test: unexpected parse for %s: bus=%d addr=0x%02x\n",
               spec, cfg.bus, cfg.addr);
        return 1;
    }
    return 0;
}

static int expect_parse_file(const char *spec, int bus, unsigned char addr,
                             const char *nv_path)
{
    struct mm_se050_cfg cfg;
    if (!mm_se050_parse_spec(spec, &cfg)) {
        printf("se050_parse_test: parse failed for %s\n", spec);
        return 1;
    }
    if (cfg.bus != bus || cfg.addr != addr) {
        printf("se050_parse_test: unexpected parse for %s: bus=%d addr=0x%02x\n",
               spec, cfg.bus, cfg.addr);
        return 1;
    }
    if (nv_path != 0) {
        if (!cfg.has_nv_path || strcmp(cfg.nv_path, nv_path) != 0) {
            printf("se050_parse_test: nv_path mismatch for %s\n", spec);
            return 1;
        }
    } else {
        if (cfg.has_nv_path) {
            printf("se050_parse_test: unexpected nv_path for %s\n", spec);
            return 1;
        }
    }
    return 0;
}

static int expect_reject(const char *spec)
{
    struct mm_se050_cfg cfg;
    if (mm_se050_parse_spec(spec, &cfg)) {
        printf("se050_parse_test: accepted invalid spec %s\n", spec);
        return 1;
    }
    return 0;
}

int main(void)
{
    int failures = 0;
    failures += expect_parse("I2C1", 1, MM_SE050_DEFAULT_ADDR);
    failures += expect_parse("I2C1:addr=48", 1, 0x48u);
    failures += expect_parse("I2C0:addr=20", 0, 0x20u);
    failures += expect_parse_file("I2C2:addr=48:file=/tmp/se050.bin",
                                  2, 0x48u, "/tmp/se050.bin");
    failures += expect_reject("SPI1");
    failures += expect_reject("I2C1:addr=zz");
    failures += expect_reject("I2C1:addr=ff");   /* > 0x7f */
    failures += expect_reject("I2C1:unknown=val");

    if (failures != 0) {
        printf("se050_parse_test: %d failure(s)\n", failures);
        return 1;
    }
    return 0;
}
