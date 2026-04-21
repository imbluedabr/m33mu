/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include <stdio.h>
#include <string.h>

#include "m33mu/se050.h"

static int expect_parse(const char *spec, int bus,
                        const char *host, unsigned port)
{
    struct mm_se050_cfg cfg;
    if (!mm_se050_parse_spec(spec, &cfg)) {
        printf("se050_parse_test: parse failed for %s\n", spec);
        return 1;
    }
    if (cfg.bus != bus || strcmp(cfg.host, host) != 0 || cfg.port != port ||
        cfg.addr != MM_SE050_DEFAULT_ADDR) {
        printf("se050_parse_test: unexpected parse for %s: bus=%d host=%s port=%u addr=0x%02x\n",
               spec, cfg.bus, cfg.host, cfg.port, cfg.addr);
        return 1;
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
    struct mm_se050_cfg cfg;
    failures += expect_parse("I2C1", 1, "127.0.0.1", 8050u);
    failures += expect_parse("I2C1:localhost", 1, "localhost", 8050u);
    failures += expect_parse("I2C1:localhost:18050", 1, "localhost", 18050u);
    failures += expect_parse("I2C0", 0, "127.0.0.1", 8050u);
    failures += expect_reject("SPI1");
    failures += expect_reject("I2C1:localhost:bad");
    failures += expect_reject("I2C1:localhost:70000");
    failures += expect_reject("I2C1:localhost:8050:extra");
    if (!mm_se050_parse_spec("I2C0", &cfg) || mm_se050_register_cfg(&cfg)) {
        printf("se050_parse_test: I2C0 registration was not rejected\n");
        failures++;
    }

    if (failures != 0) {
        printf("se050_parse_test: %d failure(s)\n", failures);
        return 1;
    }
    return 0;
}
