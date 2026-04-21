/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#define _POSIX_C_SOURCE 200112L
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#include "m33mu/se050.h"
#include "m33mu/i2c_bus.h"

#define SE050_MAX 4

struct mm_se050 {
    int bus;
    mm_u8 addr;
    char host[256];
    unsigned port;
    int fd;
};

static struct mm_se050 g_se050[SE050_MAX];
static size_t g_se050_count;

static void copy_cstr(char *dst, size_t dst_len, const char *src)
{
    size_t n;
    if (dst == 0 || dst_len == 0u) {
        return;
    }
    if (src == 0) {
        dst[0] = '\0';
        return;
    }
    n = strlen(src);
    if (n >= dst_len) {
        n = dst_len - 1u;
    }
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static int parse_i2c_bus(const char *s)
{
    char *end;
    long v;
    if (s == 0 || strncmp(s, "I2C", 3) != 0 || s[3] == '\0') {
        return -1;
    }
    v = strtol(s + 3, &end, 10);
    if (*end != '\0' || v < 0 || v > 255) {
        return -1;
    }
    return (int)v;
}

mm_bool mm_se050_parse_spec(const char *spec, struct mm_se050_cfg *out)
{
    char tmp[512];
    char *bus_tok;
    char *host_tok;
    char *port_tok;
    char *extra_tok;
    char *end;
    unsigned long port;

    if (spec == 0 || out == 0) {
        return MM_FALSE;
    }
    memset(out, 0, sizeof(*out));
    out->addr = MM_SE050_DEFAULT_ADDR;
    out->port = MM_SE050_DEFAULT_PORT;
    copy_cstr(out->host, sizeof(out->host), "127.0.0.1");

    copy_cstr(tmp, sizeof(tmp), spec);

    bus_tok = strtok(tmp, ":");
    if (bus_tok == 0) {
        return MM_FALSE;
    }
    out->bus = parse_i2c_bus(bus_tok);
    if (out->bus < 0) {
        return MM_FALSE;
    }

    host_tok = strtok(0, ":");
    port_tok = strtok(0, ":");
    extra_tok = strtok(0, ":");
    if (extra_tok != 0) {
        return MM_FALSE;
    }
    if (host_tok != 0 && host_tok[0] != '\0') {
        copy_cstr(out->host, sizeof(out->host), host_tok);
    }
    if (port_tok != 0 && port_tok[0] != '\0') {
        port = strtoul(port_tok, &end, 10);
        if (*end != '\0' || port == 0ul || port > 65535ul) {
            return MM_FALSE;
        }
        out->port = (unsigned)port;
    }
    return MM_TRUE;
}

static void se050_close(struct mm_se050 *se)
{
    if (se != 0 && se->fd >= 0) {
        close(se->fd);
        se->fd = -1;
    }
}

static mm_bool se050_connect(struct mm_se050 *se)
{
    struct addrinfo hints;
    struct addrinfo *res = 0;
    struct addrinfo *ai;
    char port_buf[16];
    int flag = 1;
    int fd = -1;

    if (se == 0) {
        return MM_FALSE;
    }
    if (se->fd >= 0) {
        return MM_TRUE;
    }

    snprintf(port_buf, sizeof(port_buf), "%u", se->port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(se->host, port_buf, &hints, &res) != 0) {
        fprintf(stderr, "se050: failed to resolve %s:%u\n", se->host, se->port);
        return MM_FALSE;
    }

    for (ai = res; ai != 0; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
        (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            se->fd = fd;
            freeaddrinfo(res);
            fprintf(stderr, "[SE050] Connected to %s:%u on I2C%d addr=0x%02x\n",
                    se->host, se->port, se->bus, se->addr);
            return MM_TRUE;
        }
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    fprintf(stderr, "se050: connect(%s:%u) failed: %s\n",
            se->host, se->port, strerror(errno));
    return MM_FALSE;
}

static mm_bool write_all(int fd, const mm_u8 *buf, size_t len)
{
    size_t total = 0;
    while (total < len) {
        ssize_t n = write(fd, buf + total, len - total);
        if (n <= 0) {
            return MM_FALSE;
        }
        total += (size_t)n;
    }
    return MM_TRUE;
}

static mm_bool read_exact_timeout(int fd, mm_u8 *buf, size_t len)
{
    size_t total = 0;
    while (total < len) {
        struct pollfd pfd;
        int ready;
        ssize_t n;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        ready = poll(&pfd, 1, 1000);
        if (ready <= 0 || (pfd.revents & POLLIN) == 0) {
            return MM_FALSE;
        }
        n = read(fd, buf + total, len - total);
        if (n <= 0) {
            return MM_FALSE;
        }
        total += (size_t)n;
    }
    return MM_TRUE;
}

static mm_bool se050_i2c_write(void *opaque, mm_u8 addr,
                               const mm_u8 *data, size_t len)
{
    struct mm_se050 *se = (struct mm_se050 *)opaque;
    (void)addr;
    if (data == 0 && len > 0u) {
        return MM_FALSE;
    }
    if (!se050_connect(se)) {
        return MM_FALSE;
    }
    if (!write_all(se->fd, data, len)) {
        se050_close(se);
        return MM_FALSE;
    }
    return MM_TRUE;
}

static mm_bool se050_i2c_read(void *opaque, mm_u8 addr, mm_u8 *data, size_t len)
{
    struct mm_se050 *se = (struct mm_se050 *)opaque;
    (void)addr;
    if (data == 0 && len > 0u) {
        return MM_FALSE;
    }
    if (!se050_connect(se)) {
        return MM_FALSE;
    }
    if (!read_exact_timeout(se->fd, data, len)) {
        return MM_FALSE;
    }
    return MM_TRUE;
}

static void se050_i2c_reset(void *opaque)
{
    se050_close((struct mm_se050 *)opaque);
}

static void se050_i2c_shutdown(void *opaque)
{
    se050_close((struct mm_se050 *)opaque);
}

mm_bool mm_se050_register_cfg(const struct mm_se050_cfg *cfg)
{
    struct mm_se050 *se;
    struct mm_i2c_device dev;
    if (cfg == 0) {
        return MM_FALSE;
    }
    if (cfg->bus <= 0) {
        fprintf(stderr, "se050: I2C%d is not implemented for STM32-style hardware naming\n",
                cfg->bus);
        return MM_FALSE;
    }
    if (g_se050_count >= SE050_MAX) {
        fprintf(stderr, "se050: max devices reached\n");
        return MM_FALSE;
    }
    se = &g_se050[g_se050_count];
    memset(se, 0, sizeof(*se));
    se->bus = cfg->bus;
    se->addr = cfg->addr;
    se->port = cfg->port;
    se->fd = -1;
    copy_cstr(se->host, sizeof(se->host), cfg->host);

    memset(&dev, 0, sizeof(dev));
    dev.bus = se->bus;
    dev.addr = se->addr;
    dev.write = se050_i2c_write;
    dev.read = se050_i2c_read;
    dev.reset = se050_i2c_reset;
    dev.shutdown = se050_i2c_shutdown;
    dev.opaque = se;
    if (!mm_i2c_bus_register_device(&dev)) {
        fprintf(stderr, "se050: failed to register I2C device\n");
        return MM_FALSE;
    }

    g_se050_count++;
    fprintf(stderr, "[SE050] Registered on I2C%d addr=0x%02x host=%s port=%u\n",
            se->bus, se->addr, se->host, se->port);
    return MM_TRUE;
}

void mm_se050_reset_all(void)
{
    size_t i;
    for (i = 0; i < g_se050_count; ++i) {
        se050_close(&g_se050[i]);
    }
}

void mm_se050_shutdown_all(void)
{
    size_t i;
    for (i = 0; i < g_se050_count; ++i) {
        se050_close(&g_se050[i]);
    }
    g_se050_count = 0;
    mm_i2c_bus_shutdown_all();
}
