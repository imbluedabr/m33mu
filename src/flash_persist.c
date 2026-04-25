/* m33mu -- an ARMv8-M Emulator
 *
 * Copyright (C) 2025  Daniele Lacamera <root@danielinux.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 */

#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "m33mu/flash_persist.h"

static void persist_close(struct mm_flash_persist *persist)
{
    int i;
    if (persist == 0 || !persist->enabled) {
        return;
    }
    for (i = 0; i < persist->count; ++i) {
        if (persist->ranges[i].fd >= 0) {
            close(persist->ranges[i].fd);
            persist->ranges[i].fd = -1;
        }
    }
}

static void sort_indices(mm_u32 *idx, const mm_u32 *offsets, int count)
{
    int i;
    int j;
    for (i = 0; i < count; ++i) {
        idx[i] = (mm_u32)i;
    }
    for (i = 0; i < count; ++i) {
        for (j = i + 1; j < count; ++j) {
            if (offsets[idx[j]] < offsets[idx[i]]) {
                mm_u32 tmp = idx[i];
                idx[i] = idx[j];
                idx[j] = tmp;
            }
        }
    }
}

static mm_bool persist_write_all(int fd, const mm_u8 *buf, mm_u32 size);

void mm_flash_persist_build(struct mm_flash_persist *persist,
                            mm_u8 *flash,
                            mm_u32 flash_size,
                            const char **paths,
                            const mm_u32 *offsets,
                            int count)
{
    int i;
    mm_u32 idx[16];
    if (persist == 0) {
        return;
    }
    persist_close(persist);
    memset(persist, 0, sizeof(*persist));
    if (flash == 0 || paths == 0 || offsets == 0 || count <= 0) {
        return;
    }
    if (count > (int)(sizeof(persist->ranges) / sizeof(persist->ranges[0]))) {
        count = (int)(sizeof(persist->ranges) / sizeof(persist->ranges[0]));
    }
    sort_indices(idx, offsets, count);
    persist->enabled = MM_TRUE;
    persist->flash = flash;
    persist->flash_size = flash_size;
    persist->count = count;
    for (i = 0; i < count; ++i) {
        int cur = (int)idx[i];
        int next = (i + 1 < count) ? (int)idx[i + 1] : -1;
        mm_u32 start = offsets[cur];
        mm_u32 end = (next >= 0) ? offsets[next] : flash_size;
        int fd = -1;
        if (end < start) {
            end = start;
        }
        if (end > flash_size) {
            end = flash_size;
        }
        persist->ranges[i].path = paths[cur];
        persist->ranges[i].offset = start;
        persist->ranges[i].length = end - start;
        persist->ranges[i].fd = -1;
        if (persist->ranges[i].path != 0) {
            struct stat st;
            mm_u32 cur_size = 0u;
            fd = open(persist->ranges[i].path, O_RDWR | O_CREAT | O_CLOEXEC, 0666);
            if (fd < 0) {
                fprintf(stderr, "persist: failed to open %s: %s\n",
                        persist->ranges[i].path, strerror(errno));
                continue;
            }
            if (fstat(fd, &st) == 0) {
                if (st.st_size > 0) {
                    if ((unsigned long)st.st_size > (unsigned long)flash_size) {
                        if (ftruncate(fd, (off_t)flash_size) != 0) {
                            fprintf(stderr, "persist: failed to truncate %s\n",
                                    persist->ranges[i].path);
                        }
                        cur_size = flash_size;
                    } else {
                        cur_size = (mm_u32)st.st_size;
                    }
                }
            }
            if (cur_size < flash_size) {
                mm_u8 ff[4096];
                mm_u32 remaining = flash_size - cur_size;
                mm_u32 chunk;
                memset(ff, 0xFF, sizeof(ff));
                if (lseek(fd, (off_t)cur_size, SEEK_SET) < 0) {
                    fprintf(stderr, "persist: failed to seek %s\n",
                            persist->ranges[i].path);
                } else {
                    while (remaining > 0u) {
                        chunk = (remaining > (mm_u32)sizeof(ff)) ? (mm_u32)sizeof(ff) : remaining;
                        if (!persist_write_all(fd, ff, chunk)) {
                            fprintf(stderr, "persist: short extend write for %s\n",
                                    persist->ranges[i].path);
                            break;
                        }
                        remaining -= chunk;
                    }
                }
            }
            persist->ranges[i].fd = fd;
        }
    }
}

static mm_bool persist_write_all(int fd, const mm_u8 *buf, mm_u32 size)
{
    mm_u32 off = 0u;
    while (off < size) {
        ssize_t n = write(fd, buf + off, (size_t)(size - off));
        if (n <= 0) {
            return MM_FALSE;
        }
        off += (mm_u32)n;
    }
    return MM_TRUE;
}

void mm_flash_persist_flush(struct mm_flash_persist *persist, mm_u32 addr, mm_u32 size)
{
    int i;
    if (persist == 0 || !persist->enabled || persist->flash == 0) {
        return;
    }
    if (size == 0u) {
        return;
    }
    for (i = 0; i < persist->count; ++i) {
        mm_u32 start = persist->ranges[i].offset;
        mm_u32 end = start + persist->ranges[i].length;
        mm_u32 eff_size = size;
        mm_u32 a0 = addr;
        mm_u32 a1;
        mm_u32 w_start;
        mm_u32 w_end;
        if (eff_size > 0xFFFFFFFFu - addr) {
            eff_size = 0xFFFFFFFFu - addr;
        }
        a1 = addr + eff_size;
        if (a1 <= start || a0 >= end) {
            continue;
        }
        if (persist->ranges[i].fd < 0) {
            continue;
        }
        w_start = (a0 > start) ? a0 : start;
        w_end = (a1 < end) ? a1 : end;
        if (w_end > w_start) {
            if (lseek(persist->ranges[i].fd, (off_t)w_start, SEEK_SET) < 0) {
                fprintf(stderr, "persist: failed to seek %s\n", persist->ranges[i].path);
                continue;
            }
            if (!persist_write_all(persist->ranges[i].fd, persist->flash + w_start, w_end - w_start)) {
                fprintf(stderr, "persist: short write for %s\n", persist->ranges[i].path);
            }
        }
    }
}
