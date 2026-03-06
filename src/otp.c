/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include "m33mu/otp.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MM_OTP_TRAILER_MAGIC 0x4d4f5450u /* "MOTP" */
#define MM_OTP_TRAILER_VERSION 1u

struct mm_otp_trailer {
    mm_u32 magic;
    mm_u32 version;
    mm_u32 size;
    mm_u32 flags;
    mm_u32 reserved[4];
};

static mm_bool otp_write_all(int fd, const mm_u8 *buf, mm_u32 size)
{
    mm_u32 done = 0u;
    while (done < size) {
        ssize_t rc = write(fd, buf + done, size - done);
        if (rc <= 0) {
            return MM_FALSE;
        }
        done += (mm_u32)rc;
    }
    return MM_TRUE;
}

static mm_bool otp_read_all(int fd, mm_u8 *buf, mm_u32 size)
{
    mm_u32 done = 0u;
    while (done < size) {
        ssize_t rc = read(fd, buf + done, size - done);
        if (rc < 0) {
            return MM_FALSE;
        }
        if (rc == 0) {
            break;
        }
        done += (mm_u32)rc;
    }
    return MM_TRUE;
}

static mm_bool otp_flush(struct mm_otp *otp)
{
    int fd;
    struct mm_otp_trailer trailer;
    if (otp == 0 || otp->data == 0 || otp->size == 0) return MM_FALSE;
    fd = open(otp->path, O_RDWR | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) {
        fprintf(stderr, "otp: failed to open %s: %s\n", otp->path, strerror(errno));
        return MM_FALSE;
    }
    if (!otp_write_all(fd, otp->data, otp->size)) {
        fprintf(stderr, "otp: short write for %s\n", otp->path);
        close(fd);
        return MM_FALSE;
    }
    memset(&trailer, 0, sizeof(trailer));
    trailer.magic = MM_OTP_TRAILER_MAGIC;
    trailer.version = MM_OTP_TRAILER_VERSION;
    trailer.size = otp->size;
    trailer.flags = otp->flags;
    if (!otp_write_all(fd, (const mm_u8 *)&trailer, (mm_u32)sizeof(trailer))) {
        fprintf(stderr, "otp: short trailer write for %s\n", otp->path);
        close(fd);
        return MM_FALSE;
    }
    close(fd);
    return MM_TRUE;
}

static mm_bool otp_load(struct mm_otp *otp)
{
    int fd;
    struct stat st;
    mm_u32 file_size = 0u;
    mm_u32 read_size = 0u;
    mm_u32 trailer_offset = 0u;
    mm_bool need_flush = MM_FALSE;
    struct mm_otp_trailer trailer;
    if (otp == 0 || otp->size == 0) return MM_FALSE;
    if (otp->loaded) return MM_TRUE;

    otp->data = (mm_u8 *)malloc(otp->size);
    if (otp->data == 0) return MM_FALSE;
    memset(otp->data, 0xff, otp->size);

    fd = open(otp->path, O_RDWR | O_CREAT, 0666);
    if (fd < 0) {
        fprintf(stderr, "otp: failed to open %s: %s\n", otp->path, strerror(errno));
        free(otp->data);
        otp->data = 0;
        return MM_FALSE;
    }
    if (fstat(fd, &st) == 0) {
        if (st.st_size > 0) {
            file_size = (mm_u32)st.st_size;
        }
    }
    if (file_size > 0u) {
        read_size = (file_size < otp->size) ? file_size : otp->size;
        if (!otp_read_all(fd, otp->data, read_size)) {
            fprintf(stderr, "otp: short read for %s\n", otp->path);
        }
        if (file_size < otp->size) {
            need_flush = MM_TRUE;
        }
    } else {
        need_flush = MM_TRUE;
    }
    memset(&trailer, 0, sizeof(trailer));
    if (file_size >= otp->size + (mm_u32)sizeof(trailer)) {
        trailer_offset = file_size - (mm_u32)sizeof(trailer);
        if (lseek(fd, (off_t)(trailer_offset), SEEK_SET) >= 0) {
            if (otp_read_all(fd, (mm_u8 *)&trailer, (mm_u32)sizeof(trailer))) {
                if (trailer.magic == MM_OTP_TRAILER_MAGIC &&
                    trailer.version == MM_OTP_TRAILER_VERSION &&
                    trailer.size == otp->size) {
                    otp->flags = trailer.flags;
                } else {
                    need_flush = MM_TRUE;
                }
            } else {
                need_flush = MM_TRUE;
            }
        } else {
            need_flush = MM_TRUE;
        }
    } else {
        need_flush = MM_TRUE;
    }
    close(fd);
    otp->loaded = MM_TRUE;
    if (need_flush) {
        otp_flush(otp);
    }
    return MM_TRUE;
}

void mm_otp_init(struct mm_otp *otp, const char *target_name, mm_u32 size)
{
    mm_u8 *old_data;
    if (otp == 0) return;
    old_data = otp->data;
    memset(otp, 0, sizeof(*otp));
    if (old_data != 0) {
        free(old_data);
    }
    otp->size = size;
    otp->write_enabled = MM_TRUE;
    if (target_name == 0 || target_name[0] == '\0') {
        snprintf(otp->path, sizeof(otp->path), "target_OTP.bin");
    } else {
        snprintf(otp->path, sizeof(otp->path), "%s_OTP.bin", target_name);
    }
}

mm_bool mm_otp_read(struct mm_otp *otp, mm_u32 offset, mm_u8 *dst, mm_u32 len)
{
    if (otp == 0 || dst == 0 || len == 0u) return MM_FALSE;
    if (len > otp->size || offset > otp->size - len) return MM_FALSE;
    if (!otp_load(otp)) return MM_FALSE;
    memcpy(dst, otp->data + offset, len);
    return MM_TRUE;
}

mm_bool mm_otp_write(struct mm_otp *otp, mm_u32 offset, const mm_u8 *src, mm_u32 len)
{
    mm_u32 i;
    mm_bool changed = MM_FALSE;
    if (otp == 0 || src == 0 || len == 0u) return MM_FALSE;
    if (len > otp->size || offset > otp->size - len) return MM_FALSE;
    if (!otp_load(otp)) return MM_FALSE;
    if (!otp->write_enabled) return MM_FALSE;
    if ((otp->flags & MM_OTP_FLAG_FINAL_LOCK) != 0u) return MM_FALSE;
    for (i = 0; i < len; ++i) {
        mm_u8 cur = otp->data[offset + i];
        mm_u8 next = src[i];
        if ((next & (mm_u8)(~cur)) != 0u) {
            return MM_FALSE;
        }
        if ((cur & next) != cur) {
            changed = MM_TRUE;
        }
    }
    if (changed) {
        for (i = 0; i < len; ++i) {
            mm_u8 cur = otp->data[offset + i];
            mm_u8 next = src[i];
            otp->data[offset + i] = (mm_u8)(cur & next);
        }
        if (!otp_flush(otp)) {
            return MM_FALSE;
        }
    }
    return MM_TRUE;
}

mm_u8 *mm_otp_data(struct mm_otp *otp)
{
    if (otp == 0) return 0;
    if (!otp_load(otp)) return 0;
    return otp->data;
}

mm_u32 mm_otp_flags(struct mm_otp *otp)
{
    if (otp == 0) return 0u;
    if (!otp_load(otp)) return 0u;
    return otp->flags;
}

mm_bool mm_otp_set_flags(struct mm_otp *otp, mm_u32 set_mask)
{
    if (otp == 0) return MM_FALSE;
    if (!otp_load(otp)) return MM_FALSE;
    if ((otp->flags | set_mask) == otp->flags) return MM_TRUE;
    otp->flags |= set_mask;
    return otp_flush(otp);
}

void mm_otp_set_write_enabled(struct mm_otp *otp, mm_bool enabled)
{
    if (otp == 0) return;
    otp->write_enabled = enabled ? MM_TRUE : MM_FALSE;
}
