/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#include <ctype.h>
#include <linux/usb/gadgetfs.h>
#include <linux/usb/ch9.h>
#include "m33mu/usbdev.h"

#define USBDEV_MAX_CFG_LEN 4096u
#define USBDEV_MAX_CTRL_LEN 4096u
#define USBDEV_MAX_ENDPOINTS 16u
#define USBDEV_MAX_EP_BUF 4096u
#define USBDEV_EP0_FALLBACK_MAX_PACKET 64u
#define USBDEV_MAX_PATH 512u
#define USBDEV_ROOT_MAX 480u
#define USBDEV_MAX_STRINGS 16u
#define USBDEV_MAX_STRING_LEN 256u

enum usbdev_desc_state {
    USBDEV_DESC_IDLE = 0,
    USBDEV_DESC_DEV_WAIT,
    USBDEV_DESC_DEV_STATUS,
    USBDEV_DESC_CFG_HDR_WAIT,
    USBDEV_DESC_CFG_HDR_STATUS,
    USBDEV_DESC_CFG_WAIT,
    USBDEV_DESC_CFG_STATUS,
    USBDEV_DESC_STR_WAIT,
    USBDEV_DESC_STR_STATUS,
    USBDEV_DESC_WRITE,
    USBDEV_DESC_DONE,
    USBDEV_DESC_FAILED
};

enum usbdev_ctrl_stage {
    USBDEV_CTRL_IDLE = 0,
    USBDEV_CTRL_OUT_READ,
    USBDEV_CTRL_OUT_DELIVER,
    USBDEV_CTRL_STATUS_WRITE,
    USBDEV_CTRL_IN_FETCH,
    USBDEV_CTRL_IN_WRITE,
    USBDEV_CTRL_IN_STATUS_READ
};

struct usbdev_ctrl {
    enum usbdev_ctrl_stage stage;
    struct usb_ctrlrequest setup;
    mm_bool active;
    mm_bool in_dir;
    mm_bool status_pending;
    mm_bool status_read;
    mm_bool status_sent;
    mm_bool local_active;
    mm_u16 local_len;
    mm_u16 local_off;
    mm_u16 expected;
    mm_u16 transferred;
    mm_u16 received;
    mm_u8 buf[USBDEV_MAX_CTRL_LEN];
    mm_u8 local_buf[USBDEV_MAX_CTRL_LEN];
    size_t buf_len;
    size_t buf_off;
};

struct usbdev_string {
    mm_u8 index;
    mm_u16 len;
    mm_u8 data[USBDEV_MAX_STRING_LEN];
    mm_bool valid;
};

struct usbdev_ep {
    int fd;
    mm_u8 addr;
    mm_bool dir_in;
    mm_u8 type;
    mm_u16 max_packet;
    mm_u8 desc[USB_DT_ENDPOINT_SIZE];
    size_t desc_len;
    mm_u8 tx_buf[USBDEV_MAX_EP_BUF];
    size_t tx_len;
    size_t tx_off;
};

struct usbdev_gadget {
    int ep0_fd;
    mm_bool running;
    mm_bool connected;
    mm_bool host_connected;
    mm_bool irq_enabled;
    mm_bool configured;
    mm_bool descriptors_written;
    mm_bool endpoints_opened;
    mm_bool logged_wait_irq;
    mm_bool setup_pending;
    mm_u32 setup_cycles;
    mm_u32 setup_timeout;
    mm_u32 setup_retry_cycles;
    mm_u32 setup_retry_delay;
    mm_bool paused;
    char udc_name[128];
    char udc_path[USBDEV_MAX_PATH];
    char gadget_root[USBDEV_ROOT_MAX];
    mm_u8 ep0_max_packet;

    enum usbdev_desc_state desc_state;
    mm_u8 dev_desc[USB_DT_DEVICE_SIZE];
    size_t dev_desc_off;
    mm_u8 cfg_hdr[USB_DT_CONFIG_SIZE];
    size_t cfg_hdr_off;
    mm_u16 cfg_total_len;
    mm_u8 cfg_desc[USBDEV_MAX_CFG_LEN];
    size_t cfg_desc_off;
    mm_u8 desc_blob[4u + USBDEV_MAX_CFG_LEN + USB_DT_DEVICE_SIZE];
    size_t desc_blob_len;
    size_t desc_blob_off;
    mm_u16 string_langid;
    mm_u8 string_indices[USBDEV_MAX_STRINGS];
    size_t string_count;
    size_t string_pos;
    mm_u8 string_buf[USBDEV_MAX_CTRL_LEN];
    size_t string_off;
    mm_u16 string_expected;
    struct usbdev_string strings[USBDEV_MAX_STRINGS];

    struct usbdev_ctrl ctrl;
    struct usbdev_ep eps[USBDEV_MAX_ENDPOINTS];
    size_t ep_count;
};

static struct usbdev_gadget g_usb;
static const struct mm_usbdev_ops *g_usb_ops = 0;
static void *g_usb_opaque = 0;
static int g_usb_trace = -1;
static int g_usb_local_strings = -1;

static mm_bool usb_trace_enabled(void)
{
    if (g_usb_trace < 0) {
        const char *v = getenv("M33MU_USB_TRACE");
        g_usb_trace = (v && v[0] != '\0') ? 1 : 0;
    }
    return g_usb_trace ? MM_TRUE : MM_FALSE;
}

static void usb_trace(const char *fmt, ...)
{
    va_list ap;
    if (!usb_trace_enabled()) return;
    va_start(ap, fmt);
    fprintf(stderr, "[USB_TRACE] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

static mm_bool usb_local_strings_enabled(void)
{
    if (g_usb_local_strings < 0) {
        const char *v = getenv("M33MU_USB_LOCAL_STRINGS");
        g_usb_local_strings = (v && v[0] != '\0') ? 1 : 0;
    }
    return g_usb_local_strings ? MM_TRUE : MM_FALSE;
}

static void usbdev_reset_ctrl(void)
{
    memset(&g_usb.ctrl, 0, sizeof(g_usb.ctrl));
    g_usb.ctrl.stage = USBDEV_CTRL_IDLE;
}

static mm_u16 usbdev_build_string_desc(mm_u8 index, mm_u16 w_index, mm_u8 *out, mm_u16 out_len)
{
    const char *str = 0;
    mm_u16 len;
    mm_u16 i;
    if (out == 0 || out_len < 4u) return 0u;
    if (index == 0u) {
        out[0] = 0x04;
        out[1] = USB_DT_STRING;
        out[2] = 0x09;
        out[3] = 0x04;
        return 4u;
    }
    (void)w_index;
    switch (index) {
    case 1u: str = "M33MU"; break;
    case 2u: str = "RP2350 USB"; break;
    case 3u: str = "00000001"; break;
    default: str = "USB Device"; break;
    }
    len = (mm_u16)strlen(str);
    if ((mm_u16)(2u + len * 2u) > out_len) {
        len = (out_len - 2u) / 2u;
    }
    out[0] = (mm_u8)(2u + len * 2u);
    out[1] = USB_DT_STRING;
    for (i = 0; i < len; ++i) {
        out[2u + (i * 2u)] = (mm_u8)str[i];
        out[3u + (i * 2u)] = 0u;
    }
    return (mm_u16)(2u + len * 2u);
}

static mm_bool usbdev_send_setup(mm_u8 bm_request, mm_u8 b_request,
                                 mm_u16 w_value, mm_u16 w_index, mm_u16 w_length)
{
    struct usb_ctrlrequest setup;
    if (g_usb_ops == 0 || g_usb_ops->ep_out == 0) return MM_FALSE;
    memset(&setup, 0, sizeof(setup));
    setup.bRequestType = bm_request;
    setup.bRequest = b_request;
    setup.wValue = w_value;
    setup.wIndex = w_index;
    setup.wLength = w_length;
    if (!g_usb_ops->ep_out(g_usb_opaque, 0, (const mm_u8 *)&setup, 8u, MM_TRUE)) {
        fprintf(stderr, "[USB] setup dispatch failed bRequest=0x%02x wValue=0x%04x\n",
                (unsigned)b_request, (unsigned)w_value);
        return MM_FALSE;
    }
    g_usb.setup_pending = MM_TRUE;
    g_usb.setup_cycles = 0;
    return MM_TRUE;
}

static mm_bool usbdev_ep0_in(mm_u8 *buf, mm_u32 *len_inout)
{
    if (g_usb_ops == 0 || g_usb_ops->ep_in == 0) return MM_FALSE;
    return g_usb_ops->ep_in(g_usb_opaque, 0, buf, len_inout);
}

static mm_bool usbdev_ep0_status_out(void)
{
    if (g_usb_ops == 0 || g_usb_ops->ep_out == 0) return MM_FALSE;
    return g_usb_ops->ep_out(g_usb_opaque, 0, 0, 0u, MM_FALSE);
}

static void usbdev_make_paths(const char *udc_name)
{
    const char *name = udc_name && udc_name[0] != '\0' ? udc_name : "dummy_udc.0";
    if (strchr(name, '/') != 0) {
        snprintf(g_usb.udc_path, sizeof(g_usb.udc_path), "%s", name);
        snprintf(g_usb.udc_name, sizeof(g_usb.udc_name), "%s", name);
    } else {
        snprintf(g_usb.udc_path, sizeof(g_usb.udc_path), "/dev/gadget/%s", name);
        snprintf(g_usb.udc_name, sizeof(g_usb.udc_name), "%s", name);
    }
    {
        size_t len = strlen(g_usb.udc_path);
        if (len >= sizeof(g_usb.gadget_root)) {
            len = sizeof(g_usb.gadget_root) - 1u;
        }
        memcpy(g_usb.gadget_root, g_usb.udc_path, len);
        g_usb.gadget_root[len] = '\0';
    }
}

static mm_bool usbdev_path_is_dir(const char *path)
{
    struct stat st;
    if (path == 0) return MM_FALSE;
    if (stat(path, &st) != 0) return MM_FALSE;
    return S_ISDIR(st.st_mode) ? MM_TRUE : MM_FALSE;
}

static void usbdev_path_parent(const char *path, char *out, size_t out_len)
{
    const char *slash;
    size_t len;
    if (out == 0 || out_len == 0u) return;
    out[0] = '\0';
    if (path == 0) return;
    slash = strrchr(path, '/');
    if (slash == 0) {
        return;
    }
    len = (size_t)(slash - path);
    if (len >= out_len) len = out_len - 1u;
    memcpy(out, path, len);
    out[len] = '\0';
}

static mm_bool usbdev_collect_desc(mm_u8 *dst, size_t *off, size_t expected)
{
    mm_u32 len;
    if (dst == 0 || off == 0) return MM_FALSE;
    if (*off >= expected) return MM_TRUE;
    len = (mm_u32)(expected - *off);
    if (len > USBDEV_MAX_CTRL_LEN) len = USBDEV_MAX_CTRL_LEN;
    if (!usbdev_ep0_in(dst + *off, &len)) {
        return MM_FALSE;
    }
    *off += (size_t)len;
    return (*off >= expected) ? MM_TRUE : MM_FALSE;
}

static void usbdev_string_cache_store(mm_u8 index, const mm_u8 *data, mm_u16 len)
{
    size_t i;
    if (data == 0 || len == 0u) return;
    for (i = 0; i < USBDEV_MAX_STRINGS; ++i) {
        if (g_usb.strings[i].valid && g_usb.strings[i].index == index) {
            mm_u16 copy = len;
            if (copy > USBDEV_MAX_STRING_LEN) copy = USBDEV_MAX_STRING_LEN;
            memcpy(g_usb.strings[i].data, data, copy);
            g_usb.strings[i].len = copy;
            return;
        }
    }
    for (i = 0; i < USBDEV_MAX_STRINGS; ++i) {
        if (!g_usb.strings[i].valid) {
            mm_u16 copy = len;
            if (copy > USBDEV_MAX_STRING_LEN) copy = USBDEV_MAX_STRING_LEN;
            g_usb.strings[i].index = index;
            g_usb.strings[i].len = copy;
            memcpy(g_usb.strings[i].data, data, copy);
            g_usb.strings[i].valid = MM_TRUE;
            return;
        }
    }
}

static const struct usbdev_string *usbdev_string_cache_find(mm_u8 index)
{
    size_t i;
    for (i = 0; i < USBDEV_MAX_STRINGS; ++i) {
        if (g_usb.strings[i].valid && g_usb.strings[i].index == index) {
            return &g_usb.strings[i];
        }
    }
    return 0;
}

static void usbdev_collect_string_indices(void)
{
    size_t off = 0;
    size_t count = 0;
    mm_u8 seen[256];
    memset(seen, 0, sizeof(seen));
    g_usb.string_count = 0;
    g_usb.string_pos = 0;
    g_usb.string_langid = 0;
    if (count < USBDEV_MAX_STRINGS) {
        g_usb.string_indices[count++] = 0u;
        seen[0] = 1u;
    }
    if (g_usb.dev_desc_off >= USB_DT_DEVICE_SIZE) {
        mm_u8 idx;
        idx = g_usb.dev_desc[14];
        if (!seen[idx] && count < USBDEV_MAX_STRINGS) {
            g_usb.string_indices[count++] = idx;
            seen[idx] = 1u;
        }
        idx = g_usb.dev_desc[15];
        if (!seen[idx] && count < USBDEV_MAX_STRINGS) {
            g_usb.string_indices[count++] = idx;
            seen[idx] = 1u;
        }
        idx = g_usb.dev_desc[16];
        if (!seen[idx] && count < USBDEV_MAX_STRINGS) {
            g_usb.string_indices[count++] = idx;
            seen[idx] = 1u;
        }
    }
    while (off + 2u <= g_usb.cfg_desc_off && off < g_usb.cfg_desc_off) {
        mm_u8 b_length = g_usb.cfg_desc[off];
        mm_u8 b_type = g_usb.cfg_desc[off + 1u];
        if (b_length == 0u) break;
        if (off + b_length > g_usb.cfg_desc_off) break;
        if (b_type == USB_DT_CONFIG && b_length >= USB_DT_CONFIG_SIZE) {
            mm_u8 idx = g_usb.cfg_desc[off + 6u];
            if (!seen[idx] && count < USBDEV_MAX_STRINGS) {
                g_usb.string_indices[count++] = idx;
                seen[idx] = 1u;
            }
        } else if (b_type == USB_DT_INTERFACE && b_length >= 9u) {
            mm_u8 idx = g_usb.cfg_desc[off + 8u];
            if (!seen[idx] && count < USBDEV_MAX_STRINGS) {
                g_usb.string_indices[count++] = idx;
                seen[idx] = 1u;
            }
        }
        off += b_length;
    }
    g_usb.string_count = count;
}

static mm_bool usbdev_collect_string_desc(void)
{
    mm_u32 len;
    if (g_usb.string_off >= USBDEV_MAX_CTRL_LEN) return MM_FALSE;
    len = USBDEV_MAX_CTRL_LEN - (mm_u32)g_usb.string_off;
    if (!usbdev_ep0_in(g_usb.string_buf + g_usb.string_off, &len)) {
        return MM_FALSE;
    }
    if (len == 0u) return MM_FALSE;
    g_usb.string_off += (size_t)len;
    if (g_usb.string_expected == 0u && g_usb.string_off >= 2u) {
        g_usb.string_expected = g_usb.string_buf[0];
        if (g_usb.string_expected == 0u || g_usb.string_expected > USBDEV_MAX_CTRL_LEN) {
            g_usb.string_expected = (mm_u16)g_usb.string_off;
        }
    }
    if (g_usb.string_expected > 0u && g_usb.string_off >= g_usb.string_expected) {
        return MM_TRUE;
    }
    return MM_FALSE;
}

static void usbdev_parse_endpoints(void)
{
    size_t off = 0;
    size_t count = 0;
    memset(g_usb.eps, 0, sizeof(g_usb.eps));
    g_usb.ep_count = 0;
    while (off + 2u <= g_usb.cfg_desc_off && off < g_usb.cfg_desc_off) {
        mm_u8 b_length = g_usb.cfg_desc[off];
        mm_u8 b_type = g_usb.cfg_desc[off + 1u];
        if (b_length == 0u) break;
        if (off + b_length > g_usb.cfg_desc_off) break;
        if (b_type == USB_DT_ENDPOINT && b_length >= USB_DT_ENDPOINT_SIZE) {
            mm_u8 ep_addr = g_usb.cfg_desc[off + 2u];
            mm_u8 attributes = g_usb.cfg_desc[off + 3u];
            mm_u16 max_packet = (mm_u16)(g_usb.cfg_desc[off + 4u] | (g_usb.cfg_desc[off + 5u] << 8));
            mm_u8 ep_num = (mm_u8)(ep_addr & USB_ENDPOINT_NUMBER_MASK);
            mm_bool dir_in = (ep_addr & USB_DIR_IN) ? MM_TRUE : MM_FALSE;
            if (ep_num != 0u && count < USBDEV_MAX_ENDPOINTS) {
                struct usbdev_ep *ep = &g_usb.eps[count];
                ep->addr = ep_addr;
                ep->dir_in = dir_in;
                ep->type = (mm_u8)(attributes & USB_ENDPOINT_XFERTYPE_MASK);
                ep->max_packet = max_packet;
                ep->desc_len = b_length;
                memcpy(ep->desc, &g_usb.cfg_desc[off], b_length);
                ep->fd = -1;
                count++;
            }
        }
        off += b_length;
    }
    g_usb.ep_count = count;
}

static void usbdev_open_endpoints(void)
{
    size_t i;
    char alt_root[USBDEV_MAX_PATH];
    mm_bool alt_root_ok = MM_FALSE;
    if (g_usb.endpoints_opened) {
        return;
    }
    if (usb_trace_enabled()) {
        usb_trace("endpoint open begin count=%zu root=%s", g_usb.ep_count, g_usb.gadget_root);
    }
    alt_root[0] = '\0';
    if (usbdev_path_is_dir(g_usb.udc_path) && strcmp(g_usb.gadget_root, g_usb.udc_path) != 0) {
        snprintf(alt_root, sizeof(alt_root), "%s", g_usb.udc_path);
        alt_root_ok = MM_TRUE;
    } else {
        usbdev_path_parent(g_usb.udc_path, alt_root, sizeof(alt_root));
        if (alt_root[0] != '\0' && strcmp(g_usb.gadget_root, alt_root) != 0) {
            alt_root_ok = MM_TRUE;
        }
    }
    for (i = 0; i < g_usb.ep_count; ++i) {
        struct usbdev_ep *ep = &g_usb.eps[i];
        char path[USBDEV_MAX_PATH];
        int fd = -1;
        const char *dir = ep->dir_in ? "in" : "out";
        int ep_num = (int)(ep->addr & USB_ENDPOINT_NUMBER_MASK);
        const char *type_suffix = "";
        mm_u8 type = ep->type;
        switch (type) {
        case USB_ENDPOINT_XFER_BULK: type_suffix = "-bulk"; break;
        case USB_ENDPOINT_XFER_INT: type_suffix = "-int"; break;
        case USB_ENDPOINT_XFER_ISOC: type_suffix = "-iso"; break;
        default: break;
        }
        snprintf(path, sizeof(path), "%s/ep%d%s%s", g_usb.gadget_root, ep_num, dir, type_suffix);
        fd = open(path, O_RDWR | O_NONBLOCK);
        if (fd < 0 && type_suffix[0] != '\0') {
            snprintf(path, sizeof(path), "%s/ep%d%s", g_usb.gadget_root, ep_num, dir);
            fd = open(path, O_RDWR | O_NONBLOCK);
        }
        if (fd < 0) {
            if (alt_root_ok && (errno == ENOENT || errno == ENOTDIR)) {
                snprintf(path, sizeof(path), "%s/ep%d%s%s", alt_root, ep_num, dir, type_suffix);
                fd = open(path, O_RDWR | O_NONBLOCK);
                if (fd < 0 && type_suffix[0] != '\0') {
                    snprintf(path, sizeof(path), "%s/ep%d%s", alt_root, ep_num, dir);
                    fd = open(path, O_RDWR | O_NONBLOCK);
                }
            }
        }
        if (fd < 0) {
            DIR *d = opendir(g_usb.gadget_root);
            struct dirent *ent;
            if (d != 0) {
                while ((ent = readdir(d)) != 0) {
                    const char *name = ent->d_name;
                    int found_num = -1;
                    int found_in = -1;
                    const char *suffix = 0;
                    const char *p;
                    if (strncmp(name, "ep", 2) != 0) continue;
                    p = name + 2;
                    if (*p == '-') p++;
                    if (!isxdigit((unsigned char)*p)) continue;
                    found_num = (int)strtol(p, (char **)&p, 16);
                    if (found_num != ep_num) continue;
                    if (strncmp(p, "in", 2) == 0) {
                        found_in = 1;
                        p += 2;
                    } else if (strncmp(p, "out", 3) == 0) {
                        found_in = 0;
                        p += 3;
                    } else {
                        continue;
                    }
                    if ((found_in != 0) != (ep->dir_in != 0)) continue;
                    if (*p == '-') {
                        suffix = p;
                    }
                    if (suffix != 0) {
                        if ((type == USB_ENDPOINT_XFER_BULK && strcmp(suffix, "-bulk") != 0) ||
                            (type == USB_ENDPOINT_XFER_INT && strcmp(suffix, "-int") != 0) ||
                            (type == USB_ENDPOINT_XFER_ISOC && strcmp(suffix, "-iso") != 0)) {
                            /* keep looking for exact type match */
                        } else {
                            if (snprintf(path, sizeof(path), "%s/%s", g_usb.gadget_root, name) < (int)sizeof(path)) {
                                fd = open(path, O_RDWR | O_NONBLOCK);
                            }
                            break;
                        }
                    }
                    if (fd < 0) {
                        if (snprintf(path, sizeof(path), "%s/%s", g_usb.gadget_root, name) < (int)sizeof(path)) {
                            fd = open(path, O_RDWR | O_NONBLOCK);
                        }
                        if (fd >= 0) break;
                    }
                }
                closedir(d);
            }
        }
        if (fd < 0) {
            usb_trace("open endpoint failed path=%s errno=%d", path, errno);
            continue;
        }
        if (ep->desc_len > 0u) {
            mm_u8 cfg[4u + USB_DT_ENDPOINT_SIZE * 2u];
            size_t cfg_len = 0;
            mm_u32 tag = 1u;
            memcpy(cfg + cfg_len, &tag, sizeof(tag));
            cfg_len += sizeof(tag);
            memcpy(cfg + cfg_len, ep->desc, ep->desc_len);
            cfg_len += ep->desc_len;
            memcpy(cfg + cfg_len, ep->desc, ep->desc_len);
            cfg_len += ep->desc_len;
            if (write(fd, cfg, cfg_len) < 0) {
                usb_trace("endpoint desc write failed path=%s errno=%d", path, errno);
                close(fd);
                ep->fd = -1;
                continue;
            }
        }
        ep->fd = fd;
        usb_trace("endpoint ready path=%s addr=0x%02x", path, ep->addr);
    }
    g_usb.endpoints_opened = MM_TRUE;
}

static void usbdev_close_endpoints(void)
{
    size_t i;
    for (i = 0; i < g_usb.ep_count; ++i) {
        if (g_usb.eps[i].fd >= 0) {
            close(g_usb.eps[i].fd);
            g_usb.eps[i].fd = -1;
        }
    }
    g_usb.endpoints_opened = MM_FALSE;
}

static void usbdev_desc_tick(void)
{
    if (g_usb.setup_retry_cycles > 0u) {
        g_usb.setup_retry_cycles--;
        return;
    }
    if (g_usb.setup_pending) {
        if (g_usb.setup_cycles < g_usb.setup_timeout) {
            g_usb.setup_cycles++;
        }
    }
    switch (g_usb.desc_state) {
    case USBDEV_DESC_IDLE:
        if (g_usb_ops == 0) return;
        if (!usbdev_send_setup(USB_DIR_IN, USB_REQ_GET_DESCRIPTOR,
                               (USB_DT_DEVICE << 8), 0u, USB_DT_DEVICE_SIZE)) {
            return;
        }
        g_usb.dev_desc_off = 0;
        g_usb.desc_state = USBDEV_DESC_DEV_WAIT;
        fprintf(stderr, "[USB] desc: request device\n");
        break;
    case USBDEV_DESC_DEV_WAIT:
        if (usbdev_collect_desc(g_usb.dev_desc, &g_usb.dev_desc_off, USB_DT_DEVICE_SIZE)) {
            g_usb.setup_pending = MM_FALSE;
            g_usb.desc_state = USBDEV_DESC_DEV_STATUS;
        }
        break;
    case USBDEV_DESC_DEV_STATUS:
        if (!usbdev_ep0_status_out()) {
            return;
        }
        g_usb.ep0_max_packet = g_usb.dev_desc[7u];
        if (g_usb.ep0_max_packet == 0u) g_usb.ep0_max_packet = USBDEV_EP0_FALLBACK_MAX_PACKET;
        if (!usbdev_send_setup(USB_DIR_IN, USB_REQ_GET_DESCRIPTOR,
                               (USB_DT_CONFIG << 8), 0u, USB_DT_CONFIG_SIZE)) {
            return;
        }
        g_usb.cfg_hdr_off = 0;
        g_usb.desc_state = USBDEV_DESC_CFG_HDR_WAIT;
        fprintf(stderr, "[USB] desc: device ok, request config header\n");
        break;
    case USBDEV_DESC_CFG_HDR_WAIT:
        if (usbdev_collect_desc(g_usb.cfg_hdr, &g_usb.cfg_hdr_off, USB_DT_CONFIG_SIZE)) {
            g_usb.setup_pending = MM_FALSE;
            g_usb.desc_state = USBDEV_DESC_CFG_HDR_STATUS;
        }
        break;
    case USBDEV_DESC_CFG_HDR_STATUS:
        if (!usbdev_ep0_status_out()) {
            return;
        }
        g_usb.cfg_total_len = (mm_u16)(g_usb.cfg_hdr[2u] | (g_usb.cfg_hdr[3u] << 8));
        if (g_usb.cfg_total_len == 0u || g_usb.cfg_total_len > USBDEV_MAX_CFG_LEN) {
            fprintf(stderr, "[USB] desc: invalid config len=%u\n", (unsigned)g_usb.cfg_total_len);
            g_usb.desc_state = USBDEV_DESC_FAILED;
            return;
        }
        if (!usbdev_send_setup(USB_DIR_IN, USB_REQ_GET_DESCRIPTOR,
                               (USB_DT_CONFIG << 8), 0u, g_usb.cfg_total_len)) {
            return;
        }
        g_usb.cfg_desc_off = 0;
        g_usb.desc_state = USBDEV_DESC_CFG_WAIT;
        fprintf(stderr, "[USB] desc: request config len=%u\n", (unsigned)g_usb.cfg_total_len);
        break;
    case USBDEV_DESC_CFG_WAIT:
        if (usbdev_collect_desc(g_usb.cfg_desc, &g_usb.cfg_desc_off, g_usb.cfg_total_len)) {
            g_usb.setup_pending = MM_FALSE;
            g_usb.desc_state = USBDEV_DESC_CFG_STATUS;
        }
        break;
    case USBDEV_DESC_CFG_STATUS:
        if (!usbdev_ep0_status_out()) {
            return;
        }
        usbdev_collect_string_indices();
        g_usb.string_pos = 0;
        g_usb.string_off = 0;
        g_usb.string_expected = 0;
        if (g_usb.string_count > 0u) {
            mm_u8 idx = g_usb.string_indices[g_usb.string_pos];
            if (!usbdev_send_setup(USB_DIR_IN, USB_REQ_GET_DESCRIPTOR,
                                   (USB_DT_STRING << 8) | idx, g_usb.string_langid, 255u)) {
                return;
            }
            g_usb.desc_state = USBDEV_DESC_STR_WAIT;
            fprintf(stderr, "[USB] desc: request string idx=%u\n", (unsigned)idx);
        } else {
            g_usb.desc_state = USBDEV_DESC_WRITE;
        }
        break;
    case USBDEV_DESC_STR_WAIT:
        if (usbdev_collect_string_desc()) {
            mm_u8 idx = g_usb.string_indices[g_usb.string_pos];
            g_usb.setup_pending = MM_FALSE;
            if (idx == 0u && g_usb.string_off >= 4u) {
                g_usb.string_langid = (mm_u16)(g_usb.string_buf[2] | (g_usb.string_buf[3] << 8));
            }
            usbdev_string_cache_store(idx, g_usb.string_buf, (mm_u16)g_usb.string_expected);
            g_usb.desc_state = USBDEV_DESC_STR_STATUS;
        }
        break;
    case USBDEV_DESC_STR_STATUS:
        if (!usbdev_ep0_status_out()) {
            return;
        }
        g_usb.string_pos++;
        g_usb.string_off = 0;
        g_usb.string_expected = 0;
        if (g_usb.string_pos < g_usb.string_count) {
            mm_u8 idx = g_usb.string_indices[g_usb.string_pos];
            if (!usbdev_send_setup(USB_DIR_IN, USB_REQ_GET_DESCRIPTOR,
                                   (USB_DT_STRING << 8) | idx, g_usb.string_langid, 255u)) {
                return;
            }
            g_usb.desc_state = USBDEV_DESC_STR_WAIT;
            fprintf(stderr, "[USB] desc: request string idx=%u\n", (unsigned)idx);
        } else {
            mm_u32 tag = 0u;
            size_t off = 0;
            memcpy(g_usb.desc_blob + off, &tag, sizeof(tag));
            off += sizeof(tag);
            memcpy(g_usb.desc_blob + off, g_usb.cfg_desc, g_usb.cfg_total_len);
            off += g_usb.cfg_total_len;
            memcpy(g_usb.desc_blob + off, g_usb.dev_desc, USB_DT_DEVICE_SIZE);
            off += USB_DT_DEVICE_SIZE;
            g_usb.desc_blob_len = off;
            g_usb.desc_blob_off = 0;
            g_usb.desc_state = USBDEV_DESC_WRITE;
            fprintf(stderr, "[USB] desc: prepared blob len=%zu\n", g_usb.desc_blob_len);
        }
        break;
    case USBDEV_DESC_WRITE:
        if (g_usb.desc_blob_off < g_usb.desc_blob_len) {
            ssize_t n = write(g_usb.ep0_fd,
                              g_usb.desc_blob + g_usb.desc_blob_off,
                              g_usb.desc_blob_len - g_usb.desc_blob_off);
            if (n > 0) {
                g_usb.desc_blob_off += (size_t)n;
            } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                g_usb.desc_state = USBDEV_DESC_FAILED;
                fprintf(stderr, "[USB] desc: write failed errno=%d\n", errno);
                return;
            }
        }
        if (g_usb.desc_blob_off >= g_usb.desc_blob_len) {
            g_usb.descriptors_written = MM_TRUE;
            g_usb.desc_state = USBDEV_DESC_DONE;
            usbdev_parse_endpoints();
            fprintf(stderr, "[USB] desc: written, endpoints=%zu\n", g_usb.ep_count);
        }
        break;
    case USBDEV_DESC_DONE:
    case USBDEV_DESC_FAILED:
    default:
        break;
    }
}

static void usbdev_handle_setup(const struct usb_ctrlrequest *setup)
{
    mm_u16 w_length;
    mm_bool local_string = MM_FALSE;
    if (setup == 0) return;
    if (usb_trace_enabled() && g_usb.ctrl.active) {
        usb_trace("ctrl: aborting active transfer for new setup");
    }
    usbdev_reset_ctrl();
    g_usb.ctrl.active = MM_TRUE;
    memcpy(&g_usb.ctrl.setup, setup, sizeof(*setup));
    g_usb.ctrl.in_dir = (setup->bRequestType & USB_DIR_IN) ? MM_TRUE : MM_FALSE;
    w_length = (mm_u16)setup->wLength;
    g_usb.ctrl.expected = w_length;

    if ((setup->bRequestType & USB_DIR_IN) != 0u &&
        setup->bRequest == USB_REQ_GET_DESCRIPTOR &&
        ((setup->wValue >> 8) & 0xffu) == USB_DT_STRING) {
        const struct usbdev_string *s = usbdev_string_cache_find((mm_u8)(setup->wValue & 0xffu));
        if (s != 0) {
            mm_u16 built = s->len;
            memcpy(g_usb.ctrl.local_buf, s->data, built);
            g_usb.ctrl.local_active = MM_TRUE;
            g_usb.ctrl.local_len = built;
            g_usb.ctrl.local_off = 0u;
            if (g_usb.ctrl.expected > built) {
                g_usb.ctrl.expected = built;
            }
            local_string = MM_TRUE;
        } else if (usb_local_strings_enabled()) {
            mm_u16 built = usbdev_build_string_desc((mm_u8)(setup->wValue & 0xffu),
                                                    (mm_u16)setup->wIndex,
                                                    g_usb.ctrl.local_buf, (mm_u16)sizeof(g_usb.ctrl.local_buf));
            g_usb.ctrl.local_active = MM_TRUE;
            g_usb.ctrl.local_len = built;
            g_usb.ctrl.local_off = 0u;
            if (g_usb.ctrl.expected > built) {
                g_usb.ctrl.expected = built;
            }
            local_string = MM_TRUE;
        } else if (g_usb_ops && g_usb_ops->ep_out) {
            (void)g_usb_ops->ep_out(g_usb_opaque, 0, (const mm_u8 *)setup, 8u, MM_TRUE);
        }
    } else if (usb_local_strings_enabled() &&
        (setup->bRequestType & USB_DIR_IN) != 0u &&
        setup->bRequest == USB_REQ_GET_DESCRIPTOR &&
        ((setup->wValue >> 8) & 0xffu) == USB_DT_STRING) {
        /* handled above */
    } else if (g_usb_ops && g_usb_ops->ep_out) {
        (void)g_usb_ops->ep_out(g_usb_opaque, 0, (const mm_u8 *)setup, 8u, MM_TRUE);
    }

    if ((setup->bRequest == USB_REQ_SET_CONFIGURATION) && (setup->bRequestType & USB_DIR_IN) == 0u) {
        mm_u16 w_value = (mm_u16)setup->wValue;
        g_usb.configured = (w_value != 0u) ? MM_TRUE : MM_FALSE;
        if (usb_trace_enabled()) {
            usb_trace("ctrl: set configuration value=%u desc_written=%u endpoints_opened=%u",
                      (unsigned)w_value,
                      g_usb.descriptors_written ? 1u : 0u,
                      g_usb.endpoints_opened ? 1u : 0u);
        }
        if (g_usb.configured && g_usb.descriptors_written) {
            usbdev_open_endpoints();
        } else if (!g_usb.configured) {
            usbdev_close_endpoints();
        }
    }

    if (!g_usb.ctrl.in_dir) {
        if (g_usb.ctrl.expected > 0u) {
            g_usb.ctrl.stage = USBDEV_CTRL_OUT_READ;
        } else {
            g_usb.ctrl.stage = USBDEV_CTRL_STATUS_WRITE;
        }
        return;
    }

    if (g_usb.ctrl.expected == 0u) {
        g_usb.ctrl.stage = USBDEV_CTRL_IN_STATUS_READ;
        g_usb.ctrl.status_pending = MM_TRUE;
        g_usb.ctrl.status_read = MM_FALSE;
        g_usb.ctrl.status_sent = MM_FALSE;
    } else {
        g_usb.ctrl.stage = USBDEV_CTRL_IN_FETCH;
        if (local_string) {
            mm_u32 len = g_usb.ctrl.expected;
            if (len > sizeof(g_usb.ctrl.buf)) len = (mm_u32)sizeof(g_usb.ctrl.buf);
            if (len > g_usb.ctrl.local_len) len = g_usb.ctrl.local_len;
            memcpy(g_usb.ctrl.buf, g_usb.ctrl.local_buf, len);
            g_usb.ctrl.buf_len = len;
            g_usb.ctrl.buf_off = 0u;
            g_usb.ctrl.local_off = (mm_u16)len;
            g_usb.ctrl.stage = USBDEV_CTRL_IN_WRITE;
            if (usb_trace_enabled()) {
                usb_trace("ctrl: local string queued len=%lu", (unsigned long)len);
            }
        }
    }
}

static void usbdev_ctrl_tick(void)
{
    ssize_t n;
    mm_u32 len;
    mm_u16 remaining;
    if (!g_usb.ctrl.active) return;

    switch (g_usb.ctrl.stage) {
    case USBDEV_CTRL_OUT_READ:
        if (g_usb.ctrl.received >= g_usb.ctrl.expected) {
            g_usb.ctrl.stage = USBDEV_CTRL_OUT_DELIVER;
            break;
        }
        n = read(g_usb.ep0_fd,
                 g_usb.ctrl.buf + g_usb.ctrl.received,
                 (size_t)(g_usb.ctrl.expected - g_usb.ctrl.received));
        if (n > 0) {
            g_usb.ctrl.received = (mm_u16)(g_usb.ctrl.received + (mm_u16)n);
            if (g_usb.ctrl.received >= g_usb.ctrl.expected) {
                g_usb.ctrl.stage = USBDEV_CTRL_OUT_DELIVER;
            }
        } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            usbdev_reset_ctrl();
        }
        break;
    case USBDEV_CTRL_OUT_DELIVER:
        if (g_usb_ops && g_usb_ops->ep_out) {
            (void)g_usb_ops->ep_out(g_usb_opaque, 0, g_usb.ctrl.buf, g_usb.ctrl.expected, MM_FALSE);
        }
        g_usb.ctrl.stage = USBDEV_CTRL_STATUS_WRITE;
        break;
    case USBDEV_CTRL_STATUS_WRITE:
        if (!g_usb.ctrl.in_dir && g_usb.ctrl.expected == 0u) {
            mm_u8 tmp = 0u;
            n = read(g_usb.ep0_fd, &tmp, 0);
        } else {
            n = write(g_usb.ep0_fd, 0, 0);
        }
        if (usb_trace_enabled()) {
            if (n >= 0) {
                usb_trace("ctrl: status write n=%ld", (long)n);
            } else {
                usb_trace("ctrl: status write n=%ld errno=%d", (long)n, errno);
            }
        }
        if (n >= 0) {
            usbdev_reset_ctrl();
        } else if (errno == ESRCH || errno == EINVAL) {
            usbdev_reset_ctrl();
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            usbdev_reset_ctrl();
        }
        break;
    case USBDEV_CTRL_IN_FETCH:
        remaining = (mm_u16)(g_usb.ctrl.expected - g_usb.ctrl.transferred);
        if (remaining == 0u) {
            g_usb.ctrl.stage = USBDEV_CTRL_IN_STATUS_READ;
            g_usb.ctrl.status_pending = MM_TRUE;
            g_usb.ctrl.status_read = MM_FALSE;
            g_usb.ctrl.status_sent = MM_FALSE;
            break;
        }
        len = remaining;
        if (len > sizeof(g_usb.ctrl.buf)) len = (mm_u32)sizeof(g_usb.ctrl.buf);
        if (g_usb.ctrl.local_active) {
            mm_u16 avail = (mm_u16)(g_usb.ctrl.local_len - g_usb.ctrl.local_off);
            if (avail == 0u) {
                g_usb.ctrl.stage = USBDEV_CTRL_IN_STATUS_READ;
                g_usb.ctrl.status_pending = MM_TRUE;
                g_usb.ctrl.status_read = MM_FALSE;
                g_usb.ctrl.status_sent = MM_FALSE;
                break;
            }
            if (len > avail) len = avail;
            memcpy(g_usb.ctrl.buf, g_usb.ctrl.local_buf + g_usb.ctrl.local_off, len);
            g_usb.ctrl.local_off = (mm_u16)(g_usb.ctrl.local_off + (mm_u16)len);
        } else {
            if (!usbdev_ep0_in(g_usb.ctrl.buf, &len)) {
                break;
            }
        }
        g_usb.ctrl.buf_len = len;
        g_usb.ctrl.buf_off = 0u;
        g_usb.ctrl.stage = USBDEV_CTRL_IN_WRITE;
        break;
    case USBDEV_CTRL_IN_WRITE:
        if (g_usb.ctrl.buf_len == 0u) {
            g_usb.ctrl.transferred = (mm_u16)(g_usb.ctrl.transferred + 0u);
            g_usb.ctrl.stage = USBDEV_CTRL_IN_STATUS_READ;
            g_usb.ctrl.status_pending = MM_TRUE;
            g_usb.ctrl.status_read = MM_FALSE;
            g_usb.ctrl.status_sent = MM_FALSE;
            break;
        }
        n = write(g_usb.ep0_fd,
                  g_usb.ctrl.buf + g_usb.ctrl.buf_off,
                  g_usb.ctrl.buf_len - g_usb.ctrl.buf_off);
        if (n > 0) {
            if (usb_trace_enabled()) {
                usb_trace("ctrl: in write n=%ld", (long)n);
            }
            g_usb.ctrl.buf_off += (size_t)n;
            if (g_usb.ctrl.buf_off >= g_usb.ctrl.buf_len) {
                mm_u16 sent = (mm_u16)g_usb.ctrl.buf_len;
                g_usb.ctrl.transferred = (mm_u16)(g_usb.ctrl.transferred + sent);
                g_usb.ctrl.buf_len = 0u;
                if (sent < g_usb.ep0_max_packet || g_usb.ctrl.transferred >= g_usb.ctrl.expected) {
                    if (g_usb.ctrl.in_dir && !g_usb.ctrl.status_sent) {
                        g_usb.ctrl.status_sent = usbdev_ep0_status_out() ? MM_TRUE : MM_FALSE;
                        if (usb_trace_enabled()) {
                            usb_trace("ctrl: status out early %s", g_usb.ctrl.status_sent ? "ok" : "fail");
                        }
                    }
                    g_usb.ctrl.stage = USBDEV_CTRL_IN_STATUS_READ;
                    g_usb.ctrl.status_pending = MM_TRUE;
                    g_usb.ctrl.status_read = MM_FALSE;
                    if (!g_usb.ctrl.status_sent) {
                        g_usb.ctrl.status_sent = MM_FALSE;
                    }
                } else {
                    g_usb.ctrl.stage = USBDEV_CTRL_IN_FETCH;
                }
            }
        } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            usbdev_reset_ctrl();
        } else if (n <= 0 && usb_trace_enabled()) {
            usb_trace("ctrl: in write n=%ld errno=%d", (long)n, errno);
        }
        break;
    case USBDEV_CTRL_IN_STATUS_READ:
        if (g_usb.ctrl.in_dir) {
            mm_bool ok = usbdev_ep0_status_out();
            if (usb_trace_enabled()) {
                usb_trace("ctrl: status out to device %s", ok ? "ok" : "fail");
            }
            if (ok) {
                usbdev_reset_ctrl();
            }
            break;
        }
        {
            mm_u8 tmp;
            n = read(g_usb.ep0_fd, &tmp, 0);
            if (usb_trace_enabled()) {
                if (n >= 0) {
                    usb_trace("ctrl: status read n=%ld", (long)n);
                } else {
                    usb_trace("ctrl: status read n=%ld errno=%d", (long)n, errno);
                }
            }
            if (n == 0) {
                usbdev_reset_ctrl();
            } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != ESRCH) {
                usbdev_reset_ctrl();
            }
        }
        break;
    case USBDEV_CTRL_IDLE:
    default:
        break;
    }
}

static void usbdev_handle_event(const struct usb_gadgetfs_event *ev)
{
    if (ev == 0) return;
    switch (ev->type) {
    case GADGETFS_CONNECT:
        g_usb.host_connected = MM_TRUE;
        g_usb.configured = MM_FALSE;
        if (g_usb_ops && g_usb_ops->bus_reset) {
            g_usb_ops->bus_reset(g_usb_opaque);
        }
        usb_trace("event: connect speed=%d", (int)ev->u.speed);
        break;
    case GADGETFS_DISCONNECT:
        g_usb.host_connected = MM_FALSE;
        g_usb.configured = MM_FALSE;
        usbdev_close_endpoints();
        usb_trace("event: disconnect");
        break;
    case GADGETFS_SETUP:
        g_usb.setup_pending = MM_FALSE;
        usb_trace("event: setup bRequest=0x%02x wLength=%u",
                  (unsigned)ev->u.setup.bRequest, (unsigned)ev->u.setup.wLength);
        usbdev_handle_setup(&ev->u.setup);
        break;
    case GADGETFS_SUSPEND:
        usb_trace("event: suspend");
        break;
    case GADGETFS_NOP:
    default:
        break;
    }
}

static void usbdev_poll_events(void)
{
    for (;;) {
        struct usb_gadgetfs_event ev;
        ssize_t n = read(g_usb.ep0_fd, &ev, sizeof(ev));
        if (n == (ssize_t)sizeof(ev)) {
            usbdev_handle_event(&ev);
            if (ev.type == GADGETFS_SETUP) {
                break;
            }
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        }
        if (n <= 0) {
            break;
        }
    }
}

static void usbdev_ep_out_tick(void)
{
    size_t i;
    for (i = 0; i < g_usb.ep_count; ++i) {
        struct usbdev_ep *ep = &g_usb.eps[i];
        mm_u8 buf[USBDEV_MAX_EP_BUF];
        ssize_t n;
        if (ep->fd < 0 || ep->dir_in) continue;
        n = read(ep->fd, buf, sizeof(buf));
        if (n > 0) {
            if (g_usb_ops && g_usb_ops->ep_out) {
                (void)g_usb_ops->ep_out(g_usb_opaque, (int)(ep->addr & USB_ENDPOINT_NUMBER_MASK), buf, (mm_u32)n, MM_FALSE);
            }
        } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            usb_trace("ep_out read error addr=0x%02x errno=%d", ep->addr, errno);
        }
    }
}

static void usbdev_ep_in_tick(void)
{
    size_t i;
    for (i = 0; i < g_usb.ep_count; ++i) {
        struct usbdev_ep *ep = &g_usb.eps[i];
        if (ep->fd < 0 || !ep->dir_in) continue;
        if (ep->tx_off < ep->tx_len) {
            ssize_t n = write(ep->fd, ep->tx_buf + ep->tx_off, ep->tx_len - ep->tx_off);
            if (n > 0) {
                ep->tx_off += (size_t)n;
                if (ep->tx_off >= ep->tx_len) {
                    ep->tx_len = 0u;
                    ep->tx_off = 0u;
                }
            } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                ep->tx_len = 0u;
                ep->tx_off = 0u;
            }
            continue;
        }
        if (g_usb_ops && g_usb_ops->ep_in) {
            mm_u32 len = (mm_u32)sizeof(ep->tx_buf);
            if (g_usb_ops->ep_in(g_usb_opaque, (int)(ep->addr & USB_ENDPOINT_NUMBER_MASK), ep->tx_buf, &len)) {
                ep->tx_len = len;
                ep->tx_off = 0u;
                if (ep->tx_len == 0u) {
                    ssize_t zlen = write(ep->fd, 0, 0);
                    if (zlen < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                        usb_trace("ep_in zlp write error addr=0x%02x errno=%d", ep->addr, errno);
                    }
                }
            }
        }
    }
}

mm_bool mm_usbdev_register(const struct mm_usbdev_ops *ops, void *opaque)
{
    if (ops == 0) return MM_FALSE;
    if (g_usb_ops != 0) return MM_FALSE;
    g_usb_ops = ops;
    g_usb_opaque = opaque;
    usb_trace("usbdev register ops=%p opaque=%p", (void *)ops, opaque);
    return MM_TRUE;
}

mm_bool mm_usbdev_start(const char *udc_name)
{
    int fd;
    mm_bool udc_is_dir;
    char parent[USBDEV_MAX_PATH];
    if (g_usb.running) {
        return MM_TRUE;
    }
    if (g_usb_ops == 0) {
        fprintf(stderr, "[USB] no USB device registered, USB backend will be inactive\n");
    }
    memset(&g_usb, 0, sizeof(g_usb));
    g_usb.ep0_fd = -1;
    usbdev_make_paths(udc_name);

    fd = open(g_usb.udc_path, O_RDWR | O_NONBLOCK);
    if (fd < 0) {
        fprintf(stderr, "[USB] open %s failed (%s). Is gadgetfs mounted and dummy_hcd loaded?\n",
                g_usb.udc_path, strerror(errno));
        return MM_FALSE;
    }
    g_usb.ep0_fd = fd;
    udc_is_dir = usbdev_path_is_dir(g_usb.udc_path);
    if (udc_is_dir) {
        size_t len = strlen(g_usb.udc_path);
        if (len >= sizeof(g_usb.gadget_root)) len = sizeof(g_usb.gadget_root) - 1u;
        memcpy(g_usb.gadget_root, g_usb.udc_path, len);
        g_usb.gadget_root[len] = '\0';
    } else {
        usbdev_path_parent(g_usb.udc_path, parent, sizeof(parent));
        if (parent[0] != '\0') {
            size_t len = strlen(parent);
            if (len >= sizeof(g_usb.gadget_root)) len = sizeof(g_usb.gadget_root) - 1u;
            memcpy(g_usb.gadget_root, parent, len);
            g_usb.gadget_root[len] = '\0';
        }
    }
    if (usb_trace_enabled()) {
        usb_trace("gadgetfs paths udc=%s root=%s udc_is_dir=%u",
                  g_usb.udc_path, g_usb.gadget_root, udc_is_dir ? 1u : 0u);
    }
    g_usb.ep0_max_packet = USBDEV_EP0_FALLBACK_MAX_PACKET;
    g_usb.desc_state = USBDEV_DESC_IDLE;
    g_usb.running = MM_TRUE;
    usbdev_reset_ctrl();
    printf("[USB] GadgetFS backend ready (udc=%s)\n", g_usb.udc_name);
    return MM_TRUE;
}

void mm_usbdev_poll(void)
{
    if (!g_usb.running) return;
    if (g_usb.paused) {
        return;
    }
    if (!g_usb.connected || !g_usb.irq_enabled) {
        if (g_usb.connected && !g_usb.irq_enabled && !g_usb.logged_wait_irq) {
            fprintf(stderr, "[USB] waiting for USB IRQ enable\n");
            g_usb.logged_wait_irq = MM_TRUE;
        }
        return;
    }
    if (g_usb.setup_pending && g_usb.setup_cycles >= g_usb.setup_timeout) {
        fprintf(stderr, "[USB] setup timeout, retrying setup\n");
        g_usb.setup_pending = MM_FALSE;
        g_usb.setup_cycles = 0;
        g_usb.desc_state = USBDEV_DESC_IDLE;
        g_usb.setup_retry_cycles = g_usb.setup_retry_delay;
        return;
    }
    if (!g_usb.descriptors_written) {
        usbdev_desc_tick();
        return;
    }
    usbdev_poll_events();
    usbdev_ctrl_tick();
    usbdev_ep_out_tick();
    usbdev_ep_in_tick();
}

void mm_usbdev_stop(void)
{
    usbdev_close_endpoints();
    if (g_usb.ep0_fd >= 0) {
        close(g_usb.ep0_fd);
        g_usb.ep0_fd = -1;
    }
    g_usb.running = MM_FALSE;
    g_usb.connected = MM_FALSE;
    g_usb.host_connected = MM_FALSE;
    g_usb.configured = MM_FALSE;
    g_usb.descriptors_written = MM_FALSE;
    usbdev_reset_ctrl();
}

void mm_usbdev_get_status(struct mm_usbdev_status *out)
{
    if (out == 0) return;
    memset(out, 0, sizeof(*out));
    out->running = g_usb.running;
    out->connected = g_usb.connected;
    out->configured = g_usb.configured;
    snprintf(out->udc, sizeof(out->udc), "%s", g_usb.udc_name);
}

void mm_usbdev_set_connected(mm_bool connected)
{
    if (g_usb.connected == connected) return;
    g_usb.connected = connected;
    g_usb.configured = MM_FALSE;
    g_usb.descriptors_written = MM_FALSE;
    g_usb.desc_state = USBDEV_DESC_IDLE;
    g_usb.setup_pending = MM_FALSE;
    g_usb.setup_cycles = 0;
    g_usb.setup_timeout = 1000000u;
    g_usb.setup_retry_delay = 1000000u;
    g_usb.setup_retry_cycles = 0u;
    g_usb.logged_wait_irq = MM_FALSE;
    usbdev_reset_ctrl();
    if (!connected) {
        usbdev_close_endpoints();
        fprintf(stderr, "[USB] device disconnect (pullup off)\n");
    } else {
        if (g_usb_ops && g_usb_ops->bus_reset) {
            g_usb_ops->bus_reset(g_usb_opaque);
        }
        fprintf(stderr, "[USB] device connect (pullup on)\n");
    }
}

void mm_usbdev_set_irq_enabled(mm_bool enabled)
{
    if (g_usb.irq_enabled == enabled) return;
    g_usb.irq_enabled = enabled;
    g_usb.logged_wait_irq = MM_FALSE;
    if (!enabled) {
        g_usb.descriptors_written = MM_FALSE;
        g_usb.desc_state = USBDEV_DESC_IDLE;
        usbdev_reset_ctrl();
    }
}

void mm_usbdev_set_paused(mm_bool paused)
{
    g_usb.paused = paused;
}
