/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include <string.h>
#include <math.h>
#include <limits.h>
#include "rp2350/rp2350_coproc.h"
#include "rp2350/rp2350_mmio.h"

enum dcp_conv_src {
    DCP_CONV_NONE = 0,
    DCP_CONV_INT,
    DCP_CONV_UINT,
    DCP_CONV_FLOAT,
    DCP_CONV_DOUBLE
};

struct rp2350_dcp_state {
    mm_u64 raw_xm;
    mm_u64 raw_ym;
    mm_u64 raw_ef;
    mm_u64 x_d_bits;
    mm_u64 y_d_bits;
    mm_u32 x_f_bits;
    mm_u32 y_f_bits;
    mm_u64 conv_d_bits;
    mm_u32 conv_f_bits;
    mm_u32 conv_u;
    mm_i32 conv_i;
    mm_u8 conv_src;
    mm_u8 round_mode;
    mm_u8 cmp_mode;
    mm_u8 status_shift;
    mm_u8 status_cmp;
    mm_u32 last_cmp_flags;
    mm_bool engaged;
};

static struct rp2350_dcp_state dcp_state_s;
static struct rp2350_dcp_state dcp_state_ns;

static struct rp2350_dcp_state *dcp_state_select(enum mm_sec_state sec, mm_u8 coproc)
{
    if (coproc == 5u) {
        if (sec != MM_SECURE) {
            return 0;
        }
        return &dcp_state_ns;
    }
    if (sec == MM_SECURE) {
        return &dcp_state_s;
    }
    return &dcp_state_ns;
}

static double u64_to_double(mm_u64 v)
{
    double out;
    memcpy(&out, &v, sizeof(out));
    return out;
}

static mm_u64 double_to_u64(double v)
{
    mm_u64 out;
    memcpy(&out, &v, sizeof(out));
    return out;
}

static float u32_to_float(mm_u32 v)
{
    float out;
    memcpy(&out, &v, sizeof(out));
    return out;
}

static mm_u32 float_to_u32(float v)
{
    mm_u32 out;
    memcpy(&out, &v, sizeof(out));
    return out;
}

static mm_u32 dcp_round_float_to_u32(float v, mm_bool round_nearest, mm_bool signed_out)
{
    double dv = (double)v;
    double out = round_nearest ? nearbyint(dv) : trunc(dv);
    if (isnan(out)) return 0u;
    if (signed_out) {
        if (out > (double)INT32_MAX) return (mm_u32)INT32_MAX;
        if (out < (double)INT32_MIN) return (mm_u32)INT32_MIN;
        return (mm_u32)(mm_i32)out;
    }
    if (out < 0.0) return 0u;
    if (out > (double)UINT32_MAX) return 0xffffffffu;
    return (mm_u32)(mm_u64)out;
}

static mm_u32 dcp_round_double_to_u32(double v, mm_bool round_nearest, mm_bool signed_out)
{
    double out = round_nearest ? nearbyint(v) : trunc(v);
    if (isnan(out)) return 0u;
    if (signed_out) {
        if (out > (double)INT32_MAX) return (mm_u32)INT32_MAX;
        if (out < (double)INT32_MIN) return (mm_u32)INT32_MIN;
        return (mm_u32)(mm_i32)out;
    }
    if (out < 0.0) return 0u;
    if (out > (double)UINT32_MAX) return 0xffffffffu;
    return (mm_u32)(mm_u64)out;
}

static mm_u32 dcp_cmp_flags_double(double a, double b)
{
    mm_u32 flags = 0u;
    if (isnan(a) || isnan(b)) {
        flags |= (1u << 29); /* C */
        flags |= (1u << 28); /* V */
        return flags;
    }
    if (a == b) {
        flags |= (1u << 30); /* Z */
        flags |= (1u << 29); /* C */
        return flags;
    }
    if (a < b) {
        flags |= (1u << 31); /* N */
        return flags;
    }
    flags |= (1u << 29); /* C */
    return flags;
}

static mm_u32 dcp_cmp_flags_float(float a, float b)
{
    return dcp_cmp_flags_double((double)a, (double)b);
}

static mm_u64 dcp_mantissa_q62(double v)
{
    double av;
    double mant;
    int exp = 0;
    mm_i64 q;
    if (v == 0.0 || isnan(v) || isinf(v)) {
        return 0u;
    }
    av = fabs(v);
    mant = frexp(av, &exp);
    mant *= 2.0;
    q = (mm_i64)llround(mant * (double)(1ull << 62));
    if (v < 0.0) {
        q = -q;
    }
    return (mm_u64)q;
}

static mm_u32 dcp_calc_status_cmp(double x, double y)
{
    double ax = fabs(x);
    double ay = fabs(y);
    if (ax > ay) return 1u;
    if (ax < ay) return 2u;
    return 0u;
}

static mm_u32 dcp_status_bits(const struct rp2350_dcp_state *state)
{
    mm_u32 shift = (mm_u32)(state->status_shift & 0x3fu);
    mm_u32 cmp = (mm_u32)(state->status_cmp & 0x3u);
    mm_u32 engaged = state->engaged ? 1u : 0u;
    return shift | (cmp << 6) | (engaged << 8);
}

void mm_rp2350_coproc_reset(void)
{
    memset(&dcp_state_s, 0, sizeof(dcp_state_s));
    memset(&dcp_state_ns, 0, sizeof(dcp_state_ns));
}

mm_bool mm_rp2350_dcp_mcrr(enum mm_sec_state sec, mm_u8 coproc, mm_u8 op1, mm_u8 crm, mm_u32 lo, mm_u32 hi)
{
    struct rp2350_dcp_state *state = dcp_state_select(sec, coproc);
    if (!mm_rp2350_active()) {
        return MM_FALSE;
    }
    if (state == 0) {
        return MM_FALSE;
    }
    switch (op1) {
    case 0u: /* WXMD/WYMD/WEFD */
        if (crm == 0u) state->raw_xm = ((mm_u64)hi << 32) | lo;
        else if (crm == 1u) state->raw_ym = ((mm_u64)hi << 32) | lo;
        else if (crm == 2u) {
            state->raw_ef = ((mm_u64)hi << 32) | lo;
            {
                mm_u32 status = (mm_u32)(state->raw_ef & 0x1ffu);
                state->status_shift = (mm_u8)(status & 0x3fu);
                state->status_cmp = (mm_u8)((status >> 6) & 0x3u);
                state->engaged = ((status >> 8) & 0x1u) ? MM_TRUE : MM_FALSE;
            }
        }
        break;
    case 1u: /* WXUP/WYUP/WXYU */
        if (crm == 0u) {
            state->x_d_bits = ((mm_u64)hi << 32) | lo;
            state->cmp_mode = 2u;
        } else if (crm == 1u) {
            state->y_d_bits = ((mm_u64)hi << 32) | lo;
            state->cmp_mode = 2u;
        } else if (crm == 2u) {
            state->x_f_bits = lo;
            state->y_f_bits = hi;
            state->cmp_mode = 1u;
        }
        state->engaged = MM_TRUE;
        break;
    case 2u: /* WXMS */
    case 3u: /* WXMO */
    case 4u: /* WXDD */
    case 5u: /* WXDQ */
    case 10u: /* WXFM */
    case 11u: /* WXFD */
    case 12u: /* WXFQ */
        if (crm == 0u) state->raw_xm = ((mm_u64)hi << 32) | lo;
        state->engaged = MM_TRUE;
        break;
    case 6u: /* WXUC */
        if (crm == 0u) {
            state->conv_u = lo;
            state->conv_src = DCP_CONV_UINT;
        }
        state->engaged = MM_TRUE;
        break;
    case 7u: /* WXIC */
        if (crm == 0u) {
            state->conv_i = (mm_i32)lo;
            state->conv_src = DCP_CONV_INT;
        }
        state->engaged = MM_TRUE;
        break;
    case 8u: /* WXDC */
        if (crm == 0u) {
            state->conv_d_bits = ((mm_u64)hi << 32) | lo;
            state->conv_src = DCP_CONV_DOUBLE;
        }
        state->engaged = MM_TRUE;
        break;
    case 9u: /* WXFC */
        if (crm == 2u) {
            state->conv_f_bits = lo;
            state->conv_src = DCP_CONV_FLOAT;
        }
        state->engaged = MM_TRUE;
        break;
    default:
        break;
    }
    return MM_TRUE;
}

mm_bool mm_rp2350_dcp_mrrc(enum mm_sec_state sec, mm_u8 coproc, mm_u8 op1, mm_u8 crm, mm_bool peek, mm_u32 *lo_out, mm_u32 *hi_out)
{
    struct rp2350_dcp_state *state = dcp_state_select(sec, coproc);
    if (!mm_rp2350_active() || lo_out == 0 || hi_out == 0) {
        return MM_FALSE;
    }
    if (state == 0) {
        return MM_FALSE;
    }
    if (op1 == 0u && (crm == 8u || crm == 9u || crm == 10u)) {
        mm_u64 v = 0u;
        if (crm == 8u) v = state->raw_xm;
        else if (crm == 9u) v = state->raw_ym;
        else if (crm == 10u) {
            mm_u32 status = dcp_status_bits(state);
            v = (state->raw_ef & ~0x1ffu) | (mm_u64)status;
        }
        *lo_out = (mm_u32)(v & 0xffffffffu);
        *hi_out = (mm_u32)(v >> 32);
        if (!peek && crm == 9u) {
            state->engaged = MM_FALSE;
        }
        return MM_TRUE;
    }
    if (crm == 0u) {
        double xd = u64_to_double(state->x_d_bits);
        double yd = u64_to_double(state->y_d_bits);
        double res = 0.0;
        switch (op1) {
        case 1u: res = xd + yd; break; /* RDDA */
        case 3u:
            if (state->conv_src == DCP_CONV_INT) res = (double)state->conv_i;
            else if (state->conv_src == DCP_CONV_UINT) res = (double)state->conv_u;
            else res = xd - yd;
            break; /* RDDS */
        case 5u: res = xd * yd; break; /* RDDM */
        case 7u: res = xd / yd; break; /* RDDD */
        case 9u: res = sqrt(xd); break; /* RDDQ */
        case 11u: res = (double)u32_to_float(state->x_f_bits); break; /* RDDG */
        default: res = 0.0; break;
        }
        {
            mm_u64 v = double_to_u64(res);
            *lo_out = (mm_u32)(v & 0xffffffffu);
            *hi_out = (mm_u32)(v >> 32);
        }
        if (!peek) {
            state->conv_src = DCP_CONV_NONE;
            state->engaged = MM_FALSE;
        }
        return MM_TRUE;
    }
    if (crm == 1u) {
        double xval = (state->cmp_mode == 1u) ? (double)u32_to_float(state->x_f_bits) : u64_to_double(state->x_d_bits);
        double yval = (state->cmp_mode == 1u) ? (double)u32_to_float(state->y_f_bits) : u64_to_double(state->y_d_bits);
        mm_u64 xm_q62 = dcp_mantissa_q62(xval);
        mm_u64 ym_q62 = dcp_mantissa_q62(yval);
        if (op1 == 1u) { /* RXYH */
            *lo_out = (mm_u32)(ym_q62 >> 32);
            *hi_out = (mm_u32)(xm_q62 >> 32);
        } else if (op1 == 2u) { /* RYMR */
            mm_u64 recip = double_to_u64(1.0 / yval);
            *lo_out = (mm_u32)(ym_q62 >> 32);
            *hi_out = (mm_u32)(recip & 0xffffffffu);
        } else if (op1 == 4u) { /* RXMQ */
            mm_u64 rsqrt = double_to_u64(1.0 / sqrt(xval));
            *lo_out = (mm_u32)(xm_q62 >> 32);
            *hi_out = (mm_u32)(rsqrt & 0xffffffffu);
        } else {
            *lo_out = 0u;
            *hi_out = 0u;
        }
        return MM_TRUE;
    }
    if (crm == 4u || crm == 5u) {
        double val = (crm == 4u)
            ? ((state->cmp_mode == 1u) ? (double)u32_to_float(state->x_f_bits) : u64_to_double(state->x_d_bits))
            : ((state->cmp_mode == 1u) ? (double)u32_to_float(state->y_f_bits) : u64_to_double(state->y_d_bits));
        mm_i64 q = (mm_i64)dcp_mantissa_q62(val);
        mm_u8 shift = op1;
        if (shift >= 63u) {
            q = (q < 0) ? -1 : 0;
        } else if (shift != 0u) {
            q >>= shift;
        }
        *lo_out = (mm_u32)((mm_u64)q & 0xffffffffu);
        *hi_out = (mm_u32)(((mm_u64)q >> 32) & 0xffffffffu);
        return MM_TRUE;
    }
    *lo_out = 0u;
    *hi_out = 0u;
    return MM_TRUE;
}

mm_bool mm_rp2350_dcp_mrc(enum mm_sec_state sec, mm_u8 coproc, mm_u8 op1, mm_u8 crn, mm_u8 crm, mm_u8 op2, mm_bool peek, mm_u32 *value_out)
{
    float xf;
    float yf;
    double xd;
    double yd;
    mm_u32 out = 0u;
    struct rp2350_dcp_state *state = dcp_state_select(sec, coproc);
    if (!mm_rp2350_active() || value_out == 0 || state == 0) {
        return MM_FALSE;
    }
    if (op1 != 0u || (crn & 0x0fu) != 0u) {
        return MM_FALSE;
    }
    xf = u32_to_float(state->x_f_bits);
    yf = u32_to_float(state->y_f_bits);
    xd = u64_to_double(state->x_d_bits);
    yd = u64_to_double(state->y_d_bits);
    (void)yd;
    if (crm == 0u && op2 == 0u) {
        mm_u32 xf_flags = 0u;
        if (state->cmp_mode == 1u) {
            float xf_val = xf;
            if (signbit(xf_val)) xf_flags |= 1u;
            if (xf_val == 0.0f) xf_flags |= 1u << 1;
            if (isinf(xf_val)) xf_flags |= 1u << 2;
            if (isnan(xf_val)) xf_flags |= 1u << 3;
        } else {
            if (signbit(xd)) xf_flags |= 1u;
            if (xd == 0.0) xf_flags |= 1u << 1;
            if (isinf(xd)) xf_flags |= 1u << 2;
            if (isnan(xd)) xf_flags |= 1u << 3;
        }
        out = xf_flags | (1u << 8);
    } else if (crm == 0u && op2 == 1u) {
        out = state->last_cmp_flags;
        if (!peek) {
            state->engaged = MM_FALSE;
        }
    } else if (crm == 2u) {
        float fres = 0.0f;
        switch (op2) {
        case 0u: fres = xf + yf; break;
        case 1u:
            if (state->conv_src == DCP_CONV_INT) fres = (float)state->conv_i;
            else if (state->conv_src == DCP_CONV_UINT) fres = (float)state->conv_u;
            else fres = xf - yf;
            break;
        case 2u: fres = xf * yf; break;
        case 3u: fres = xf / yf; break;
        case 4u: fres = sqrtf(xf); break;
        case 5u: fres = (float)u64_to_double(state->x_d_bits); break;
        default: fres = 0.0f; break;
        }
        out = float_to_u32(fres);
        if (!peek && op2 <= 5u) {
            state->conv_src = DCP_CONV_NONE;
            state->engaged = MM_FALSE;
        }
    } else if (crm == 3u) {
        mm_bool round_nearest = (state->round_mode != 0u);
        if (op2 == 0u) {
            if (state->conv_src == DCP_CONV_DOUBLE) {
                out = dcp_round_double_to_u32(u64_to_double(state->conv_d_bits), round_nearest, MM_TRUE);
            } else if (state->conv_src == DCP_CONV_FLOAT) {
                out = dcp_round_float_to_u32(u32_to_float(state->conv_f_bits), round_nearest, MM_TRUE);
            } else if (state->cmp_mode == 2u) {
                out = dcp_round_double_to_u32(u64_to_double(state->x_d_bits), round_nearest, MM_TRUE);
            } else {
                out = dcp_round_float_to_u32(u32_to_float(state->x_f_bits), round_nearest, MM_TRUE);
            }
        } else if (op2 == 1u) {
            if (state->conv_src == DCP_CONV_DOUBLE) {
                out = dcp_round_double_to_u32(u64_to_double(state->conv_d_bits), round_nearest, MM_FALSE);
            } else if (state->conv_src == DCP_CONV_FLOAT) {
                out = dcp_round_float_to_u32(u32_to_float(state->conv_f_bits), round_nearest, MM_FALSE);
            } else if (state->cmp_mode == 2u) {
                out = dcp_round_double_to_u32(u64_to_double(state->x_d_bits), round_nearest, MM_FALSE);
            } else {
                out = dcp_round_float_to_u32(u32_to_float(state->x_f_bits), round_nearest, MM_FALSE);
            }
        }
        if (!peek) {
            state->conv_src = DCP_CONV_NONE;
            state->engaged = MM_FALSE;
        }
    }
    *value_out = out;
    return MM_TRUE;
}

mm_bool mm_rp2350_dcp_cdp(enum mm_sec_state sec, mm_u8 coproc, mm_u8 op1, mm_u8 op2, mm_u8 crd, mm_u8 crn, mm_u8 crm)
{
    struct rp2350_dcp_state *state = dcp_state_select(sec, coproc);
    (void)crd;
    if (!mm_rp2350_active()) {
        return MM_FALSE;
    }
    if (state == 0) {
        return MM_FALSE;
    }
    if (op1 == 0u && crn == 0u && crm == 0u && op2 == 0u) {
        memset(state, 0, sizeof(*state));
        state->engaged = MM_TRUE;
        return MM_TRUE;
    }
    if (crn == 0u && crm == 1u) {
        float xf = u32_to_float(state->x_f_bits);
        float yf = u32_to_float(state->y_f_bits);
        double xd = u64_to_double(state->x_d_bits);
        double yd = u64_to_double(state->y_d_bits);
        if (op1 == 0u && op2 == 0u) { /* ADD0 */
            mm_u8 shift = 0u;
            int ex = 0;
            int ey = 0;
            if (state->cmp_mode == 1u) {
                (void)frexp((double)xf, &ex);
                (void)frexp((double)yf, &ey);
            } else {
                (void)frexp(xd, &ex);
                (void)frexp(yd, &ey);
            }
            if (ex > ey) shift = (mm_u8)(ex - ey);
            else if (ey > ex) shift = (mm_u8)(ey - ex);
            if (shift > 63u) shift = 63u;
            state->status_shift = shift;
            if (state->cmp_mode == 1u) {
                state->status_cmp = (mm_u8)dcp_calc_status_cmp((double)xf, (double)yf);
                state->last_cmp_flags = dcp_cmp_flags_float(xf, yf);
            } else {
                state->status_cmp = (mm_u8)dcp_calc_status_cmp(xd, yd);
                state->last_cmp_flags = dcp_cmp_flags_double(xd, yd);
            }
            state->engaged = MM_TRUE;
            return MM_TRUE;
        }
        if (op1 == 1u && op2 == 0u) { /* ADD1 */
            if (state->cmp_mode == 1u) {
                state->x_f_bits = float_to_u32(xf + yf);
            } else {
                state->x_d_bits = double_to_u64(xd + yd);
            }
            state->engaged = MM_TRUE;
            return MM_TRUE;
        }
        if (op1 == 1u && op2 == 1u) { /* SUB1 */
            if (state->cmp_mode == 1u) {
                state->x_f_bits = float_to_u32(xf - yf);
            } else {
                state->x_d_bits = double_to_u64(xd - yd);
            }
            state->engaged = MM_TRUE;
            return MM_TRUE;
        }
        if (op1 == 2u && op2 == 0u) { /* SQR0 */
            if (state->cmp_mode == 1u) {
                state->x_f_bits = float_to_u32(sqrtf(xf));
            } else {
                state->x_d_bits = double_to_u64(sqrt(xd));
            }
            state->engaged = MM_TRUE;
            return MM_TRUE;
        }
    }
    if (op1 == 8u && crn == 0u && crm == 2u) { /* NORM/NRDF */
        state->engaged = MM_TRUE;
        return MM_TRUE;
    }
    if (op1 == 8u && crn == 0u && crm == 0u) { /* NRDD/NTDC/NRDC */
        state->engaged = MM_TRUE;
        if (op2 == 2u) {
            state->round_mode = 0u;
        } else if (op2 == 3u) {
            state->round_mode = 1u;
        }
        return MM_TRUE;
    }
    return MM_TRUE;
}
