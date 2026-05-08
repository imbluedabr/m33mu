/* ffi.rs
 *
 * Copyright (C) 2026 Daniele Lacamera <root@danielinux.net>
 *
 * This file is part of m33mu and is the FFI export layer for atecc608-sim.
 *
 * m33mu is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation; either version 3 of the License, or (at your
 * option) any later version.
 */

use std::ffi::CStr;
use std::os::raw::c_char;

use crate::dispatch;
use crate::object_store::Store;
use crate::session::Session;

pub struct Atecc608Ctx {
    store: Store,
    session: Session,
}

/// Create a new ATECC608 context.
/// If `nv_path` is non-NULL, the device state is loaded from (or initialized
/// into) that JSON file.  Pass NULL for a transient in-memory device.
/// Returns NULL on failure.
#[no_mangle]
pub extern "C" fn atecc608_ffi_create(nv_path: *const c_char) -> *mut Atecc608Ctx {
    let store = if nv_path.is_null() {
        Store::fresh()
    } else {
        let path_cstr = unsafe { CStr::from_ptr(nv_path) };
        let path_str = path_cstr.to_string_lossy();
        let path = std::path::Path::new(path_str.as_ref());
        match Store::load_or_init(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[atecc608] failed to load/init store: {}", e);
                return std::ptr::null_mut();
            }
        }
    };
    let ctx = Box::new(Atecc608Ctx { store, session: Session::new() });
    Box::into_raw(ctx)
}

/// Destroy a context created by atecc608_ffi_create.
#[no_mangle]
pub extern "C" fn atecc608_ffi_destroy(ctx: *mut Atecc608Ctx) {
    if !ctx.is_null() {
        unsafe { drop(Box::from_raw(ctx)) };
    }
}

/// word_addr dispatch.
///
/// - 0x00 (wake)  — no-op, returns false (no response).
/// - 0x01 (sleep) — wipes volatile session state, returns false.
/// - 0x02 (idle)  — no-op, returns false.
/// - 0x03 (cmd)   — dispatches `payload[0..payload_len]` through the
///   simulator and copies the response into `resp[0..resp_max]`.
///   Sets `*resp_len_out` to the response length and returns true.
///
/// Returns false on invalid input or non-command word_addr.
#[no_mangle]
pub extern "C" fn atecc608_ffi_transaction(
    ctx: *mut Atecc608Ctx,
    word_addr: u8,
    payload: *const u8,
    payload_len: usize,
    resp: *mut u8,
    resp_max: usize,
    resp_len_out: *mut usize,
) -> bool {
    if ctx.is_null() {
        return false;
    }
    let ctx = unsafe { &mut *ctx };

    match word_addr {
        0x00 => return false, /* wake */
        0x01 => { ctx.session.volatile_reset(); return false; } /* sleep */
        0x02 => return false, /* idle */
        0x03 => {}
        _ => return false,
    }

    let pkt: &[u8] = if payload.is_null() || payload_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(payload, payload_len) }
    };

    let response = dispatch::dispatch(&mut ctx.store.device, &mut ctx.session, pkt);

    let out_len = unsafe { resp_len_out.as_mut() };
    if let Some(out) = out_len {
        let copy_len = response.len().min(resp_max);
        if !resp.is_null() && copy_len > 0 {
            unsafe { std::ptr::copy_nonoverlapping(response.as_ptr(), resp, copy_len) };
        }
        *out = response.len();
        true
    } else {
        false
    }
}
