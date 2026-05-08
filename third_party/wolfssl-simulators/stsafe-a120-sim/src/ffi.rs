/* ffi.rs
 *
 * Copyright (C) 2026 Daniele Lacamera <root@danielinux.net>
 *
 * This file is part of m33mu and is the FFI export layer for stsafe-a120-sim.
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

pub struct StsafeCtx {
    store: Store,
    session: Session,
    /// Buffered response from the last write; drained by read calls.
    resp_buf: Vec<u8>,
}

/// Create a new STSAFE-A120 context.
/// If `nv_path` is non-NULL the device state is persisted to that path.
/// Returns NULL on failure.
#[no_mangle]
pub extern "C" fn stsafe_ffi_create(nv_path: *const c_char) -> *mut StsafeCtx {
    let store = if nv_path.is_null() {
        Store::fresh()
    } else {
        let path_cstr = unsafe { CStr::from_ptr(nv_path) };
        let path_str = path_cstr.to_string_lossy();
        let path_owned = path_str.as_ref().to_owned();
        let path = std::path::Path::new(&path_owned);
        match Store::load_or_init(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[stsafe] failed to load/init store: {}", e);
                return std::ptr::null_mut();
            }
        }
    };
    let ctx = Box::new(StsafeCtx {
        store,
        session: Session::new(),
        resp_buf: Vec::new(),
    });
    Box::into_raw(ctx)
}

/// Destroy a context created by stsafe_ffi_create.
#[no_mangle]
pub extern "C" fn stsafe_ffi_destroy(ctx: *mut StsafeCtx) {
    if !ctx.is_null() {
        unsafe { drop(Box::from_raw(ctx)) };
    }
}

/// I2C write: dispatch the raw STSAFE frame and buffer the response.
/// Returns true on success (response buffered), false on bad input.
#[no_mangle]
pub extern "C" fn stsafe_ffi_write(
    ctx: *mut StsafeCtx,
    data: *const u8,
    len: usize,
) -> bool {
    if ctx.is_null() || data.is_null() || len == 0 {
        return false;
    }
    let ctx = unsafe { &mut *ctx };
    let frame = unsafe { std::slice::from_raw_parts(data, len) };
    ctx.resp_buf = dispatch::dispatch(&mut ctx.store, &mut ctx.session, frame);
    true
}

/// I2C read: copy up to `len` bytes of the buffered response into `buf`.
/// Sets `*nread_out` to the number of bytes actually copied.
/// Returns true if there was data to read, false if the buffer was empty.
#[no_mangle]
pub extern "C" fn stsafe_ffi_read(
    ctx: *mut StsafeCtx,
    buf: *mut u8,
    len: usize,
    nread_out: *mut usize,
) -> bool {
    if ctx.is_null() || buf.is_null() {
        return false;
    }
    let ctx = unsafe { &mut *ctx };
    if ctx.resp_buf.is_empty() {
        if let Some(n) = unsafe { nread_out.as_mut() } {
            *n = 0;
        }
        return false;
    }
    let copy_len = ctx.resp_buf.len().min(len);
    unsafe { std::ptr::copy_nonoverlapping(ctx.resp_buf.as_ptr(), buf, copy_len) };
    ctx.resp_buf.drain(..copy_len);
    if let Some(n) = unsafe { nread_out.as_mut() } {
        *n = copy_len;
    }
    true
}
