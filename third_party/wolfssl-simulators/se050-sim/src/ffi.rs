/* ffi.rs
 *
 * Copyright (C) 2026 Daniele Lacamera <root@danielinux.net>
 *
 * This file is part of m33mu and is the FFI export layer for se050-sim.
 *
 * m33mu is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation; either version 3 of the License, or (at your
 * option) any later version.
 */

use std::ffi::CStr;
use std::os::raw::c_char;

use embedded_hal::blocking::i2c::{Read, Write};

use crate::transport::Se050Simulator;

/// Create a new SE050 context.
/// If `nv_path` is non-NULL the object store is persisted to that path.
/// Returns NULL on failure.
#[no_mangle]
pub extern "C" fn se050_ffi_create(nv_path: *const c_char) -> *mut Se050Simulator {
    let sim = if nv_path.is_null() {
        Se050Simulator::new()
    } else {
        let path_cstr = unsafe { CStr::from_ptr(nv_path) };
        let path = std::path::PathBuf::from(path_cstr.to_string_lossy().as_ref());
        Se050Simulator::with_persistence(path)
    };
    Box::into_raw(Box::new(sim))
}

/// Destroy a context created by se050_ffi_create.
#[no_mangle]
pub extern "C" fn se050_ffi_destroy(ctx: *mut Se050Simulator) {
    if !ctx.is_null() {
        unsafe { drop(Box::from_raw(ctx)) };
    }
}

/// I2C write: feed a T=1 frame to the T1Responder and queue responses.
/// Returns true on success, false on protocol error.
#[no_mangle]
pub extern "C" fn se050_ffi_write(
    ctx: *mut Se050Simulator,
    data: *const u8,
    len: usize,
) -> bool {
    if ctx.is_null() || data.is_null() {
        return false;
    }
    let sim = unsafe { &mut *ctx };
    let buf = unsafe { std::slice::from_raw_parts(data, len) };
    /* addr is ignored by Se050Simulator (any value works) */
    sim.write(0x48u8, buf).is_ok()
}

/// I2C read: pop the next response chunk into `buf[0..len]`.
/// Returns true if a chunk was available, false if none queued (NACK).
#[no_mangle]
pub extern "C" fn se050_ffi_read(
    ctx: *mut Se050Simulator,
    buf: *mut u8,
    len: usize,
) -> bool {
    if ctx.is_null() || buf.is_null() {
        return false;
    }
    let sim = unsafe { &mut *ctx };
    let out = unsafe { std::slice::from_raw_parts_mut(buf, len) };
    sim.read(0x48u8, out).is_ok()
}
