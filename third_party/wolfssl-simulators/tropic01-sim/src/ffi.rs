/* ffi.rs
 *
 * Copyright (C) 2026 Daniele Lacamera <root@danielinux.net>
 *
 * This file is part of m33mu and is the FFI export layer for tropic01-sim.
 *
 * m33mu is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation; either version 3 of the License, or (at your
 * option) any later version.
 */

//! C ABI for byte-accurate SPI exchange.
//!
//! Mapping (mirrors the protocol described in `spi.rs`):
//!
//!   tropic01_ffi_create(path)             -> *mut Ctx
//!   tropic01_ffi_destroy(ctx)
//!   tropic01_ffi_csn(ctx, level: u8)      // 0 = CSN low (active), 1 = CSN high
//!   tropic01_ffi_xfer(ctx, mosi: u8)      -> u8 (MISO byte)
//!
//! The host emulator is expected to call `csn(0)` on the falling edge,
//! issue one or more `xfer()` calls for the bytes the SPI controller clocks
//! out, and `csn(1)` on the rising edge. Whenever the SPI emulator reports
//! `RequestComplete` mid-stream, this layer pulls the assembled L2 request,
//! runs `Dispatcher::dispatch`, and stages the response so the next polled-
//! read transaction serves it.

use std::ffi::CStr;
use std::os::raw::c_char;

use crate::dispatch::Dispatcher;
use crate::object_store::Store;
use crate::session::Session;
use crate::spi::{SpiEmulator, SpiOutcome};

pub struct Tropic01Ctx {
    store: Store,
    session: Session,
    spi: SpiEmulator,
}

/// Create a new TROPIC01 context.
///
/// If `nv_path` is non-NULL, the device state is loaded from (or initialised
/// into) that JSON file. Pass NULL for a transient in-memory device.
/// Returns NULL on failure.
#[no_mangle]
pub extern "C" fn tropic01_ffi_create(nv_path: *const c_char) -> *mut Tropic01Ctx {
    let store = if nv_path.is_null() {
        Store::fresh()
    } else {
        let path_cstr = unsafe { CStr::from_ptr(nv_path) };
        let path_str = path_cstr.to_string_lossy();
        let path = std::path::Path::new(path_str.as_ref());
        match Store::load_or_init(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[tropic01] failed to load/init store: {}", e);
                return std::ptr::null_mut();
            }
        }
    };
    let ctx = Box::new(Tropic01Ctx {
        store,
        session: Session::new(),
        spi: SpiEmulator::new(),
    });
    Box::into_raw(ctx)
}

/// Destroy a context created by `tropic01_ffi_create`.
#[no_mangle]
pub extern "C" fn tropic01_ffi_destroy(ctx: *mut Tropic01Ctx) {
    if !ctx.is_null() {
        unsafe { drop(Box::from_raw(ctx)) };
    }
}

/// Notify the simulator of a chip-select edge.
///
/// `level == 0` means CSN is low (chip selected). `level != 0` means CSN
/// is high (deselected). The simulator preserves any staged response
/// across the CSN_HIGH so a subsequent poll-read transaction can drain it.
#[no_mangle]
pub extern "C" fn tropic01_ffi_csn(ctx: *mut Tropic01Ctx, level: u8) {
    if ctx.is_null() {
        return;
    }
    let ctx = unsafe { &mut *ctx };
    if level == 0 {
        ctx.spi.csn_low();
    } else {
        ctx.spi.csn_high();
    }
}

/// Exchange one byte over SPI.
///
/// Should only be called while CSN is asserted (after `csn(0)` and before
/// the matching `csn(1)`). Returns the MISO byte the chip drives in
/// response to `mosi`.
#[no_mangle]
pub extern "C" fn tropic01_ffi_xfer(ctx: *mut Tropic01Ctx, mosi: u8) -> u8 {
    if ctx.is_null() {
        return 0xFF;
    }
    let ctx = unsafe { &mut *ctx };

    let (miso, outcome) = ctx.spi.spi_transfer(&[mosi]);

    if matches!(outcome, SpiOutcome::RequestComplete) {
        let raw = ctx.spi.take_request();
        let response = Dispatcher::dispatch(&mut ctx.store, &mut ctx.session, &raw);
        ctx.spi.stage_response(Some(response));
        let _ = ctx.store.persist();
    }

    miso.first().copied().unwrap_or(0xFF)
}
