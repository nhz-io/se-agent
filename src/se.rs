//! Safe wrappers over the Swift shim (swift/SEShim.swift).

use anyhow::{Result, anyhow};
use std::ffi::{CStr, CString, c_char};
use std::ptr;

unsafe extern "C" {
    fn se_is_available() -> i32;
    fn se_create(
        blob_out: *mut *mut u8,
        blob_len: *mut usize,
        pub_out: *mut *mut u8,
        pub_len: *mut usize,
        err_out: *mut *mut c_char,
    ) -> i32;
    fn se_public_key(
        blob: *const u8,
        blob_len: usize,
        pub_out: *mut *mut u8,
        pub_len: *mut usize,
        err_out: *mut *mut c_char,
    ) -> i32;
    fn se_sign(
        blob: *const u8,
        blob_len: usize,
        data: *const u8,
        data_len: usize,
        reason: *const c_char,
        sig_out: *mut *mut u8,
        sig_len: *mut usize,
        err_out: *mut *mut c_char,
    ) -> i32;
    fn se_peer_identity(
        token: *const u8,
        token_len: usize,
        path_out: *mut *mut c_char,
        signing_id_out: *mut *mut c_char,
        flags_out: *mut u32,
        err_out: *mut *mut c_char,
    ) -> i32;
}

/// Takes ownership of a malloc'd buffer from the shim.
unsafe fn take_bytes(p: *mut u8, len: usize) -> Vec<u8> {
    if p.is_null() {
        return Vec::new();
    }
    let v = unsafe { std::slice::from_raw_parts(p, len) }.to_vec();
    unsafe { libc::free(p.cast()) };
    v
}

unsafe fn take_string(p: *mut c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
    unsafe { libc::free(p.cast()) };
    s
}

fn check(rc: i32, err: *mut c_char) -> Result<()> {
    let msg = unsafe { take_string(err) };
    if rc == 0 {
        Ok(())
    } else {
        Err(anyhow!("Secure Enclave: {msg}"))
    }
}

pub fn available() -> bool {
    unsafe { se_is_available() == 1 }
}

/// Returns (Secure Enclave-wrapped key blob, 65-byte public point).
pub fn create() -> Result<(Vec<u8>, Vec<u8>)> {
    let (mut b, mut bl, mut p, mut pl, mut e) =
        (ptr::null_mut(), 0, ptr::null_mut(), 0, ptr::null_mut());
    let rc = unsafe { se_create(&mut b, &mut bl, &mut p, &mut pl, &mut e) };
    let (blob, public) = unsafe { (take_bytes(b, bl), take_bytes(p, pl)) };
    check(rc, e)?;
    Ok((blob, public))
}

pub fn public_key(blob: &[u8]) -> Result<Vec<u8>> {
    let (mut p, mut pl, mut e) = (ptr::null_mut(), 0, ptr::null_mut());
    let rc = unsafe { se_public_key(blob.as_ptr(), blob.len(), &mut p, &mut pl, &mut e) };
    let public = unsafe { take_bytes(p, pl) };
    check(rc, e)?;
    Ok(public)
}

/// Signs the full message (SHA-256 is applied inside CryptoKit). Blocks on Touch ID / password.
/// Returns the 64-byte raw r || s.
pub fn sign(blob: &[u8], data: &[u8], reason: &str) -> Result<Vec<u8>> {
    let reason = CString::new(reason.replace('\0', " "))?;
    let (mut s, mut sl, mut e) = (ptr::null_mut(), 0, ptr::null_mut());
    let rc = unsafe {
        se_sign(
            blob.as_ptr(),
            blob.len(),
            data.as_ptr(),
            data.len(),
            reason.as_ptr(),
            &mut s,
            &mut sl,
            &mut e,
        )
    };
    let sig = unsafe { take_bytes(s, sl) };
    check(rc, e)?;
    Ok(sig)
}

pub struct PeerIdentity {
    pub path: String,
    pub signing_id: String,
    pub valid: bool,
    pub apple_platform: bool,
}

pub fn peer_identity(audit_token: &[u8]) -> Result<PeerIdentity> {
    let (mut p, mut s, mut flags, mut e) =
        (ptr::null_mut(), ptr::null_mut(), 0u32, ptr::null_mut());
    let rc = unsafe {
        se_peer_identity(
            audit_token.as_ptr(),
            audit_token.len(),
            &mut p,
            &mut s,
            &mut flags,
            &mut e,
        )
    };
    let (path, signing_id) = unsafe { (take_string(p), take_string(s)) };
    check(rc, e)?;
    Ok(PeerIdentity {
        path,
        signing_id,
        valid: flags & 1 != 0,
        apple_platform: flags & 2 != 0,
    })
}
