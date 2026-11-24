//! Safe wrappers over the Swift shim (swift/SEShim.swift).

use anyhow::{Result, anyhow};
use std::ffi::{CStr, CString, c_char, c_void};
use std::ptr::{self, NonNull};

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
    fn se_context_new(reason: *const c_char) -> *mut c_void;
    fn se_context_free(ctx: *mut c_void);
    fn se_sign(
        blob: *const u8,
        blob_len: usize,
        data: *const u8,
        data_len: usize,
        ctx: *mut c_void,
        sig_out: *mut *mut u8,
        sig_len: *mut usize,
        err_out: *mut *mut c_char,
    ) -> i32;
    fn se_age_public(
        blob: *const u8,
        blob_len: usize,
        pub_out: *mut *mut u8,
        pub_len: *mut usize,
        err_out: *mut *mut c_char,
    ) -> i32;
    fn se_age_tag(
        public: *const u8,
        pub_len: usize,
        kind: i32,
        share: *const u8,
        share_len: usize,
        tag_out: *mut *mut u8,
        tag_len: *mut usize,
        err_out: *mut *mut c_char,
    ) -> i32;
    fn se_age_unwrap(
        blob: *const u8,
        blob_len: usize,
        kind: i32,
        share: *const u8,
        share_len: usize,
        body: *const u8,
        body_len: usize,
        ctx: *mut c_void,
        key_out: *mut *mut u8,
        key_len: *mut usize,
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

/// Like take_bytes, for secrets: the shim's copy is zeroed before it is freed.
unsafe fn take_secret(p: *mut u8, len: usize) -> Vec<u8> {
    if p.is_null() {
        return Vec::new();
    }
    let v = unsafe { std::slice::from_raw_parts(p, len) }.to_vec();
    for i in 0..len {
        unsafe { std::ptr::write_volatile(p.add(i), 0) };
    }
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

/// An authentication context (LAContext). The first signature with it asks for Touch ID /
/// password; later ones reuse that approval without a prompt for as long as it lives.
/// Dropping it ends the approval.
pub struct Context(NonNull<c_void>);

// Signatures are serialized by the agent's sign lock, so a context is never used concurrently.
unsafe impl Send for Context {}

impl Context {
    /// `reason` is shown in the Touch ID / password dialog.
    pub fn new(reason: &str) -> Result<Context> {
        let reason = CString::new(reason.replace('\0', " "))?;
        let p = unsafe { se_context_new(reason.as_ptr()) };
        NonNull::new(p)
            .map(Context)
            .ok_or_else(|| anyhow!("LAContext allocation failed"))
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe { se_context_free(self.0.as_ptr()) }
    }
}

/// Signs the full message (SHA-256 is applied inside CryptoKit). Blocks on Touch ID / password
/// unless `ctx` was already approved. Returns the 64-byte raw r || s.
pub fn sign(blob: &[u8], data: &[u8], ctx: &Context) -> Result<Vec<u8>> {
    let (mut s, mut sl, mut e) = (ptr::null_mut(), 0, ptr::null_mut());
    let rc = unsafe {
        se_sign(
            blob.as_ptr(),
            blob.len(),
            data.as_ptr(),
            data.len(),
            ctx.0.as_ptr(),
            &mut s,
            &mut sl,
            &mut e,
        )
    };
    let sig = unsafe { take_bytes(s, sl) };
    check(rc, e)?;
    Ok(sig)
}

/// age-plugin-se stanza types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgeKind {
    /// `piv-p256` (age1se1 recipients): share is a 33-byte compressed point.
    Piv = 0,
    /// `p256tag` (age1tag1 recipients): share is a 65-byte uncompressed point (HPKE enc).
    Tag = 1,
}

/// Compressed public key of an age-plugin-se identity blob. No prompt.
pub fn age_public(blob: &[u8]) -> Result<Vec<u8>> {
    let (mut p, mut pl, mut e) = (ptr::null_mut(), 0, ptr::null_mut());
    let rc = unsafe { se_age_public(blob.as_ptr(), blob.len(), &mut p, &mut pl, &mut e) };
    let public = unsafe { take_bytes(p, pl) };
    check(rc, e)?;
    Ok(public)
}

/// The 4-byte tag a stanza must carry to be meant for `public` (compressed). No prompt.
pub fn age_tag(public: &[u8], kind: AgeKind, share: &[u8]) -> Result<Vec<u8>> {
    let (mut t, mut tl, mut e) = (ptr::null_mut(), 0, ptr::null_mut());
    let rc = unsafe {
        se_age_tag(
            public.as_ptr(),
            public.len(),
            kind as i32,
            share.as_ptr(),
            share.len(),
            &mut t,
            &mut tl,
            &mut e,
        )
    };
    let tag = unsafe { take_bytes(t, tl) };
    check(rc, e)?;
    Ok(tag)
}

/// Unwraps a stanza's file key with the Secure Enclave (ECDH). Blocks on Touch ID / password
/// unless `ctx` was already approved.
pub fn age_unwrap(
    blob: &[u8],
    kind: AgeKind,
    share: &[u8],
    body: &[u8],
    ctx: &Context,
) -> Result<Vec<u8>> {
    let (mut k, mut kl, mut e) = (ptr::null_mut(), 0, ptr::null_mut());
    let rc = unsafe {
        se_age_unwrap(
            blob.as_ptr(),
            blob.len(),
            kind as i32,
            share.as_ptr(),
            share.len(),
            body.as_ptr(),
            body.len(),
            ctx.0.as_ptr(),
            &mut k,
            &mut kl,
            &mut e,
        )
    };
    let key = unsafe { take_secret(k, kl) };
    check(rc, e)?;
    Ok(key)
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
