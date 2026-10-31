//! Who is on the other end of the socket, and may they use the agent.
//!
//! Identity comes from the connection's audit token (LOCAL_PEERTOKEN), not the PID:
//! a PID can exit and be reused between the check and the signature, an audit token cannot.

use crate::se;
use std::os::fd::RawFd;

const SOL_LOCAL: libc::c_int = 0;
const LOCAL_PEERTOKEN: libc::c_int = 0x006;
const AUDIT_TOKEN_LEN: usize = 32; // audit_token_t: 8 x u32

/// Apple OS binaries allowed to request signatures (Signing ID; must also satisfy "anchor apple").
pub const SIGN_CALLERS: [&str; 4] = [
    "com.apple.ssh",
    "com.apple.scp",
    "com.apple.sftp",
    "com.apple.ssh-keygen",
];
/// Allowed to list public keys only (`ssh-add -l` / `-L`); can never get a signature.
pub const LIST_ONLY_CALLERS: [&str; 1] = ["com.apple.ssh-add"];

#[derive(Clone, Debug, Default)]
pub struct Peer {
    pub pid: i32,
    pub path: String,
    pub signing_id: String,
    pub apple_platform: bool,
    pub valid: bool,
    pub error: Option<String>,
}

impl Peer {
    pub fn from_fd(fd: RawFd) -> Peer {
        let mut token = [0u8; AUDIT_TOKEN_LEN];
        let mut len = AUDIT_TOKEN_LEN as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                SOL_LOCAL,
                LOCAL_PEERTOKEN,
                token.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if rc != 0 || len as usize != AUDIT_TOKEN_LEN {
            return Peer {
                error: Some(format!(
                    "LOCAL_PEERTOKEN: {}",
                    std::io::Error::last_os_error()
                )),
                ..Default::default()
            };
        }
        // audit_token_to_pid(): val[5]
        let pid = i32::from_ne_bytes(token[20..24].try_into().unwrap());
        match se::peer_identity(&token) {
            Ok(id) => Peer {
                pid,
                path: id.path,
                signing_id: id.signing_id,
                apple_platform: id.apple_platform,
                valid: id.valid,
                error: None,
            },
            Err(e) => Peer {
                pid,
                error: Some(format!("{e:#}")),
                ..Default::default()
            },
        }
    }

    fn trusted_apple(&self, ids: &[&str]) -> bool {
        self.error.is_none()
            && self.valid
            && self.apple_platform
            && ids.contains(&self.signing_id.as_str())
    }

    pub fn may_sign(&self) -> bool {
        self.trusted_apple(&SIGN_CALLERS)
    }

    pub fn may_list(&self) -> bool {
        self.may_sign() || self.trusted_apple(&LIST_ONLY_CALLERS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(id: &str, apple: bool) -> Peer {
        Peer {
            pid: 1,
            path: "/usr/bin/x".into(),
            signing_id: id.into(),
            apple_platform: apple,
            valid: true,
            error: None,
        }
    }

    #[test]
    fn policy() {
        assert!(peer("com.apple.ssh", true).may_sign());
        assert!(peer("com.apple.ssh-keygen", true).may_sign());
        // Claimed Apple Signing ID without the Apple anchor: a self-signed impostor.
        assert!(!peer("com.apple.ssh", false).may_sign());
        assert!(!peer("com.apple.ssh", false).may_list());
        assert!(!peer("com.apple.ssh-add", true).may_sign());
        assert!(peer("com.apple.ssh-add", true).may_list());
        assert!(!peer("org.openbsd.ssh", true).may_list());
        let mut invalid = peer("com.apple.ssh", true);
        invalid.valid = false;
        assert!(!invalid.may_sign());
        let mut errored = peer("com.apple.ssh", true);
        errored.error = Some("x".into());
        assert!(!errored.may_sign());
    }
}
