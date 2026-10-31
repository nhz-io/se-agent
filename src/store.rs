//! Keys on disk: ~/.se-agent/keys/<label> holds the Secure Enclave-wrapped blob (0600),
//! ~/.se-agent/keys/<label>.pub the OpenSSH public key. The directory is kept at 0700.
//! The blob is useless off this Mac: only this Secure Enclave can unwrap it.

use crate::{se, wire};
use anyhow::{Context, Result, bail};
use ssh_key::{HashAlg, PublicKey};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

pub struct Key {
    pub label: String,
    pub blob: Vec<u8>,
    /// SSH public key blob (wire format), used to match sign requests.
    pub public_blob: Vec<u8>,
}

impl Key {
    pub fn public(&self) -> PublicKey {
        let mut pk = PublicKey::from_bytes(&self.public_blob).expect("valid public key blob");
        pk.set_comment(format!("se-agent:{}", self.label));
        pk
    }

    pub fn openssh(&self) -> String {
        self.public().to_openssh().expect("encode public key")
    }

    pub fn fingerprint(&self) -> String {
        self.public().fingerprint(HashAlg::Sha256).to_string()
    }
}

pub fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME not set")
}

pub fn keys_dir() -> Result<PathBuf> {
    Ok(home()?.join(".se-agent/keys"))
}

pub fn validate_label(label: &str) -> Result<()> {
    let ok = !label.is_empty()
        && label.len() <= 64
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !ok {
        bail!("invalid label {label:?}: use 1-64 characters from A-Z a-z 0-9 - _");
    }
    Ok(())
}

/// Creates the directory if needed and enforces 0700; refuses to continue otherwise.
fn ensure_dir() -> Result<PathBuf> {
    let dir = keys_dir()?;
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    for d in [dir.parent().unwrap(), dir.as_path()] {
        fs::set_permissions(d, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 700 {}", d.display()))?;
    }
    Ok(dir)
}

fn write_new(path: &PathBuf, data: &[u8], mode: u32) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

pub fn create(label: &str) -> Result<Key> {
    validate_label(label)?;
    if !se::available() {
        bail!("Secure Enclave is not available on this Mac");
    }
    let dir = ensure_dir()?;
    let path = dir.join(label);
    if path.exists() {
        bail!("key {label:?} already exists ({})", path.display());
    }
    let (blob, point) = se::create()?;
    let key = Key {
        label: label.into(),
        public_blob: wire::public_key_blob(&point)?,
        blob,
    };
    write_new(&path, &key.blob, 0o600)?;
    let pub_path = dir.join(format!("{label}.pub"));
    let _ = fs::remove_file(&pub_path);
    write_new(&pub_path, format!("{}\n", key.openssh()).as_bytes(), 0o644)?;
    Ok(key)
}

pub fn load(label: &str) -> Result<Key> {
    validate_label(label)?;
    let path = keys_dir()?.join(label);
    let meta = fs::metadata(&path).with_context(|| format!("key {label:?} not found"))?;
    if meta.permissions().mode() & 0o077 != 0 {
        bail!(
            "{} is accessible by other users; chmod 600 it",
            path.display()
        );
    }
    let blob = fs::read(&path)?;
    let point = se::public_key(&blob)
        .with_context(|| format!("key {label:?} is not usable on this Mac"))?;
    Ok(Key {
        label: label.into(),
        public_blob: wire::public_key_blob(&point)?,
        blob,
    })
}

/// All keys, sorted by label. Unreadable keys are reported on stderr and skipped.
pub fn list() -> Result<Vec<Key>> {
    let dir = keys_dir()?;
    let Ok(entries) = fs::read_dir(&dir) else {
        return Ok(Vec::new());
    };
    let mut labels: Vec<String> = entries
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| validate_label(n).is_ok())
        .collect();
    labels.sort();
    let mut keys = Vec::new();
    for l in labels {
        match load(&l) {
            Ok(k) => keys.push(k),
            Err(e) => eprintln!("se-agent: skipping {l}: {e:#}"),
        }
    }
    Ok(keys)
}

pub fn delete(label: &str) -> Result<()> {
    validate_label(label)?;
    let dir = keys_dir()?;
    let path = dir.join(label);
    fs::remove_file(&path).with_context(|| format!("delete {}", path.display()))?;
    let _ = fs::remove_file(dir.join(format!("{label}.pub")));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_label;

    #[test]
    fn labels() {
        for ok in ["github", "a", "work_key-2", &"x".repeat(64)] {
            assert!(validate_label(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "../x",
            "a/b",
            "a.pub",
            "a:b",
            "a b",
            "ключ",
            &"x".repeat(65),
        ] {
            assert!(validate_label(bad).is_err(), "{bad}");
        }
    }
}
