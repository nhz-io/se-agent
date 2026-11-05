//! Append-only JSON-lines log of every signature and every refused request.
//! Default: ~/Library/Logs/se-agent.log (0600). Never contains message data or key material.

use crate::peer::Peer;
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub struct AuditLog {
    file: Mutex<File>,
    pub path: PathBuf,
}

pub fn default_path() -> Result<PathBuf> {
    Ok(crate::store::home()?.join("Library/Logs/se-agent.log"))
}

impl AuditLog {
    pub fn open(path: &Path) -> Result<AuditLog> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("open audit log {}", path.display()))?;
        Ok(AuditLog {
            file: Mutex::new(file),
            path: path.into(),
        })
    }

    pub fn record(&self, event: &str, peer: &Peer, extra: Value) {
        let mut rec = json!({
            "pid": peer.pid,
            "caller": peer.path,
            "signing_id": peer.signing_id,
            "apple": peer.apple_platform,
        });
        if let Some(e) = &peer.error {
            rec["peer_error"] = json!(e);
        }
        if let (Value::Object(r), Value::Object(x)) = (&mut rec, extra) {
            r.extend(x);
        }
        self.event(event, rec);
    }

    /// An event without a peer (e.g. a reuse window ending).
    pub fn event(&self, event: &str, extra: Value) {
        let now = OffsetDateTime::now_utc();
        let mut rec = json!({
            "time": now.format(&Rfc3339).unwrap_or_default(),
            "event": event,
        });
        if let (Value::Object(r), Value::Object(x)) = (&mut rec, extra) {
            r.extend(x);
        }
        let line = format!("{rec}\n");
        if let Ok(mut f) = self.file.lock() {
            let _ = f.write_all(line.as_bytes());
        }
        eprint!("{line}");
    }
}
