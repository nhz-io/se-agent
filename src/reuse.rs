//! Approval reuse window (opt-in, per key).
//!
//! After a fresh Touch ID / password approval, further signatures with the same key from the same
//! caller (Signing ID, e.g. `com.apple.ssh-keygen`) reuse that approval without a prompt: the agent
//! keeps the approved LAContext. The window is set per key in ~/.se-agent/config.json (max 30 min)
//! and ends, whichever comes first:
//! - at its deadline, counted from the approval and not extended by use,
//! - when the Mac sleeps,
//! - on `se-agent forget` (SIGUSR1 to the agent),
//! - when the key's setting is removed or shortened below the time already used,
//! - when a reused signature fails, or the agent exits.

use crate::store;
use anyhow::{Context as _, Result, bail};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::time::Duration;
use time::OffsetDateTime;

pub const MAX: Duration = Duration::from_secs(30 * 60);
/// What `se-agent reuse <label> on` sets.
pub const DEFAULT: Duration = MAX;

// --- settings ---------------------------------------------------------------------------------

pub fn config_path() -> Result<PathBuf> {
    Ok(store::home()?.join(".se-agent/config.json"))
}

/// Per-key windows from config.json (`{"reuse": {"<label>": <seconds>}}`). No file: none.
/// Refuses a file that other users can write, and caps every value at MAX.
pub fn load() -> Result<BTreeMap<String, Duration>> {
    let path = config_path()?;
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    if fs::metadata(&path)?.permissions().mode() & 0o022 != 0 {
        bail!(
            "{} is writable by other users; chmod 600 it",
            path.display()
        );
    }
    let v: Value =
        serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    let mut out = BTreeMap::new();
    if let Some(m) = v.get("reuse").and_then(Value::as_object) {
        for (label, secs) in m {
            if let Some(s) = secs.as_u64().filter(|&s| s > 0) {
                out.insert(label.clone(), Duration::from_secs(s).min(MAX));
            }
        }
    }
    Ok(out)
}

/// Sets (Some) or removes (None) one key's window, keeping the rest of the file.
pub fn set(label: &str, window: Option<Duration>) -> Result<()> {
    store::validate_label(label)?;
    let path = config_path()?;
    let dir = path.parent().unwrap();
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    let mut v: Value = match fs::read_to_string(&path) {
        Ok(t) => serde_json::from_str(&t).with_context(|| format!("parse {}", path.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => json!({}),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    if !v.is_object() {
        v = json!({});
    }
    if !v["reuse"].is_object() {
        v["reuse"] = json!({});
    }
    let m = v["reuse"].as_object_mut().unwrap();
    match window {
        Some(d) => m.insert(label.into(), json!(d.as_secs())),
        None => m.remove(label),
    };
    let tmp = path.with_extension("json.tmp");
    let _ = fs::remove_file(&tmp);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("create {}", tmp.display()))?;
    f.write_all(format!("{}\n", serde_json::to_string_pretty(&v)?).as_bytes())?;
    f.sync_all()?;
    fs::rename(&tmp, &path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// `off` / `0` → None; `on` → DEFAULT; `90s`, `15m`, `1h` or plain seconds, at most MAX.
pub fn parse(s: &str) -> Result<Option<Duration>> {
    let s = s.trim().to_ascii_lowercase();
    match s.as_str() {
        "off" | "0" => return Ok(None),
        "on" => return Ok(Some(DEFAULT)),
        _ => {}
    }
    let (num, unit) = match s.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((i, _)) => s.split_at(i),
        None => (s.as_str(), "s"),
    };
    let n: u64 = num
        .parse()
        .with_context(|| format!("invalid duration {s:?}: use e.g. 90s, 15m, on, off"))?;
    let secs = match unit {
        "s" => n,
        "m" => n.saturating_mul(60),
        "h" => n.saturating_mul(3600),
        _ => bail!("invalid duration {s:?}: use e.g. 90s, 15m, on, off"),
    };
    if secs == 0 {
        return Ok(None);
    }
    if secs > MAX.as_secs() {
        bail!("{s} is longer than the maximum, {}", fmt(MAX));
    }
    Ok(Some(Duration::from_secs(secs)))
}

pub fn fmt(d: Duration) -> String {
    let s = d.as_secs();
    if s.is_multiple_of(60) {
        format!("{}m", s / 60)
    } else {
        format!("{s}s")
    }
}

// --- clocks -----------------------------------------------------------------------------------

fn clock_ns(id: libc::clockid_t) -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(id, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// A point in time on two macOS clocks: MONOTONIC keeps counting while the Mac sleeps,
/// UPTIME_RAW does not. Their difference grows only by time spent asleep.
#[derive(Clone, Copy, Debug)]
pub struct Stamp {
    mono: u64,
    uptime: u64,
}

impl Stamp {
    pub fn now() -> Stamp {
        Stamp {
            mono: clock_ns(libc::CLOCK_MONOTONIC),
            uptime: clock_ns(libc::CLOCK_UPTIME_RAW),
        }
    }

    fn elapsed_since(&self, earlier: &Stamp) -> Duration {
        Duration::from_nanos(self.mono.saturating_sub(earlier.mono))
    }

    fn slept_since(&self, earlier: &Stamp) -> bool {
        let asleep = (self.mono.saturating_sub(self.uptime))
            .saturating_sub(earlier.mono.saturating_sub(earlier.uptime));
        asleep > 1_000_000_000
    }
}

// --- windows ------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    Expired,
    Sleep,
    Forget,
    Setting,
    Failed,
}

impl End {
    pub fn as_str(self) -> &'static str {
        match self {
            End::Expired => "expired",
            End::Sleep => "sleep",
            End::Forget => "forget",
            End::Setting => "setting",
            End::Failed => "sign_failed",
        }
    }
}

/// (key label, caller Signing ID)
pub type Scope = (String, String);

pub struct Window<C> {
    pub ctx: C,
    opened: Stamp,
    /// The length it opened with; a longer setting later does not stretch it.
    length: Duration,
    pub until: OffsetDateTime,
}

impl<C> Window<C> {
    pub fn new(ctx: C, opened: Stamp, length: Duration) -> Window<C> {
        Window {
            ctx,
            opened,
            length,
            until: OffsetDateTime::now_utc() + length,
        }
    }

    /// Why this window is over, given the key's current setting; None while it is live.
    fn end(&self, now: &Stamp, setting: Option<Duration>) -> Option<End> {
        if now.slept_since(&self.opened) {
            Some(End::Sleep)
        } else if let Some(d) = setting {
            (now.elapsed_since(&self.opened) >= d.min(self.length)).then_some(End::Expired)
        } else {
            Some(End::Setting)
        }
    }
}

/// Live windows. Generic over the context so the rules can be tested without a Secure Enclave.
pub struct Windows<C> {
    map: HashMap<Scope, Window<C>>,
}

impl<C> Default for Windows<C> {
    fn default() -> Self {
        Windows {
            map: HashMap::new(),
        }
    }
}

impl<C> Windows<C> {
    /// Removes every window that is over and returns them with the reason.
    pub fn sweep(
        &mut self,
        now: &Stamp,
        settings: &BTreeMap<String, Duration>,
    ) -> Vec<(Scope, Window<C>, End)> {
        let over: Vec<(Scope, End)> = self
            .map
            .iter()
            .filter_map(|(scope, w)| {
                w.end(now, settings.get(&scope.0).copied())
                    .map(|e| (scope.clone(), e))
            })
            .collect();
        over.into_iter()
            .map(|(scope, e)| {
                let w = self.map.remove(&scope).unwrap();
                (scope, w, e)
            })
            .collect()
    }

    /// Takes a live window out for one signature; put it back with `insert` if it still holds.
    pub fn take(&mut self, scope: &Scope) -> Option<Window<C>> {
        self.map.remove(scope)
    }

    pub fn insert(&mut self, scope: Scope, w: Window<C>) {
        self.map.insert(scope, w);
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn drain(&mut self) -> Vec<(Scope, Window<C>)> {
        self.map.drain().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(mono_s: u64, asleep_s: u64) -> Stamp {
        Stamp {
            mono: mono_s * 1_000_000_000,
            uptime: (mono_s - asleep_s) * 1_000_000_000,
        }
    }

    fn scope(k: &str, c: &str) -> Scope {
        (k.into(), c.into())
    }

    #[test]
    fn durations() {
        assert_eq!(parse("off").unwrap(), None);
        assert_eq!(parse("0").unwrap(), None);
        assert_eq!(parse("0m").unwrap(), None);
        assert_eq!(parse("on").unwrap(), Some(MAX));
        assert_eq!(parse("90").unwrap(), Some(Duration::from_secs(90)));
        assert_eq!(parse("90s").unwrap(), Some(Duration::from_secs(90)));
        assert_eq!(parse("15m").unwrap(), Some(Duration::from_secs(900)));
        assert_eq!(parse("30m").unwrap(), Some(MAX));
        assert!(parse("31m").is_err());
        assert!(parse("1h").is_err());
        assert!(parse("5x").is_err());
        assert!(parse("m").is_err());
        assert_eq!(fmt(Duration::from_secs(1800)), "30m");
        assert_eq!(fmt(Duration::from_secs(90)), "90s");
    }

    #[test]
    fn window_rules() {
        let mut ws: Windows<()> = Windows::default();
        let mut cfg = BTreeMap::new();
        cfg.insert("github".to_string(), Duration::from_secs(60));
        let k = scope("github", "com.apple.ssh-keygen");
        ws.insert(
            k.clone(),
            Window::new((), at(100, 0), Duration::from_secs(60)),
        );

        // Live, and use does not extend it.
        assert!(ws.sweep(&at(130, 0), &cfg).is_empty());
        let w = ws.take(&k).unwrap();
        ws.insert(k.clone(), w);
        // Other caller or key: no window.
        assert!(ws.take(&scope("github", "com.apple.ssh")).is_none());
        assert!(ws.take(&scope("nhz-io", "com.apple.ssh-keygen")).is_none());

        let ends = |now, cfg: &BTreeMap<String, Duration>| {
            let mut ws: Windows<()> = Windows::default();
            ws.insert(
                k.clone(),
                Window::new((), at(100, 0), Duration::from_secs(60)),
            );
            ws.sweep(&now, cfg).pop().map(|(_, _, e)| e)
        };
        assert_eq!(ends(at(159, 0), &cfg), None);
        assert_eq!(ends(at(160, 0), &cfg), Some(End::Expired));
        assert_eq!(ends(at(110, 5), &cfg), Some(End::Sleep));
        assert_eq!(ends(at(101, 0), &BTreeMap::new()), Some(End::Setting));
        let mut shorter = BTreeMap::new();
        shorter.insert("github".to_string(), Duration::from_secs(10));
        assert_eq!(ends(at(120, 0), &shorter), Some(End::Expired));
        let mut longer = BTreeMap::new();
        longer.insert("github".to_string(), MAX);
        assert_eq!(ends(at(160, 0), &longer), Some(End::Expired));
    }
}
