//! Reuse-window settings.
//!
//! `~/.config/se-agent/config.toml` (yours, e.g. via chezmoi) sets per key and per program how long
//! one approval is reused:
//!
//! ```toml
//! [defaults]
//! reuse = {}                                  # keys without their own section: always prompt
//!
//! [keys.github]
//! reuse = { ssh-keygen = "30m" }              # commit signing only; ssh still prompts
//!
//! [keys.nhz-io]
//! reuse = { ssh-keygen = "30m", ssh = "5m" }
//! ```
//!
//! Programs: `ssh`, `ssh-keygen`, `scp`, `sftp`. Values: `"90s"`, `"15m"`, `"1h"` or seconds.
//! A key's `reuse` replaces `[defaults]` entirely. Every value must be at most the cap: 1 hour,
//! unless root-owned `/etc/se-agent/max` says otherwise (higher or lower). An entry above the cap,
//! or naming an unknown program, is skipped and reported. A file that other users can write, or
//! that does not parse, means no reuse at all.

use crate::store;
use anyhow::{Context as _, Result, bail};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The cap when /etc/se-agent/max is absent or not trustworthy.
pub const BUILTIN_CAP: Duration = Duration::from_secs(60 * 60);
pub const CEILING_PATH: &str = "/etc/se-agent/max";

/// Program name in the config → code-signing identifier of Apple's binary.
pub const PROGRAMS: [(&str, &str); 4] = [
    ("ssh", "com.apple.ssh"),
    ("ssh-keygen", "com.apple.ssh-keygen"),
    ("scp", "com.apple.scp"),
    ("sftp", "com.apple.sftp"),
];

pub fn program_name(signing_id: &str) -> &str {
    PROGRAMS
        .iter()
        .find(|(_, id)| *id == signing_id)
        .map_or(signing_id, |(name, _)| name)
}

fn signing_id(program: &str) -> Option<&'static str> {
    PROGRAMS
        .iter()
        .find(|(name, _)| *name == program)
        .map(|(_, id)| *id)
}

pub fn config_path() -> Result<PathBuf> {
    Ok(store::home()?.join(".config/se-agent/config.toml"))
}

/// `"90s"`, `"15m"`, `"1h"` or plain seconds; zero is off (None).
pub fn parse_duration(s: &str) -> Result<Option<Duration>> {
    let s = s.trim().to_ascii_lowercase();
    let bad = || format!("invalid duration {s:?}: use e.g. 90s, 15m, 1h");
    let (num, unit) = match s.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((i, _)) => s.split_at(i),
        None => (s.as_str(), "s"),
    };
    let n: u64 = num.parse().with_context(bad)?;
    let secs = match unit {
        "s" => n,
        "m" => n.saturating_mul(60),
        "h" => n.saturating_mul(3600),
        _ => bail!(bad()),
    };
    Ok((secs > 0).then(|| Duration::from_secs(secs)))
}

pub fn fmt(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 3600 && s.is_multiple_of(3600) {
        format!("{}h", s / 3600)
    } else if s.is_multiple_of(60) {
        format!("{}m", s / 60)
    } else {
        format!("{s}s")
    }
}

// --- cap ----------------------------------------------------------------------------------------

pub struct Cap {
    pub max: Duration,
    /// Where it came from, for `se-agent reuse`.
    pub source: String,
}

/// The cap from /etc/se-agent/max if root owns it and its directory and nobody else can write
/// either; otherwise the built-in one (with the reason in `source`).
pub fn cap() -> Cap {
    match cap_from(Path::new(CEILING_PATH), 0) {
        Ok(Some(max)) => Cap {
            max,
            source: CEILING_PATH.into(),
        },
        Ok(None) => Cap {
            max: BUILTIN_CAP,
            source: "built in".into(),
        },
        Err(e) => Cap {
            max: BUILTIN_CAP,
            source: format!("built in; {CEILING_PATH} ignored: {e:#}"),
        },
    }
}

fn trusted(path: &Path, owner: u32) -> Result<()> {
    let m = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if m.uid() != owner {
        bail!("{} is not owned by root", path.display());
    }
    if m.permissions().mode() & 0o022 != 0 {
        bail!("{} is writable by group or others", path.display());
    }
    Ok(())
}

/// `owner` is the uid that must own the file and its directory (root; a test passes its own).
fn cap_from(path: &Path, owner: u32) -> Result<Option<Duration>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("stat {}", path.display())),
        Ok(m) if !m.file_type().is_file() => bail!("{} is not a regular file", path.display()),
        Ok(_) => {}
    }
    trusted(path.parent().context("no parent")?, owner)?;
    trusted(path, owner)?;
    let text = fs::read_to_string(path)?;
    match parse_duration(&text)? {
        Some(d) => Ok(Some(d)),
        None => Ok(Some(Duration::ZERO)),
    }
}

// --- settings -----------------------------------------------------------------------------------

/// Window length per signing identifier.
type Programs = BTreeMap<String, Duration>;

#[derive(Default)]
pub struct Settings {
    defaults: Programs,
    keys: BTreeMap<String, Programs>,
    /// Skipped entries, for `se-agent reuse` and the agent's error log.
    pub problems: Vec<String>,
}

impl Settings {
    /// The window for this key and caller; None = always prompt.
    pub fn get(&self, label: &str, signing_id: &str) -> Option<Duration> {
        self.keys
            .get(label)
            .unwrap_or(&self.defaults)
            .get(signing_id)
            .copied()
    }

    /// Effective windows for one key, as (program, length).
    pub fn for_key(&self, label: &str) -> Vec<(&'static str, Duration)> {
        let m = self.keys.get(label).unwrap_or(&self.defaults);
        PROGRAMS
            .iter()
            .filter_map(|(name, id)| m.get(*id).map(|d| (*name, *d)))
            .collect()
    }

    pub fn configured_keys(&self) -> impl Iterator<Item = &String> {
        self.keys.keys()
    }
}

/// Reads config.toml. No file: no reuse. Unsafe or unparsable file: error (the agent then
/// reuses nothing).
pub fn load(cap: Duration) -> Result<Settings> {
    load_from(&config_path()?, cap)
}

fn load_from(path: &Path, cap: Duration) -> Result<Settings> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Settings::default()),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    if fs::metadata(path)?.permissions().mode() & 0o022 != 0 {
        bail!(
            "{} is writable by group or others; chmod 600 it",
            path.display()
        );
    }
    parse(&text, cap).with_context(|| format!("parse {}", path.display()))
}

fn parse(text: &str, cap: Duration) -> Result<Settings> {
    let doc: toml::Table = text.parse()?;
    let mut s = Settings::default();
    for key in doc.keys() {
        if key != "defaults" && key != "keys" {
            s.problems.push(format!("unknown section [{key}]"));
        }
    }
    if let Some(d) = doc.get("defaults") {
        s.defaults = programs("defaults", d, cap, &mut s.problems)?;
    }
    if let Some(keys) = doc.get("keys") {
        let keys = keys.as_table().context("[keys] must be a table")?;
        for (label, section) in keys {
            if let Err(e) = store::validate_label(label) {
                s.problems.push(format!("[keys.{label}]: {e:#}"));
                continue;
            }
            let p = programs(&format!("keys.{label}"), section, cap, &mut s.problems)?;
            s.keys.insert(label.clone(), p);
        }
    }
    Ok(s)
}

/// One `[defaults]` / `[keys.<label>]` section → its `reuse` table.
fn programs(
    name: &str,
    section: &toml::Value,
    cap: Duration,
    problems: &mut Vec<String>,
) -> Result<Programs> {
    let section = section
        .as_table()
        .with_context(|| format!("[{name}] must be a table"))?;
    let mut out = Programs::new();
    for k in section.keys() {
        if k != "reuse" {
            problems.push(format!("[{name}]: unknown option {k:?}"));
        }
    }
    let Some(reuse) = section.get("reuse") else {
        return Ok(out);
    };
    let reuse = reuse.as_table().with_context(|| {
        format!("[{name}] reuse must be a table, e.g. {{ ssh-keygen = \"30m\" }}")
    })?;
    for (program, v) in reuse {
        let Some(id) = signing_id(program) else {
            problems.push(format!(
                "[{name}] reuse: unknown program {program:?} (ssh, ssh-keygen, scp, sftp)"
            ));
            continue;
        };
        let d = match v {
            toml::Value::String(s) => parse_duration(s),
            toml::Value::Integer(n) if *n >= 0 => {
                Ok((*n > 0).then(|| Duration::from_secs(*n as u64)))
            }
            _ => Err(anyhow::anyhow!("use a string like \"30m\" or seconds")),
        };
        match d {
            Ok(None) => {}
            Ok(Some(d)) if d > cap => problems.push(format!(
                "[{name}] reuse.{program} = {} is above the cap ({}); skipped",
                fmt(d),
                fmt(cap)
            )),
            Ok(Some(d)) => {
                out.insert(id.to_string(), d);
            }
            Err(e) => problems.push(format!("[{name}] reuse.{program}: {e:#}")),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KG: &str = "com.apple.ssh-keygen";
    const SSH: &str = "com.apple.ssh";

    #[test]
    fn durations() {
        assert_eq!(parse_duration("0").unwrap(), None);
        assert_eq!(parse_duration("0m").unwrap(), None);
        assert_eq!(parse_duration("90").unwrap(), Some(Duration::from_secs(90)));
        assert_eq!(
            parse_duration("90s").unwrap(),
            Some(Duration::from_secs(90))
        );
        assert_eq!(
            parse_duration("15M").unwrap(),
            Some(Duration::from_secs(900))
        );
        assert_eq!(parse_duration("1h").unwrap(), Some(BUILTIN_CAP));
        assert!(parse_duration("5x").is_err());
        assert!(parse_duration("m").is_err());
        assert!(parse_duration("1.5m").is_err());
        assert_eq!(fmt(Duration::from_secs(3600)), "1h");
        assert_eq!(fmt(Duration::from_secs(1800)), "30m");
        assert_eq!(fmt(Duration::from_secs(90)), "90s");
        assert_eq!(program_name(KG), "ssh-keygen");
    }

    #[test]
    fn settings() {
        let s = parse(
            r#"
            [defaults]
            reuse = { ssh = "5m" }

            [keys.github]
            reuse = { ssh-keygen = "30m", sftp = 0 }

            [keys.nhz-io]
            reuse = { ssh-keygen = "2h", ssh = 600, telnet = "1m" }

            [keys.off]
            "#,
            BUILTIN_CAP,
        )
        .unwrap();
        // A key's own section replaces the defaults.
        assert_eq!(s.get("github", KG), Some(Duration::from_secs(1800)));
        assert_eq!(s.get("github", SSH), None);
        assert_eq!(s.get("github", "com.apple.sftp"), None);
        // Defaults for keys without a section; an empty section means always prompt.
        assert_eq!(s.get("runpod", SSH), Some(Duration::from_secs(300)));
        assert_eq!(s.get("off", SSH), None);
        // Above the cap and unknown programs are skipped and reported.
        assert_eq!(s.get("nhz-io", KG), None);
        assert_eq!(s.get("nhz-io", SSH), Some(Duration::from_secs(600)));
        assert_eq!(s.problems.len(), 2, "{:?}", s.problems);
        assert_eq!(
            s.for_key("github"),
            vec![("ssh-keygen", Duration::from_secs(1800))]
        );

        // A higher cap allows it.
        let s = parse(
            "[keys.nhz-io]\nreuse = { ssh-keygen = \"2h\" }",
            Duration::from_secs(8 * 3600),
        )
        .unwrap();
        assert_eq!(s.get("nhz-io", KG), Some(Duration::from_secs(7200)));

        assert!(parse("[keys.github]\nreuse = \"30m\"", BUILTIN_CAP).is_err());
        assert!(parse("not toml =", BUILTIN_CAP).is_err());
    }

    #[test]
    fn files() {
        let dir = std::env::temp_dir().join(format!("se-agent-config-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = unsafe { libc::getuid() };

        // config.toml: missing = nothing; group/other-writable = refused.
        let cfg = dir.join("config.toml");
        assert!(
            load_from(&cfg, BUILTIN_CAP)
                .unwrap()
                .for_key("github")
                .is_empty()
        );
        fs::write(&cfg, "[keys.github]\nreuse = { ssh-keygen = \"30m\" }\n").unwrap();
        fs::set_permissions(&cfg, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            load_from(&cfg, BUILTIN_CAP).unwrap().get("github", KG),
            Some(Duration::from_secs(1800))
        );
        fs::set_permissions(&cfg, fs::Permissions::from_mode(0o620)).unwrap();
        assert!(load_from(&cfg, BUILTIN_CAP).is_err());

        // Ceiling: missing = None; trusted = value; wrong owner, writable or symlink = error.
        let max = dir.join("max");
        assert_eq!(cap_from(&max, uid).unwrap(), None);
        fs::write(&max, "8h\n").unwrap();
        fs::set_permissions(&max, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            cap_from(&max, uid).unwrap(),
            Some(Duration::from_secs(8 * 3600))
        );
        assert!(cap_from(&max, uid + 1).is_err());
        fs::set_permissions(&max, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(cap_from(&max, uid).is_err());
        fs::set_permissions(&max, fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(cap_from(&max, uid).is_err());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&max, &link).unwrap();
        assert!(cap_from(&link, uid).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
