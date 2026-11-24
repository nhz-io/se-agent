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
//!
//! [age]
//! reuse = { sops = "30m" }                    # age-plugin-se keys (decryption, see age.rs)
//!
//! [relay.box]                             # requests another Mac relays over ssh (relay.rs)
//! age = true                                  # may decrypt with this Mac's age keys; default no
//! reuse = { ssh-keygen = "30m", age = "15m" } # its own windows, never the local ones
//!
//! [upstream]                                  # on the other Mac: where this Mac's agent is
//! socket = "~/.ssh/agent-desk.sock"
//! ```
//!
//! Programs: `ssh`, `ssh-keygen`, `scp`, `sftp`; under `[age]`: `sops`, `age`; under `[relay.<host>]`:
//! `ssh` (logins), `ssh-keygen` (SSHSIG signatures, e.g. git commits), `age`. Values: `"90s"`, `"15m"`, `"1h"` or seconds.
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

/// Programs under `[age]`: the caller's executable name (they are not Apple-signed; see age.rs).
pub const AGE_PROGRAMS: [(&str, &str); 2] = [("sops", "sops"), ("age", "age")];

/// Programs under `[relay.<host>]`: what kind of request the other Mac relays (its programs are
/// not visible from here). Scopes are `relay:<host>:<program>`, so they never meet local ones.
pub const RELAY_PROGRAMS: [(&str, &str); 3] =
    [("ssh", "ssh"), ("ssh-keygen", "ssh-keygen"), ("age", "age")];

/// `[relay.<host>]` for `se-agent reuse`: (host, age allowed, windows).
pub type RelayView<'a> = (&'a str, bool, Vec<(&'static str, Duration)>);

/// `[relay.<host>]`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelayHost {
    /// Relayed age decryption allowed.
    pub age: bool,
    reuse: Programs,
}

pub fn program_name(signing_id: &str) -> &str {
    PROGRAMS
        .iter()
        .find(|(_, id)| *id == signing_id)
        .map_or(signing_id, |(name, _)| name)
}

fn signing_id(table: &[(&str, &'static str)], program: &str) -> Option<&'static str> {
    table
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
    /// `[age]`: per program name, for every age-plugin-se key.
    age: Programs,
    /// `[relay.<host>]`, by host name.
    relays: BTreeMap<String, RelayHost>,
    /// `[upstream] socket`, `~` expanded.
    pub upstream: Option<PathBuf>,
    /// Skipped entries, for `se-agent reuse` and the agent's error log.
    pub problems: Vec<String>,
}

impl Settings {
    /// The window for this key and caller; None = always prompt.
    /// Age keys are labelled `age:<recipient>` (age::SCOPE_PREFIX) and use `[age]`.
    pub fn get(&self, label: &str, signing_id: &str) -> Option<Duration> {
        if label.starts_with(crate::age::SCOPE_PREFIX) {
            return self.age.get(signing_id).copied();
        }
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

    /// Effective `[age]` windows, as (program, length).
    pub fn for_age(&self) -> Vec<(&'static str, Duration)> {
        AGE_PROGRAMS
            .iter()
            .filter_map(|(name, id)| self.age.get(*id).map(|d| (*name, *d)))
            .collect()
    }

    /// The `[relay.<name>]` section for the first of `names` (a relayed host's names) that has one.
    pub fn relay(&self, names: &[String]) -> Option<(&str, &RelayHost)> {
        names
            .iter()
            .find_map(|n| self.relays.get_key_value(n))
            .map(|(k, v)| (k.as_str(), v))
    }

    /// The window for a relayed request of `program` (ssh, ssh-keygen, age) from that host.
    pub fn relay_window(&self, names: &[String], program: &str) -> Option<Duration> {
        self.relay(names)?.1.reuse.get(program).copied()
    }

    /// `[relay.<host>]` sections, for `se-agent reuse`.
    pub fn relays(&self) -> Vec<RelayView<'_>> {
        self.relays
            .iter()
            .map(|(h, r)| {
                let w = RELAY_PROGRAMS
                    .iter()
                    .filter_map(|(name, id)| r.reuse.get(*id).map(|d| (*name, *d)))
                    .collect();
                (h.as_str(), r.age, w)
            })
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
        if !["defaults", "keys", "age", "relay", "upstream"].contains(&key.as_str()) {
            s.problems.push(format!("unknown section [{key}]"));
        }
    }
    if let Some(d) = doc.get("defaults") {
        s.defaults = programs("defaults", d, &PROGRAMS, &[], cap, &mut s.problems)?;
    }
    if let Some(a) = doc.get("age") {
        s.age = programs("age", a, &AGE_PROGRAMS, &[], cap, &mut s.problems)?;
    }
    if let Some(relay) = doc.get("relay") {
        let relay = relay
            .as_table()
            .context("[relay] must hold [relay.<host>] sections")?;
        for (host, section) in relay {
            if host.is_empty()
                || !host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-._".contains(c))
            {
                s.problems.push(format!("[relay.{host}]: not a host name"));
                continue;
            }
            let name = format!("relay.{host}");
            let reuse = programs(
                &name,
                section,
                &RELAY_PROGRAMS,
                &["age"],
                cap,
                &mut s.problems,
            )?;
            let age = match section.get("age") {
                None => false,
                Some(toml::Value::Boolean(b)) => *b,
                Some(_) => {
                    s.problems
                        .push(format!("[{name}] age must be true or false; off"));
                    false
                }
            };
            s.relays
                .insert(host.to_ascii_lowercase(), RelayHost { age, reuse });
        }
    }
    if let Some(u) = doc.get("upstream") {
        let u = u.as_table().context("[upstream] must be a table")?;
        for k in u.keys() {
            if k != "socket" {
                s.problems.push(format!("[upstream]: unknown option {k:?}"));
            }
        }
        match u.get("socket") {
            None => {}
            Some(toml::Value::String(p)) => match expand(p) {
                Some(p) => s.upstream = Some(p),
                None => s.problems.push(format!(
                    "[upstream] socket = {p:?}: use an absolute path or ~/…"
                )),
            },
            Some(_) => s
                .problems
                .push("[upstream] socket must be a path string".into()),
        }
    }
    if let Some(keys) = doc.get("keys") {
        let keys = keys.as_table().context("[keys] must be a table")?;
        for (label, section) in keys {
            if let Err(e) = store::validate_label(label) {
                s.problems.push(format!("[keys.{label}]: {e:#}"));
                continue;
            }
            let p = programs(
                &format!("keys.{label}"),
                section,
                &PROGRAMS,
                &[],
                cap,
                &mut s.problems,
            )?;
            s.keys.insert(label.clone(), p);
        }
    }
    Ok(s)
}

/// `~/x` → $HOME/x; absolute paths as they are; anything else None.
fn expand(p: &str) -> Option<PathBuf> {
    match p.strip_prefix("~/") {
        Some(rest) => store::home().ok().map(|h| h.join(rest)),
        None => Some(PathBuf::from(p)).filter(|p| p.is_absolute()),
    }
}

/// One `[defaults]` / `[keys.<label>]` / … section → its `reuse` table. `other` are further
/// options the section may have.
fn programs(
    name: &str,
    section: &toml::Value,
    table: &[(&str, &'static str)],
    other: &[&str],
    cap: Duration,
    problems: &mut Vec<String>,
) -> Result<Programs> {
    let section = section
        .as_table()
        .with_context(|| format!("[{name}] must be a table"))?;
    let mut out = Programs::new();
    for k in section.keys() {
        if k != "reuse" && !other.contains(&k.as_str()) {
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
        let Some(id) = signing_id(table, program) else {
            let known: Vec<&str> = table.iter().map(|(n, _)| *n).collect();
            problems.push(format!(
                "[{name}] reuse: unknown program {program:?} ({})",
                known.join(", ")
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

            [age]
            reuse = { sops = "30m", ssh = "1m" }
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
        assert_eq!(s.problems.len(), 3, "{:?}", s.problems);
        // [age] applies to age keys only, by program name; [defaults] does not reach them.
        assert_eq!(
            s.get("age:age1se1x", "sops"),
            Some(Duration::from_secs(1800))
        );
        assert_eq!(s.get("age:age1se1x", "age"), None);
        assert_eq!(s.get("age:age1se1x", SSH), None);
        assert_eq!(s.get("github", "sops"), None);
        assert_eq!(s.for_age(), vec![("sops", Duration::from_secs(1800))]);
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
        assert!(s.relay(&["box".into()]).is_none());
        assert_eq!(s.upstream, None);
        assert!(parse("not toml =", BUILTIN_CAP).is_err());
    }

    #[test]
    fn relay_and_upstream() {
        let names = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let s = parse(
            r#"
            [age]
            reuse = { sops = "30m" }

            [relay.Box]
            age = true
            reuse = { ssh-keygen = "30m", age = "15m", sops = "1m", ssh = "2h" }

            [relay.migi]
            reuse = { ssh = "5m" }

            [relay.bad]
            age = "yes"
            colour = 1

            [relay."no/slash"]
            age = true

            [upstream]
            socket = "~/.ssh/agent-desk.sock"
            "#,
            BUILTIN_CAP,
        )
        .unwrap();
        // Section names match any of the relayed host's names, case-insensitively written.
        let headless = names(&["box.local", "box"]);
        let (host, r) = s.relay(&headless).unwrap();
        assert_eq!((host, r.age), ("box", true));
        assert_eq!(
            s.relay_window(&headless, "ssh-keygen"),
            Some(Duration::from_secs(1800))
        );
        assert_eq!(
            s.relay_window(&headless, "age"),
            Some(Duration::from_secs(900))
        );
        // Above the cap and unknown programs: skipped.
        assert_eq!(s.relay_window(&headless, "ssh"), None);
        assert_eq!(s.relay_window(&headless, "sops"), None);
        // Age off unless `age = true`; a wrong type is off and reported.
        assert!(!s.relay(&names(&["migi"])).unwrap().1.age);
        assert!(!s.relay(&names(&["bad"])).unwrap().1.age);
        assert!(s.relay(&names(&["no/slash"])).is_none());
        assert!(s.relay(&names(&["elsewhere"])).is_none());
        // Relay windows and local ones never mix.
        assert_eq!(
            s.get("age:age1se1x", "sops"),
            Some(Duration::from_secs(1800))
        );
        assert_eq!(s.relay_window(&headless, "sops"), None);
        assert_eq!(s.problems.len(), 5, "{:?}", s.problems);
        assert_eq!(
            s.upstream,
            Some(store::home().unwrap().join(".ssh/agent-desk.sock"))
        );
        let s = parse("[upstream]\nsocket = \"rel/path\"", BUILTIN_CAP).unwrap();
        assert_eq!((s.upstream, s.problems.len()), (None, 1));
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
