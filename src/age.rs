//! age decryption with age-plugin-se identities, through the agent.
//!
//! `age-plugin-se` (github.com/remko/age-plugin-se) authenticates once per process, so every file
//! `sops -d` opens asks for Touch ID / password. se-agent links itself in as a drop-in
//! `age-plugin-se` ahead of Homebrew's on PATH (`se-agent age-plugin install`). Run under that name
//! it speaks the age plugin protocol (identity-v1) on stdin/stdout and forwards the recipient
//! stanzas to the agent, which does the ECDH in the Secure Enclave with an LAContext it keeps, so
//! one approval covers further decryptions for a window, per key and calling program (`[age]` in
//! config.toml). Same key, same identity file, same recipients: nothing is re-encrypted.
//!
//! Everything else goes to the real plugin, unchanged: other state machines (recipient-v1 for
//! encryption), `keygen` / `recipients`, an agent that is not running or refuses the caller, and
//! identities it cannot load (e.g. post-quantum ones).

use crate::{se, wire};
use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD as B64;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The name the drop-in runs under.
pub const PLUGIN_NAME: &str = "age-plugin-se";
/// Where Homebrew puts the real one; the first that is not se-agent itself is used.
pub const REAL_PLUGINS: [&str; 2] = [
    "/opt/homebrew/bin/age-plugin-se",
    "/usr/local/bin/age-plugin-se",
];
/// SSH agent extension name (SSH_AGENTC_EXTENSION) for an unwrap request.
pub const EXTENSION: &str = "age-unwrap@se-agent.nhz.io";
/// Programs that may decrypt through the agent (executable name of the plugin's parent).
pub const CALLERS: [&str; 2] = ["sops", "age"];
/// Window scopes for age keys start with this (not a valid SSH key label).
pub const SCOPE_PREFIX: &str = "age:";

const IDENTITY_HRP: &str = "age-plugin-se-";

// --- bech32 (BIP 173, without the 90-character limit, as age uses it) ---------------------------

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn polymod(values: impl Iterator<Item = u8>) -> u32 {
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk = 1u32;
    for v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v as u32;
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let b = hrp.as_bytes();
    b.iter()
        .map(|c| c >> 5)
        .chain([0])
        .chain(b.iter().map(|c| c & 31))
        .collect()
}

fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Result<Vec<u8>> {
    let (mut acc, mut bits, mut out) = (0u32, 0u32, Vec::new());
    let maxv = (1u32 << to) - 1;
    for &v in data {
        if (v as u32) >> from != 0 {
            bail!("bech32: invalid data");
        }
        acc = (acc << from) | v as u32;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        bail!("bech32: invalid padding");
    }
    Ok(out)
}

/// Returns (lower-case HRP, data).
pub fn bech32_decode(s: &str) -> Result<(String, Vec<u8>)> {
    if s.chars().any(|c| c.is_ascii_lowercase()) && s.chars().any(|c| c.is_ascii_uppercase()) {
        bail!("bech32: mixed case");
    }
    let s = s.to_ascii_lowercase();
    let pos = s.rfind('1').context("bech32: no separator")?;
    let (hrp, rest) = (&s[..pos], &s[pos + 1..]);
    if hrp.is_empty() || rest.len() < 6 || !hrp.bytes().all(|b| (33..=126).contains(&b)) {
        bail!("bech32: malformed");
    }
    let values = rest
        .bytes()
        .map(|c| CHARSET.iter().position(|&x| x == c).map(|p| p as u8))
        .collect::<Option<Vec<u8>>>()
        .context("bech32: invalid character")?;
    if polymod(hrp_expand(hrp).into_iter().chain(values.iter().copied())) != 1 {
        bail!("bech32: bad checksum");
    }
    let data = convert_bits(&values[..values.len() - 6], 5, 8, false)?;
    Ok((hrp.to_string(), data))
}

pub fn bech32_encode(hrp: &str, data: &[u8]) -> String {
    let values = convert_bits(data, 8, 5, true).expect("8-bit input");
    let pm = polymod(
        hrp_expand(hrp)
            .into_iter()
            .chain(values.iter().copied())
            .chain([0; 6]),
    ) ^ 1;
    let mut s = format!("{hrp}1");
    for v in values
        .iter()
        .copied()
        .chain((0..6).map(|i| ((pm >> (5 * (5 - i))) & 31) as u8))
    {
        s.push(CHARSET[v as usize] as char);
    }
    s
}

// --- stanzas (age plugin protocol framing) -----------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stanza {
    pub kind: String,
    pub args: Vec<String>,
    pub body: Vec<u8>,
}

impl Stanza {
    pub fn new(kind: &str, args: &[&str], body: &[u8]) -> Stanza {
        Stanza {
            kind: kind.into(),
            args: args.iter().map(|s| s.to_string()).collect(),
            body: body.to_vec(),
        }
    }

    /// Reads one stanza; every byte read is appended to `raw` (for replaying to the real plugin).
    /// None at a clean end of input.
    pub fn read(r: &mut impl BufRead, raw: &mut Vec<u8>) -> Result<Option<Stanza>> {
        let Some(header) = read_line(r, raw)? else {
            return Ok(None);
        };
        let mut parts = header.split(' ');
        if parts.next() != Some("->") {
            bail!("invalid stanza header");
        }
        let kind = parts
            .next()
            .filter(|k| !k.is_empty())
            .context("invalid stanza header")?;
        let args = parts.map(String::from).collect();
        let mut body = Vec::new();
        loop {
            let line = read_line(r, raw)?.context("incomplete stanza")?;
            if line.len() > 64 {
                bail!("invalid stanza body line");
            }
            body.extend(B64.decode(&line).context("invalid stanza body")?);
            if line.len() < 64 {
                break;
            }
        }
        Ok(Some(Stanza {
            kind: kind.into(),
            args,
            body,
        }))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = format!("-> {}", self.kind);
        for a in &self.args {
            out.push(' ');
            out.push_str(a);
        }
        out.push('\n');
        let b = B64.encode(&self.body);
        let mut rest = b.as_str();
        // Full 64-column lines, then a shorter (possibly empty) last one.
        while rest.len() >= 64 {
            out.push_str(&rest[..64]);
            out.push('\n');
            rest = &rest[64..];
        }
        out.push_str(rest);
        out.push('\n');
        out.into_bytes()
    }
}

fn read_line(r: &mut impl BufRead, raw: &mut Vec<u8>) -> Result<Option<String>> {
    let mut line = Vec::new();
    if r.read_until(b'\n', &mut line)? == 0 {
        return Ok(None);
    }
    raw.extend_from_slice(&line);
    if line.pop() != Some(b'\n') {
        bail!("incomplete line");
    }
    Ok(Some(String::from_utf8(line).context("non-UTF-8 line")?))
}

// --- identities and the unwrap plan ------------------------------------------------------------

pub struct Identity {
    /// SecureEnclave.P256.KeyAgreement `dataRepresentation` (only this Mac's Secure Enclave can use it).
    pub blob: Vec<u8>,
    /// Compressed public key.
    pub public: Vec<u8>,
}

impl Identity {
    /// `AGE-PLUGIN-SE-1…` → the key. Fails for anything else, including post-quantum identities
    /// (those go to the real plugin).
    pub fn parse(s: &str) -> Result<Identity> {
        let (hrp, blob) = bech32_decode(s.trim())?;
        if hrp != IDENTITY_HRP {
            bail!("not an age-plugin-se identity");
        }
        let public = se::age_public(&blob)?;
        if public.len() != 33 {
            bail!("unexpected public key length {}", public.len());
        }
        Ok(Identity { blob, public })
    }

    /// `age1se1…`, the spelling in .sops.yaml; names the key in windows and the log.
    pub fn recipient(&self) -> String {
        bech32_encode("age1se", &self.public)
    }
}

/// One stanza an identity's tag matched: needs the Secure Enclave.
#[derive(Debug, PartialEq, Eq)]
pub struct Job {
    pub file: String,
    pub identity: usize,
    pub kind: se::AgeKind,
    pub share: Vec<u8>,
    pub body: Vec<u8>,
}

/// What to do with a request, before any prompt: per-file errors for malformed stanzas, and the
/// stanzas meant for one of the identities. Mirrors age-plugin-se's runIdentityV1: the same
/// structural checks and messages; other stanza types (X25519 for the backup key, …) are ignored.
pub fn plan(
    stanzas: &[Stanza],
    tag: impl Fn(usize, se::AgeKind, &[u8]) -> Result<Vec<u8>>,
    identities: usize,
) -> (BTreeMap<String, Stanza>, Vec<Job>) {
    let mut responses: BTreeMap<String, Stanza> = BTreeMap::new();
    let mut checked = Vec::new();
    for s in stanzas {
        if s.kind != "recipient-stanza" || s.args.len() < 2 {
            continue;
        }
        let file = s.args[0].clone();
        let kind = match s.args[1].as_str() {
            "piv-p256" => Some(se::AgeKind::Piv),
            "p256tag" => Some(se::AgeKind::Tag),
            "mlkem768p256tag" => None,
            _ => continue,
        };
        let error = |m: &str| Stanza::new("error", &["stanza", &file], m.as_bytes());
        if s.args.len() != 4 {
            responses.insert(file.clone(), error("incorrect argument count"));
            continue;
        }
        let tag = B64.decode(&s.args[2]).ok().filter(|t| t.len() == 4);
        let Some(tag) = tag else {
            responses.insert(file.clone(), error("invalid tag"));
            continue;
        };
        let want = match s.args[1].as_str() {
            "piv-p256" => 33,
            "p256tag" => 65,
            _ => 1153,
        };
        let share = B64.decode(&s.args[3]).ok().filter(|v| v.len() == want);
        let Some(share) = share else {
            responses.insert(file.clone(), error("invalid share"));
            continue;
        };
        if s.body.len() != 32 {
            responses.insert(file.clone(), error("invalid body"));
            continue;
        }
        // Post-quantum stanzas need an ML-KEM key, which these identities don't have.
        if let Some(kind) = kind {
            checked.push((file, kind, tag, share, s.body.clone()));
        }
    }
    let mut jobs = Vec::new();
    for (file, kind, want, share, body) in checked {
        if responses.contains_key(&file) {
            continue;
        }
        for identity in 0..identities {
            if tag(identity, kind, &share).is_ok_and(|t| t == want) {
                jobs.push(Job {
                    file: file.clone(),
                    identity,
                    kind,
                    share: share.clone(),
                    body: body.clone(),
                });
            }
        }
    }
    (responses, jobs)
}

// --- agent request / response (SSH agent framing) ---------------------------------------------

pub const SSH_AGENTC_EXTENSION: u8 = 27;
pub const SSH_AGENT_SUCCESS: u8 = 6;

fn put_stanza(out: &mut Vec<u8>, s: &Stanza) {
    wire::put_string(out, s.kind.as_bytes());
    wire::put_u32(out, s.args.len() as u32);
    for a in &s.args {
        wire::put_string(out, a.as_bytes());
    }
    wire::put_string(out, &s.body);
}

fn get_stanza(r: &mut wire::Reader) -> Result<Stanza> {
    let text = |b: &[u8]| String::from_utf8(b.to_vec()).context("non-UTF-8 stanza");
    let kind = text(r.string()?)?;
    let n = r.u32()? as usize;
    if n > 64 {
        bail!("too many stanza arguments");
    }
    let args = (0..n)
        .map(|_| text(r.string()?))
        .collect::<Result<Vec<_>>>()?;
    let body = r.string()?.to_vec();
    Ok(Stanza { kind, args, body })
}

fn get_stanzas(r: &mut wire::Reader) -> Result<Vec<Stanza>> {
    let n = r.u32()? as usize;
    if n > 4096 {
        bail!("too many stanzas");
    }
    (0..n).map(|_| get_stanza(r)).collect()
}

/// `command` (optional, after the stanzas): the plugin's caller, e.g. `sops decrypt x.yaml`. The
/// agent shows it only for relayed requests (it reads local callers itself); older agents ignore it.
pub fn encode_request(identities: &[String], stanzas: &[Stanza], command: &str) -> Vec<u8> {
    let mut out = vec![SSH_AGENTC_EXTENSION];
    wire::put_string(&mut out, EXTENSION.as_bytes());
    wire::put_u32(&mut out, identities.len() as u32);
    for i in identities {
        wire::put_string(&mut out, i.as_bytes());
    }
    wire::put_u32(&mut out, stanzas.len() as u32);
    for s in stanzas {
        put_stanza(&mut out, s);
    }
    wire::put_string(&mut out, command.as_bytes());
    out
}

pub struct Request {
    pub identities: Vec<String>,
    pub stanzas: Vec<Stanza>,
    pub command: Option<String>,
}

/// The request after the extension name.
pub fn decode_request(r: &mut wire::Reader) -> Result<Request> {
    let n = r.u32()? as usize;
    if n > 64 {
        bail!("too many identities");
    }
    let ids = (0..n)
        .map(|_| Ok(String::from_utf8(r.string()?.to_vec())?))
        .collect::<Result<Vec<_>>>()?;
    let stanzas = get_stanzas(r)?;
    let command = match r.0.is_empty() {
        true => None,
        false => Some(String::from_utf8_lossy(r.string()?).into_owned()),
    };
    Ok(Request {
        identities: ids,
        stanzas,
        command,
    })
}

pub fn encode_response(stanzas: &[Stanza]) -> Vec<u8> {
    let mut out = vec![SSH_AGENT_SUCCESS];
    wire::put_u32(&mut out, stanzas.len() as u32);
    for s in stanzas {
        put_stanza(&mut out, s);
    }
    out
}

/// None: the agent declined (old agent, refused caller, unusable identity) → use the real plugin.
fn decode_response(msg: &[u8]) -> Result<Option<Vec<Stanza>>> {
    let mut r = wire::Reader(msg);
    if r.u8()? != SSH_AGENT_SUCCESS {
        return Ok(None);
    }
    Ok(Some(get_stanzas(&mut r)?))
}

// --- the drop-in plugin -------------------------------------------------------------------------

fn canonical(p: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(p).ok()
}

/// The real age-plugin-se: the first of REAL_PLUGINS that exists and is not this binary.
pub fn real_plugin() -> Option<PathBuf> {
    let me = std::env::current_exe().ok().and_then(|p| canonical(&p));
    REAL_PLUGINS
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file() && canonical(p).is_some() && canonical(p) != me)
}

fn exec_real(args: &[String]) -> ! {
    let Some(real) = real_plugin() else {
        eprintln!(
            "se-agent ({PLUGIN_NAME}): the agent is not available and the real {PLUGIN_NAME} was not found in {}",
            REAL_PLUGINS.join(", ")
        );
        std::process::exit(1);
    };
    let err = Command::new(&real).arg0(&real).args(args).exec();
    eprintln!("se-agent ({PLUGIN_NAME}): exec {}: {err}", real.display());
    std::process::exit(1);
}

/// The real plugin, after phase 1 was already read: replay it, then pass the rest through.
fn replay_real(args: &[String], raw: &[u8], mut stdin: BufReader<std::io::Stdin>) -> ! {
    let Some(real) = real_plugin() else {
        eprintln!("se-agent ({PLUGIN_NAME}): the real {PLUGIN_NAME} was not found");
        std::process::exit(1);
    };
    let child = Command::new(&real)
        .arg0(&real)
        .args(args)
        .stdin(Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            eprintln!("se-agent ({PLUGIN_NAME}): run {}: {e}", real.display());
            std::process::exit(1);
        }
    };
    let mut to = child.stdin.take().unwrap();
    let raw = raw.to_vec();
    std::thread::spawn(move || {
        if to.write_all(&raw).is_ok() {
            let _ = std::io::copy(&mut stdin, &mut to);
        }
    });
    let code = child.wait().map(|s| s.code().unwrap_or(1)).unwrap_or(1);
    std::process::exit(code);
}

fn state_machine(args: &[String]) -> Option<&str> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if let Some(v) = a.strip_prefix("--age-plugin=") {
            return Some(v);
        }
        if a == "--age-plugin" {
            return it.next().map(String::as_str);
        }
    }
    None
}

fn agent_request(msg: &[u8], stream: &mut std::os::unix::net::UnixStream) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(msg.len() + 4);
    wire::put_u32(&mut out, msg.len() as u32);
    out.extend_from_slice(msg);
    stream.write_all(&out)?;
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > 1 << 20 {
        bail!("bad reply length");
    }
    let mut reply = vec![0u8; len];
    stream.read_exact(&mut reply)?;
    Ok(reply)
}

/// The agents the drop-in asks, in order: this Mac's agent, then an upstream one (another Mac's
/// agent reached over ssh): `$SE_AGENT_UPSTREAM`, else `[upstream] socket` in config.toml, else
/// `$SSH_AUTH_SOCK` if `forwarded` says it is an ssh login's forwarded agent. Duplicates dropped.
pub fn plugin_sockets(
    local: PathBuf,
    env_upstream: Option<PathBuf>,
    config_upstream: Option<PathBuf>,
    ssh_auth_sock: Option<PathBuf>,
    forwarded: impl Fn(&Path) -> bool,
) -> Vec<PathBuf> {
    let upstream = env_upstream
        .filter(|p| !p.as_os_str().is_empty())
        .or(config_upstream)
        .or_else(|| ssh_auth_sock.filter(|p| forwarded(p)));
    let mut out = vec![local];
    if let Some(u) = upstream
        && !out
            .iter()
            .any(|p| canonical(p).is_some() && canonical(p) == canonical(&u))
        && !out.contains(&u)
    {
        out.push(u);
    }
    out
}

/// The command line of the plugin's caller (sops / age), for the agent's dialog.
fn caller_command() -> String {
    let ppid = unsafe { libc::getppid() };
    crate::purpose::pid_args(ppid)
        .map(|a| {
            let mut words = a;
            if let Some(first) = words.first_mut() {
                *first = first.rsplit('/').next().unwrap_or(first).to_string();
            }
            words.join(" ")
        })
        .unwrap_or_default()
}

/// One identity's answer from one agent: None if it declined (or is not there).
fn ask(socket: &Path, identity: &str, stanzas: &[Stanza], command: &str) -> Option<Vec<Stanza>> {
    let mut stream = std::os::unix::net::UnixStream::connect(socket).ok()?;
    let msg = encode_request(&[identity.to_string()], stanzas, command);
    agent_request(&msg, &mut stream)
        .and_then(|r| decode_response(&r))
        .ok()
        .flatten()
}

/// Entry point when run as `age-plugin-se`. Each identity goes to the first agent in `sockets`
/// that takes it (this Mac's agent declines identities of another Mac's Secure Enclave, so those
/// reach the upstream one). If an identity no agent takes leaves a file undecrypted, the whole
/// request goes to the real plugin, as before.
pub fn plugin_main(sockets: &[PathBuf]) -> ! {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if state_machine(&args) != Some("identity-v1") {
        exec_real(&args);
    }
    // An agent first: if none is there, the real plugin gets an untouched stdin.
    if !sockets
        .iter()
        .any(|s| std::os::unix::net::UnixStream::connect(s).is_ok())
    {
        exec_real(&args);
    }

    let mut stdin = BufReader::new(std::io::stdin());
    let mut raw = Vec::new();
    let mut identities = Vec::new();
    let mut stanzas = Vec::new();
    loop {
        match Stanza::read(&mut stdin, &mut raw) {
            Ok(Some(s)) if s.kind == "done" => break,
            Ok(Some(s)) if s.kind == "add-identity" && !s.args.is_empty() => {
                identities.push(s.args[0].clone())
            }
            Ok(Some(s)) if s.kind == "recipient-stanza" => stanzas.push(s),
            Ok(Some(_)) => {}
            // Let the real plugin produce its own error for broken input.
            Ok(None) | Err(_) => replay_real(&args, &raw, stdin),
        }
    }

    let command = caller_command();
    // Per file: its file-key or error. Messages go out as they are.
    let mut done: BTreeMap<String, Stanza> = BTreeMap::new();
    let mut msgs = Vec::new();
    let mut declined = false;
    for id in &identities {
        let open: Vec<Stanza> = stanzas
            .iter()
            .filter(|s| s.args.first().is_some_and(|f| !done.contains_key(f)))
            .cloned()
            .collect();
        if open.is_empty() {
            break;
        }
        let Some(reply) = sockets.iter().find_map(|s| ask(s, id, &open, &command)) else {
            declined = true;
            continue;
        };
        for r in reply {
            let file = match r.kind.as_str() {
                "file-key" => r.args.first().cloned(),
                "error" if r.args.first().map(String::as_str) == Some("stanza") => {
                    r.args.get(1).cloned()
                }
                _ => None,
            };
            match file {
                Some(f) => {
                    done.entry(f).or_insert(r);
                }
                None => msgs.push(r),
            }
        }
    }
    let files: std::collections::BTreeSet<&String> =
        stanzas.iter().filter_map(|s| s.args.first()).collect();
    if declined && files.iter().any(|f| !done.contains_key(*f)) {
        replay_real(&args, &raw, stdin);
    }
    let responses: Vec<Stanza> = msgs.into_iter().chain(done.into_values()).collect();

    let mut stdout = std::io::stdout().lock();
    let mut ignored = Vec::new();
    for s in &responses {
        if stdout
            .write_all(&s.encode())
            .and_then(|_| stdout.flush())
            .is_err()
        {
            std::process::exit(1);
        }
        // age answers each command with ok / fail.
        match Stanza::read(&mut stdin, &mut ignored) {
            Ok(Some(_)) => {}
            _ => std::process::exit(1),
        }
    }
    let _ = stdout.write_all(&Stanza::new("done", &[], &[]).encode());
    let _ = stdout.flush();
    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bech32_roundtrip() {
        // BIP 173 test vector, and an age X25519 recipient (age-keygen output).
        assert!(bech32_decode("A12UEL5L").is_ok());
        assert!(bech32_decode("a12uel5l").is_ok());
        assert!(bech32_decode("A12uEL5L").is_err());
        let r = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
        let (hrp, data) = bech32_decode(r).unwrap();
        assert_eq!(hrp, "age");
        assert_eq!(data.len(), 32);
        assert_eq!(bech32_encode(&hrp, &data), r);
        let mut bad = r.to_string();
        bad.replace_range(10..11, "q");
        assert!(bech32_decode(&bad).is_err());
        // Long data (identity blobs are ~430 bytes): no length limit.
        let long: Vec<u8> = (0..=255).chain(0..=200).collect();
        let s = bech32_encode("age-plugin-se-", &long);
        assert_eq!(
            bech32_decode(&s.to_uppercase()).unwrap(),
            ("age-plugin-se-".into(), long)
        );
    }

    #[test]
    fn stanza_framing() {
        for len in [0, 1, 32, 47, 48, 49, 96, 200] {
            let s = Stanza::new("file-key", &["0"], &vec![7u8; len]);
            let enc = s.encode();
            let mut raw = Vec::new();
            let back = Stanza::read(&mut &enc[..], &mut raw).unwrap().unwrap();
            assert_eq!(back, s);
            assert_eq!(raw, enc);
            // The last body line is always shorter than 64 columns.
            let text = String::from_utf8(enc).unwrap();
            assert!(text.lines().last().unwrap().len() < 64, "{len}");
        }
        assert_eq!(Stanza::new("done", &[], &[]).encode(), b"-> done\n\n");
        assert!(Stanza::read(&mut &b"-> x\n"[..], &mut Vec::new()).is_err());
        assert!(Stanza::read(&mut &b"x y\n\n"[..], &mut Vec::new()).is_err());
        assert!(Stanza::read(&mut &b"-> x\nAA==\n"[..], &mut Vec::new()).is_err());
        assert_eq!(Stanza::read(&mut &b""[..], &mut Vec::new()).unwrap(), None);
    }

    #[test]
    fn wire_roundtrip() {
        let st = vec![
            Stanza::new(
                "recipient-stanza",
                &["0", "piv-p256", "abcd", "ef"],
                &[1, 2, 3],
            ),
            Stanza::new("recipient-stanza", &["1", "X25519", "zz"], &[]),
        ];
        let ids = vec!["AGE-PLUGIN-SE-1X".to_string()];
        let req = encode_request(&ids, &st, "sops decrypt x.yaml");
        let mut r = wire::Reader(&req);
        assert_eq!(r.u8().unwrap(), SSH_AGENTC_EXTENSION);
        assert_eq!(r.string().unwrap(), EXTENSION.as_bytes());
        let d = decode_request(&mut r).unwrap();
        assert_eq!((&d.identities, &d.stanzas), (&ids, &st));
        assert_eq!(d.command.as_deref(), Some("sops decrypt x.yaml"));
        // v0.3.0's request had no command.
        let mut old = vec![SSH_AGENTC_EXTENSION];
        wire::put_string(&mut old, EXTENSION.as_bytes());
        wire::put_u32(&mut old, 0);
        wire::put_u32(&mut old, 0);
        let mut r = wire::Reader(&old[1..]);
        r.string().unwrap();
        assert_eq!(decode_request(&mut r).unwrap().command, None);
        assert_eq!(decode_response(&encode_response(&st)).unwrap(), Some(st));
        assert_eq!(decode_response(&[5]).unwrap(), None);
    }

    #[test]
    fn plans() {
        let b = |n: usize| B64.encode(vec![9u8; n]);
        let st = |file: &str, kind: &str, tag: &str, share: &str, body: usize| {
            Stanza::new(
                "recipient-stanza",
                &[file, kind, tag, share],
                &vec![0u8; body],
            )
        };
        let ours = B64.encode([1, 2, 3, 4]);
        let other = B64.encode([4, 3, 2, 1]);
        let stanzas = vec![
            Stanza::new("recipient-stanza", &["0", "X25519", "abc"], &[0; 32]),
            st("0", "piv-p256", &ours, &b(33), 32),
            st("1", "p256tag", &ours, &b(65), 32),
            st("2", "piv-p256", &other, &b(33), 32),
            st("3", "piv-p256", &ours, &b(65), 32),
            st("4", "p256tag", "AAA", &b(65), 32),
            st("5", "piv-p256", &ours, &b(33), 31),
            Stanza::new("recipient-stanza", &["6", "piv-p256", &ours], &[0; 32]),
            st("7", "mlkem768p256tag", &ours, &b(1153), 32),
        ];
        // Identity 0 answers to tag 01020304, identity 1 to nothing.
        let (errors, jobs) = plan(
            &stanzas,
            |i, _, _| Ok(if i == 0 { vec![1, 2, 3, 4] } else { vec![0; 4] }),
            2,
        );
        let msgs: Vec<(&str, String)> = errors
            .iter()
            .map(|(f, s)| (f.as_str(), String::from_utf8(s.body.clone()).unwrap()))
            .collect();
        assert_eq!(
            msgs,
            vec![
                ("3", "invalid share".into()),
                ("4", "invalid tag".into()),
                ("5", "invalid body".into()),
                ("6", "incorrect argument count".into()),
            ]
        );
        assert_eq!(errors["3"].args, vec!["stanza", "3"]);
        let got: Vec<(&str, usize, se::AgeKind)> = jobs
            .iter()
            .map(|j| (j.file.as_str(), j.identity, j.kind))
            .collect();
        assert_eq!(
            got,
            vec![("0", 0, se::AgeKind::Piv), ("1", 0, se::AgeKind::Tag)]
        );
    }

    #[test]
    fn sockets() {
        let p = |s: &str| PathBuf::from(s);
        let local = p("/l/agent.sock");
        let fwd = |x: &Path| x.starts_with("/fwd");
        // Nothing upstream: only this Mac's agent.
        assert_eq!(
            plugin_sockets(local.clone(), None, None, None, fwd),
            std::slice::from_ref(&local)
        );
        // $SSH_AUTH_SOCK only if it is a forwarded agent (not, say, this Mac's own).
        assert_eq!(
            plugin_sockets(local.clone(), None, None, Some(p("/fwd/s")), fwd),
            [local.clone(), p("/fwd/s")]
        );
        assert_eq!(
            plugin_sockets(local.clone(), None, None, Some(p("/other/s")), fwd),
            std::slice::from_ref(&local)
        );
        // config.toml beats $SSH_AUTH_SOCK, the environment beats both; empty env is unset.
        assert_eq!(
            plugin_sockets(local.clone(), None, Some(p("/cfg")), Some(p("/fwd/s")), fwd),
            [local.clone(), p("/cfg")]
        );
        assert_eq!(
            plugin_sockets(
                local.clone(),
                Some(p("/env")),
                Some(p("/cfg")),
                Some(p("/fwd/s")),
                fwd
            ),
            [local.clone(), p("/env")]
        );
        assert_eq!(
            plugin_sockets(local.clone(), Some(p("")), Some(p("/cfg")), None, fwd),
            [local.clone(), p("/cfg")]
        );
        // The local socket named as upstream is not asked twice.
        assert_eq!(
            plugin_sockets(local.clone(), Some(local.clone()), None, None, fwd),
            [local]
        );
    }

    #[test]
    fn state_machines() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            state_machine(&a(&["--age-plugin=identity-v1"])),
            Some("identity-v1")
        );
        assert_eq!(
            state_machine(&a(&["--age-plugin", "recipient-v1"])),
            Some("recipient-v1")
        );
        assert_eq!(state_machine(&a(&["keygen"])), None);
    }
}
