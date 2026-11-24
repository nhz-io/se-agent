//! SSH agent protocol (draft-miller-ssh-agent) over a Unix socket.
//! Supported: REQUEST_IDENTITIES, SIGN_REQUEST (ecdsa-sha2-nistp256), the age-unwrap extension.
//! session-bind@openssh.com is read (to tell relayed requests, see relay.rs) and answered with
//! SSH_AGENT_FAILURE like everything else.
//!
//! Two sockets: `agent.sock` and, next to it, `relay.sock` for a persistent ssh RemoteForward from
//! another Mac. With `[upstream] socket` in config.toml, keys this agent does not hold are listed
//! and signed through that socket (another Mac's agent, reached over ssh).

use crate::audit::AuditLog;
use crate::peer::Peer;
use crate::relay::{self, Conn, Relay};
use crate::reuse::{End, Scope, Stamp, Window, Windows};
use crate::{age, config, purpose, se, store, wire};
use anyhow::{Context, Result, bail};
use serde_json::json;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

const MAX_MESSAGE: usize = 256 * 1024;
const IDLE_TIMEOUT: Duration = Duration::from_secs(600);
/// An upstream agent may wait for someone at the other Mac.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(120);
/// How often ended reuse windows are closed (and logged) without waiting for the next request.
const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

pub fn default_socket() -> Result<PathBuf> {
    Ok(store::home()?.join("Library/Caches/se-agent/agent.sock"))
}

/// The socket for a persistent ssh RemoteForward from another Mac, next to `socket`.
pub fn relay_socket(socket: &Path) -> PathBuf {
    socket.with_file_name("relay.sock")
}

/// Whether `path` is an ssh login's forwarded agent: its server is Apple's sshd.
pub fn is_forwarded_agent(path: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(path)
        .map(|s| Peer::from_fd(s.as_raw_fd()).is_forwarded_agent())
        .unwrap_or(false)
}

struct State {
    log: AuditLog,
    /// agent.sock and relay.sock, never used as upstream.
    own: Vec<PathBuf>,
    /// One Touch ID / password prompt at a time.
    sign_lock: Mutex<()>,
    /// Approved contexts per (key, caller); see reuse.rs.
    windows: std::sync::Mutex<Windows<se::Context>>,
    /// Bumped by `forget`. A signature that was in flight when it changed keeps no window,
    /// since its window was out of the map while `forget` drained it.
    forgets: AtomicU64,
}

impl State {
    fn close(&self, scope: &Scope, until: time::OffsetDateTime, end: End) {
        self.log.event(
            "window_close",
            json!({
                "key": scope.0,
                "signing_id": scope.1,
                "reason": end.as_str(),
                "until": until.format(&Rfc3339).unwrap_or_default(),
            }),
        );
    }

    /// Closes every window that is over, given the current settings.
    fn sweep(&self, settings: &config::Settings) {
        let over = self
            .windows
            .lock()
            .unwrap()
            .sweep(&Stamp::now(), |s| settings.get(&s.0, &s.1));
        for (scope, w, end) in over {
            self.close(&scope, w.until, end);
        }
    }

    /// The periodic sweep: reads the settings only while a window is open.
    fn tick(&self) {
        if !self.windows.lock().unwrap().is_empty() {
            self.sweep(&settings());
        }
    }

    fn forget(&self) {
        self.forgets.fetch_add(1, Ordering::SeqCst);
        let all = self.windows.lock().unwrap().drain();
        for (scope, w) in all {
            self.close(&scope, w.until, End::Forget);
        }
    }
}

/// Reuse settings; an unreadable or unsafe file means no reuse at all.
fn settings() -> config::Settings {
    config::load(config::cap().max).unwrap_or_else(|e| {
        eprintln!("se-agent: reuse settings ignored: {e:#}");
        Default::default()
    })
}

fn listen(socket: &Path) -> Result<UnixListener> {
    if socket.as_os_str().len() >= 104 {
        bail!(
            "socket path is too long for sun_path (max 103 bytes): {}",
            socket.display()
        );
    }
    let dir = socket.parent().context("socket path has no parent")?;
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    if socket.exists() {
        if std::os::unix::net::UnixStream::connect(socket).is_ok() {
            bail!("another agent is already listening on {}", socket.display());
        }
        std::fs::remove_file(socket)?;
    }
    let old = unsafe { libc::umask(0o177) };
    let listener = UnixListener::bind(socket);
    unsafe { libc::umask(old) };
    let listener = listener.with_context(|| format!("bind {}", socket.display()))?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

pub async fn run(socket: &Path, log: AuditLog) -> Result<()> {
    let listener = listen(socket)?;
    let relay_path = relay_socket(socket);
    let relay_listener = match listen(&relay_path) {
        Ok(l) => l,
        Err(e) => {
            let _ = std::fs::remove_file(socket);
            return Err(e);
        }
    };
    eprintln!(
        "se-agent: listening on {} and {}, audit log {}",
        socket.display(),
        relay_path.display(),
        log.path.display()
    );
    let state = Arc::new(State {
        log,
        own: [socket, relay_path.as_path()]
            .iter()
            .map(|p| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf()))
            .collect(),
        sign_lock: Mutex::new(()),
        windows: Default::default(),
        forgets: AtomicU64::new(0),
    });

    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate())?;
    // `se-agent forget`
    let mut usr1 = signal(SignalKind::user_defined1())?;
    let mut sweep = tokio::time::interval(SWEEP_INTERVAL);
    let result = loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    let state = state.clone();
                    tokio::spawn(async move { let _ = serve(stream, state, false).await; });
                }
                Err(e) => {
                    eprintln!("se-agent: accept: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
            accepted = relay_listener.accept() => match accepted {
                Ok((stream, _)) => {
                    let state = state.clone();
                    tokio::spawn(async move { let _ = serve(stream, state, true).await; });
                }
                Err(e) => {
                    eprintln!("se-agent: accept (relay): {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
            _ = usr1.recv() => state.forget(),
            _ = sweep.tick() => state.tick(),
            _ = tokio::signal::ctrl_c() => break Ok(()),
            _ = term.recv() => break Ok(()),
        }
    };
    state.forget();
    let _ = std::fs::remove_file(socket);
    let _ = std::fs::remove_file(&relay_path);
    result
}

/// How a signature gets approved: a live reuse window, or a new prompt.
enum Approval {
    Reused(Window<se::Context>),
    Fresh(se::Context),
}

impl Approval {
    fn ctx(&self) -> &se::Context {
        match self {
            Approval::Reused(w) => &w.ctx,
            Approval::Fresh(c) => c,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Approval::Reused(_) => "reused",
            Approval::Fresh(_) => "prompt",
        }
    }
}

/// One client connection: what it has said so far, and its upstream connection if any.
struct Link {
    conn: Conn,
    /// session-bind messages as received, replayed to the upstream agent.
    binds_raw: Vec<Vec<u8>>,
    upstream: Option<UnixStream>,
    denied_logged: bool,
}

async fn serve(mut stream: UnixStream, state: Arc<State>, relay_socket: bool) -> Result<()> {
    let peer = Peer::from_fd(stream.as_raw_fd());
    let mut link = Link {
        conn: Conn {
            relay_socket,
            ..Default::default()
        },
        binds_raw: Vec::new(),
        upstream: None,
        denied_logged: false,
    };
    loop {
        let mut len = [0u8; 4];
        match tokio::time::timeout(IDLE_TIMEOUT, stream.read_exact(&mut len)).await {
            Ok(Ok(_)) => {}
            _ => return Ok(()), // EOF, error or idle
        }
        let len = u32::from_be_bytes(len) as usize;
        if len == 0 || len > MAX_MESSAGE {
            return Ok(());
        }
        let mut msg = vec![0u8; len];
        tokio::time::timeout(IDLE_TIMEOUT, stream.read_exact(&mut msg)).await??;

        let reply = handle(&msg, &peer, &state, &mut link)
            .await
            .unwrap_or_else(|e| {
                eprintln!("se-agent: request failed: {e:#}");
                vec![SSH_AGENT_FAILURE]
            });
        let mut out = Vec::with_capacity(reply.len() + 4);
        wire::put_u32(&mut out, reply.len() as u32);
        out.extend_from_slice(&reply);
        stream.write_all(&out).await?;
    }
}

impl Link {
    /// Logs the first refusal on this connection only.
    fn deny(&mut self, state: &State, peer: &Peer, info: serde_json::Value) {
        if !self.denied_logged {
            state.log.record("denied", peer, info);
            self.denied_logged = true;
        }
    }

    fn relay(&self, peer: &Peer) -> Option<Relay> {
        let via = self.conn.relayed(peer)?;
        let args = purpose::pid_args(peer.pid).unwrap_or_default();
        Some(relay::describe(&self.conn, via, &args, relay::known_names))
    }

    /// The upstream agent's reply to `msg`. Opens the connection on first use and replays this
    /// connection's session-binds to it first, so the upstream agent sees the destination too.
    async fn upstream_call(&mut self, socket: &Path, msg: &[u8]) -> Result<Vec<u8>> {
        if self.upstream.is_none() {
            let mut s = tokio::time::timeout(UPSTREAM_TIMEOUT, UnixStream::connect(socket))
                .await
                .context("upstream: timeout")?
                .with_context(|| format!("upstream {}", socket.display()))?;
            for b in &self.binds_raw {
                exchange(&mut s, b).await?;
            }
            self.upstream = Some(s);
        }
        let s = self.upstream.as_mut().unwrap();
        match exchange(s, msg).await {
            Ok(r) => Ok(r),
            Err(e) => {
                self.upstream = None;
                Err(e)
            }
        }
    }
}

/// One request / reply with another agent.
async fn exchange(s: &mut UnixStream, msg: &[u8]) -> Result<Vec<u8>> {
    let io = async {
        let mut out = Vec::with_capacity(msg.len() + 4);
        wire::put_u32(&mut out, msg.len() as u32);
        out.extend_from_slice(msg);
        s.write_all(&out).await?;
        let mut len = [0u8; 4];
        s.read_exact(&mut len).await?;
        let len = u32::from_be_bytes(len) as usize;
        if len == 0 || len > MAX_MESSAGE {
            bail!("upstream: bad reply length");
        }
        let mut reply = vec![0u8; len];
        s.read_exact(&mut reply).await?;
        Ok(reply)
    };
    tokio::time::timeout(UPSTREAM_TIMEOUT, io)
        .await
        .context("upstream: timeout")?
}

/// `[upstream] socket`, unless it is this agent's own socket.
fn upstream(state: &State, settings: &config::Settings) -> Option<PathBuf> {
    let u = settings.upstream.clone()?;
    let c = std::fs::canonicalize(&u).unwrap_or_else(|_| u.clone());
    (!state.own.contains(&c)).then_some(u)
}

async fn handle(msg: &[u8], peer: &Peer, state: &State, link: &mut Link) -> Result<Vec<u8>> {
    let mut r = wire::Reader(msg);
    let kind = r.u8()?;
    let allowed = match kind {
        SSH_AGENTC_REQUEST_IDENTITIES => peer.may_list(),
        SSH_AGENTC_SIGN_REQUEST => peer.may_sign(),
        age::SSH_AGENTC_EXTENSION => {
            let name = r.string()?;
            if name == relay::EXTENSION.as_bytes() {
                // Only Apple's ssh binds; anything else is ignored.
                if peer.may_sign()
                    && let Ok(b) = relay::parse_bind(&mut r)
                {
                    link.conn.add_bind(b);
                    if link.binds_raw.len() < 16 {
                        link.binds_raw.push(msg.to_vec());
                    }
                    if let Some(s) = link.upstream.as_mut() {
                        let _ = exchange(s, msg).await;
                    }
                }
                return Ok(vec![SSH_AGENT_FAILURE]);
            }
            if name != age::EXTENSION.as_bytes() {
                return Ok(vec![SSH_AGENT_FAILURE]);
            }
            return age_unwrap(&mut r, peer, state, link).await;
        }
        _ => return Ok(vec![SSH_AGENT_FAILURE]),
    };
    if !allowed {
        link.deny(state, peer, json!({ "request": kind }));
        return Ok(vec![SSH_AGENT_FAILURE]);
    }
    // On relay.sock only Apple's ssh, relaying another Mac.
    let relay = link.relay(peer);
    if link.conn.relay_socket && relay.is_none() {
        link.deny(
            state,
            peer,
            json!({ "request": kind, "reason": "relay.sock is for ssh only" }),
        );
        return Ok(vec![SSH_AGENT_FAILURE]);
    }
    // Never pass another Mac's requests further upstream (no loops between two Macs).
    let upstream = match relay {
        Some(_) => None,
        None => upstream(state, &settings()),
    };

    match kind {
        SSH_AGENTC_REQUEST_IDENTITIES => {
            let keys = store::list()?;
            let mut ids: Vec<(Vec<u8>, Vec<u8>)> = keys
                .iter()
                .map(|k| {
                    (
                        k.public_blob.clone(),
                        format!("se-agent:{}", k.label).into_bytes(),
                    )
                })
                .collect();
            if let Some(u) = upstream {
                match link.upstream_call(&u, msg).await {
                    Ok(reply) => {
                        for (blob, comment) in parse_identities(&reply).unwrap_or_default() {
                            if !ids.iter().any(|(b, _)| *b == blob) {
                                ids.push((blob, comment));
                            }
                        }
                    }
                    Err(e) => eprintln!("se-agent: upstream list: {e:#}"),
                }
            }
            let mut out = vec![SSH_AGENT_IDENTITIES_ANSWER];
            wire::put_u32(&mut out, ids.len() as u32);
            for (blob, comment) in &ids {
                wire::put_string(&mut out, blob);
                wire::put_string(&mut out, comment);
            }
            Ok(out)
        }
        _ => {
            let key_blob = r.string()?.to_vec();
            let data = r.string()?.to_vec();
            let _flags = r.u32()?; // only meaningful for RSA
            let Some(key) = store::list()?
                .into_iter()
                .find(|k| k.public_blob == key_blob)
            else {
                return match upstream {
                    Some(u) => sign_upstream(state, peer, link, &u, msg, &key_blob, &data).await,
                    None => Ok(vec![SSH_AGENT_FAILURE]),
                };
            };

            let _guard = state.sign_lock.lock().await;
            let settings = settings();
            state.sweep(&settings);
            let mut info = json!({
                "key": key.label,
                "fingerprint": key.fingerprint(),
            });
            let (purpose, scope, setting, program) = match &relay {
                Some(relay) => {
                    let (purpose, program) =
                        purpose::describe_relayed(&data, peer.pid, &key.label, relay);
                    let section = settings.relay(&relay.names).map(|(h, _)| h.to_string());
                    let host = section.unwrap_or_else(|| relay.host.clone());
                    info["relay"] = relay_info(relay);
                    (
                        purpose,
                        (
                            key.label.clone(),
                            format!("relay:{host}:{program}"),
                            key.fingerprint(),
                        ),
                        settings.relay_window(&relay.names, program),
                        format!("{} ({program})", relay.host),
                    )
                }
                None => (
                    purpose::describe(&data, peer.pid, &key.label),
                    (
                        key.label.clone(),
                        peer.signing_id.clone(),
                        key.fingerprint(),
                    ),
                    settings.get(&key.label, &peer.signing_id),
                    config::program_name(&peer.signing_id).to_string(),
                ),
            };
            info["purpose"] = json!(purpose.text);
            let reason = purpose::dialog(&purpose.text, &program, setting);
            let blob = key.blob.clone();
            let op = move |ctx: &se::Context| {
                se::sign(&blob, &data, ctx).and_then(|raw| wire::signature_blob(&raw))
            };
            match approved(state, peer, &scope, setting, &reason, "sign", info, op).await? {
                Some(sig) => {
                    let mut out = vec![SSH_AGENT_SIGN_RESPONSE];
                    wire::put_string(&mut out, &sig);
                    Ok(out)
                }
                None => Ok(vec![SSH_AGENT_FAILURE]),
            }
        }
    }
}

fn relay_info(r: &Relay) -> serde_json::Value {
    json!({
        "host": r.host,
        "names": r.names,
        "via": r.via,
        "destination": r.destination,
        "hops": r.hops,
    })
}

/// IDENTITIES_ANSWER → (key blob, comment).
fn parse_identities(reply: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut r = wire::Reader(reply);
    if r.u8()? != SSH_AGENT_IDENTITIES_ANSWER {
        bail!("not an identities answer");
    }
    let n = r.u32()? as usize;
    if n > 1024 {
        bail!("too many identities");
    }
    (0..n)
        .map(|_| Ok((r.string()?.to_vec(), r.string()?.to_vec())))
        .collect()
}

/// A signature with a key this agent does not hold, by the upstream agent (which asks for its
/// own approval). Logged here as `sign_upstream` / `sign_upstream_failed`.
async fn sign_upstream(
    state: &State,
    peer: &Peer,
    link: &mut Link,
    socket: &Path,
    msg: &[u8],
    key_blob: &[u8],
    data: &[u8],
) -> Result<Vec<u8>> {
    let fingerprint = ssh_key::PublicKey::from_bytes(key_blob)
        .map(|k| k.fingerprint(ssh_key::HashAlg::Sha256).to_string())
        .unwrap_or_default();
    let mut info = json!({
        "fingerprint": fingerprint,
        "upstream": socket,
        "purpose": purpose::describe(data, peer.pid, "upstream").text,
    });
    match link.upstream_call(socket, msg).await {
        Ok(reply) if reply.first() == Some(&SSH_AGENT_SIGN_RESPONSE) => {
            state.log.record("sign_upstream", peer, info);
            Ok(reply)
        }
        Ok(_) => {
            info["error"] = json!("refused upstream");
            state.log.record("sign_upstream_failed", peer, info);
            Ok(vec![SSH_AGENT_FAILURE])
        }
        Err(e) => {
            info["error"] = json!(format!("{e:#}"));
            state.log.record("sign_upstream_failed", peer, info);
            Ok(vec![SSH_AGENT_FAILURE])
        }
    }
}

/// Runs `op` with an approval: the live window for `scope`, or a fresh context (a prompt with
/// `reason`). A fresh approval opens a window if `setting` says so. Logs `event` (with `info`,
/// `approval` and `window_until`) or `<event>_failed`. If a reused approval fails, the window is
/// closed and it prompts once. None: failed (logged). The caller holds the sign lock and swept.
#[allow(clippy::too_many_arguments)]
async fn approved<T: Send + 'static>(
    state: &State,
    peer: &Peer,
    scope: &Scope,
    setting: Option<Duration>,
    reason: &str,
    event: &str,
    info: serde_json::Value,
    op: impl Fn(&se::Context) -> Result<T> + Send + Clone + 'static,
) -> Result<Option<T>> {
    let mut window = state.windows.lock().unwrap().take(scope);
    loop {
        let approval = match window.take() {
            Some(w) => Approval::Reused(w),
            None => Approval::Fresh(se::Context::new(reason)?),
        };
        let forgets = state.forgets.load(Ordering::SeqCst);
        let reused_until = match &approval {
            Approval::Reused(w) => Some(w.until),
            Approval::Fresh(_) => None,
        };
        let op = op.clone();
        let joined = tokio::task::spawn_blocking(move || {
            let r = op(approval.ctx());
            (r, approval)
        })
        .await;
        let (result, approval) = match joined {
            Ok(x) => x,
            Err(e) => {
                // The context went down with the task: record that the window ended.
                if let Some(until) = reused_until {
                    state.close(scope, until, End::Failed);
                }
                return Err(e.into());
            }
        };
        let mut info = info.clone();
        info["approval"] = json!(approval.kind());
        match result {
            Ok(value) => {
                let kept = match approval {
                    Approval::Reused(w) => Some(w),
                    Approval::Fresh(ctx) => setting.map(|d| Window::new(ctx, Stamp::now(), d)),
                };
                // `forget` ran meanwhile: end the window now instead of keeping it.
                let kept = match kept {
                    Some(w) if state.forgets.load(Ordering::SeqCst) != forgets => {
                        state.close(scope, w.until, End::Forget);
                        None
                    }
                    k => k,
                };
                if let Some(w) = &kept {
                    info["window_until"] = json!(w.until.format(&Rfc3339).unwrap_or_default());
                }
                state.log.record(event, peer, info);
                if let Some(w) = kept {
                    state.windows.lock().unwrap().insert(scope.clone(), w);
                }
                return Ok(Some(value));
            }
            Err(e) => {
                info["error"] = json!(format!("{e:#}"));
                state.log.record(&format!("{event}_failed"), peer, info);
                if let Approval::Reused(w) = approval {
                    state.close(scope, w.until, End::Failed);
                    continue;
                }
                return Ok(None);
            }
        }
    }
}

/// The program that ran the drop-in age-plugin-se, if it may decrypt through the agent: the peer
/// must be this very se-agent binary (checked from the audit token, like SSH callers), and its
/// parent one of age::CALLERS. sops and age are ad-hoc signed (Signing ID `a.out`), so the parent
/// is named by its executable path, read twice around the peer's parent PID: if the parent had
/// exited in between, the peer would have been re-parented and the PID would differ.
fn age_caller(peer: &Peer) -> std::result::Result<Peer, String> {
    static SELF: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    let me = SELF.get_or_init(|| std::env::current_exe().and_then(std::fs::canonicalize).ok());
    if let Some(e) = &peer.error {
        return Err(e.clone());
    }
    let peer_path = std::fs::canonicalize(&peer.path).ok();
    if !peer.valid || me.is_none() || peer_path != *me {
        return Err("not se-agent's age-plugin-se".into());
    }
    let parent = purpose::ppid(peer.pid).ok_or("no parent process")?;
    let path = purpose::pid_path(parent).ok_or("parent has no path")?;
    if purpose::ppid(peer.pid) != Some(parent) {
        return Err("parent exited".into());
    }
    let name = path.rsplit('/').next().unwrap_or("");
    if !age::CALLERS.contains(&name) {
        return Err(format!(
            "parent {path} is not one of {}",
            age::CALLERS.join(", ")
        ));
    }
    Ok(Peer {
        pid: parent,
        path: path.clone(),
        signing_id: name.to_string(),
        apple_platform: false,
        valid: true,
        error: None,
    })
}

/// Who an age-unwrap is for: a local sops / age, or another Mac relaying over ssh.
struct AgeCaller {
    /// Logged as the caller; for a relay, this Mac's ssh.
    peer: Peer,
    /// Window scope (program part): `sops`, or `relay:<host>:age`.
    scope: String,
    /// In the dialog: `sops`, or `box (age)`.
    program: String,
    relay: Option<Relay>,
}

/// An age-unwrap request from the drop-in plugin. SSH_AGENT_FAILURE makes it try the next agent
/// or run the real plugin.
async fn age_unwrap(
    r: &mut wire::Reader<'_>,
    peer: &Peer,
    state: &State,
    link: &mut Link,
) -> Result<Vec<u8>> {
    let caller = match link.relay(peer) {
        Some(relay) => {
            let settings = settings();
            match settings.relay(&relay.names) {
                Some((host, r)) if r.age => AgeCaller {
                    peer: peer.clone(),
                    scope: format!("relay:{host}:age"),
                    program: format!("{} (age)", relay.host),
                    relay: Some(relay),
                },
                found => {
                    let host = found.map_or(relay.host.as_str(), |(h, _)| h);
                    let why = format!(
                        "age decryption over ssh from {} is off; to allow it: [relay.{host}] age = true",
                        relay.host
                    );
                    link.deny(
                        state,
                        peer,
                        json!({ "request": "age", "reason": why, "relay": relay_info(&relay) }),
                    );
                    return Ok(vec![SSH_AGENT_FAILURE]);
                }
            }
        }
        None if link.conn.relay_socket => {
            link.deny(
                state,
                peer,
                json!({ "request": "age", "reason": "relay.sock is for ssh only" }),
            );
            return Ok(vec![SSH_AGENT_FAILURE]);
        }
        None => match age_caller(peer) {
            Ok(c) => AgeCaller {
                scope: c.signing_id.clone(),
                program: c.signing_id.clone(),
                peer: c,
                relay: None,
            },
            Err(why) => {
                link.deny(state, peer, json!({ "request": "age", "reason": why }));
                return Ok(vec![SSH_AGENT_FAILURE]);
            }
        },
    };
    let req = age::decode_request(r)?;
    let identities = match req
        .identities
        .iter()
        .map(|s| age::Identity::parse(s))
        .collect::<Result<Vec<_>>>()
    {
        Ok(i) => i,
        Err(e) => {
            eprintln!(
                "se-agent: age identity not usable here, next agent or real plugin takes over: {e:#}"
            );
            return Ok(vec![SSH_AGENT_FAILURE]);
        }
    };
    let (mut responses, jobs) = age::plan(
        &req.stanzas,
        |i, kind, share| se::age_tag(&identities[i].public, kind, share),
        identities.len(),
    );
    let mut msgs = Vec::new();
    for (idx, identity) in identities.iter().enumerate() {
        let mine: Vec<(String, se::AgeKind, Vec<u8>, Vec<u8>)> = jobs
            .iter()
            .filter(|j| j.identity == idx && !responses.contains_key(&j.file))
            .map(|j| (j.file.clone(), j.kind, j.share.clone(), j.body.clone()))
            .collect();
        if mine.is_empty() {
            continue;
        }
        let recipient = identity.recipient();
        let purpose = match &caller.relay {
            Some(relay) => {
                purpose::describe_age_relayed(peer.pid, &recipient, relay, req.command.as_deref())
            }
            None => purpose::describe_age(caller.peer.pid, &recipient),
        };

        let _guard = state.sign_lock.lock().await;
        let settings = settings();
        state.sweep(&settings);
        let label = format!("{}{recipient}", age::SCOPE_PREFIX);
        let setting = match &caller.relay {
            Some(relay) => settings.relay_window(&relay.names, "age"),
            None => settings.get(&label, &caller.scope),
        };
        let scope: Scope = (label, caller.scope.clone(), recipient.clone());
        let mut info = json!({
            "key": recipient,
            "program": caller.program,
            "via": peer.path,
            "stanzas": mine.len(),
            "purpose": purpose.text,
        });
        if let Some(relay) = &caller.relay {
            info["relay"] = relay_info(relay);
        }
        let reason = purpose::dialog(&purpose.text, &caller.program, setting);
        let blob = identity.blob.clone();
        // Succeeds if any stanza unwraps; the others become messages, as in age-plugin-se.
        let op = move |ctx: &se::Context| {
            let results: Vec<(String, Result<Vec<u8>>)> = mine
                .iter()
                .map(|(file, kind, share, body)| {
                    (file.clone(), se::age_unwrap(&blob, *kind, share, body, ctx))
                })
                .collect();
            if results.iter().any(|(_, r)| r.is_ok()) {
                Ok(results)
            } else {
                let (_, first) = results.into_iter().next().unwrap();
                Err(first.unwrap_err())
            }
        };
        match approved(state, &caller.peer, &scope, setting, &reason, "decrypt", info, op).await? {
            Some(results) => {
                for (file, res) in results {
                    match res {
                        Ok(key) => {
                            responses
                                .entry(file.clone())
                                .or_insert_with(|| age::Stanza::new("file-key", &[&file], &key));
                        }
                        Err(e) => msgs.push(age::Stanza::new("msg", &[], format!("{e:#}").as_bytes())),
                    }
                }
            }
            None => msgs.push(age::Stanza::new(
                "msg",
                &[],
                b"se-agent: decryption was not approved or failed (see ~/Library/Logs/se-agent.log)",
            )),
        }
    }
    msgs.extend(responses.into_values());
    Ok(age::encode_response(&msgs))
}
