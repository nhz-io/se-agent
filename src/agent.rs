//! SSH agent protocol (draft-miller-ssh-agent) over a Unix socket.
//! Supported: REQUEST_IDENTITIES, SIGN_REQUEST (ecdsa-sha2-nistp256). Everything else,
//! including extensions such as session-bind@openssh.com, gets SSH_AGENT_FAILURE.

use crate::audit::AuditLog;
use crate::peer::Peer;
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
/// How often ended reuse windows are closed (and logged) without waiting for the next request.
const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

pub fn default_socket() -> Result<PathBuf> {
    Ok(store::home()?.join("Library/Caches/se-agent/agent.sock"))
}

struct State {
    log: AuditLog,
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

pub async fn run(socket: &Path, log: AuditLog) -> Result<()> {
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

    eprintln!(
        "se-agent: listening on {}, audit log {}",
        socket.display(),
        log.path.display()
    );
    let state = Arc::new(State {
        log,
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
                    tokio::spawn(async move { let _ = serve(stream, state).await; });
                }
                Err(e) => {
                    eprintln!("se-agent: accept: {e}");
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

async fn serve(mut stream: UnixStream, state: Arc<State>) -> Result<()> {
    let peer = Peer::from_fd(stream.as_raw_fd());
    let mut denied_logged = false;
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

        let reply = handle(&msg, &peer, &state, &mut denied_logged)
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

async fn handle(
    msg: &[u8],
    peer: &Peer,
    state: &State,
    denied_logged: &mut bool,
) -> Result<Vec<u8>> {
    let mut r = wire::Reader(msg);
    let kind = r.u8()?;
    let allowed = match kind {
        SSH_AGENTC_REQUEST_IDENTITIES => peer.may_list(),
        SSH_AGENTC_SIGN_REQUEST => peer.may_sign(),
        age::SSH_AGENTC_EXTENSION => {
            if r.string()? != age::EXTENSION.as_bytes() {
                return Ok(vec![SSH_AGENT_FAILURE]);
            }
            return age_unwrap(&mut r, peer, state, denied_logged).await;
        }
        _ => return Ok(vec![SSH_AGENT_FAILURE]),
    };
    if !allowed {
        if !*denied_logged {
            state.log.record("denied", peer, json!({ "request": kind }));
            *denied_logged = true;
        }
        return Ok(vec![SSH_AGENT_FAILURE]);
    }

    match kind {
        SSH_AGENTC_REQUEST_IDENTITIES => {
            let keys = store::list()?;
            let mut out = vec![SSH_AGENT_IDENTITIES_ANSWER];
            wire::put_u32(&mut out, keys.len() as u32);
            for k in &keys {
                wire::put_string(&mut out, &k.public_blob);
                wire::put_string(&mut out, format!("se-agent:{}", k.label).as_bytes());
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
                return Ok(vec![SSH_AGENT_FAILURE]);
            };
            let program = config::program_name(&peer.signing_id).to_string();
            let purpose = purpose::describe(&data, peer.pid, &key.label);

            let _guard = state.sign_lock.lock().await;
            let settings = settings();
            state.sweep(&settings);
            let setting = settings.get(&key.label, &peer.signing_id);
            let scope: Scope = (
                key.label.clone(),
                peer.signing_id.clone(),
                key.fingerprint(),
            );
            let info = json!({
                "key": key.label,
                "fingerprint": key.fingerprint(),
                "purpose": purpose.text,
            });
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

/// An age-unwrap request from the drop-in plugin. SSH_AGENT_FAILURE makes it run the real plugin.
async fn age_unwrap(
    r: &mut wire::Reader<'_>,
    peer: &Peer,
    state: &State,
    denied_logged: &mut bool,
) -> Result<Vec<u8>> {
    let caller = match age_caller(peer) {
        Ok(c) => c,
        Err(why) => {
            if !*denied_logged {
                state
                    .log
                    .record("denied", peer, json!({ "request": "age", "reason": why }));
                *denied_logged = true;
            }
            return Ok(vec![SSH_AGENT_FAILURE]);
        }
    };
    let (ids, stanzas) = age::decode_request(r)?;
    let identities = match ids
        .iter()
        .map(|s| age::Identity::parse(s))
        .collect::<Result<Vec<_>>>()
    {
        Ok(i) => i,
        Err(e) => {
            eprintln!("se-agent: age identity not usable here, real plugin takes over: {e:#}");
            return Ok(vec![SSH_AGENT_FAILURE]);
        }
    };
    let (mut responses, jobs) = age::plan(
        &stanzas,
        |i, kind, share| se::age_tag(&identities[i].public, kind, share),
        identities.len(),
    );
    let mut msgs = Vec::new();
    let program = caller.signing_id.clone();
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
        let purpose = purpose::describe_age(caller.pid, &recipient);

        let _guard = state.sign_lock.lock().await;
        let settings = settings();
        state.sweep(&settings);
        let label = format!("{}{recipient}", age::SCOPE_PREFIX);
        let setting = settings.get(&label, &program);
        let scope: Scope = (label, program.clone(), recipient.clone());
        let info = json!({
            "key": recipient,
            "program": program,
            "via": peer.path,
            "stanzas": mine.len(),
            "purpose": purpose.text,
        });
        let reason = purpose::dialog(&purpose.text, &program, setting);
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
        match approved(state, &caller, &scope, setting, &reason, "decrypt", info, op).await? {
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
