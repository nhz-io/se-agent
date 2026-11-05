//! SSH agent protocol (draft-miller-ssh-agent) over a Unix socket.
//! Supported: REQUEST_IDENTITIES, SIGN_REQUEST (ecdsa-sha2-nistp256). Everything else,
//! including extensions such as session-bind@openssh.com, gets SSH_AGENT_FAILURE.

use crate::audit::AuditLog;
use crate::peer::Peer;
use crate::reuse::{End, Scope, Stamp, Window, Windows};
use crate::{config, purpose, se, store, wire};
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

            // A live window first; if a reused approval fails, close it and prompt once.
            let mut window = state.windows.lock().unwrap().take(&scope);
            loop {
                let approval = match window.take() {
                    Some(w) => Approval::Reused(w),
                    None => {
                        // macOS prefixes "se-agent is trying to".
                        let mut reason = format!("{}.", purpose.text);
                        if let Some(d) = setting {
                            reason += &format!(
                                " Approving lets {program} use this key for {} without asking.",
                                config::fmt(d)
                            );
                        }
                        Approval::Fresh(se::Context::new(&reason)?)
                    }
                };
                let forgets = state.forgets.load(Ordering::SeqCst);
                let reused_until = match &approval {
                    Approval::Reused(w) => Some(w.until),
                    Approval::Fresh(_) => None,
                };
                let blob = key.blob.clone();
                let data = data.clone();
                let joined = tokio::task::spawn_blocking(move || {
                    let r = se::sign(&blob, &data, approval.ctx());
                    (r, approval)
                })
                .await;
                let (result, approval) = match joined {
                    Ok(x) => x,
                    Err(e) => {
                        // The context went down with the task: record that the window ended.
                        if let Some(until) = reused_until {
                            state.close(&scope, until, End::Failed);
                        }
                        return Err(e.into());
                    }
                };
                let mut info = info.clone();
                info["approval"] = json!(approval.kind());
                match result.and_then(|raw| wire::signature_blob(&raw)) {
                    Ok(sig) => {
                        let kept = match approval {
                            Approval::Reused(w) => Some(w),
                            Approval::Fresh(ctx) => {
                                setting.map(|d| Window::new(ctx, Stamp::now(), d))
                            }
                        };
                        // `forget` ran meanwhile: end the window now instead of keeping it.
                        let kept = match kept {
                            Some(w) if state.forgets.load(Ordering::SeqCst) != forgets => {
                                state.close(&scope, w.until, End::Forget);
                                None
                            }
                            k => k,
                        };
                        if let Some(w) = &kept {
                            info["window_until"] =
                                json!(w.until.format(&Rfc3339).unwrap_or_default());
                        }
                        state.log.record("sign", peer, info);
                        if let Some(w) = kept {
                            state.windows.lock().unwrap().insert(scope, w);
                        }
                        let mut out = vec![SSH_AGENT_SIGN_RESPONSE];
                        wire::put_string(&mut out, &sig);
                        return Ok(out);
                    }
                    Err(e) => {
                        info["error"] = json!(format!("{e:#}"));
                        state.log.record("sign_failed", peer, info);
                        if let Approval::Reused(w) = approval {
                            state.close(&scope, w.until, End::Failed);
                            continue;
                        }
                        return Ok(vec![SSH_AGENT_FAILURE]);
                    }
                }
            }
        }
    }
}
