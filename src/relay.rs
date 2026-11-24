//! Requests that another Mac relays to this agent over SSH (delegation).
//!
//! A headless Mac (say box) can use this Mac's keys through SSH unix-socket forwarding:
//!
//! - `ForwardAgent <agent.sock>` in `Host box`: for each agent channel box opens, this Mac's
//!   `ssh` connects to the agent and first sends `session-bind@openssh.com` with box's host key
//!   and `is_forwarding` set, then relays box's bytes.
//! - A persistent `RemoteForward <path on box> <relay.sock>` (e.g. held by a LaunchAgent): this
//!   Mac's `ssh` connects to `relay.sock` and relays, with no bind of its own. Everything on
//!   `relay.sock` counts as relayed.
//!
//! Either way the peer is Apple's `ssh` on this Mac, and the request itself comes from the other
//! Mac. Such requests are labelled with the host (from `known_hosts` for the bound host key, or
//! ssh's command line), get their own reuse windows (`[relay.<host>]` in config.toml, never the
//! local `ssh` ones), and age decryption is refused unless `[relay.<host>] age = true`.
//!
//! The host comes from this Mac's view (its ssh process and known_hosts). Binds after the first
//! (the destination box's ssh logs in to) come from the other Mac: a hint, like the purpose.

use crate::peer::Peer;
use crate::{purpose, store, wire};
use anyhow::Result;
use std::path::Path;

pub const EXTENSION: &str = "session-bind@openssh.com";
/// Binds kept per connection (a chain of forwarded agents adds one per hop).
const MAX_BINDS: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bind {
    pub hostkey: Vec<u8>,
    pub session_id: Vec<u8>,
    pub forwarding: bool,
}

/// The body of a session-bind request, after the extension name:
/// string hostkey, string session_id, string signature, bool is_forwarding.
pub fn parse_bind(r: &mut wire::Reader) -> Result<Bind> {
    let hostkey = r.string()?.to_vec();
    let session_id = r.string()?.to_vec();
    r.string()?;
    let forwarding = r.u8()? != 0;
    Ok(Bind {
        hostkey,
        session_id,
        forwarding,
    })
}

/// What one agent connection has seen so far.
#[derive(Default)]
pub struct Conn {
    /// Accepted on relay.sock.
    pub relay_socket: bool,
    pub binds: Vec<Bind>,
}

impl Conn {
    pub fn add_bind(&mut self, b: Bind) {
        if self.binds.len() < MAX_BINDS {
            self.binds.push(b);
        }
    }

    /// Whether this connection is relayed from another Mac, by Apple's ssh: on relay.sock, or
    /// opened by ssh with a forwarding bind first. (A bind the other Mac sends can only make a
    /// connection count as relayed, never as local: ssh's own bind is always first.)
    pub fn relayed(&self, peer: &Peer) -> Option<Via> {
        if !peer.may_relay() {
            return None;
        }
        if self.relay_socket {
            Some(Via::RelaySocket)
        } else if self.binds.first().is_some_and(|b| b.forwarding) {
            Some(Via::ForwardAgent)
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Via {
    ForwardAgent,
    RelaySocket,
}

impl Via {
    pub fn as_str(self) -> &'static str {
        match self {
            Via::ForwardAgent => "forward-agent",
            Via::RelaySocket => "relay-socket",
        }
    }
}

/// The Mac a relayed request comes from, and where it goes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Relay {
    /// Shown in the dialog and log: ssh's destination, else the first known_hosts name.
    pub host: String,
    /// Every name the host is known by here; `[relay.<name>]` matches any of them.
    pub names: Vec<String>,
    /// The host the other Mac is logging in to (from its bind, matched in known_hosts).
    pub destination: Option<String>,
    /// Forwarding binds: 1 for a direct ForwardAgent, more through a chain of hosts.
    pub hops: usize,
    pub via: &'static str,
}

/// Names a relayed connection. `ssh_args` is the relaying ssh's argv (a ControlMaster rewrites
/// it to `ssh: <path> [mux]`, so it can be useless), `known` looks a host key up in known_hosts.
pub fn describe(
    conn: &Conn,
    via: Via,
    ssh_args: &[String],
    known: impl Fn(&[u8]) -> Vec<String>,
) -> Relay {
    let mut names: Vec<String> = Vec::new();
    fn push(names: &mut Vec<String>, n: String) {
        let n = n.to_ascii_lowercase();
        if !n.is_empty() && !names.contains(&n) {
            names.push(n);
        }
    }
    let dest = (!ssh_args.first().is_some_and(|a| a.starts_with("ssh: ")))
        .then(|| purpose::ssh_destination(ssh_args).0)
        .flatten()
        .map(|d| d.rsplit('@').next().unwrap_or(&d).to_string());
    if let Some(d) = &dest {
        push(&mut names, d.clone());
    }
    let first = conn.binds.first().filter(|b| b.forwarding);
    if let Some(b) = first {
        for n in known(&b.hostkey) {
            push(&mut names, n);
        }
    }
    // mDNS names: `[relay.box]` matches box.local.
    for n in names.clone() {
        if let Some(short) = n.strip_suffix(".local") {
            push(&mut names, short.to_string());
        }
    }
    let host = names
        .first()
        .cloned()
        .unwrap_or_else(|| "an unknown host".into());
    let destination = conn.binds.iter().rev().find(|b| !b.forwarding).map(|b| {
        known(&b.hostkey)
            .into_iter()
            .next()
            .unwrap_or_else(|| "an unknown host".into())
    });
    Relay {
        host,
        names,
        destination,
        hops: conn.binds.iter().filter(|b| b.forwarding).count(),
        via: via.as_str(),
    }
}

// --- known_hosts ------------------------------------------------------------------------------

/// Host names for a host key blob in ~/.ssh/known_hosts{,2} and /etc/ssh/ssh_known_hosts.
/// Hashed entries and patterns are skipped.
pub fn known_names(hostkey: &[u8]) -> Vec<String> {
    let mut files = vec![std::path::PathBuf::from("/etc/ssh/ssh_known_hosts")];
    if let Ok(home) = store::home() {
        files.insert(0, home.join(".ssh/known_hosts2"));
        files.insert(0, home.join(".ssh/known_hosts"));
    }
    let mut out = Vec::new();
    for f in files {
        for n in names_in(&f, hostkey) {
            if !out.contains(&n) {
                out.push(n);
            }
        }
    }
    out
}

fn names_in(file: &Path, hostkey: &[u8]) -> Vec<String> {
    std::fs::read_to_string(file)
        .map(|t| parse_known_hosts(&t, hostkey))
        .unwrap_or_default()
}

fn parse_known_hosts(text: &str, hostkey: &[u8]) -> Vec<String> {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('@') {
            continue;
        }
        let mut f = line.split_whitespace();
        let (Some(hosts), Some(_kind), Some(key)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        if hosts.starts_with('|') || b64.decode(key).ok().as_deref() != Some(hostkey) {
            continue;
        }
        for h in hosts.split(',') {
            if h.starts_with('!') || h.contains(['*', '?']) {
                continue;
            }
            // [host]:port
            let h = h
                .strip_prefix('[')
                .and_then(|r| r.split_once("]:"))
                .map_or(h, |(name, _)| name);
            if !out.iter().any(|o| o == h) {
                out.push(h.to_string());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(id: &str) -> Peer {
        Peer {
            pid: 1,
            path: "/usr/bin/ssh".into(),
            signing_id: id.into(),
            apple_platform: true,
            valid: true,
            error: None,
        }
    }

    fn bind(key: u8, fwd: bool) -> Bind {
        Bind {
            hostkey: vec![key],
            session_id: vec![9],
            forwarding: fwd,
        }
    }

    #[test]
    fn bind_wire() {
        let mut m = Vec::new();
        for s in [&b"KEY"[..], b"SID", b"SIG"] {
            wire::put_string(&mut m, s);
        }
        m.push(1);
        let b = parse_bind(&mut wire::Reader(&m)).unwrap();
        assert_eq!(
            (b.hostkey, b.session_id, b.forwarding),
            (b"KEY".to_vec(), b"SID".to_vec(), true)
        );
        assert!(parse_bind(&mut wire::Reader(&m[..m.len() - 1])).is_err());
    }

    #[test]
    fn relayed_rules() {
        let ssh = peer("com.apple.ssh");
        let mut c = Conn::default();
        // Local ssh: no bind, or its own login bind.
        assert_eq!(c.relayed(&ssh), None);
        c.add_bind(bind(1, false));
        assert_eq!(c.relayed(&ssh), None);
        // A forwarding bind that is not first (sent from the far side later) changes nothing.
        c.add_bind(bind(2, true));
        assert_eq!(c.relayed(&ssh), None);
        // ssh's own forwarding bind comes first.
        let mut f = Conn::default();
        f.add_bind(bind(1, true));
        f.add_bind(bind(2, false));
        assert_eq!(f.relayed(&ssh), Some(Via::ForwardAgent));
        // Only Apple's ssh relays: not ssh-keygen, not an impostor, not se-agent.
        assert_eq!(f.relayed(&peer("com.apple.ssh-keygen")), None);
        let mut fake = peer("com.apple.ssh");
        fake.apple_platform = false;
        assert_eq!(f.relayed(&fake), None);
        let r = Conn {
            relay_socket: true,
            ..Default::default()
        };
        assert_eq!(r.relayed(&ssh), Some(Via::RelaySocket));
        assert_eq!(r.relayed(&peer("se-agent")), None);
        for _ in 0..40 {
            f.add_bind(bind(3, true));
        }
        assert_eq!(f.binds.len(), MAX_BINDS);
    }

    #[test]
    fn names() {
        let known = |k: &[u8]| match k {
            [1] => vec!["box.local".to_string(), "10.0.0.5".into()],
            [2] => vec!["github.com".to_string()],
            _ => vec![],
        };
        let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let mut c = Conn::default();
        c.add_bind(bind(1, true));
        c.add_bind(bind(2, false));
        let r = describe(
            &c,
            Via::ForwardAgent,
            &args(&["ssh", "-A", "dev@box"]),
            known,
        );
        assert_eq!(r.host, "box");
        assert_eq!(r.names, ["box", "box.local", "10.0.0.5"]);
        assert_eq!(r.destination.as_deref(), Some("github.com"));
        assert_eq!(r.hops, 1);
        // A ControlMaster's rewritten argv: names from known_hosts only.
        let r = describe(
            &c,
            Via::ForwardAgent,
            &args(&["ssh: /Users/x/.ssh/cm-box-abc [mux]"]),
            known,
        );
        assert_eq!(r.host, "box.local");
        assert_eq!(r.names, ["box.local", "10.0.0.5", "box"]);
        // relay.sock: no bind of ssh's own; the far side's login bind is the destination.
        let mut s = Conn {
            relay_socket: true,
            ..Default::default()
        };
        s.add_bind(bind(7, false));
        let r = describe(
            &s,
            Via::RelaySocket,
            &args(&["ssh", "-N", "-R", "/x:/y", "box"]),
            known,
        );
        assert_eq!((r.host.as_str(), r.hops), ("box", 0));
        assert_eq!(r.destination.as_deref(), Some("an unknown host"));
        let r = describe(&Conn::default(), Via::RelaySocket, &[], known);
        assert_eq!((r.host.as_str(), r.destination), ("an unknown host", None));
    }

    #[test]
    fn known_hosts_file() {
        use base64::Engine as _;
        let k = base64::engine::general_purpose::STANDARD.encode(b"hostkey");
        let text = format!(
            "# comment\n\
             github.com,140.82.1.1 ssh-ed25519 {k}\n\
             [box.local]:2222 ssh-ed25519 {k} comment\n\
             |1|salt|hash ssh-ed25519 {k}\n\
             *.example ssh-ed25519 {k}\n\
             @revoked bad ssh-ed25519 {k}\n\
             other ssh-ed25519 AAAA\n"
        );
        assert_eq!(
            parse_known_hosts(&text, b"hostkey"),
            ["github.com", "140.82.1.1", "box.local"]
        );
        assert!(parse_known_hosts(&text, b"nope").is_empty());
    }
}
