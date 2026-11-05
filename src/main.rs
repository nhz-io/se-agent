mod agent;
mod audit;
mod config;
mod launchd;
mod peer;
mod purpose;
mod reuse;
mod se;
mod store;
mod wire;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// SSH agent with keys in the Secure Enclave. Every signature needs Touch ID,
/// or the Mac login password when Touch ID is unavailable (e.g. lid closed).
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a key in the Secure Enclave and print its OpenSSH public key.
    Create {
        label: String,
        /// Skip the sign-and-verify check (which asks for Touch ID / password once).
        #[arg(long)]
        no_self_test: bool,
    },
    /// Print the OpenSSH public keys (all, or one label).
    List { label: Option<String> },
    /// Delete a key. It cannot be recovered; remove it from GitHub as well.
    Delete { label: String },
    /// Run the agent in the foreground.
    Run {
        #[arg(long)]
        socket: Option<PathBuf>,
        #[arg(long)]
        log: Option<PathBuf>,
    },
    /// Install and start the LaunchAgent (io.nhz.se-agent) for the installed binary.
    Install {
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Stop and remove the LaunchAgent.
    Uninstall,
    /// Print the default socket path (for IdentityAgent / SSH_AUTH_SOCK).
    Socket,
    /// Show the approval reuse windows from ~/.config/se-agent/config.toml (off unless set) and
    /// the cap. After one approval, further signatures with that key from the same program don't
    /// prompt until the window ends: timeout (from the approval, not extended by use), sleep or
    /// `se-agent forget`.
    Reuse,
    /// End all reuse windows now: the next signature prompts again.
    Forget,
}

fn self_test(key: &store::Key) -> Result<()> {
    use signature::Verifier;
    let msg = b"se-agent: creation self-test";
    eprintln!("Self-test: authenticate once (Touch ID or password)...");
    let ctx = se::Context::new(&format!("confirm new SSH key \"{}\"", key.label))?;
    let raw = se::sign(&key.blob, msg, &ctx)?;
    let blob = wire::signature_blob(&raw)?;
    let mut r = wire::Reader(&blob);
    r.string()?;
    let sig = ssh_key::Signature::new(
        ssh_key::Algorithm::Ecdsa {
            curve: ssh_key::EcdsaCurve::NistP256,
        },
        r.string()?.to_vec(),
    )?;
    key.public()
        .key_data()
        .verify(msg, &sig)
        .context("self-test signature does not verify")?;
    eprintln!("Self-test passed.");
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Create {
            label,
            no_self_test,
        } => {
            let key = store::create(&label)?;
            if !no_self_test && let Err(e) = self_test(&key) {
                store::delete(&label)?;
                bail!("{e:#}\nkey {label:?} removed again");
            }
            println!("{}", key.openssh());
            eprintln!(
                "{}  saved to {}",
                key.fingerprint(),
                store::keys_dir()?.join(format!("{label}.pub")).display()
            );
        }
        Cmd::List { label } => {
            let keys = match label {
                Some(l) => vec![store::load(&l)?],
                None => store::list()?,
            };
            for k in keys {
                println!("{}", k.openssh());
            }
        }
        Cmd::Delete { label } => {
            store::delete(&label)?;
            eprintln!("deleted {label}");
        }
        Cmd::Run { socket, log } => {
            let socket = socket.map_or_else(agent::default_socket, Ok)?;
            let log = audit::AuditLog::open(&log.map_or_else(audit::default_path, Ok)?)?;
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(agent::run(&socket, log))?;
        }
        Cmd::Install { socket } => {
            launchd::install(&socket.map_or_else(agent::default_socket, Ok)?)?
        }
        Cmd::Uninstall => launchd::uninstall()?,
        Cmd::Socket => println!("{}", agent::default_socket()?.display()),
        Cmd::Reuse => {
            let cap = config::cap();
            println!("cap\t{} ({})", config::fmt(cap.max), cap.source);
            println!("config\t{}", config::config_path()?.display());
            let settings = config::load(cap.max)?;
            let keys = store::list()?;
            for k in &keys {
                let w = settings.for_key(&k.label);
                let w = if w.is_empty() {
                    "off".to_string()
                } else {
                    w.iter()
                        .map(|(p, d)| format!("{p} {}", config::fmt(*d)))
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                println!("{}\t{w}", k.label);
            }
            for l in settings.configured_keys() {
                if !keys.iter().any(|k| &k.label == l) {
                    println!("warning\t[keys.{l}]: no such key");
                }
            }
            for p in &settings.problems {
                println!("warning\t{p}");
            }
            let old = store::home()?.join(".se-agent/config.json");
            if old.exists() {
                println!(
                    "warning\t{} is from v0.2.0/0.2.1 and no longer read; move its settings to config.toml and delete it",
                    old.display()
                );
            }
        }
        Cmd::Forget => launchd::forget()?,
    }
    Ok(())
}
