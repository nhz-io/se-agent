//! The drop-in age-plugin-se against the real one (Homebrew `age-plugin-se` and `age`), with a
//! throwaway Secure Enclave key made by the real plugin with `--access-control none` (no prompts):
//! files encrypted by the real tools (piv-p256 stanzas from age-plugin-se for age1se1, p256tag from
//! age for age1tag1, plus an X25519 recipient) decrypt through a test agent, one approval then
//! reused; with the agent stopped the fallback to the real plugin decrypts them; a caller that is
//! not sops / age is refused by the agent and still served by the real plugin.
//! Skipped (passes with a note) where the tools or a Secure Enclave are missing.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const REAL: &str = "/opt/homebrew/bin/age-plugin-se";
const AGE: &str = "/opt/homebrew/bin/age";
const AGE_KEYGEN: &str = "/opt/homebrew/bin/age-keygen";

struct Dir(PathBuf);
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Agent(Child);
impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn run(cmd: &mut Command) -> String {
    let out = cmd.output().expect("run");
    assert!(
        out.status.success(),
        "{cmd:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn path_env(bin: &Path) -> String {
    format!("{}:/opt/homebrew/bin:/usr/bin:/bin", bin.display())
}

fn decrypt(home: &Path, bin: &Path, id: &Path, file: &Path) -> Vec<u8> {
    let out = Command::new(AGE)
        .env("HOME", home)
        .env("PATH", path_env(bin))
        .args(["-d", "-i"])
        .arg(id)
        .arg(file)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "decrypt {}: {}",
        file.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

fn start_agent(exe: &Path, home: &Path, socket: &Path, log: &Path) -> Agent {
    let child = Command::new(exe)
        .env("HOME", home)
        .args(["run", "--socket"])
        .arg(socket)
        .arg("--log")
        .arg(log)
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let t = Instant::now();
    while std::os::unix::net::UnixStream::connect(socket).is_err() {
        assert!(t.elapsed() < Duration::from_secs(10), "agent did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
    Agent(child)
}

fn log_events(log: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// The age header's recipient stanzas: (type + args, body).
fn header_stanzas(file: &Path) -> Vec<(Vec<String>, String)> {
    let text = std::fs::read(file).unwrap();
    let mut out = Vec::new();
    let mut lines = text
        .split(|&b| b == b'\n')
        .map(|l| String::from_utf8_lossy(l).into_owned());
    assert_eq!(lines.next().unwrap(), "age-encryption.org/v1");
    let mut current: Option<(Vec<String>, String)> = None;
    for l in lines {
        if l.starts_with("---") {
            break;
        }
        if let Some(h) = l.strip_prefix("-> ") {
            current = Some((h.split(' ').map(String::from).collect(), String::new()));
        } else if let Some((args, mut body)) = current.take() {
            body.push_str(&l);
            if l.len() < 64 {
                out.push((args, body));
            } else {
                current = Some((args, body));
            }
        }
    }
    out
}

#[test]
fn drop_in_plugin_against_real_plugin() {
    for tool in [REAL, AGE, AGE_KEYGEN] {
        if !Path::new(tool).exists() {
            eprintln!("skipped: {tool} not installed");
            return;
        }
    }
    let exe = PathBuf::from(env!("CARGO_BIN_EXE_se-agent"));
    // Short: the socket path must fit in sun_path.
    let dir = Dir(PathBuf::from(format!("/tmp/sea-{}", std::process::id())));
    let home = dir.0.clone();
    let bin = home.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::os::unix::fs::symlink(&exe, bin.join("age-plugin-se")).unwrap();

    let id = home.join("se-identity.txt");
    let keygen = Command::new(REAL)
        .args(["keygen", "--access-control", "none", "-o"])
        .arg(&id)
        .output()
        .unwrap();
    if !keygen.status.success() {
        eprintln!(
            "skipped: no Secure Enclave key: {}",
            String::from_utf8_lossy(&keygen.stderr)
        );
        return;
    }
    let recipient = |t: &str| {
        run(Command::new(REAL)
            .args(["recipients", "--recipient-type", t, "-i"])
            .arg(&id))
        .trim()
        .to_string()
    };
    let (se_r, tag_r) = (recipient("se"), recipient("tag"));
    assert!(se_r.starts_with("age1se1") && tag_r.starts_with("age1tag1"));
    let x25519 = home.join("x25519.txt");
    run(Command::new(AGE_KEYGEN).arg("-o").arg(&x25519));
    let x_r = run(Command::new(AGE_KEYGEN).arg("-y").arg(&x25519))
        .trim()
        .to_string();

    // Files from the real tools: age1se1 goes through the drop-in to the real plugin
    // (recipient-v1 is passed straight on), age1tag1 is native in age 1.3.
    let mut files = Vec::new();
    for (i, r) in [&se_r, &tag_r, &se_r].into_iter().enumerate() {
        let plain = format!("secret {i} {}\n", "x".repeat(i * 100)).into_bytes();
        let f = home.join(format!("f{i}.age"));
        let mut c = Command::new(AGE)
            .env("HOME", &home)
            .env("PATH", path_env(&bin))
            .args(["-e", "-r", r, "-r", &x_r, "-o"])
            .arg(&f)
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        c.stdin.take().unwrap().write_all(&plain).unwrap();
        assert!(c.wait().unwrap().success());
        files.push((f, plain));
    }
    let kinds: Vec<String> = files
        .iter()
        .map(|(f, _)| header_stanzas(f)[0].0[0].clone())
        .collect();
    assert_eq!(kinds, ["piv-p256", "p256tag", "piv-p256"]);

    // Agent with a window for `age`.
    let cfg = home.join(".config/se-agent");
    std::fs::create_dir_all(&cfg).unwrap();
    std::fs::write(cfg.join("config.toml"), "[age]\nreuse = { age = \"5m\" }\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        cfg.join("config.toml"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let socket = home.join("Library/Caches/se-agent/agent.sock");
    let log = home.join("agent.log");
    let agent = start_agent(&exe, &home, &socket, &log);

    for (f, plain) in &files {
        assert_eq!(&decrypt(&home, &bin, &id, f), plain);
    }
    let decrypts: Vec<serde_json::Value> = log_events(&log)
        .into_iter()
        .filter(|e| e["event"] == "decrypt")
        .collect();
    let approvals: Vec<&str> = decrypts
        .iter()
        .map(|e| e["approval"].as_str().unwrap())
        .collect();
    assert_eq!(approvals, ["prompt", "reused", "reused"], "{decrypts:#?}");
    for e in &decrypts {
        assert_eq!(e["key"], se_r.as_str());
        assert_eq!(e["program"], "age");
        assert!(e["caller"].as_str().unwrap().ends_with("/age"));
        assert!(e["window_until"].is_string());
    }

    // A caller that is not sops / age (this test, running the drop-in itself): the agent refuses,
    // the drop-in replays the request to the real plugin, which unwraps it.
    let (args, body) = header_stanzas(&files[0].0).remove(0);
    let identity = std::fs::read_to_string(&id)
        .unwrap()
        .lines()
        .find(|l| l.starts_with("AGE-PLUGIN-SE-"))
        .unwrap()
        .to_string();
    let mut plugin = Command::new(bin.join("age-plugin-se"))
        .env("HOME", &home)
        .arg("--age-plugin=identity-v1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut to = plugin.stdin.take().unwrap();
    write!(
        to,
        "-> add-identity {identity}\n\n-> recipient-stanza 0 {}\n{body}\n-> done\n\n",
        args.join(" ")
    )
    .unwrap();
    to.flush().unwrap();
    let mut from = BufReader::new(plugin.stdout.take().unwrap());
    let mut header = String::new();
    from.read_line(&mut header).unwrap();
    assert!(header.starts_with("-> file-key 0"), "{header}");
    let mut key = String::new();
    from.read_line(&mut key).unwrap();
    assert_eq!(key.trim_end().len(), 22, "16-byte file key"); // base64, no padding
    writeln!(to, "-> ok\n").unwrap();
    let mut done = String::new();
    from.read_line(&mut done).unwrap();
    assert_eq!(done, "-> done\n");
    drop(to);
    assert!(plugin.wait().unwrap().success());
    let denied = log_events(&log)
        .into_iter()
        .filter(|e| e["event"] == "denied")
        .count();
    assert_eq!(denied, 1);

    // Agent stopped: the drop-in execs the real plugin.
    drop(agent);
    let _ = std::fs::remove_file(&socket);
    for (f, plain) in &files {
        assert_eq!(&decrypt(&home, &bin, &id, f), plain);
    }
    assert_eq!(
        log_events(&log)
            .iter()
            .filter(|e| e["event"] == "decrypt")
            .count(),
        3
    );
}
