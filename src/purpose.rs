//! What a signature is for, in words, for the approval dialog and the audit log.
//!
//! From the data being signed (an SSHSIG namespace such as `git`, or an SSH login) and from the
//! caller's process ancestry (the `git` command and repository, the ssh destination, the app it
//! runs in). All of it is a **hint**: a process running as you can fake its arguments or working
//! directory. The security boundary stays the caller check and the prompt itself.

use crate::wire;
use std::ffi::CStr;
use std::path::Path;

/// Longest piece of untrusted text put into the dialog.
const MAX_PART: usize = 60;
/// How far up the process tree to look.
const MAX_DEPTH: usize = 16;

pub struct Purpose {
    /// e.g. `sign for "git commit" in se-agent from WezTerm with key "github"`
    pub text: String,
}

/// Describes a signature request. `pid` is the caller (ssh / ssh-keygen).
pub fn describe(data: &[u8], pid: i32, key: &str) -> Purpose {
    let chain = ancestry(pid);
    let caller = chain.first();
    let git = chain.iter().find(|p| p.name() == "git");
    let app = chain.iter().find_map(|p| app_name(&p.path));
    let from = app
        .map(|a| format!(" from {}", clean(&a)))
        .unwrap_or_default();
    let key = clean(key);

    let text = if let Some(ns) = sshsig_namespace(data) {
        if ns == "git" {
            let what = git
                .and_then(|g| git_subcommand(&g.args))
                .map_or("sign git data".to_string(), |sub| {
                    format!("sign for \"git {}\"", clean(&sub))
                });
            let repo = git
                .and_then(|g| g.cwd.as_deref())
                .and_then(repo_name)
                .map(|r| format!(" in {}", clean(&r)))
                .unwrap_or_default();
            format!("{what}{repo}{from} with key \"{key}\"")
        } else {
            format!("sign \"{}\" data{from} with key \"{key}\"", clean(&ns))
        }
    } else if let Some(user) = userauth_user(data) {
        let (dest, remote) = caller
            .map(|c| ssh_destination(&c.args))
            .unwrap_or((None, None));
        let host = dest
            .map(|d| clean(d.rsplit('@').next().unwrap_or(&d)))
            .unwrap_or_default();
        match remote.as_deref().and_then(git_remote) {
            Some((op, repo)) => format!(
                "log in to {host} for git {op} of {}{from} with key \"{key}\"",
                clean(&repo)
            ),
            None if !host.is_empty() => format!(
                "log in to {host} as {}{from} with key \"{key}\"",
                clean(&user)
            ),
            None => format!("log in as {}{from} with key \"{key}\"", clean(&user)),
        }
    } else {
        let name = caller.map(|c| c.name()).unwrap_or("?");
        format!("use key \"{key}\" for {}{from}", clean(name))
    };
    Purpose { text }
}

/// Characters that reorder, hide or break text: bidi marks, embeddings, overrides, isolates,
/// line and paragraph separators, zero-width characters and the BOM.
fn invisible(c: char) -> bool {
    matches!(c,
        '\u{061C}' | '\u{200B}'..='\u{200F}' | '\u{2028}'..='\u{202E}'
        | '\u{2060}'..='\u{2069}' | '\u{FEFF}')
}

/// Untrusted text for the dialog: no control or invisible characters, bounded length.
fn clean(s: &str) -> String {
    let s: String = s
        .chars()
        .filter(|c| !invisible(*c))
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let s = s.trim();
    if s.chars().count() > MAX_PART {
        format!("{}…", s.chars().take(MAX_PART - 1).collect::<String>())
    } else {
        s.to_string()
    }
}

// --- signed data ------------------------------------------------------------------------------

/// PROTOCOL.sshsig: "SSHSIG" || string namespace || string reserved || string hash || string H(m).
fn sshsig_namespace(data: &[u8]) -> Option<String> {
    let rest = data.strip_prefix(b"SSHSIG")?;
    let mut r = wire::Reader(rest);
    let ns = r.string().ok()?;
    String::from_utf8(ns.to_vec()).ok()
}

/// RFC 4252 publickey: string session_id || byte 50 || string user || string service ||
/// string method || ... Apple's ssh uses OpenSSH's `publickey-hostbound-v00@openssh.com` method.
fn userauth_user(data: &[u8]) -> Option<String> {
    let mut r = wire::Reader(data);
    r.string().ok()?;
    if r.u8().ok()? != 50 {
        return None;
    }
    let user = r.string().ok()?;
    r.string().ok()?;
    let method = r.string().ok()?;
    (method == b"publickey" || method == b"publickey-hostbound-v00@openssh.com").then_some(())?;
    String::from_utf8(user.to_vec()).ok()
}

// --- command lines ----------------------------------------------------------------------------

/// `git -c x=y -C dir commit -S ...` → `commit`.
fn git_subcommand(args: &[String]) -> Option<String> {
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "-c" | "-C" | "--git-dir" | "--work-tree" | "--namespace" | "--exec-path" => {
                it.next();
            }
            a if a.starts_with('-') => {}
            a => return Some(a.to_string()),
        }
    }
    None
}

/// ssh's argv → (destination, remote command). Options that take a value per ssh(1).
fn ssh_destination(args: &[String]) -> (Option<String>, Option<String>) {
    const WITH_VALUE: &str = "BbcDEeFIiJLlmOoPpQRSWw";
    let mut i = 1;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            i += 1;
            break;
        }
        if let Some(opts) = a.strip_prefix('-').filter(|o| !o.is_empty()) {
            // `-p22` carries its value; `-p 22` takes the next argument.
            if let Some(pos) = opts.find(|c| WITH_VALUE.contains(c))
                && pos == opts.len() - 1
            {
                i += 1;
            }
            i += 1;
            continue;
        }
        break;
    }
    let dest = args.get(i).cloned();
    let rest = (i + 1 < args.len()).then(|| args[i + 1..].join(" "));
    (dest, rest)
}

/// `git-receive-pack 'owner/repo.git'` → ("push", "owner/repo.git").
fn git_remote(cmd: &str) -> Option<(&'static str, String)> {
    let (op, rest) = [
        ("push", "git-receive-pack"),
        ("fetch", "git-upload-pack"),
        ("archive", "git-upload-archive"),
    ]
    .into_iter()
    .find_map(|(op, prog)| Some((op, cmd.strip_prefix(prog)?)))?;
    let repo = rest.trim().trim_matches(|c| c == '\'' || c == '"');
    Some((op, repo.trim_start_matches('/').to_string()))
}

/// The repository folder name: nearest directory at or above `cwd` that has `.git`.
fn repo_name(cwd: &str) -> Option<String> {
    let mut dir = Some(Path::new(cwd));
    while let Some(d) = dir {
        if d.join(".git").exists() {
            return d.file_name().map(|n| n.to_string_lossy().into_owned());
        }
        dir = d.parent();
    }
    None
}

/// `/Applications/WezTerm.app/Contents/MacOS/wezterm-gui` → `WezTerm` (the outermost bundle).
fn app_name(path: &str) -> Option<String> {
    let i = path.find(".app/")?;
    let name = path[..i].rsplit('/').next()?;
    (!name.is_empty()).then(|| name.to_string())
}

// --- processes --------------------------------------------------------------------------------

struct Proc {
    path: String,
    args: Vec<String>,
    cwd: Option<String>,
}

impl Proc {
    fn name(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or("")
    }
}

/// The caller and its ancestors, nearest first, up to (not including) launchd.
fn ancestry(pid: i32) -> Vec<Proc> {
    let mut out = Vec::new();
    let mut pid = pid;
    while pid > 1 && out.len() < MAX_DEPTH {
        let Some(path) = pid_path(pid) else { break };
        out.push(Proc {
            path,
            args: pid_args(pid).unwrap_or_default(),
            cwd: pid_cwd(pid),
        });
        match ppid(pid) {
            Some(p) if p != pid => pid = p,
            _ => break,
        }
    }
    out
}

fn pid_path(pid: i32) -> Option<String> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    (n > 0).then(|| String::from_utf8_lossy(&buf[..n as usize]).into_owned())
}

fn ppid(pid: i32) -> Option<i32> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
    let n =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size) };
    (n == size).then_some(info.pbi_ppid as i32)
}

fn pid_cwd(pid: i32) -> Option<String> {
    let mut info: libc::proc_vnodepathinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_vnodepathinfo>() as i32;
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDVNODEPATHINFO,
            0,
            (&raw mut info).cast(),
            size,
        )
    };
    if n != size {
        return None;
    }
    let p = unsafe { CStr::from_ptr(info.pvi_cdir.vip_path.as_ptr().cast()) };
    Some(p.to_string_lossy().into_owned()).filter(|s| !s.is_empty())
}

/// argv via sysctl KERN_PROCARGS2: int argc, exec path, NUL padding, then argc strings.
fn pid_args(pid: i32) -> Option<Vec<String>> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut size: libc::size_t = 0;
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || size < 4 {
        return None;
    }
    let mut buf = vec![0u8; size];
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    parse_procargs(&buf[..size])
}

fn parse_procargs(buf: &[u8]) -> Option<Vec<String>> {
    let argc = i32::from_ne_bytes(buf.get(..4)?.try_into().ok()?) as usize;
    let mut rest = &buf[4..];
    let end = rest.iter().position(|&b| b == 0)?; // exec path
    rest = &rest[end..];
    let start = rest.iter().position(|&b| b != 0)?;
    rest = &rest[start..];
    let args: Vec<String> = rest
        .split(|&b| b == 0)
        .take(argc)
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .collect();
    (args.len() == argc).then_some(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    fn put(out: &mut Vec<u8>, s: &[u8]) {
        out.extend_from_slice(&(s.len() as u32).to_be_bytes());
        out.extend_from_slice(s);
    }

    #[test]
    fn signed_data() {
        let mut sig = b"SSHSIG".to_vec();
        for s in [&b"git"[..], b"", b"sha512", &[7u8; 64]] {
            put(&mut sig, s);
        }
        assert_eq!(sshsig_namespace(&sig).as_deref(), Some("git"));
        assert_eq!(userauth_user(&sig), None);

        let mut auth = Vec::new();
        put(&mut auth, &[1u8; 32]);
        auth.push(50);
        for s in [&b"git"[..], b"ssh-connection", b"publickey"] {
            put(&mut auth, s);
        }
        assert_eq!(userauth_user(&auth).as_deref(), Some("git"));
        let mut bound = Vec::new();
        put(&mut bound, &[1u8; 32]);
        bound.push(50);
        for s in [
            &b"git"[..],
            b"ssh-connection",
            b"publickey-hostbound-v00@openssh.com",
        ] {
            put(&mut bound, s);
        }
        assert_eq!(userauth_user(&bound).as_deref(), Some("git"));
        assert_eq!(sshsig_namespace(&auth), None);
        assert_eq!(userauth_user(b"junk"), None);
    }

    #[test]
    fn command_lines() {
        assert_eq!(
            git_subcommand(&v(&[
                "git",
                "-c",
                "a=b",
                "-C",
                "x",
                "--no-pager",
                "commit",
                "-S"
            ]))
            .as_deref(),
            Some("commit")
        );
        assert_eq!(git_subcommand(&v(&["git"])), None);

        let (d, r) = ssh_destination(&v(&[
            "ssh",
            "-o",
            "SendEnv=GIT_PROTOCOL",
            "git@github.com",
            "git-receive-pack 'nhz-io/se-agent.git'",
        ]));
        assert_eq!(d.as_deref(), Some("git@github.com"));
        assert_eq!(
            git_remote(r.as_deref().unwrap()),
            Some(("push", "nhz-io/se-agent.git".into()))
        );
        let (d, r) = ssh_destination(&v(&[
            "ssh",
            "-p22",
            "-T",
            "nhz-io",
            "git-upload-pack",
            "'/x/y.git'",
        ]));
        assert_eq!(d.as_deref(), Some("nhz-io"));
        assert_eq!(
            git_remote(r.as_deref().unwrap()),
            Some(("fetch", "x/y.git".into()))
        );
        let (d, r) = ssh_destination(&v(&["ssh", "-T", "git@github.com"]));
        assert_eq!((d.as_deref(), r), (Some("git@github.com"), None));

        assert_eq!(
            app_name("/Applications/WezTerm.app/Contents/MacOS/wezterm-gui").as_deref(),
            Some("WezTerm")
        );
        assert_eq!(
            app_name(
                "/Applications/Claude.app/Contents/Frameworks/Claude Helper.app/Contents/MacOS/x"
            )
            .as_deref(),
            Some("Claude")
        );
        assert_eq!(app_name("/bin/zsh"), None);
        assert_eq!(clean("a\nb\u{1b}[31m"), "a b [31m");
        assert_eq!(
            clean("repo\u{202E}gnp.exe\u{2066}x\u{200B}\u{2028}y"),
            "repognp.exexy"
        );
        assert_eq!(clean(&"x".repeat(100)).chars().count(), MAX_PART);
    }

    #[test]
    fn procargs_and_self() {
        let mut buf = 2i32.to_ne_bytes().to_vec();
        buf.extend_from_slice(b"/usr/bin/git\0\0\0git\0commit\0HOME=/x\0");
        assert_eq!(parse_procargs(&buf), Some(v(&["git", "commit"])));
        // Our own process: path, argv and cwd are readable, and the chain reaches a parent.
        let me = std::process::id() as i32;
        let chain = ancestry(me);
        assert!(chain.len() >= 2);
        assert!(!chain[0].args.is_empty());
        assert!(chain[0].cwd.is_some());
    }
}
