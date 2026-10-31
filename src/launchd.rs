//! Per-user LaunchAgent: starts `se-agent run` at login and restarts it if it exits.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const LABEL: &str = "io.nhz.se-agent";

pub fn plist_path() -> Result<PathBuf> {
    Ok(crate::store::home()?.join(format!("Library/LaunchAgents/{LABEL}.plist")))
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub fn plist(exe: &Path, socket: &Path, stderr_log: &Path) -> String {
    let [exe, socket, stderr_log] =
        [exe, socket, stderr_log].map(|p| xml_escape(&p.to_string_lossy()));
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{LABEL}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{exe}</string>
		<string>run</string>
		<string>--socket</string>
		<string>{socket}</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ProcessType</key>
	<string>Interactive</string>
	<key>StandardErrorPath</key>
	<string>{stderr_log}</string>
</dict>
</plist>
"#
    )
}

fn domain() -> String {
    format!("gui/{}", unsafe { libc::getuid() })
}

pub fn install(socket: &Path) -> Result<()> {
    let exe = std::env::current_exe()?.canonicalize()?;
    if exe.components().any(|c| c.as_os_str() == "target") {
        bail!(
            "refusing to install a LaunchAgent pointing into a build directory ({}); install the binary first, e.g. `cargo install --path . --root ~/.local`",
            exe.display()
        );
    }
    let path = plist_path()?;
    let stderr_log = crate::store::home()?.join("Library/Logs/se-agent.err.log");
    std::fs::create_dir_all(path.parent().unwrap())?;
    // Reload cleanly if already installed.
    let _ = Command::new("launchctl")
        .args(["bootout", &format!("{}/{LABEL}", domain())])
        .status();
    std::fs::write(&path, plist(&exe, socket, &stderr_log))
        .with_context(|| format!("write {}", path.display()))?;
    let st = Command::new("launchctl")
        .args(["bootstrap", &domain()])
        .arg(&path)
        .status()?;
    if !st.success() {
        bail!("launchctl bootstrap failed");
    }
    println!("installed {} -> {} run", path.display(), exe.display());
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let path = plist_path()?;
    let _ = Command::new("launchctl")
        .args(["bootout", &format!("{}/{LABEL}", domain())])
        .status();
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    println!("removed {}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn plist_lints() {
        let p = super::plist(
            "/Users/a b/.local/bin/se-agent".as_ref(),
            "/Users/a/Library/Caches/se-agent/agent.sock".as_ref(),
            "/tmp/x&y.log".as_ref(),
        );
        assert!(p.contains("x&amp;y"));
        let dir = std::env::temp_dir().join(format!("se-agent-plist-{}", std::process::id()));
        std::fs::write(&dir, p).unwrap();
        let ok = std::process::Command::new("plutil")
            .arg("-lint")
            .arg(&dir)
            .output()
            .unwrap()
            .status
            .success();
        std::fs::remove_file(&dir).unwrap();
        assert!(ok);
    }
}
