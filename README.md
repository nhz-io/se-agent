# se-agent

A small SSH agent for macOS (Apple Silicon) that keeps ECDSA P-256 keys in the Secure Enclave.
Every signature needs **Touch ID**, or the **Mac login password** when Touch ID is unavailable
(lid closed, external keyboard without Touch ID). Rust plus a ~150-line Swift shim; builds with
Command Line Tools only.

It also decrypts for **sops / age** with an existing [age-plugin-se](https://github.com/remko/age-plugin-se)
key, so one approval can cover a whole run of `sops -d` instead of one prompt per file (see
[age-plugin-se drop-in](#age-plugin-se-drop-in)).

A headless Mac can **use another Mac's keys over ssh** (agent forwarding): signing works as with any
forwarded agent, and age decryption can be allowed per host; every use still needs approval on the
Mac that holds the key (see [Delegation](#delegation-another-mac-uses-these-keys-over-ssh)).

## Why

- `sc_auth` / CTK keys are Touch ID-only (`-t bio`): no password fallback, so they fail with the lid closed.
- Secretive 4.0.0 signs CTK (smart card) keys with `SecKeyCreateSignature`, which returns DER, then
  splits that DER in half as if it were raw r‖s. The signature is invalid and GitHub just hangs.
- touchid-agent has the right design, but it is in Go and uses `.biometryAny` (no password fallback).

## Design

| Piece | How |
|---|---|
| Key | `SecureEnclave.P256.Signing.PrivateKey`, access control `[.privateKeyUsage, .userPresence]`, `WhenUnlockedThisDeviceOnly` |
| Storage | CryptoKit `dataRepresentation` (Secure Enclave-wrapped, useless on another Mac) in `~/.se-agent/keys/<label>` (0600, dir 0700); public key in `<label>.pub`. No keychain, so no entitlements needed. |
| Signature | CryptoKit hashes the message with SHA-256 (no pre-hash), returns `rawRepresentation` (exactly 64 bytes, anything else is an error), encoded as `string "ecdsa-sha2-nistp256", string(mpint r, mpint s)` with canonical mpints. |
| Protocol | `REQUEST_IDENTITIES`, `SIGN_REQUEST`, the `age-unwrap@se-agent.nhz.io` extension. `session-bind@openssh.com` is read (to recognise relayed requests and their destination) and, like everything else (add/remove keys, lock, other extensions), answered `SSH_AGENT_FAILURE`. |
| Caller check | Audit token from `LOCAL_PEERTOKEN` → `SecCodeCopyGuestWithAttributes` (no PID-reuse race). Signing: valid signature + `anchor apple` + Signing ID `com.apple.ssh` / `scp` / `sftp` / `ssh-keygen`. Listing only: also `com.apple.ssh-add`. Everything else is refused (Homebrew `ssh` included). Requests Apple's `ssh` relays from another Mac are labelled with that host and have their own rules (see Delegation). |
| age | Drop-in `age-plugin-se` (identity-v1) forwarding stanzas to the agent (`SSH_AGENTC_EXTENSION` `age-unwrap@se-agent.nhz.io`); ECDH in the Secure Enclave, wrap identical to age-plugin-se v0.2.1. See below. |
| Audit log | `~/Library/Logs/se-agent.log` (0600), JSON lines: time, event (`sign` / `sign_failed` / `decrypt` / `decrypt_failed` / `sign_upstream` / `sign_upstream_failed` / `denied` / `window_close`), key, fingerprint, caller path, pid, signing id, `purpose`, `approval` (`prompt` or `reused`), `window_until`, and for relayed requests `relay` (host, its names, `via`, `destination`, `hops`). |
| Prompts | One at a time; the dialog says what is being signed (see below). |
| Reuse window | Opt-in per key and program, capped at 1 hour (see below). Keeps the approved `LAContext` in memory; no key material leaves the Secure Enclave. |
| Socket | `~/Library/Caches/se-agent/agent.sock` (0600, dir 0700), and `relay.sock` next to it for a persistent ssh `RemoteForward`; stale sockets are replaced, refuses to start if another agent is live. No TCP. |

## Install

```bash
brew install --cask nhz-io/tap/se-agent
```

The cask links `se-agent` into `/opt/homebrew/bin` and (re)starts the LaunchAgent on install and upgrade.
Keys in `~/.se-agent` are not touched by upgrades or `brew uninstall`.

## Build from source

```bash
cargo test
```

```bash
cargo install --path . --root ~/.local
```

```bash
se-agent install
```

`install` writes `~/Library/LaunchAgents/io.nhz.se-agent.plist` (RunAtLoad, KeepAlive) for the installed
binary and starts it. It refuses to point at `target/`. `se-agent uninstall` removes it.

## Use

```bash
se-agent create github
```

Creates the key, then signs and verifies a test message (one Touch ID / password prompt) before
printing the public key. Also saved to `~/.se-agent/keys/github.pub`.

```bash
se-agent list
```

```bash
se-agent delete github
```

### Approval reuse window (opt-in)

By default every signature prompts. For commit signing (a rebase signs every commit) a key can reuse
one approval for a while, per program. In `~/.config/se-agent/config.toml` (0600):

```toml
[defaults]
reuse = {}                                  # keys without their own section: always prompt

[keys.github]
reuse = { ssh-keygen = "30m" }              # commit signing only; ssh (push, fetch) still prompts

[keys.nhz-io]
reuse = { ssh-keygen = "30m", ssh = "5m" }
```

Programs: `ssh`, `ssh-keygen` (git uses it for signing), `scp`, `sftp`. Values: `"90s"`, `"15m"`,
`"1h"` or seconds. A key's `reuse` replaces `[defaults]`. The agent rereads the file on every
signature; no restart needed.

```bash
se-agent reuse
```

shows the cap, the effective window per key and program, and any mistakes (unknown keys or programs,
values above the cap; those entries are skipped). A file that other users can write, or that does not
parse, means no reuse at all.

After one Touch ID / password approval, further signatures with **that key from that program** don't
prompt until the window ends, whichever comes first:

- its length, counted from the approval and **not** extended by use,
- sleep,
- `se-agent forget` (ends all windows now),
- the setting removed, or shortened below the time already used,
- a failed signature, or the agent restarting.

**Cap.** No window is longer than 1 hour, unless root-owned `/etc/se-agent/max` sets another cap
(higher or lower), e.g. `sudo mkdir -p /etc/se-agent && echo 8h | sudo tee /etc/se-agent/max`. The
file counts only if root owns it and its directory and nobody else can write either; otherwise the
1 hour cap applies and `se-agent reuse` says why. A process running as you can edit config.toml, but
not raise the cap.

While a window is open, **any process running as you** can get signatures from that key by running
the allowed Apple program (the caller check proves the program, not who started it). Keep it short,
and `se-agent forget` when stepping away. A locked screen does not end a window, but nothing can
sign while it is locked (the key is `WhenUnlocked`).

### The approval dialog

It says what is being signed: `sign for "git commit" in se-agent from WezTerm with key "github"`,
`log in to github.com for git push of nhz-io/se-agent.git from Zed with key "github"`, or
`sign "file" data …`. It comes from the signed data (the SSHSIG namespace, or an SSH login) and the
caller's process tree (the `git` command and repository folder, ssh's destination, the app it runs
in). That is a **hint** for you, not proof: a process running as you can fake its arguments and
folder. When a window would open, the dialog says for how long. The buttons are Touch ID, password
and **Deny**. The audit log records the same text as `purpose`.

Measured on macOS 27: `LAContext.invalidate()` alone does not stop an approved context from signing
again, so se-agent ends a window by releasing the context. `touchIDAuthenticationAllowableReuseDuration`
is not used: it only skips a prompt after a recent *device unlock* by Touch ID, and is capped at 5 minutes.

### age-plugin-se drop-in

`age-plugin-se` authenticates once per process, so sops asks for Touch ID / password for every file
it opens. se-agent can stand in for it:

```bash
se-agent age-plugin install
```

links `~/.local/bin/age-plugin-se` → se-agent (`--dir` for another directory; it must come before
`/opt/homebrew/bin` on PATH; `se-agent age-plugin status` shows what is found). Run under that name,
se-agent speaks the age plugin protocol: for decryption (identity-v1) it sends the identities and
recipient stanzas to the agent, which loads the same Secure Enclave key from the identity
(`AGE-PLUGIN-SE-1…`, i.e. `~/.config/age/se-identity.txt`) and does the ECDH in the Secure Enclave
with an `LAContext` it keeps. Both stanza types are handled (`piv-p256` for `age1se1…` recipients,
`p256tag` for `age1tag1…`), with the same HKDF / HPKE / ChaCha20-Poly1305 steps as age-plugin-se
v0.2.1. Same key, same identity file, same recipients: nothing is re-encrypted, and recovery never
needs se-agent.

Reuse is set under `[age]` in config.toml, per program, and applies per age key:

```toml
[age]
reuse = { sops = "30m" }                    # programs: sops, age
```

Same rules as SSH windows (cap, sleep, `se-agent forget`, …). Every decryption is logged as
`decrypt` with `approval` `prompt` or `reused`, the key (`age1se1…`), program, and `window_until`.

**Caller.** The agent accepts the request only from its own binary (audit token, valid signature,
same executable as the agent) whose parent process is `sops` or `age`. Homebrew's sops and age are
ad-hoc signed (Signing ID `a.out`), so the parent is identified by its executable path, not a
Signing ID: this scopes windows per program, it does not stop a process running as you, which could
run sops itself while a window is open.

**Fallback.** Everything else goes to the real `/opt/homebrew/bin/age-plugin-se`, unchanged:
encryption (recipient-v1), `keygen` / `recipients`, the agent not running, a refused caller (it is
replayed the request), and identities the agent cannot load (post-quantum ones). So with the agent
down, sops still decrypts, one prompt per file as before. `se-agent age-plugin uninstall` removes
the link.

### Delegation: another Mac uses these keys over ssh

A headless Mac (here **box**) can't show its own approval dialog to anyone. Over ssh it can use
the keys of the Mac you sit at (here **desk**) instead, through ssh's unix-socket forwarding; every
use is approved on desk (Touch ID / password, or a reuse window started there). No TCP listener.

**Transport**, either:

- **While logged in**: in desk's `~/.ssh/config`, `Host box` → `ForwardAgent ~/Library/Caches/se-agent/agent.sock`.
  On box `$SSH_AUTH_SOCK` is then desk's agent. (Through an existing ControlMaster connection
  agent forwarding may not be set up; a fresh connection, `-o ControlPath=none`, is.)
- **Persistent**: desk holds `ssh -N -R <path on box>:<desk's relay.sock> box` (e.g. as a
  LaunchAgent); `se-agent socket --relay` prints the relay socket. Point it at `relay.sock`, not
  `agent.sock`: ssh sends no session-bind for a `RemoteForward`, and only `relay.sock` marks those
  connections as relayed. On `relay.sock` only Apple's `ssh` is served.

**How relayed requests are told apart.** For a forwarded agent, desk's `ssh` opens one connection
per channel and first sends `session-bind@openssh.com` with box's host key and
`is_forwarding` set; everything on `relay.sock` is relayed. The host is named from desk's side:
ssh's destination (`ssh box`; a ControlMaster's rewritten argv is skipped) and the names of the
bound host key in desk's `known_hosts`. Where box logs in to comes from box's own
session-bind (a hint, matched in `known_hosts`), so a forwarded GitHub login reads
`log in to github.com as git for box (forwarded over ssh from WezTerm) with key "github"`, and
the log has `"relay": {"host": "box", "via": "forward-agent", "destination": "github.com", ...}`.

**Signing** through a forwarded agent works without configuration (as before). Relayed requests get
**their own reuse windows**, never desk's local ones (before 0.4.0 a forwarded login could reuse
desk's `ssh` window). In desk's `config.toml`:

```toml
[relay.box]                              # any of the host's names: box, box.local, …
age = true                                   # allow age decryption from box (default: no)
reuse = { ssh-keygen = "30m", age = "15m" }  # optional windows for relayed requests
```

Programs under `[relay.<host>]` are what kind of request it is, since box's processes aren't
visible from desk: `ssh` (logins), `ssh-keygen` (SSHSIG signatures, e.g. git commits), `age`.
Same cap and endings as other windows; scoped per key and host.

**age decryption** through the relay is refused (and logged as `denied`, with the setting to
change) unless `[relay.<host>] age = true`. The dialog names the host and what box's drop-in
plugin reports as its caller: `decrypt for "sops decrypt x.yaml" on box (forwarded over ssh)
with age key age1se1…` (the command is box's word for it; the host is desk's).

**On box**, the drop-in `age-plugin-se` (`se-agent age-plugin install`) asks, per identity,
first box's own agent, then an **upstream** agent: `$SE_AGENT_UPSTREAM`, else `[upstream]
socket` in box's `config.toml`, else `$SSH_AUTH_SOCK` if its server is Apple's sshd (a forwarded
agent). box's agent declines identities of desk's Secure Enclave, so those go upstream. Use a
copy of desk's identity file (`AGE-PLUGIN-SE-1…`, only desk's Secure Enclave can use it), e.g.
`age -d -i desk-se-identity.txt`, and add desk's `age1se1…` as a recipient where needed.

```toml
[upstream]                                   # box's config.toml
socket = "~/.ssh/agent-desk.sock"           # the RemoteForward path (or leave it to $SSH_AUTH_SOCK)
```

With `[upstream] socket` set, **box's agent** also lists the upstream keys after its own and
passes signatures with keys it doesn't hold to that socket (logged on box as `sign_upstream`,
approved on desk), replaying the connection's session-binds so desk sees the destination. So
`IdentityAgent ~/Library/Caches/se-agent/agent.sock` on box covers both Macs' keys. Requests that
arrive relayed are never passed further upstream. Not done: falling back to upstream for box's
own keys when nobody can approve at box's screen.

`se-agent reuse` shows `relay <host>` lines and the upstream socket.

### Wire into ssh

```
Host github.com
    User git
    IdentityAgent ~/Library/Caches/se-agent/agent.sock
    IdentityFile ~/.se-agent/keys/github.pub
    IdentitiesOnly yes
```

`IdentityFile` with a `.pub` makes ssh offer exactly that key from the agent.

## Verify

```bash
SSH_AUTH_SOCK=~/Library/Caches/se-agent/agent.sock ssh-keygen -Y sign -f ~/.se-agent/keys/github.pub -n file README.md
```

```bash
printf 'me %s\n' "$(cat ~/.se-agent/keys/github.pub)" > /tmp/allowed && ssh-keygen -Y verify -f /tmp/allowed -I me -n file -s README.md.sig < README.md
```

```bash
tail -f ~/Library/Logs/se-agent.log
```

## Limits

- A same-user process that can inject into an allowed Apple binary, or repoint `SSH_AUTH_SOCK`, is out of
  scope; Touch ID / password per signature is the hardware-enforced guarantee. With a reuse window
  on, that guarantee becomes one approval per window, enforced by the agent, not the hardware.
- Delegation trusts the relaying Mac's ssh to name the host and what it relays: the dialog shows
  what box says, and approval on desk is the guarantee. A process on box that can reach the
  forwarded socket can ask for approvals (and use a relay window while it is open).
- Keys cannot be exported or backed up. One key per Mac; add each to GitHub.
- Erasing / replacing the Secure Enclave (e.g. logic board) or deleting the blob file loses the key.
