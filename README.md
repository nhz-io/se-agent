# se-agent

A small SSH agent for macOS (Apple Silicon) that keeps ECDSA P-256 keys in the Secure Enclave.
Every signature needs **Touch ID**, or the **Mac login password** when Touch ID is unavailable
(lid closed, external keyboard without Touch ID). Rust plus a ~150-line Swift shim; builds with
Command Line Tools only.

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
| Protocol | `REQUEST_IDENTITIES`, `SIGN_REQUEST`. Everything else (add/remove keys, lock, extensions incl. `session-bind@openssh.com`) → `SSH_AGENT_FAILURE`. |
| Caller check | Audit token from `LOCAL_PEERTOKEN` → `SecCodeCopyGuestWithAttributes` (no PID-reuse race). Signing: valid signature + `anchor apple` + Signing ID `com.apple.ssh` / `scp` / `sftp` / `ssh-keygen`. Listing only: also `com.apple.ssh-add`. Everything else is refused (Homebrew `ssh` included). |
| Audit log | `~/Library/Logs/se-agent.log` (0600), JSON lines: time, event (`sign` / `sign_failed` / `denied`), key, fingerprint, caller path, pid, signing id. |
| Prompts | One at a time; the dialog names the key, caller and pid. |
| Socket | `~/Library/Caches/se-agent/agent.sock` (0600, dir 0700); stale sockets are replaced, refuses to start if another agent is live. |

## Build and install

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
  scope; Touch ID / password per signature is the hardware-enforced guarantee.
- Keys cannot be exported or backed up. One key per Mac; add each to GitHub.
- Erasing / replacing the Secure Enclave (e.g. logic board) or deleting the blob file loses the key.
