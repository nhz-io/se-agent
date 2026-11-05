//! Approval reuse windows.
//!
//! After a fresh Touch ID / password approval, further signatures with the same key from the same
//! caller (Signing ID, e.g. `com.apple.ssh-keygen`) reuse that approval without a prompt: the agent
//! keeps the approved LAContext. How long is set per key and program in config.toml (config.rs).
//! A window ends, whichever comes first:
//! - at its deadline, counted from the approval and not extended by use,
//! - when the Mac sleeps,
//! - on `se-agent forget` (SIGUSR1 to the agent),
//! - when its setting is removed or shortened below the time already used,
//! - when a reused signature fails, or the agent exits.

use std::collections::HashMap;
use std::time::Duration;
use time::OffsetDateTime;

// --- clocks -----------------------------------------------------------------------------------

fn clock_ns(id: libc::clockid_t) -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(id, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// A point in time on two macOS clocks: MONOTONIC keeps counting while the Mac sleeps,
/// UPTIME_RAW does not. Their difference grows only by time spent asleep.
#[derive(Clone, Copy, Debug)]
pub struct Stamp {
    mono: u64,
    uptime: u64,
}

impl Stamp {
    pub fn now() -> Stamp {
        Stamp {
            mono: clock_ns(libc::CLOCK_MONOTONIC),
            uptime: clock_ns(libc::CLOCK_UPTIME_RAW),
        }
    }

    fn elapsed_since(&self, earlier: &Stamp) -> Duration {
        Duration::from_nanos(self.mono.saturating_sub(earlier.mono))
    }

    fn slept_since(&self, earlier: &Stamp) -> bool {
        let asleep = (self.mono.saturating_sub(self.uptime))
            .saturating_sub(earlier.mono.saturating_sub(earlier.uptime));
        asleep > 1_000_000_000
    }
}

// --- windows ------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    Expired,
    Sleep,
    Forget,
    Setting,
    Failed,
}

impl End {
    pub fn as_str(self) -> &'static str {
        match self {
            End::Expired => "expired",
            End::Sleep => "sleep",
            End::Forget => "forget",
            End::Setting => "setting",
            End::Failed => "sign_failed",
        }
    }
}

/// (key label, caller Signing ID, key fingerprint). The fingerprint keeps a key re-created under
/// the same label from inheriting the old key's window.
pub type Scope = (String, String, String);

pub struct Window<C> {
    pub ctx: C,
    opened: Stamp,
    /// The length it opened with; a longer setting later does not stretch it.
    length: Duration,
    pub until: OffsetDateTime,
}

impl<C> Window<C> {
    pub fn new(ctx: C, opened: Stamp, length: Duration) -> Window<C> {
        Window {
            ctx,
            opened,
            length,
            until: OffsetDateTime::now_utc() + length,
        }
    }

    /// Why this window is over, given the key's current setting; None while it is live.
    fn end(&self, now: &Stamp, setting: Option<Duration>) -> Option<End> {
        if now.slept_since(&self.opened) {
            Some(End::Sleep)
        } else if let Some(d) = setting {
            (now.elapsed_since(&self.opened) >= d.min(self.length)).then_some(End::Expired)
        } else {
            Some(End::Setting)
        }
    }
}

/// Live windows. Generic over the context so the rules can be tested without a Secure Enclave.
pub struct Windows<C> {
    map: HashMap<Scope, Window<C>>,
}

impl<C> Default for Windows<C> {
    fn default() -> Self {
        Windows {
            map: HashMap::new(),
        }
    }
}

impl<C> Windows<C> {
    /// Removes every window that is over and returns them with the reason.
    pub fn sweep(
        &mut self,
        now: &Stamp,
        setting: impl Fn(&Scope) -> Option<Duration>,
    ) -> Vec<(Scope, Window<C>, End)> {
        let over: Vec<(Scope, End)> = self
            .map
            .iter()
            .filter_map(|(scope, w)| w.end(now, setting(scope)).map(|e| (scope.clone(), e)))
            .collect();
        over.into_iter()
            .map(|(scope, e)| {
                let w = self.map.remove(&scope).unwrap();
                (scope, w, e)
            })
            .collect()
    }

    /// Takes a live window out for one signature; put it back with `insert` if it still holds.
    pub fn take(&mut self, scope: &Scope) -> Option<Window<C>> {
        self.map.remove(scope)
    }

    pub fn insert(&mut self, scope: Scope, w: Window<C>) {
        self.map.insert(scope, w);
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn drain(&mut self) -> Vec<(Scope, Window<C>)> {
        self.map.drain().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(mono_s: u64, asleep_s: u64) -> Stamp {
        Stamp {
            mono: mono_s * 1_000_000_000,
            uptime: (mono_s - asleep_s) * 1_000_000_000,
        }
    }

    fn scope(k: &str, c: &str) -> Scope {
        (k.into(), c.into(), "SHA256:x".into())
    }

    #[test]
    fn window_rules() {
        let secs = Duration::from_secs;
        let k = scope("github", "com.apple.ssh-keygen");
        let mut ws: Windows<()> = Windows::default();
        ws.insert(k.clone(), Window::new((), at(100, 0), secs(60)));

        // Live, and use does not extend it.
        assert!(ws.sweep(&at(130, 0), |_| Some(secs(60))).is_empty());
        let w = ws.take(&k).unwrap();
        ws.insert(k.clone(), w);
        // Other caller, key or re-created key: no window.
        assert!(ws.take(&scope("github", "com.apple.ssh")).is_none());
        assert!(ws.take(&scope("nhz-io", "com.apple.ssh-keygen")).is_none());
        let recreated = (k.0.clone(), k.1.clone(), "SHA256:y".to_string());
        assert!(ws.take(&recreated).is_none());

        let ends = |now, setting: Option<Duration>| {
            let mut ws: Windows<()> = Windows::default();
            ws.insert(k.clone(), Window::new((), at(100, 0), secs(60)));
            ws.sweep(&now, |_| setting).pop().map(|(_, _, e)| e)
        };
        assert_eq!(ends(at(159, 0), Some(secs(60))), None);
        assert_eq!(ends(at(160, 0), Some(secs(60))), Some(End::Expired));
        assert_eq!(ends(at(110, 5), Some(secs(60))), Some(End::Sleep));
        assert_eq!(ends(at(101, 0), None), Some(End::Setting));
        // A shorter setting ends it early; a longer one does not stretch it.
        assert_eq!(ends(at(120, 0), Some(secs(10))), Some(End::Expired));
        assert_eq!(ends(at(160, 0), Some(secs(3600))), Some(End::Expired));
    }
}
