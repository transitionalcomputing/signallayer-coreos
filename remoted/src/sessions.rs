//! In-memory web sessions (docs/remote-api-0.0.3.md). Nothing is persisted.
use std::{collections::HashMap, sync::Mutex};

pub const COOKIE_NAME: &str = "__Host-sl_session";
pub const IDLE_TIMEOUT: u64 = 15 * 60;
pub const ABSOLUTE_TIMEOUT: u64 = 8 * 60 * 60;
pub const MAX_SESSIONS: usize = 64;
const ID_BYTES: usize = 32;

pub trait Clock: Send + Sync {
    /// CLOCK_BOOTTIME seconds: monotonic, including suspend.
    fn now(&self) -> Option<u64>;
}

pub struct BootClock;

impl Clock for BootClock {
    fn now(&self) -> Option<u64> {
        let mut time = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: the pointer refers to a live, writable timespec.
        let result = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) };
        (result == 0)
            .then(|| u64::try_from(time.tv_sec).ok())
            .flatten()
    }
}

pub trait Random: Send + Sync {
    fn fill(&self, buffer: &mut [u8]) -> Result<(), ()>;
}

/// getrandom(2) with flags 0, filled completely; EINTR is retried and any
/// other failure fails closed.
pub struct KernelRandom;

impl Random for KernelRandom {
    fn fill(&self, buffer: &mut [u8]) -> Result<(), ()> {
        let mut filled = 0;
        while filled < buffer.len() {
            let remaining = &mut buffer[filled..];
            // SAFETY: the pointer and length describe a live, writable slice.
            let result =
                unsafe { libc::getrandom(remaining.as_mut_ptr().cast(), remaining.len(), 0) };
            if result > 0 && (result as usize) <= remaining.len() {
                filled += result as usize;
            } else if result < 0
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
            {
                continue;
            } else {
                buffer.fill(0);
                return Err(());
            }
        }
        Ok(())
    }
}

struct Session {
    created: u64,
    last_used: u64,
}

pub struct Sessions {
    sessions: Mutex<HashMap<String, Session>>,
    clock: Box<dyn Clock>,
    random: Box<dyn Random>,
}

/// Only a well-formed identifier is ever looked up.
fn well_formed(id: &str) -> bool {
    id.len() == ID_BYTES * 2
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl Sessions {
    pub fn new(clock: impl Clock + 'static, random: impl Random + 'static) -> Self {
        Self {
            sessions: Mutex::default(),
            clock: Box::new(clock),
            random: Box::new(random),
        }
    }

    /// A fresh identifier from the CSPRNG; never derived from client input.
    pub fn create(&self) -> Result<String, ()> {
        let now = self.clock.now().ok_or(())?;
        let mut bytes = [0u8; ID_BYTES];
        self.random.fill(&mut bytes)?;
        let id: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        let mut sessions = self.sessions.lock().map_err(|_| ())?;
        sessions.retain(|_, session| !expired(session, now));
        if sessions.len() >= MAX_SESSIONS {
            if let Some(oldest) = sessions
                .iter()
                .min_by_key(|(_, session)| session.created)
                .map(|(id, _)| id.clone())
            {
                sessions.remove(&oldest);
            }
        }
        sessions.insert(
            id.clone(),
            Session {
                created: now,
                last_used: now,
            },
        );
        Ok(id)
    }

    /// True for a live session, which is then marked as used. Unknown,
    /// malformed and expired identifiers are all simply false.
    pub fn validate(&self, id: &str) -> bool {
        if !well_formed(id) {
            return false;
        }
        let Some(now) = self.clock.now() else {
            return false;
        };
        let Ok(mut sessions) = self.sessions.lock() else {
            return false;
        };
        match sessions.get_mut(id) {
            Some(session) if !expired(session, now) => {
                session.last_used = now;
                true
            }
            Some(_) => {
                sessions.remove(id);
                false
            }
            None => false,
        }
    }

    pub fn remove(&self, id: &str) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.remove(id);
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }
}

fn expired(session: &Session, now: u64) -> bool {
    now.saturating_sub(session.last_used) >= IDLE_TIMEOUT
        || now.saturating_sub(session.created) >= ABSOLUTE_TIMEOUT
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    };

    #[derive(Clone, Default)]
    pub struct TestClock(pub Arc<AtomicU64>);

    impl Clock for TestClock {
        fn now(&self) -> Option<u64> {
            Some(self.0.load(Ordering::SeqCst))
        }
    }

    impl TestClock {
        pub fn advance(&self, seconds: u64) {
            self.0.fetch_add(seconds, Ordering::SeqCst);
        }
    }

    fn sessions(clock: &TestClock) -> Sessions {
        Sessions::new(clock.clone(), KernelRandom)
    }

    #[test]
    fn identifiers_are_256_bit_csprng_hex_and_distinct() {
        let clock = TestClock::default();
        let store = sessions(&clock);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let id = store.create().unwrap();
            assert_eq!(id.len(), 64);
            assert!(well_formed(&id));
            assert!(seen.insert(id));
        }
    }

    #[test]
    fn idle_timeout_is_fifteen_minutes_since_last_use() {
        let clock = TestClock::default();
        let store = sessions(&clock);
        let id = store.create().unwrap();
        clock.advance(IDLE_TIMEOUT - 1);
        assert!(store.validate(&id), "use refreshes the idle timer");
        clock.advance(IDLE_TIMEOUT - 1);
        assert!(store.validate(&id));
        clock.advance(IDLE_TIMEOUT);
        assert!(!store.validate(&id));
        assert!(!store.validate(&id), "an expired session is gone");
    }

    #[test]
    fn absolute_timeout_is_eight_hours_despite_use() {
        let clock = TestClock::default();
        let store = sessions(&clock);
        let id = store.create().unwrap();
        for _ in 0..(ABSOLUTE_TIMEOUT / 600 - 1) {
            clock.advance(600);
            assert!(store.validate(&id));
        }
        clock.advance(600);
        assert!(!store.validate(&id));
    }

    #[test]
    fn unknown_malformed_and_removed_identifiers_are_uniformly_invalid() {
        let clock = TestClock::default();
        let store = sessions(&clock);
        let id = store.create().unwrap();
        for invalid in [
            String::new(),
            "0".repeat(64),
            id.to_ascii_uppercase(),
            format!("{id}0"),
            id[..63].to_owned(),
            "g".repeat(64),
            "\u{e9}".repeat(32),
        ] {
            assert!(!store.validate(&invalid), "{invalid}");
        }
        store.remove(&id);
        assert!(!store.validate(&id));
    }

    #[test]
    fn capacity_evicts_the_oldest_session() {
        let clock = TestClock::default();
        let store = sessions(&clock);
        let first = store.create().unwrap();
        clock.advance(1);
        let second = store.create().unwrap();
        for _ in 2..MAX_SESSIONS {
            clock.advance(1);
            store.create().unwrap();
        }
        assert_eq!(store.len(), MAX_SESSIONS);
        store.create().unwrap();
        assert_eq!(store.len(), MAX_SESSIONS);
        assert!(!store.validate(&first));
        assert!(store.validate(&second));
    }

    struct FailingRandom;
    impl Random for FailingRandom {
        fn fill(&self, _: &mut [u8]) -> Result<(), ()> {
            Err(())
        }
    }

    #[test]
    fn randomness_failure_creates_no_session() {
        let store = Sessions::new(TestClock::default(), FailingRandom);
        assert!(store.create().is_err());
    }
}
