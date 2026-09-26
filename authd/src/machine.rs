use crate::{
    codes::{self, PAIRING_CODE_BYTES, RECOVERY_KEY_BYTES},
    hash::{Hasher, SALT_BYTES},
    random::RandomSource,
    store::{Persisted, Store},
};
use std::collections::HashMap;

pub const PAIRING_LIFETIME: u64 = 10 * 60;
pub const CONFIRMATION_WINDOW: u64 = 10 * 60;
pub const PAIRING_ATTEMPTS: u8 = 5;
pub const PASSWORD_MIN_CODE_POINTS: usize = 12;
pub const PASSWORD_MAX_BYTES: usize = 1024;
pub const CODE_MAX_BYTES: usize = 64;
pub const BACKOFF_THRESHOLD: u32 = 5;
pub const BACKOFF_CAP: u64 = 15 * 60;

/// The frozen Auth1 errors, without their D-Bus names or messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    NotEnrolled,
    EnrollmentUnconfirmed,
    AlreadyEnrolled,
    NoPendingPairing,
    InvalidPairingCode,
    PairingAttemptsExhausted,
    NoProvisionalEnrollment,
    ConfirmationExpired,
    InvalidCredential,
    PasswordRejected,
    RateLimited,
    Busy,
    InvalidArgument,
    Unavailable,
}

pub trait Clock: Send {
    /// Wall-clock Unix seconds (UTC). Used only for the persisted
    /// confirmation deadline and the reported pairing expiry.
    fn wall(&self) -> u64;
    /// CLOCK_BOOTTIME seconds: monotonic and including suspend. Every
    /// in-memory timer (pairing expiry, backoff) uses this clock.
    fn boot(&self) -> Option<u64>;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn wall(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0)
    }

    fn boot(&self) -> Option<u64> {
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

/// Backoff scopes. The password scope is keyed by the D-Bus sender's UID,
/// which the service layer obtains from the bus; callers cannot supply it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    Password(u32),
    Recovery,
    Confirmation,
}

/// `last_failure` is CLOCK_BOOTTIME seconds.
#[derive(Default)]
struct Counter {
    failures: u32,
    last_failure: u64,
}

/// `expires_boot` (CLOCK_BOOTTIME) decides expiry; `expires_at` (wall clock)
/// is only reported through GetPendingPairing.
struct Pairing {
    code: [u8; PAIRING_CODE_BYTES],
    expires_boot: u64,
    expires_at: u64,
    wrong_attempts: u8,
}

pub struct Core {
    store: Store,
    clock: Box<dyn Clock>,
    random: Box<dyn RandomSource>,
    hasher: Box<dyn Hasher>,
    /// None when the state file is unreadable, corrupt or of unknown version,
    /// or when a write failed after its rename made the new file visible.
    persisted: Option<Persisted>,
    pairing: Option<Pairing>,
    /// Set when normalization discarded an expired provisional enrollment, so
    /// ConfirmRecoveryKey can report ConfirmationExpired. Memory only.
    expired_provisional: bool,
    backoff: HashMap<Scope, Counter>,
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

/// The persisted deadline is wall-clock time. A deadline further in the future
/// than a fresh enrollment could set (the wall clock moved backward, or the
/// file is inconsistent) is treated as expired.
fn deadline_expired(deadline: u64, wall: u64) -> bool {
    wall >= deadline || deadline > wall.saturating_add(CONFIRMATION_WINDOW)
}

fn backoff_delay(failures: u32) -> u64 {
    if failures < BACKOFF_THRESHOLD {
        return 0;
    }
    let exponent = failures - BACKOFF_THRESHOLD;
    if exponent >= 10 {
        BACKOFF_CAP
    } else {
        (1u64 << exponent).min(BACKOFF_CAP)
    }
}

impl Core {
    /// Startup: remove a stale temporary file, load the state and normalize an
    /// expired provisional enrollment. A pending pairing never survives.
    pub fn open(
        store: Store,
        clock: Box<dyn Clock>,
        random: Box<dyn RandomSource>,
        hasher: Box<dyn Hasher>,
    ) -> Self {
        let persisted = match store.remove_stale_temporary() {
            Ok(()) => store.load().ok(),
            Err(_) => None,
        };
        let mut core = Self {
            store,
            clock,
            random,
            hasher,
            persisted,
            pairing: None,
            expired_provisional: false,
            backoff: HashMap::new(),
        };
        let _ = core.prepare();
        core
    }

    fn commit(&mut self, state: Persisted) -> Result<(), Failure> {
        match self.store.write(&state) {
            Ok(()) => {
                self.persisted = Some(state);
                Ok(())
            }
            Err(failed) => {
                if failed.after_rename {
                    self.persisted = None;
                    self.pairing = None;
                }
                Err(Failure::Unavailable)
            }
        }
    }

    /// Refuses on invalid state, drops an expired pairing and durably
    /// normalizes an expired provisional enrollment.
    fn prepare(&mut self) -> Result<(), Failure> {
        let Some(persisted) = &self.persisted else {
            return Err(Failure::Unavailable);
        };
        let boot = self.boot_now()?;
        if self
            .pairing
            .as_ref()
            .is_some_and(|pairing| boot >= pairing.expires_boot)
        {
            self.pairing = None;
        }
        if let Persisted::EnrolledUnconfirmed {
            confirmation_deadline,
            ..
        } = persisted
        {
            if deadline_expired(*confirmation_deadline, self.clock.wall()) {
                self.commit(Persisted::Unenrolled)?;
                self.expired_provisional = true;
            }
        }
        Ok(())
    }

    fn boot_now(&self) -> Result<u64, Failure> {
        self.clock.boot().ok_or(Failure::Unavailable)
    }

    fn check_backoff(&self, scope: Scope) -> Result<(), Failure> {
        let Some(counter) = self.backoff.get(&scope) else {
            return Ok(());
        };
        let until = counter
            .last_failure
            .saturating_add(backoff_delay(counter.failures));
        if self.boot_now()? < until {
            return Err(Failure::RateLimited);
        }
        Ok(())
    }

    /// The failure is counted even if the clock cannot be read; the caller
    /// then reports Unavailable instead of the credential error.
    fn record_failure(&mut self, scope: Scope) -> Result<(), Failure> {
        let boot = self.clock.boot();
        let counter = self.backoff.entry(scope).or_default();
        counter.failures = counter.failures.saturating_add(1);
        counter.last_failure = boot.ok_or(Failure::Unavailable)?;
        Ok(())
    }

    fn record_success(&mut self, scope: Scope) {
        self.backoff.remove(&scope);
    }

    fn random_bytes<const N: usize>(&mut self) -> Result<[u8; N], Failure> {
        let mut bytes = [0u8; N];
        self.random
            .fill(&mut bytes)
            .map_err(|_| Failure::Unavailable)?;
        Ok(bytes)
    }

    fn hash(&mut self, secret: &[u8]) -> Result<String, Failure> {
        let salt: [u8; SALT_BYTES] = self.random_bytes()?;
        self.hasher
            .hash(secret, &salt)
            .map_err(|_| Failure::Unavailable)
    }

    fn verify(&self, secret: &[u8], phc: &str) -> Result<bool, Failure> {
        self.hasher
            .verify(secret, phc)
            .map_err(|_| Failure::Unavailable)
    }

    fn check_password_bound(password: &str) -> Result<(), Failure> {
        if password.len() > PASSWORD_MAX_BYTES {
            return Err(Failure::InvalidArgument);
        }
        Ok(())
    }

    fn parse_recovery_key(input: &str) -> Result<[u8; RECOVERY_KEY_BYTES], Failure> {
        if input.len() > CODE_MAX_BYTES {
            return Err(Failure::InvalidArgument);
        }
        codes::parse_recovery_key(input).ok_or(Failure::InvalidArgument)
    }

    fn password_equals_key(password: &str, key: &[u8; RECOVERY_KEY_BYTES]) -> bool {
        codes::parse_recovery_key(&password.to_ascii_uppercase()).as_ref() == Some(key)
    }

    fn check_new_password(password: &str) -> Result<(), Failure> {
        if password.chars().count() < PASSWORD_MIN_CODE_POINTS {
            return Err(Failure::PasswordRejected);
        }
        Ok(())
    }

    pub fn verify_password(&mut self, sender_uid: u32, password: &str) -> Result<(), Failure> {
        self.prepare()?;
        Self::check_password_bound(password)?;
        let password_hash = match self.persisted.as_ref() {
            Some(Persisted::Enrolled { password_hash, .. }) => password_hash.clone(),
            Some(Persisted::EnrolledUnconfirmed { .. }) => {
                return Err(Failure::EnrollmentUnconfirmed)
            }
            _ => return Err(Failure::NotEnrolled),
        };
        let scope = Scope::Password(sender_uid);
        self.check_backoff(scope)?;
        if self.verify(password.as_bytes(), &password_hash)? {
            self.record_success(scope);
            Ok(())
        } else {
            self.record_failure(scope)?;
            Err(Failure::InvalidCredential)
        }
    }

    pub fn consume_pairing(
        &mut self,
        pairing_code: &str,
        new_password: &str,
    ) -> Result<String, Failure> {
        self.prepare()?;
        Self::check_password_bound(new_password)?;
        if pairing_code.len() > CODE_MAX_BYTES {
            return Err(Failure::InvalidArgument);
        }
        let submitted = codes::parse_pairing_code(pairing_code).ok_or(Failure::InvalidArgument)?;
        match self.persisted.as_ref() {
            Some(Persisted::Enrolled { .. }) => return Err(Failure::AlreadyEnrolled),
            Some(Persisted::EnrolledUnconfirmed { .. }) => {
                return Err(Failure::EnrollmentUnconfirmed)
            }
            _ => {}
        }
        let pairing = self.pairing.as_mut().ok_or(Failure::NoPendingPairing)?;
        if !constant_time_eq(&submitted, &pairing.code) {
            pairing.wrong_attempts += 1;
            if pairing.wrong_attempts >= PAIRING_ATTEMPTS {
                self.pairing = None;
                return Err(Failure::PairingAttemptsExhausted);
            }
            return Err(Failure::InvalidPairingCode);
        }
        let code = pairing.code;
        Self::check_new_password(new_password)?;
        if codes::parse_pairing_code(new_password) == Some(code) {
            return Err(Failure::PasswordRejected);
        }
        let key: [u8; RECOVERY_KEY_BYTES] = self.random_bytes()?;
        if Self::password_equals_key(new_password, &key) {
            return Err(Failure::PasswordRejected);
        }
        let encoded_key = codes::encode_recovery_key(&key);
        let password_hash = self.hash(new_password.as_bytes())?;
        let recovery_key_hash = self.hash(encoded_key.as_bytes())?;
        // The deadline starts when the enrollment commits, after the hashing.
        let confirmation_deadline = self.clock.wall() + CONFIRMATION_WINDOW;
        self.commit(Persisted::EnrolledUnconfirmed {
            password_hash,
            recovery_key_hash,
            confirmation_deadline,
        })?;
        self.pairing = None;
        self.expired_provisional = false;
        Ok(encoded_key)
    }

    pub fn confirm_recovery_key(&mut self, recovery_key: &str) -> Result<(), Failure> {
        self.prepare()?;
        Self::parse_recovery_key(recovery_key)?;
        let (password_hash, recovery_key_hash) = match self.persisted.as_ref() {
            Some(Persisted::EnrolledUnconfirmed {
                password_hash,
                recovery_key_hash,
                ..
            }) => (password_hash.clone(), recovery_key_hash.clone()),
            _ if self.expired_provisional => return Err(Failure::ConfirmationExpired),
            _ => return Err(Failure::NoProvisionalEnrollment),
        };
        self.check_backoff(Scope::Confirmation)?;
        let matches = self.verify(recovery_key.as_bytes(), &recovery_key_hash)?;
        // The deadline may have passed during the hash: re-check before any
        // commit, and never finalize late.
        self.prepare()?;
        if self.expired_provisional
            && !matches!(self.persisted, Some(Persisted::EnrolledUnconfirmed { .. }))
        {
            return Err(Failure::ConfirmationExpired);
        }
        if !matches {
            self.record_failure(Scope::Confirmation)?;
            return Err(Failure::InvalidCredential);
        }
        self.commit(Persisted::Enrolled {
            password_hash,
            recovery_key_hash,
        })?;
        self.record_success(Scope::Confirmation);
        Ok(())
    }

    pub fn recover_password(
        &mut self,
        recovery_key: &str,
        new_password: &str,
    ) -> Result<(), Failure> {
        self.prepare()?;
        let key = Self::parse_recovery_key(recovery_key)?;
        Self::check_password_bound(new_password)?;
        let recovery_key_hash = match self.persisted.as_ref() {
            Some(Persisted::Enrolled {
                recovery_key_hash, ..
            }) => recovery_key_hash.clone(),
            Some(Persisted::EnrolledUnconfirmed { .. }) => {
                return Err(Failure::EnrollmentUnconfirmed)
            }
            _ => return Err(Failure::NotEnrolled),
        };
        self.check_backoff(Scope::Recovery)?;
        if !self.verify(recovery_key.as_bytes(), &recovery_key_hash)? {
            self.record_failure(Scope::Recovery)?;
            return Err(Failure::InvalidCredential);
        }
        self.record_success(Scope::Recovery);
        Self::check_new_password(new_password)?;
        if Self::password_equals_key(new_password, &key) {
            return Err(Failure::PasswordRejected);
        }
        let password_hash = self.hash(new_password.as_bytes())?;
        self.commit(Persisted::Enrolled {
            password_hash,
            recovery_key_hash,
        })
    }

    pub fn ensure_pending_pairing(&mut self) -> Result<(), Failure> {
        self.prepare()?;
        if self.persisted != Some(Persisted::Unenrolled) || self.pairing.is_some() {
            return Ok(());
        }
        let expires_boot = self.boot_now()? + PAIRING_LIFETIME;
        let code: [u8; PAIRING_CODE_BYTES] = self.random_bytes()?;
        self.pairing = Some(Pairing {
            code,
            expires_boot,
            expires_at: self.clock.wall() + PAIRING_LIFETIME,
            wrong_attempts: 0,
        });
        self.expired_provisional = false;
        Ok(())
    }

    pub fn cancel_pending_pairing(&mut self) -> Result<(), Failure> {
        self.prepare()?;
        self.pairing = None;
        Ok(())
    }

    /// Succeeds from any state, including an invalid state file, which it
    /// replaces with a clean, durable Unenrolled state. Only after that commit
    /// does it clear the pending pairing (with its attempt count) and every
    /// in-memory backoff counter.
    pub fn reset_enrollment(&mut self) -> Result<(), Failure> {
        self.commit(Persisted::Unenrolled)?;
        self.pairing = None;
        self.expired_provisional = false;
        self.backoff.clear();
        Ok(())
    }

    pub fn get_pending_pairing(&mut self) -> Result<(bool, String, u64), Failure> {
        self.prepare()?;
        Ok(match &self.pairing {
            Some(pairing) => (
                true,
                codes::encode_pairing_code(&pairing.code),
                pairing.expires_at,
            ),
            None => (false, String::new(), 0),
        })
    }

    pub fn get_enrollment_state(&mut self) -> Result<(bool, bool), Failure> {
        self.prepare()?;
        Ok((
            matches!(self.persisted, Some(Persisted::Enrolled { .. })),
            self.pairing.is_some(),
        ))
    }
}

#[cfg(test)]
pub(crate) mod tests;
