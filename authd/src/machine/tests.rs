use super::*;
use crate::{
    codes::{encode_pairing_code, encode_recovery_key, parse_recovery_key},
    hash::{Argon2id, HashFailed},
    random::RandomUnavailable,
    store::{tests::TempDir, Step, STATE_FILE},
};
use std::{
    collections::VecDeque,
    fs, io,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

pub const START: u64 = 1_800_000_000;
pub const PASSWORD: &str = "correct horse battery";
pub const OTHER_PASSWORD: &str = "another long passphrase";

type Hook = Box<dyn FnMut() + Send>;

/// Shared handles to the injected clock, random source, hasher and store
/// faults, so a test can drive them while a Core owns the other ends.
#[derive(Clone)]
pub struct Harness {
    pub directory: Arc<TempDir>,
    pub clock: Arc<AtomicU64>,
    pub scripted: Arc<Mutex<VecDeque<u8>>>,
    pub counter: Arc<AtomicU64>,
    pub random_fails: Arc<AtomicBool>,
    pub hashes: Arc<AtomicUsize>,
    pub verifies: Arc<AtomicUsize>,
    pub verify_hook: Arc<Mutex<Option<Hook>>>,
    pub fault: Arc<Mutex<Option<Step>>>,
}

struct TestClock(Arc<AtomicU64>);

impl Clock for TestClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Scripted bytes first, then a deterministic counter stream.
struct TestRandom(Harness);

impl RandomSource for TestRandom {
    fn fill(&mut self, buffer: &mut [u8]) -> Result<(), RandomUnavailable> {
        if self.0.random_fails.load(Ordering::SeqCst) {
            return Err(RandomUnavailable);
        }
        let mut scripted = self.0.scripted.lock().unwrap();
        for byte in buffer {
            *byte = scripted.pop_front().unwrap_or_else(|| {
                let next = self.0.counter.fetch_add(1, Ordering::SeqCst);
                (next.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 56) as u8
            });
        }
        Ok(())
    }
}

/// Real Argon2id with minimal cost, counting calls.
struct TestHasher(Harness, Argon2id);

impl Hasher for TestHasher {
    fn hash(&self, secret: &[u8], salt: &[u8; SALT_BYTES]) -> Result<String, HashFailed> {
        self.0.hashes.fetch_add(1, Ordering::SeqCst);
        self.1.hash(secret, salt)
    }

    fn verify(&self, secret: &[u8], phc: &str) -> Result<bool, HashFailed> {
        self.0.verifies.fetch_add(1, Ordering::SeqCst);
        if let Some(hook) = self.0.verify_hook.lock().unwrap().as_mut() {
            hook();
        }
        self.1.verify(secret, phc)
    }
}

impl Harness {
    pub fn new() -> Self {
        Self {
            directory: Arc::new(TempDir::new()),
            clock: Arc::new(AtomicU64::new(START)),
            scripted: Arc::default(),
            counter: Arc::default(),
            random_fails: Arc::default(),
            hashes: Arc::default(),
            verifies: Arc::default(),
            verify_hook: Arc::default(),
            fault: Arc::default(),
        }
    }

    /// Opens a Core on the same directory: a fresh open is a simulated restart.
    pub fn open(&self) -> Core {
        let fault = Arc::clone(&self.fault);
        Core::open(
            Store::with_faults(&self.directory.0, move |step| {
                if *fault.lock().unwrap() == Some(step) {
                    Err(io::Error::other("injected"))
                } else {
                    Ok(())
                }
            }),
            Box::new(TestClock(Arc::clone(&self.clock))),
            Box::new(TestRandom(self.clone())),
            Box::new(TestHasher(self.clone(), Argon2id::with_cost(8, 1, 1))),
        )
    }

    pub fn advance(&self, seconds: u64) {
        self.clock.fetch_add(seconds, Ordering::SeqCst);
    }

    pub fn script(&self, bytes: &[u8]) {
        self.scripted.lock().unwrap().extend(bytes);
    }

    pub fn state_file(&self) -> Option<String> {
        fs::read_to_string(self.directory.0.join(STATE_FILE)).ok()
    }

    pub fn state_json(&self) -> serde_json::Value {
        serde_json::from_str(&self.state_file().unwrap()).unwrap()
    }

    pub fn persisted_state(&self) -> String {
        self.state_json()["state"].as_str().unwrap().to_owned()
    }

    pub fn set_verify_hook(&self, hook: impl FnMut() + Send + 'static) {
        *self.verify_hook.lock().unwrap() = Some(Box::new(hook));
    }

    pub fn clear_verify_hook(&self) {
        *self.verify_hook.lock().unwrap() = None;
    }

    pub fn fail_at(&self, step: Option<Step>) {
        *self.fault.lock().unwrap() = step;
    }
}

pub fn pairing_code(core: &mut Core) -> String {
    let (pending, code, _) = core.get_pending_pairing().unwrap();
    assert!(pending);
    code
}

/// Unenrolled -> PendingPairing -> EnrolledUnconfirmed; returns the key.
pub fn enroll_unconfirmed(core: &mut Core) -> String {
    core.ensure_pending_pairing().unwrap();
    let code = pairing_code(core);
    core.consume_pairing(&code, PASSWORD).unwrap()
}

pub fn enroll(core: &mut Core) -> String {
    let key = enroll_unconfirmed(core);
    core.confirm_recovery_key(&key).unwrap();
    key
}

fn wrong_code(code: &str) -> String {
    let replacement = if code.starts_with('0') { "1" } else { "0" };
    format!("{replacement}{}", &code[1..])
}

fn wrong_key(key: &str) -> String {
    let replacement = if key.starts_with('0') { "1" } else { "0" };
    format!("{replacement}{}", &key[1..])
}

// State machine: Unenrolled.

#[test]
fn unenrolled_reports_nothing_and_refuses_credentials() {
    let harness = Harness::new();
    let mut core = harness.open();
    assert_eq!(core.get_enrollment_state(), Ok((false, false)));
    assert_eq!(core.get_pending_pairing(), Ok((false, String::new(), 0)));
    assert_eq!(core.verify_password(1, PASSWORD), Err(Failure::NotEnrolled));
    let key = encode_recovery_key(&[0; 16]);
    assert_eq!(
        core.recover_password(&key, PASSWORD),
        Err(Failure::NotEnrolled)
    );
    assert_eq!(
        core.confirm_recovery_key(&key),
        Err(Failure::NoProvisionalEnrollment)
    );
    assert_eq!(
        core.consume_pairing("00000000", PASSWORD),
        Err(Failure::NoPendingPairing)
    );
    assert_eq!(core.cancel_pending_pairing(), Ok(()));
    assert_eq!(core.get_enrollment_state(), Ok((false, false)));
    assert_eq!(harness.hashes.load(Ordering::SeqCst), 0);
    assert_eq!(harness.verifies.load(Ordering::SeqCst), 0);
    assert_eq!(harness.state_file(), None);
}

// PendingPairing.

#[test]
fn ensure_creates_a_pairing_from_the_injected_source_without_rotation() {
    let harness = Harness::new();
    let mut core = harness.open();
    harness.script(&[0xde, 0xad, 0xbe, 0xef, 0x01]);
    core.ensure_pending_pairing().unwrap();
    assert_eq!(
        core.get_pending_pairing(),
        Ok((true, "VTPVXVR1".into(), START + PAIRING_LIFETIME))
    );
    assert_eq!(core.get_enrollment_state(), Ok((false, true)));
    harness.advance(60);
    core.ensure_pending_pairing().unwrap();
    assert_eq!(
        core.get_pending_pairing(),
        Ok((true, "VTPVXVR1".into(), START + PAIRING_LIFETIME))
    );
    assert_eq!(
        harness.state_file(),
        None,
        "a pending pairing is never persisted"
    );
}

#[test]
fn pending_pairing_refuses_credential_methods_with_named_errors() {
    let harness = Harness::new();
    let mut core = harness.open();
    core.ensure_pending_pairing().unwrap();
    let key = encode_recovery_key(&[0; 16]);
    assert_eq!(core.verify_password(1, PASSWORD), Err(Failure::NotEnrolled));
    assert_eq!(
        core.recover_password(&key, PASSWORD),
        Err(Failure::NotEnrolled)
    );
    assert_eq!(
        core.confirm_recovery_key(&key),
        Err(Failure::NoProvisionalEnrollment)
    );
    assert_eq!(core.get_enrollment_state(), Ok((false, true)));
}

#[test]
fn pairing_expires_after_ten_minutes() {
    let harness = Harness::new();
    let mut core = harness.open();
    core.ensure_pending_pairing().unwrap();
    let code = pairing_code(&mut core);
    harness.advance(PAIRING_LIFETIME - 1);
    assert_eq!(core.get_enrollment_state(), Ok((false, true)));
    harness.advance(1);
    assert_eq!(core.get_enrollment_state(), Ok((false, false)));
    assert_eq!(core.get_pending_pairing(), Ok((false, String::new(), 0)));
    assert_eq!(
        core.consume_pairing(&code, PASSWORD),
        Err(Failure::NoPendingPairing)
    );
    core.ensure_pending_pairing().unwrap();
    assert_eq!(
        core.get_pending_pairing().unwrap().2,
        START + 2 * PAIRING_LIFETIME
    );
}

#[test]
fn the_fifth_wrong_code_destroys_the_pairing() {
    let harness = Harness::new();
    let mut core = harness.open();
    core.ensure_pending_pairing().unwrap();
    let code = pairing_code(&mut core);
    let wrong = wrong_code(&code);
    for _ in 0..4 {
        assert_eq!(
            core.consume_pairing(&wrong, PASSWORD),
            Err(Failure::InvalidPairingCode)
        );
    }
    assert_eq!(
        core.consume_pairing(&wrong, PASSWORD),
        Err(Failure::PairingAttemptsExhausted)
    );
    assert_eq!(core.get_enrollment_state(), Ok((false, false)));
    assert_eq!(
        core.consume_pairing(&code, PASSWORD),
        Err(Failure::NoPendingPairing)
    );
    assert_eq!(harness.hashes.load(Ordering::SeqCst), 0);
    core.ensure_pending_pairing().unwrap();
    assert_ne!(pairing_code(&mut core), code);
}

#[test]
fn malformed_codes_are_invalid_arguments_and_consume_no_attempt() {
    let harness = Harness::new();
    let mut core = harness.open();
    core.ensure_pending_pairing().unwrap();
    let code = pairing_code(&mut core);
    for malformed in ["", "0000000", "000000000", "UUUUUUUU", &"0".repeat(65)] {
        assert_eq!(
            core.consume_pairing(malformed, PASSWORD),
            Err(Failure::InvalidArgument)
        );
    }
    for _ in 0..4 {
        assert_eq!(
            core.consume_pairing(&wrong_code(&code), PASSWORD),
            Err(Failure::InvalidPairingCode)
        );
    }
    let lower_hyphenated = format!("{}-{}", &code[..4], &code[4..]).to_ascii_lowercase();
    assert!(core.consume_pairing(&lower_hyphenated, PASSWORD).is_ok());
}

#[test]
fn cancel_removes_a_pending_pairing() {
    let harness = Harness::new();
    let mut core = harness.open();
    core.ensure_pending_pairing().unwrap();
    let code = pairing_code(&mut core);
    core.cancel_pending_pairing().unwrap();
    assert_eq!(core.get_enrollment_state(), Ok((false, false)));
    assert_eq!(
        core.consume_pairing(&code, PASSWORD),
        Err(Failure::NoPendingPairing)
    );
}

#[test]
fn a_restart_drops_a_pending_pairing() {
    let harness = Harness::new();
    let mut core = harness.open();
    core.ensure_pending_pairing().unwrap();
    let code = pairing_code(&mut core);
    drop(core);
    let mut core = harness.open();
    assert_eq!(core.get_enrollment_state(), Ok((false, false)));
    assert_eq!(
        core.consume_pairing(&code, PASSWORD),
        Err(Failure::NoPendingPairing)
    );
}

// ConsumePairing and EnrolledUnconfirmed.

#[test]
fn consume_commits_enrolled_unconfirmed_and_returns_a_canonical_key() {
    let harness = Harness::new();
    let mut core = harness.open();
    core.ensure_pending_pairing().unwrap();
    let code = pairing_code(&mut core);
    let key_bytes = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    harness.script(&key_bytes);
    harness.advance(30);
    let key = core.consume_pairing(&code, PASSWORD).unwrap();
    assert_eq!(key, "04HMASW9NF6YZZPWQAC7CN1J20");
    assert_eq!(parse_recovery_key(&key), Some(key_bytes));
    assert_eq!(harness.hashes.load(Ordering::SeqCst), 2);
    let state = harness.state_json();
    assert_eq!(state["state"], "enrolled_unconfirmed");
    assert_eq!(
        state["confirmation_deadline"],
        START + 30 + CONFIRMATION_WINDOW
    );
    assert_eq!(core.get_enrollment_state(), Ok((false, false)));
    assert_eq!(core.get_pending_pairing(), Ok((false, String::new(), 0)));
    assert_eq!(
        core.consume_pairing(&code, PASSWORD),
        Err(Failure::EnrollmentUnconfirmed)
    );
}

#[test]
fn enrolled_unconfirmed_refuses_or_ignores_every_other_method() {
    let harness = Harness::new();
    let mut core = harness.open();
    let key = enroll_unconfirmed(&mut core);
    let before = harness.state_file();
    assert_eq!(
        core.verify_password(1, PASSWORD),
        Err(Failure::EnrollmentUnconfirmed)
    );
    assert_eq!(
        core.recover_password(&key, OTHER_PASSWORD),
        Err(Failure::EnrollmentUnconfirmed)
    );
    assert_eq!(
        core.consume_pairing("00000000", PASSWORD),
        Err(Failure::EnrollmentUnconfirmed)
    );
    assert_eq!(core.ensure_pending_pairing(), Ok(()));
    assert_eq!(core.cancel_pending_pairing(), Ok(()));
    assert_eq!(core.get_pending_pairing(), Ok((false, String::new(), 0)));
    assert_eq!(core.get_enrollment_state(), Ok((false, false)));
    assert_eq!(harness.state_file(), before);
    core.confirm_recovery_key(&key).unwrap();
    assert_eq!(core.get_enrollment_state(), Ok((true, false)));
}

#[test]
fn a_restart_preserves_an_unexpired_provisional_enrollment_without_finalizing() {
    let harness = Harness::new();
    let mut core = harness.open();
    let key = enroll_unconfirmed(&mut core);
    drop(core);
    harness.advance(CONFIRMATION_WINDOW - 1);
    let mut core = harness.open();
    assert_eq!(harness.persisted_state(), "enrolled_unconfirmed");
    assert_eq!(
        core.verify_password(1, PASSWORD),
        Err(Failure::EnrollmentUnconfirmed)
    );
    core.confirm_recovery_key(&key).unwrap();
    assert_eq!(harness.persisted_state(), "enrolled");
}

// ConfirmRecoveryKey and the deadline.

#[test]
fn confirmation_finalizes_only_on_the_matching_key() {
    let harness = Harness::new();
    let mut core = harness.open();
    let key = enroll_unconfirmed(&mut core);
    assert_eq!(
        core.confirm_recovery_key(&wrong_key(&key)),
        Err(Failure::InvalidCredential)
    );
    assert_eq!(harness.persisted_state(), "enrolled_unconfirmed");
    assert_eq!(
        core.confirm_recovery_key(&key.to_ascii_lowercase()),
        Err(Failure::InvalidArgument)
    );
    core.confirm_recovery_key(&key).unwrap();
    let state = harness.state_json();
    assert_eq!(state["state"], "enrolled");
    assert!(state.get("confirmation_deadline").is_none());
    assert_eq!(
        core.confirm_recovery_key(&key),
        Err(Failure::NoProvisionalEnrollment)
    );
}

#[test]
fn wrong_confirmation_keys_back_off_but_never_discard_the_enrollment() {
    let harness = Harness::new();
    let mut core = harness.open();
    let key = enroll_unconfirmed(&mut core);
    let wrong = wrong_key(&key);
    for _ in 0..5 {
        assert_eq!(
            core.confirm_recovery_key(&wrong),
            Err(Failure::InvalidCredential)
        );
    }
    let verifies = harness.verifies.load(Ordering::SeqCst);
    assert_eq!(core.confirm_recovery_key(&key), Err(Failure::RateLimited));
    assert_eq!(harness.verifies.load(Ordering::SeqCst), verifies);
    for _ in 0..3 {
        harness.advance(60);
        assert_eq!(
            core.confirm_recovery_key(&wrong),
            Err(Failure::InvalidCredential)
        );
    }
    assert_eq!(harness.persisted_state(), "enrolled_unconfirmed");
    harness.advance(60);
    core.confirm_recovery_key(&key).unwrap();
    assert_eq!(harness.persisted_state(), "enrolled");
}

#[test]
fn confirmation_after_the_deadline_normalizes_then_reports_expired() {
    let harness = Harness::new();
    let mut core = harness.open();
    let key = enroll_unconfirmed(&mut core);
    harness.advance(CONFIRMATION_WINDOW);
    assert_eq!(harness.persisted_state(), "enrolled_unconfirmed");
    assert_eq!(
        core.confirm_recovery_key(&key),
        Err(Failure::ConfirmationExpired)
    );
    assert_eq!(
        harness.state_json(),
        serde_json::json!({"version": 1, "state": "unenrolled"})
    );
    assert_eq!(
        core.confirm_recovery_key(&key),
        Err(Failure::ConfirmationExpired)
    );
    assert_eq!(core.get_enrollment_state(), Ok((false, false)));
    core.ensure_pending_pairing().unwrap();
    assert_eq!(
        core.confirm_recovery_key(&key),
        Err(Failure::NoProvisionalEnrollment)
    );
}

#[test]
fn generic_normalization_keeps_the_expiry_for_a_later_confirmation() {
    let harness = Harness::new();
    let mut core = harness.open();
    let key = enroll_unconfirmed(&mut core);
    harness.advance(CONFIRMATION_WINDOW + 5);
    assert_eq!(core.get_enrollment_state(), Ok((false, false)));
    assert_eq!(harness.persisted_state(), "unenrolled");
    assert_eq!(
        core.confirm_recovery_key(&key),
        Err(Failure::ConfirmationExpired)
    );
}

#[test]
fn restart_normalization_discards_an_expired_enrollment_durably() {
    let harness = Harness::new();
    let mut core = harness.open();
    let key = enroll_unconfirmed(&mut core);
    drop(core);
    harness.advance(CONFIRMATION_WINDOW);
    let mut core = harness.open();
    assert_eq!(
        harness.state_json(),
        serde_json::json!({"version": 1, "state": "unenrolled"}),
        "normalized at startup, before any operation"
    );
    assert_eq!(
        core.confirm_recovery_key(&key),
        Err(Failure::ConfirmationExpired)
    );
    assert_eq!(core.verify_password(1, PASSWORD), Err(Failure::NotEnrolled));
}

#[test]
fn ensure_after_the_deadline_discards_the_material_then_creates_a_pairing() {
    let harness = Harness::new();
    let mut core = harness.open();
    let key = enroll_unconfirmed(&mut core);
    harness.advance(CONFIRMATION_WINDOW);
    core.ensure_pending_pairing().unwrap();
    assert_eq!(harness.persisted_state(), "unenrolled");
    assert_eq!(core.get_enrollment_state(), Ok((false, true)));
    assert_eq!(
        core.confirm_recovery_key(&key),
        Err(Failure::NoProvisionalEnrollment)
    );
}

#[test]
fn a_deadline_passing_during_the_hash_never_finalizes() {
    let harness = Harness::new();
    let mut core = harness.open();
    let key = enroll_unconfirmed(&mut core);
    harness.advance(CONFIRMATION_WINDOW - 1);
    let clock = Arc::clone(&harness.clock);
    harness.set_verify_hook(move || {
        clock.fetch_add(2, Ordering::SeqCst);
    });
    assert_eq!(
        core.confirm_recovery_key(&key),
        Err(Failure::ConfirmationExpired)
    );
    harness.clear_verify_hook();
    assert_eq!(harness.persisted_state(), "unenrolled");
}

// Enrolled.

#[test]
fn enrolled_verifies_and_ignores_pairing_management() {
    let harness = Harness::new();
    let mut core = harness.open();
    enroll(&mut core);
    let before = harness.state_file();
    assert_eq!(core.verify_password(1, PASSWORD), Ok(()));
    assert_eq!(
        core.verify_password(1, OTHER_PASSWORD),
        Err(Failure::InvalidCredential)
    );
    assert_eq!(
        core.consume_pairing("00000000", PASSWORD),
        Err(Failure::AlreadyEnrolled)
    );
    assert_eq!(core.ensure_pending_pairing(), Ok(()));
    assert_eq!(core.cancel_pending_pairing(), Ok(()));
    assert_eq!(core.get_pending_pairing(), Ok((false, String::new(), 0)));
    assert_eq!(core.get_enrollment_state(), Ok((true, false)));
    assert_eq!(harness.state_file(), before);
    drop(core);
    let mut core = harness.open();
    assert_eq!(core.get_enrollment_state(), Ok((true, false)));
    assert_eq!(core.verify_password(1, PASSWORD), Ok(()));
}

#[test]
fn recover_password_replaces_only_the_password_and_keeps_the_key_valid() {
    let harness = Harness::new();
    let mut core = harness.open();
    let key = enroll(&mut core);
    let recovery_hash = harness.state_json()["recovery_key_hash"].clone();
    core.recover_password(&key, OTHER_PASSWORD).unwrap();
    assert_eq!(harness.state_json()["recovery_key_hash"], recovery_hash);
    assert_eq!(
        core.verify_password(1, PASSWORD),
        Err(Failure::InvalidCredential)
    );
    assert_eq!(core.verify_password(1, OTHER_PASSWORD), Ok(()));
    core.recover_password(&key, "a third long passphrase")
        .unwrap();
    assert_eq!(core.verify_password(1, "a third long passphrase"), Ok(()));
    assert_eq!(harness.state_json()["recovery_key_hash"], recovery_hash);
}

#[test]
fn recover_password_refuses_a_wrong_or_malformed_key() {
    let harness = Harness::new();
    let mut core = harness.open();
    let key = enroll(&mut core);
    let before = harness.state_file();
    assert_eq!(
        core.recover_password(&wrong_key(&key), OTHER_PASSWORD),
        Err(Failure::InvalidCredential)
    );
    assert_eq!(
        core.recover_password(&key[..25], OTHER_PASSWORD),
        Err(Failure::InvalidArgument)
    );
    assert_eq!(harness.state_file(), before);
    assert_eq!(core.verify_password(1, PASSWORD), Ok(()));
}

#[test]
fn reset_returns_every_state_to_a_durable_unenrolled_state() {
    let unenrolled = serde_json::json!({"version": 1, "state": "unenrolled"});
    for setup in 0..4 {
        let harness = Harness::new();
        let mut core = harness.open();
        let key = match setup {
            0 => None,
            1 => {
                core.ensure_pending_pairing().unwrap();
                None
            }
            2 => Some(enroll_unconfirmed(&mut core)),
            _ => Some(enroll(&mut core)),
        };
        core.reset_enrollment().unwrap();
        assert_eq!(harness.state_json(), unenrolled);
        assert_eq!(core.get_enrollment_state(), Ok((false, false)));
        if let Some(key) = key {
            assert_eq!(
                core.confirm_recovery_key(&key),
                Err(Failure::NoProvisionalEnrollment)
            );
            assert_eq!(
                core.recover_password(&key, OTHER_PASSWORD),
                Err(Failure::NotEnrolled)
            );
        }
        assert_eq!(core.verify_password(1, PASSWORD), Err(Failure::NotEnrolled));
        drop(core);
        assert_eq!(harness.open().get_enrollment_state(), Ok((false, false)));
    }
}

// Password rules.

#[test]
fn password_bounds_and_minimum_length() {
    let harness = Harness::new();
    let mut core = harness.open();
    core.ensure_pending_pairing().unwrap();
    let code = pairing_code(&mut core);
    let eleven = "\u{e9}".repeat(11);
    assert_eq!(
        core.consume_pairing(&code, &eleven),
        Err(Failure::PasswordRejected)
    );
    assert_eq!(
        core.consume_pairing(&code, &"a".repeat(1025)),
        Err(Failure::InvalidArgument)
    );
    assert_eq!(
        core.consume_pairing(&code, &"\u{e9}".repeat(513)),
        Err(Failure::InvalidArgument)
    );
    assert_eq!(
        core.get_enrollment_state(),
        Ok((false, true)),
        "rejections keep the pairing"
    );
    let twelve = "\u{e9}".repeat(12);
    core.consume_pairing(&code, &twelve).unwrap();
    let key = {
        core.reset_enrollment().unwrap();
        core.ensure_pending_pairing().unwrap();
        let code = pairing_code(&mut core);
        core.consume_pairing(&code, &"a".repeat(1024)).unwrap()
    };
    core.confirm_recovery_key(&key).unwrap();
    assert_eq!(core.verify_password(1, &"a".repeat(1024)), Ok(()));
    assert_eq!(
        core.verify_password(1, &"a".repeat(1025)),
        Err(Failure::InvalidArgument)
    );
    assert_eq!(
        core.recover_password(&key, &eleven),
        Err(Failure::PasswordRejected)
    );
    assert_eq!(
        core.recover_password(&key, &"a".repeat(1025)),
        Err(Failure::InvalidArgument)
    );
}

#[test]
fn a_password_equal_to_the_pairing_code_or_recovery_key_is_rejected() {
    let harness = Harness::new();
    let mut core = harness.open();
    core.ensure_pending_pairing().unwrap();
    let code = pairing_code(&mut core);
    // Every accepted form of a pairing code has at most 9 code points, so the
    // length rule already rejects it; the explicit equality check is defensive.
    assert_eq!(
        core.consume_pairing(&code, &code),
        Err(Failure::PasswordRejected)
    );
    let key_bytes = [0x5a; 16];
    let key_text = encode_recovery_key(&key_bytes);
    harness.script(&key_bytes);
    assert_eq!(
        core.consume_pairing(&code, &key_text.to_ascii_lowercase()),
        Err(Failure::PasswordRejected)
    );
    assert_eq!(harness.hashes.load(Ordering::SeqCst), 0);
    assert_eq!(harness.state_file(), None);
    let key = core.consume_pairing(&code, PASSWORD).unwrap();
    core.confirm_recovery_key(&key).unwrap();
    assert_eq!(
        core.recover_password(&key, &key.to_ascii_lowercase()),
        Err(Failure::PasswordRejected)
    );
    assert_eq!(core.verify_password(1, PASSWORD), Ok(()));
}

#[test]
fn the_pairing_code_equality_rule_covers_every_accepted_form() {
    let code = [0xde, 0xad, 0xbe, 0xef, 0x01];
    for form in ["VTPVXVR1", "vtpvxvr1", "VTPV-XVR1", "vtpv-xvr1"] {
        assert_eq!(crate::codes::parse_pairing_code(form), Some(code));
    }
    assert_eq!(encode_pairing_code(&code), "VTPVXVR1");
}

// Backoff.

#[test]
fn backoff_schedule_starts_after_five_failures_and_caps_at_fifteen_minutes() {
    let delays: Vec<u64> = (0..=16).map(backoff_delay).collect();
    assert_eq!(
        delays,
        [0, 0, 0, 0, 0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 900, 900]
    );
    assert_eq!(backoff_delay(u32::MAX), BACKOFF_CAP);
}

#[test]
fn password_backoff_is_per_sender_uid_and_skips_evaluation() {
    let harness = Harness::new();
    let mut core = harness.open();
    enroll(&mut core);
    for _ in 0..5 {
        assert_eq!(
            core.verify_password(990, "wrong password!"),
            Err(Failure::InvalidCredential)
        );
    }
    let verifies = harness.verifies.load(Ordering::SeqCst);
    assert_eq!(
        core.verify_password(990, PASSWORD),
        Err(Failure::RateLimited)
    );
    assert_eq!(harness.verifies.load(Ordering::SeqCst), verifies);
    assert_eq!(
        core.verify_password(991, PASSWORD),
        Ok(()),
        "another sender is unaffected"
    );
    harness.advance(1);
    assert_eq!(
        core.verify_password(990, "wrong password!"),
        Err(Failure::InvalidCredential)
    );
    harness.advance(1);
    assert_eq!(
        core.verify_password(990, PASSWORD),
        Err(Failure::RateLimited)
    );
    harness.advance(1);
    assert_eq!(core.verify_password(990, PASSWORD), Ok(()));
    assert_eq!(
        core.verify_password(990, "wrong password!"),
        Err(Failure::InvalidCredential)
    );
    assert_eq!(
        core.verify_password(990, PASSWORD),
        Ok(()),
        "a success reset the scope"
    );
}

#[test]
fn recovery_and_confirmation_scopes_are_independent_of_passwords() {
    let harness = Harness::new();
    let mut core = harness.open();
    let key = enroll(&mut core);
    for _ in 0..5 {
        assert_eq!(
            core.recover_password(&wrong_key(&key), OTHER_PASSWORD),
            Err(Failure::InvalidCredential)
        );
    }
    assert_eq!(
        core.recover_password(&key, OTHER_PASSWORD),
        Err(Failure::RateLimited)
    );
    assert_eq!(core.verify_password(990, PASSWORD), Ok(()));
    core.reset_enrollment().unwrap();
    assert_eq!(
        core.verify_password(990, PASSWORD),
        Err(Failure::NotEnrolled)
    );
    let key = enroll_unconfirmed(&mut core);
    core.confirm_recovery_key(&key).unwrap();
    assert_eq!(
        core.recover_password(&key, OTHER_PASSWORD),
        Err(Failure::RateLimited)
    );
    harness.advance(1);
    core.recover_password(&key, OTHER_PASSWORD).unwrap();
}

#[test]
fn counters_are_memory_only_and_reset_on_restart() {
    let harness = Harness::new();
    let mut core = harness.open();
    let key = enroll(&mut core);
    for _ in 0..6 {
        let _ = core.verify_password(990, "wrong password!");
        let _ = core.recover_password(&wrong_key(&key), OTHER_PASSWORD);
    }
    assert_eq!(
        core.verify_password(990, PASSWORD),
        Err(Failure::RateLimited)
    );
    let state = harness.state_json();
    let mut fields: Vec<&str> = state
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort();
    assert_eq!(
        fields,
        ["password_hash", "recovery_key_hash", "state", "version"]
    );
    drop(core);
    let mut core = harness.open();
    assert_eq!(core.verify_password(990, PASSWORD), Ok(()));
    core.recover_password(&key, OTHER_PASSWORD).unwrap();
}

// Persistence and secrecy.

#[test]
fn state_json_never_holds_secrets_counters_or_the_pairing_code() {
    let harness = Harness::new();
    let mut core = harness.open();
    core.ensure_pending_pairing().unwrap();
    let code = pairing_code(&mut core);
    let _ = core.consume_pairing(&wrong_code(&code), PASSWORD);
    let key = core.consume_pairing(&code, PASSWORD).unwrap();
    for state in [harness.state_json(), {
        core.confirm_recovery_key(&key).unwrap();
        harness.state_json()
    }] {
        let text = state.to_string();
        for secret in [code.as_str(), key.as_str(), PASSWORD] {
            assert!(!text.contains(secret));
            assert!(!text
                .to_ascii_lowercase()
                .contains(&secret.to_ascii_lowercase()));
        }
        let keys: Vec<&String> = state.as_object().unwrap().keys().collect();
        for field in keys {
            assert!(
                [
                    "version",
                    "state",
                    "password_hash",
                    "recovery_key_hash",
                    "confirmation_deadline"
                ]
                .contains(&field.as_str()),
                "{field}"
            );
        }
        assert!(state["password_hash"]
            .as_str()
            .unwrap()
            .starts_with("$argon2id$v=19$"));
        assert!(state["recovery_key_hash"]
            .as_str()
            .unwrap()
            .starts_with("$argon2id$v=19$"));
    }
}

#[test]
fn a_write_failure_before_rename_changes_nothing() {
    for step in [Step::Create, Step::Write, Step::FileSync, Step::Rename] {
        let harness = Harness::new();
        let mut core = harness.open();
        core.ensure_pending_pairing().unwrap();
        let code = pairing_code(&mut core);
        harness.fail_at(Some(step));
        assert_eq!(
            core.consume_pairing(&code, PASSWORD),
            Err(Failure::Unavailable)
        );
        assert_eq!(harness.state_file(), None);
        assert_eq!(core.get_enrollment_state(), Ok((false, true)), "{step:?}");
        harness.fail_at(None);
        let key = core.consume_pairing(&code, PASSWORD).unwrap();
        let before = harness.state_file();
        harness.fail_at(Some(step));
        assert_eq!(core.confirm_recovery_key(&key), Err(Failure::Unavailable));
        assert_eq!(harness.state_file(), before);
        assert_eq!(
            core.verify_password(1, PASSWORD),
            Err(Failure::EnrollmentUnconfirmed)
        );
        harness.fail_at(None);
        core.confirm_recovery_key(&key).unwrap();
        assert_eq!(core.verify_password(1, PASSWORD), Ok(()));
    }
}

#[test]
fn a_write_failure_after_rename_makes_the_service_unavailable_until_restart() {
    let harness = Harness::new();
    let mut core = harness.open();
    let key = enroll_unconfirmed(&mut core);
    harness.fail_at(Some(Step::DirectorySync));
    assert_eq!(core.confirm_recovery_key(&key), Err(Failure::Unavailable));
    harness.fail_at(None);
    assert_eq!(core.get_enrollment_state(), Err(Failure::Unavailable));
    assert_eq!(core.verify_password(1, PASSWORD), Err(Failure::Unavailable));
    drop(core);
    let mut core = harness.open();
    assert_eq!(core.get_enrollment_state(), Ok((true, false)));
}

#[test]
fn a_random_failure_fails_closed_without_state_change() {
    let harness = Harness::new();
    let mut core = harness.open();
    harness.random_fails.store(true, Ordering::SeqCst);
    assert_eq!(core.ensure_pending_pairing(), Err(Failure::Unavailable));
    assert_eq!(core.get_enrollment_state(), Ok((false, false)));
    harness.random_fails.store(false, Ordering::SeqCst);
    core.ensure_pending_pairing().unwrap();
    let code = pairing_code(&mut core);
    harness.random_fails.store(true, Ordering::SeqCst);
    assert_eq!(
        core.consume_pairing(&code, PASSWORD),
        Err(Failure::Unavailable)
    );
    assert_eq!(harness.state_file(), None);
    harness.random_fails.store(false, Ordering::SeqCst);
    assert!(core.consume_pairing(&code, PASSWORD).is_ok());
}

// Corrupt state.

fn assert_everything_but_reset_is_unavailable(core: &mut Core) {
    let key = encode_recovery_key(&[0; 16]);
    assert_eq!(core.verify_password(1, PASSWORD), Err(Failure::Unavailable));
    assert_eq!(
        core.consume_pairing("00000000", PASSWORD),
        Err(Failure::Unavailable)
    );
    assert_eq!(core.confirm_recovery_key(&key), Err(Failure::Unavailable));
    assert_eq!(
        core.recover_password(&key, PASSWORD),
        Err(Failure::Unavailable)
    );
    assert_eq!(core.ensure_pending_pairing(), Err(Failure::Unavailable));
    assert_eq!(core.cancel_pending_pairing(), Err(Failure::Unavailable));
    assert_eq!(core.get_pending_pairing(), Err(Failure::Unavailable));
    assert_eq!(core.get_enrollment_state(), Err(Failure::Unavailable));
}

#[test]
fn corrupt_state_is_unavailable_except_reset_which_writes_a_clean_state() {
    for contents in [
        "garbage".to_string(),
        r#"{"version":2,"state":"unenrolled"}"#.to_string(),
        r#"{"version":1,"state":"enrolled"}"#.to_string(),
    ] {
        let harness = Harness::new();
        fs::write(harness.directory.0.join(STATE_FILE), &contents).unwrap();
        let mut core = harness.open();
        assert_everything_but_reset_is_unavailable(&mut core);
        assert_eq!(
            harness.state_file().as_deref(),
            Some(contents.as_str()),
            "untouched"
        );
        harness.fail_at(Some(Step::Rename));
        assert_eq!(core.reset_enrollment(), Err(Failure::Unavailable));
        assert_everything_but_reset_is_unavailable(&mut core);
        harness.fail_at(None);
        core.reset_enrollment().unwrap();
        assert_eq!(
            harness.state_json(),
            serde_json::json!({"version": 1, "state": "unenrolled"})
        );
        assert_eq!(core.get_enrollment_state(), Ok((false, false)));
        drop(core);
        let mut core = harness.open();
        assert_eq!(core.get_enrollment_state(), Ok((false, false)));
        enroll(&mut core);
    }
}

#[test]
fn a_stale_temporary_file_is_removed_at_startup() {
    let harness = Harness::new();
    let mut core = harness.open();
    enroll(&mut core);
    drop(core);
    fs::write(harness.directory.0.join("state.json.tmp"), b"partial").unwrap();
    let mut core = harness.open();
    assert!(!harness.directory.0.join("state.json.tmp").exists());
    assert_eq!(core.get_enrollment_state(), Ok((true, false)));
}
