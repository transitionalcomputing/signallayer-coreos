use super::*;
use crate::machine::tests::{enroll, enroll_unconfirmed, Harness, PASSWORD};
use std::{
    sync::{atomic::Ordering, mpsc},
    thread,
    time::Duration,
};
use zbus::DBusError;

const ALL_FAILURES: [(Failure, &str); 14] = [
    (Failure::NotEnrolled, "NotEnrolled"),
    (Failure::EnrollmentUnconfirmed, "EnrollmentUnconfirmed"),
    (Failure::AlreadyEnrolled, "AlreadyEnrolled"),
    (Failure::NoPendingPairing, "NoPendingPairing"),
    (Failure::InvalidPairingCode, "InvalidPairingCode"),
    (
        Failure::PairingAttemptsExhausted,
        "PairingAttemptsExhausted",
    ),
    (Failure::NoProvisionalEnrollment, "NoProvisionalEnrollment"),
    (Failure::ConfirmationExpired, "ConfirmationExpired"),
    (Failure::InvalidCredential, "InvalidCredential"),
    (Failure::PasswordRejected, "PasswordRejected"),
    (Failure::RateLimited, "RateLimited"),
    (Failure::Busy, "Busy"),
    (Failure::InvalidArgument, "InvalidArgument"),
    (Failure::Unavailable, "Unavailable"),
];

#[test]
fn every_failure_has_its_frozen_dbus_name_and_a_fixed_message() {
    for (failure, name) in ALL_FAILURES {
        let error = to_dbus(failure);
        assert_eq!(
            error.name().as_str(),
            format!("org.signallayer.Auth1.Error.{name}")
        );
        let description = error.description().unwrap();
        assert!(!description.is_empty());
        assert_eq!(to_dbus(failure).description(), Some(description));
    }
}

#[test]
fn event_lines_name_the_outcome_and_never_the_arguments() {
    assert_eq!(
        event_line(
            "VerifyPassword",
            Some(990),
            &Err::<(), _>(Failure::InvalidCredential)
        ),
        "sl-authd: VerifyPassword uid=990: InvalidCredential"
    );
    assert_eq!(
        event_line(
            "ConsumePairing",
            None,
            &Ok("04HMASW9NF6YZZPWQAC7CN1J20".to_string())
        ),
        "sl-authd: ConsumePairing: ok"
    );
}

#[test]
fn admission_allows_one_active_plus_four_queued_then_busy() {
    let harness = Harness::new();
    let shared = Shared::new(harness.open());
    let permits: Vec<Permit> = (0..MAX_ADMITTED).map(|_| shared.admit().unwrap()).collect();
    assert_eq!(MAX_ADMITTED, 5);
    assert!(matches!(shared.admit(), Err(Failure::Busy)));
    drop(permits);
    let _again = shared.admit().unwrap();
}

#[test]
fn busy_changes_no_counter_or_state() {
    let harness = Harness::new();
    let mut core = harness.open();
    let key = enroll(&mut core);
    let shared = Shared::new(core);
    let before = harness.state_file();
    let verifies = harness.verifies.load(Ordering::SeqCst);
    let permits: Vec<Permit> = (0..MAX_ADMITTED).map(|_| shared.admit().unwrap()).collect();
    for _ in 0..20 {
        assert!(matches!(shared.admit(), Err(Failure::Busy)));
    }
    drop(permits);
    assert_eq!(harness.verifies.load(Ordering::SeqCst), verifies);
    assert_eq!(harness.state_file(), before);
    // No failure was counted: five wrong attempts are still needed for backoff.
    shared
        .with_core(|core| {
            for _ in 0..4 {
                assert_eq!(
                    core.verify_password(1, "wrong password!"),
                    Err(Failure::InvalidCredential)
                );
            }
            core.verify_password(1, PASSWORD)?;
            core.recover_password(&key, "another long passphrase")
        })
        .unwrap();
}

/// Runs `first` on a thread whose first hash verification blocks until
/// released, queues `second` behind it, then releases the first.
fn run_queued<A, B>(
    harness: &Harness,
    shared: &Arc<Shared>,
    first: A,
    second: B,
) -> (Result<(), Failure>, Result<(), Failure>)
where
    A: FnOnce(&mut Core) -> Result<(), Failure> + Send + 'static,
    B: FnOnce(&mut Core) -> Result<(), Failure> + Send + 'static,
{
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let mut gate = Some((entered_tx, release_rx));
    harness.set_verify_hook(move || {
        if let Some((entered, release)) = gate.take() {
            entered.send(()).unwrap();
            release.recv().unwrap();
        }
    });
    let first_permit = shared.admit().unwrap();
    let first_shared = Arc::clone(shared);
    let first_thread = thread::spawn(move || {
        let _permit = first_permit;
        first_shared.with_core(first)
    });
    entered_rx.recv().unwrap();
    let second_permit = shared.admit().unwrap();
    let second_shared = Arc::clone(shared);
    let (queued_tx, queued_rx) = mpsc::channel();
    let second_thread = thread::spawn(move || {
        let _permit = second_permit;
        queued_tx.send(()).unwrap();
        second_shared.with_core(second)
    });
    queued_rx.recv().unwrap();
    thread::sleep(Duration::from_millis(100));
    assert_eq!(shared.admitted.load(Ordering::SeqCst), 2);
    release_tx.send(()).unwrap();
    let results = (first_thread.join().unwrap(), second_thread.join().unwrap());
    harness.clear_verify_hook();
    results
}

#[test]
fn a_queued_confirmation_rechecks_state_after_the_earlier_commit() {
    let harness = Harness::new();
    let mut core = harness.open();
    let key = enroll_unconfirmed(&mut core);
    let shared = Shared::new(core);
    let (first_key, second_key) = (key.clone(), key.clone());
    let (first, second) = run_queued(
        &harness,
        &shared,
        move |core| core.confirm_recovery_key(&first_key),
        move |core| core.confirm_recovery_key(&second_key),
    );
    assert_eq!(first, Ok(()));
    assert_eq!(second, Err(Failure::NoProvisionalEnrollment));
    assert_eq!(harness.persisted_state(), "enrolled");
}

#[test]
fn a_queued_verification_rechecks_backoff_after_the_earlier_failure() {
    let harness = Harness::new();
    let mut core = harness.open();
    enroll(&mut core);
    for _ in 0..4 {
        assert_eq!(
            core.verify_password(990, "wrong password!"),
            Err(Failure::InvalidCredential)
        );
    }
    let shared = Shared::new(core);
    let verifies = harness.verifies.load(Ordering::SeqCst);
    let (first, second) = run_queued(
        &harness,
        &shared,
        |core| core.verify_password(990, "wrong password!"),
        |core| core.verify_password(990, PASSWORD),
    );
    assert_eq!(first, Err(Failure::InvalidCredential));
    assert_eq!(second, Err(Failure::RateLimited));
    assert_eq!(
        harness.verifies.load(Ordering::SeqCst),
        verifies + 1,
        "the queued call was not evaluated"
    );
}

#[test]
fn a_queued_recovery_rechecks_state_after_a_reset() {
    let harness = Harness::new();
    let mut core = harness.open();
    let key = enroll(&mut core);
    let shared = Shared::new(core);
    let (first, second) = run_queued(
        &harness,
        &shared,
        |core| core.verify_password(990, PASSWORD),
        move |core| core.recover_password(&key, "another long passphrase"),
    );
    assert_eq!(first, Ok(()));
    assert_eq!(second, Ok(()));
    // The reverse order: a reset committed first is seen by the queued call.
    let harness = Harness::new();
    let mut core = harness.open();
    let key = enroll(&mut core);
    let shared = Shared::new(core);
    let (first, second) = run_queued(
        &harness,
        &shared,
        |core| {
            let result = core.verify_password(990, PASSWORD);
            core.reset_enrollment()?;
            result
        },
        move |core| core.recover_password(&key, "another long passphrase"),
    );
    assert_eq!(first, Ok(()));
    assert_eq!(second, Err(Failure::NotEnrolled));
}
