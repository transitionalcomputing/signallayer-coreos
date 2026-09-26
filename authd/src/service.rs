use crate::machine::{Core, Failure};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use zbus::{message::Header, names::BusName, Connection};

/// One active Argon2id operation plus a queue of 4.
pub const MAX_ADMITTED: usize = 5;

/// Serializes every operation on one lock, so a queued request reads state and
/// backoff only when it runs, after every earlier commit.
pub struct Shared {
    core: Mutex<Core>,
    admitted: AtomicUsize,
}

pub struct Permit(Arc<Shared>);

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.admitted.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Shared {
    pub fn new(core: Core) -> Arc<Self> {
        Arc::new(Self {
            core: Mutex::new(core),
            admitted: AtomicUsize::new(0),
        })
    }

    /// Admission happens before the lock and before any counter or state is
    /// read or changed.
    pub fn admit(self: &Arc<Self>) -> Result<Permit, Failure> {
        self.admitted
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |admitted| {
                (admitted < MAX_ADMITTED).then_some(admitted + 1)
            })
            .map(|_| Permit(Arc::clone(self)))
            .map_err(|_| Failure::Busy)
    }

    pub fn with_core<T>(
        &self,
        operation: impl FnOnce(&mut Core) -> Result<T, Failure>,
    ) -> Result<T, Failure> {
        let mut core = self.core.lock().map_err(|_| Failure::Unavailable)?;
        operation(&mut core)
    }
}

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.signallayer.Auth1.Error")]
pub enum AuthError {
    NotEnrolled(String),
    EnrollmentUnconfirmed(String),
    AlreadyEnrolled(String),
    NoPendingPairing(String),
    InvalidPairingCode(String),
    PairingAttemptsExhausted(String),
    NoProvisionalEnrollment(String),
    ConfirmationExpired(String),
    InvalidCredential(String),
    PasswordRejected(String),
    RateLimited(String),
    Busy(String),
    InvalidArgument(String),
    Unavailable(String),
    #[zbus(error)]
    ZBus(zbus::Error),
}

/// Fixed messages only: no argument, secret or counter ever reaches a reply.
pub fn to_dbus(failure: Failure) -> AuthError {
    let message = |text: &str| text.to_owned();
    match failure {
        Failure::NotEnrolled => AuthError::NotEnrolled(message("No operator is enrolled")),
        Failure::EnrollmentUnconfirmed => AuthError::EnrollmentUnconfirmed(message(
            "A provisional enrollment awaits recovery-key confirmation",
        )),
        Failure::AlreadyEnrolled => {
            AuthError::AlreadyEnrolled(message("An operator is already enrolled"))
        }
        Failure::NoPendingPairing => AuthError::NoPendingPairing(message("No pairing is pending")),
        Failure::InvalidPairingCode => {
            AuthError::InvalidPairingCode(message("The pairing code is incorrect"))
        }
        Failure::PairingAttemptsExhausted => AuthError::PairingAttemptsExhausted(message(
            "Too many incorrect pairing codes; the pairing was cancelled",
        )),
        Failure::NoProvisionalEnrollment => AuthError::NoProvisionalEnrollment(message(
            "No provisional enrollment awaits confirmation",
        )),
        Failure::ConfirmationExpired => AuthError::ConfirmationExpired(message(
            "The confirmation deadline passed; the provisional enrollment was discarded",
        )),
        Failure::InvalidCredential => {
            AuthError::InvalidCredential(message("The credential is incorrect"))
        }
        Failure::PasswordRejected => AuthError::PasswordRejected(message(
            "The new password does not meet the password rules",
        )),
        Failure::RateLimited => {
            AuthError::RateLimited(message("Too many attempts; try again later"))
        }
        Failure::Busy => AuthError::Busy(message("Authentication is busy; try again")),
        Failure::InvalidArgument => AuthError::InvalidArgument(message("An argument is invalid")),
        Failure::Unavailable => {
            AuthError::Unavailable(message("Authentication state is unavailable"))
        }
    }
}

fn outcome<T>(result: &Result<T, Failure>) -> String {
    match result {
        Ok(_) => "ok".into(),
        Err(failure) => format!("{failure:?}"),
    }
}

/// Journal line for an operation: the method, an optional caller UID and the
/// outcome name. It never includes arguments.
pub fn event_line<T>(method: &str, uid: Option<u32>, result: &Result<T, Failure>) -> String {
    match uid {
        Some(uid) => format!("sl-authd: {method} uid={uid}: {}", outcome(result)),
        None => format!("sl-authd: {method}: {}", outcome(result)),
    }
}

pub struct AuthService {
    pub shared: Arc<Shared>,
}

async fn run<T: Send + 'static>(
    shared: &Arc<Shared>,
    method: &'static str,
    uid: Option<u32>,
    permit: Option<Permit>,
    operation: impl FnOnce(&mut Core) -> Result<T, Failure> + Send + 'static,
) -> Result<T, AuthError> {
    let shared = Arc::clone(shared);
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        shared.with_core(operation)
    })
    .await
    .unwrap_or(Err(Failure::Unavailable));
    eprintln!("{}", event_line(method, uid, &result));
    result.map_err(to_dbus)
}

fn admit(shared: &Arc<Shared>, method: &str) -> Result<Permit, AuthError> {
    shared.admit().map_err(|failure| {
        eprintln!("{}", event_line::<()>(method, None, &Err(failure)));
        to_dbus(failure)
    })
}

async fn sender_uid(connection: &Connection, header: &Header<'_>) -> Result<u32, AuthError> {
    let unavailable = || to_dbus(Failure::Unavailable);
    let sender = header.sender().ok_or_else(unavailable)?.to_owned();
    zbus::fdo::DBusProxy::new(connection)
        .await
        .map_err(|_| unavailable())?
        .get_connection_unix_user(BusName::Unique(sender.into()))
        .await
        .map_err(|_| unavailable())
}

#[zbus::interface(name = "org.signallayer.Auth1")]
impl AuthService {
    async fn verify_password(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
        password: String,
    ) -> Result<(), AuthError> {
        let permit = admit(&self.shared, "VerifyPassword")?;
        let uid = sender_uid(connection, &header).await?;
        run(
            &self.shared,
            "VerifyPassword",
            Some(uid),
            Some(permit),
            move |core| core.verify_password(uid, &password),
        )
        .await
    }

    async fn consume_pairing(
        &self,
        pairing_code: String,
        new_password: String,
    ) -> Result<String, AuthError> {
        let permit = admit(&self.shared, "ConsumePairing")?;
        run(
            &self.shared,
            "ConsumePairing",
            None,
            Some(permit),
            move |core| core.consume_pairing(&pairing_code, &new_password),
        )
        .await
    }

    async fn confirm_recovery_key(&self, recovery_key: String) -> Result<(), AuthError> {
        let permit = admit(&self.shared, "ConfirmRecoveryKey")?;
        run(
            &self.shared,
            "ConfirmRecoveryKey",
            None,
            Some(permit),
            move |core| core.confirm_recovery_key(&recovery_key),
        )
        .await
    }

    async fn recover_password(
        &self,
        recovery_key: String,
        new_password: String,
    ) -> Result<(), AuthError> {
        let permit = admit(&self.shared, "RecoverPassword")?;
        run(
            &self.shared,
            "RecoverPassword",
            None,
            Some(permit),
            move |core| core.recover_password(&recovery_key, &new_password),
        )
        .await
    }

    async fn ensure_pending_pairing(&self) -> Result<(), AuthError> {
        run(
            &self.shared,
            "EnsurePendingPairing",
            None,
            None,
            Core::ensure_pending_pairing,
        )
        .await
    }

    async fn cancel_pending_pairing(&self) -> Result<(), AuthError> {
        run(
            &self.shared,
            "CancelPendingPairing",
            None,
            None,
            Core::cancel_pending_pairing,
        )
        .await
    }

    async fn reset_enrollment(&self) -> Result<(), AuthError> {
        run(
            &self.shared,
            "ResetEnrollment",
            None,
            None,
            Core::reset_enrollment,
        )
        .await
    }

    async fn get_pending_pairing(&self) -> Result<(bool, String, u64), AuthError> {
        run(
            &self.shared,
            "GetPendingPairing",
            None,
            None,
            Core::get_pending_pairing,
        )
        .await
    }

    async fn get_enrollment_state(&self) -> Result<(bool, bool), AuthError> {
        run(
            &self.shared,
            "GetEnrollmentState",
            None,
            None,
            Core::get_enrollment_state,
        )
        .await
    }
}

#[cfg(test)]
mod tests;
