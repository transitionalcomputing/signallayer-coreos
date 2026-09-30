//! sl-remoted's only D-Bus peers: org.signallayer.Auth1 and
//! org.signallayer.Session1.
use std::{future::poll_fn, io, pin::Pin, time::Duration};
use zbus::export::async_trait::async_trait;
use zbus::export::futures_core::Stream;

const AUTH_BUS: &str = "org.signallayer.Auth1";
const AUTH_PATH: &str = "/org/signallayer/Auth1";
const AUTH_ERROR_PREFIX: &str = "org.signallayer.Auth1.Error.";
const SESSION_BUS: &str = "org.signallayer.Session1";
const SESSION_PATH: &str = "/org/signallayer/Session1";
/// Argon2id admission can queue several hashes.
const AUTH_TIMEOUT: Duration = Duration::from_secs(30);
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(20);

/// An exact-name owner-change subscription installed before the first status
/// fetch. Any owner change invalidates Session1-derived state; only a later
/// successful status fetch may establish it again.
pub struct SessionOwnerEvents {
    changes: zbus::proxy::OwnerChangedStream<'static>,
}

impl SessionOwnerEvents {
    pub async fn new(connection: &zbus::Connection) -> zbus::Result<Self> {
        let proxy = zbus::Proxy::new(connection, SESSION_BUS, SESSION_PATH, SESSION_BUS).await?;
        let changes = proxy.receive_owner_changed().await?;
        Ok(Self { changes })
    }

    pub async fn changed(&mut self) -> io::Result<()> {
        match poll_fn(|context| Pin::new(&mut self.changes).poll_next(context)).await {
            Some(_) => Ok(()),
            None => Err(io::Error::other("Session1 owner-change stream ended")),
        }
    }
}

/// The frozen Auth1 errors; anything else (including bus failures and
/// timeouts) is `Unavailable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailure {
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

impl AuthFailure {
    pub fn from_error_name(name: &str) -> Self {
        match name.strip_prefix(AUTH_ERROR_PREFIX) {
            Some("NotEnrolled") => Self::NotEnrolled,
            Some("EnrollmentUnconfirmed") => Self::EnrollmentUnconfirmed,
            Some("AlreadyEnrolled") => Self::AlreadyEnrolled,
            Some("NoPendingPairing") => Self::NoPendingPairing,
            Some("InvalidPairingCode") => Self::InvalidPairingCode,
            Some("PairingAttemptsExhausted") => Self::PairingAttemptsExhausted,
            Some("NoProvisionalEnrollment") => Self::NoProvisionalEnrollment,
            Some("ConfirmationExpired") => Self::ConfirmationExpired,
            Some("InvalidCredential") => Self::InvalidCredential,
            Some("PasswordRejected") => Self::PasswordRejected,
            Some("RateLimited") => Self::RateLimited,
            Some("Busy") => Self::Busy,
            Some("InvalidArgument") => Self::InvalidArgument,
            _ => Self::Unavailable,
        }
    }
}

#[async_trait]
pub trait Auth: Send + Sync {
    async fn verify_password(&self, password: String) -> Result<(), AuthFailure>;
    /// Returns the recovery key, exactly once.
    async fn consume_pairing(
        &self,
        pairing_code: String,
        new_password: String,
    ) -> Result<String, AuthFailure>;
    async fn confirm_recovery_key(&self, recovery_key: String) -> Result<(), AuthFailure>;
}

#[async_trait]
pub trait StatusSource: Send + Sync {
    /// Session1's status (schema 0.4) as the JSON text Session1 returned.
    async fn status(&self) -> Result<String, ()>;
}

pub struct BusAuth {
    pub connection: zbus::Connection,
}

impl BusAuth {
    async fn call<B, R>(&self, member: &'static str, body: &B) -> Result<R, AuthFailure>
    where
        B: serde::Serialize + zbus::zvariant::DynamicType + Sync,
        R: for<'d> serde::Deserialize<'d> + zbus::zvariant::Type,
    {
        let call = async {
            let proxy = zbus::Proxy::new(&self.connection, AUTH_BUS, AUTH_PATH, AUTH_BUS).await?;
            proxy.call::<_, B, R>(member, body).await
        };
        match tokio::time::timeout(AUTH_TIMEOUT, call).await {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(zbus::Error::MethodError(name, _, _))) => {
                Err(AuthFailure::from_error_name(name.as_str()))
            }
            _ => Err(AuthFailure::Unavailable),
        }
    }
}

#[async_trait]
impl Auth for BusAuth {
    async fn verify_password(&self, password: String) -> Result<(), AuthFailure> {
        self.call("VerifyPassword", &(password,)).await
    }

    async fn consume_pairing(
        &self,
        pairing_code: String,
        new_password: String,
    ) -> Result<String, AuthFailure> {
        self.call("ConsumePairing", &(pairing_code, new_password))
            .await
    }

    async fn confirm_recovery_key(&self, recovery_key: String) -> Result<(), AuthFailure> {
        self.call("ConfirmRecoveryKey", &(recovery_key,)).await
    }
}

pub struct BusSession {
    pub connection: zbus::Connection,
}

#[async_trait]
impl StatusSource for BusSession {
    async fn status(&self) -> Result<String, ()> {
        let call = async {
            let proxy =
                zbus::Proxy::new(&self.connection, SESSION_BUS, SESSION_PATH, SESSION_BUS).await?;
            proxy.call::<_, _, String>("GetPlatformStatus", &()).await
        };
        match tokio::time::timeout(SESSION_TIMEOUT, call).await {
            Ok(Ok(status)) => Ok(status),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_frozen_auth_error_name_maps_and_others_are_unavailable() {
        for (name, failure) in [
            ("NotEnrolled", AuthFailure::NotEnrolled),
            ("EnrollmentUnconfirmed", AuthFailure::EnrollmentUnconfirmed),
            ("AlreadyEnrolled", AuthFailure::AlreadyEnrolled),
            ("NoPendingPairing", AuthFailure::NoPendingPairing),
            ("InvalidPairingCode", AuthFailure::InvalidPairingCode),
            (
                "PairingAttemptsExhausted",
                AuthFailure::PairingAttemptsExhausted,
            ),
            (
                "NoProvisionalEnrollment",
                AuthFailure::NoProvisionalEnrollment,
            ),
            ("ConfirmationExpired", AuthFailure::ConfirmationExpired),
            ("InvalidCredential", AuthFailure::InvalidCredential),
            ("PasswordRejected", AuthFailure::PasswordRejected),
            ("RateLimited", AuthFailure::RateLimited),
            ("Busy", AuthFailure::Busy),
            ("InvalidArgument", AuthFailure::InvalidArgument),
            ("Unavailable", AuthFailure::Unavailable),
        ] {
            assert_eq!(
                AuthFailure::from_error_name(&format!("{AUTH_ERROR_PREFIX}{name}")),
                failure
            );
        }
        for other in [
            "org.freedesktop.DBus.Error.AccessDenied",
            "org.signallayer.Auth1.Error.Something",
            "InvalidCredential",
        ] {
            assert_eq!(
                AuthFailure::from_error_name(other),
                AuthFailure::Unavailable
            );
        }
    }
}
