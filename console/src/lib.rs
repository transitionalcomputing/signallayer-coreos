//! State and fixed D-Bus operations for the local appliance console.
#![allow(async_fn_in_trait)]

use sl_protocol::{RemoteManagementStatus, SessionStatus, SESSION_SCHEMA_VERSION};
use std::time::Duration;

const AUTH_BUS: &str = "org.signallayer.Auth1";
const AUTH_PATH: &str = "/org/signallayer/Auth1";
const PLATFORM_BUS: &str = "org.signallayer.Platform1";
const PLATFORM_PATH: &str = "/org/signallayer/Platform1";
const SESSION_BUS: &str = "org.signallayer.Session1";
const SESSION_PATH: &str = "/org/signallayer/Session1";
const CALL_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrollment {
    pub url: String,
    pub fingerprint: String,
    pub pairing_code: String,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct View {
    pub product: String,
    pub version: String,
    pub machine_id: String,
    pub remote: RemoteManagementStatus,
    pub enrollment: Enrollment,
    pub authenticated: bool,
    pub reset_incomplete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Enable,
    Disable,
    Reenroll,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailure {
    NotEnrolled,
    EnrollmentUnconfirmed,
    InvalidCredential,
    PasswordRejected,
    RateLimited,
    Busy,
    InvalidArgument,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformFailure {
    ResetIncomplete,
    Busy,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleError {
    AuthenticationRequired,
    Auth(AuthFailure),
    Platform(PlatformFailure),
    StatusUnavailable,
}

pub trait Backend {
    async fn status(&self) -> Result<SessionStatus, ConsoleError>;
    async fn enrollment(&self) -> Result<Enrollment, ConsoleError>;
    async fn verify_password(&self, password: &str) -> Result<(), AuthFailure>;
    async fn recover_password(
        &self,
        recovery_key: &str,
        new_password: &str,
    ) -> Result<(), AuthFailure>;
    async fn platform(&self, action: Action) -> Result<(), PlatformFailure>;
}

pub struct Controller<B> {
    backend: B,
    authenticated: bool,
    last_enrolled: Option<bool>,
    reset_incomplete: bool,
}

impl<B: Backend> Controller<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            authenticated: false,
            last_enrolled: None,
            reset_incomplete: false,
        }
    }

    async fn status(&mut self) -> Result<SessionStatus, ConsoleError> {
        let status = self.backend.status().await?;
        let enrolled = status.remote_management.enrolled;
        if self
            .last_enrolled
            .is_some_and(|previous| previous != enrolled)
        {
            self.authenticated = false;
        }
        self.last_enrolled = Some(enrolled);
        Ok(status)
    }

    pub async fn refresh(&mut self) -> Result<View, ConsoleError> {
        let status = self.status().await?;
        let enrollment = self.backend.enrollment().await?;
        Ok(View {
            product: status.product,
            version: status.version,
            machine_id: status.machine.machine_id,
            remote: status.remote_management,
            enrollment,
            authenticated: self.authenticated,
            reset_incomplete: self.reset_incomplete,
        })
    }

    pub async fn authenticate(&mut self, password: &str) -> Result<(), ConsoleError> {
        if !self.status().await?.remote_management.enrolled {
            self.authenticated = false;
            return Err(ConsoleError::Auth(AuthFailure::NotEnrolled));
        }
        self.backend
            .verify_password(password)
            .await
            .map_err(ConsoleError::Auth)?;
        // Do not publish a successful authentication if enrollment changed
        // while verification was in flight.
        if !self.status().await?.remote_management.enrolled {
            self.authenticated = false;
            return Err(ConsoleError::Auth(AuthFailure::NotEnrolled));
        }
        self.authenticated = true;
        Ok(())
    }

    pub fn logout(&mut self) {
        self.authenticated = false;
    }

    pub async fn act(&mut self, action: Action) -> Result<View, ConsoleError> {
        let enrolled = self.status().await?.remote_management.enrolled;
        if enrolled && !self.authenticated {
            return Err(ConsoleError::AuthenticationRequired);
        }
        if action == Action::Enable && self.reset_incomplete {
            return Err(ConsoleError::Platform(PlatformFailure::ResetIncomplete));
        }
        if let Err(error) = self.backend.platform(action).await {
            if error == PlatformFailure::ResetIncomplete {
                self.reset_incomplete = true;
            }
            return Err(ConsoleError::Platform(error));
        }
        if action == Action::Reenroll {
            self.authenticated = false;
            self.reset_incomplete = false;
        }
        self.refresh().await
    }

    pub async fn recover_password(
        &mut self,
        recovery_key: &str,
        new_password: &str,
    ) -> Result<View, ConsoleError> {
        self.backend
            .recover_password(recovery_key, new_password)
            .await
            .map_err(ConsoleError::Auth)?;
        self.authenticated = false;
        self.refresh().await
    }
}

pub struct BusBackend {
    connection: zbus::Connection,
}

impl BusBackend {
    pub async fn connect() -> Result<Self, ConsoleError> {
        let connection = zbus::connection::Builder::system()
            .map_err(|_| ConsoleError::StatusUnavailable)?
            .build()
            .await
            .map_err(|_| ConsoleError::StatusUnavailable)?;
        Ok(Self { connection })
    }

    async fn call<B, R>(
        &self,
        bus: &'static str,
        path: &'static str,
        member: &'static str,
        body: &B,
    ) -> Result<R, zbus::Error>
    where
        B: serde::Serialize + zbus::zvariant::DynamicType + Sync,
        R: for<'d> serde::Deserialize<'d> + zbus::zvariant::Type,
    {
        tokio::time::timeout(CALL_TIMEOUT, async {
            let proxy = zbus::Proxy::new(&self.connection, bus, path, bus).await?;
            proxy.call(member, body).await
        })
        .await
        .map_err(|_| zbus::Error::Failure("local service request timed out".into()))?
    }
}

impl Backend for BusBackend {
    async fn status(&self) -> Result<SessionStatus, ConsoleError> {
        let text: String = self
            .call(SESSION_BUS, SESSION_PATH, "GetPlatformStatus", &())
            .await
            .map_err(|_| ConsoleError::StatusUnavailable)?;
        let status: SessionStatus =
            serde_json::from_str(&text).map_err(|_| ConsoleError::StatusUnavailable)?;
        (status.schema_version == SESSION_SCHEMA_VERSION)
            .then_some(status)
            .ok_or(ConsoleError::StatusUnavailable)
    }

    async fn enrollment(&self) -> Result<Enrollment, ConsoleError> {
        let (url, fingerprint, pairing_code, expires_at) = self
            .call(
                PLATFORM_BUS,
                PLATFORM_PATH,
                "GetRemoteManagementEnrollment",
                &(),
            )
            .await
            .map_err(|error| ConsoleError::Platform(platform_failure(&error)))?;
        Ok(Enrollment {
            url,
            fingerprint,
            pairing_code,
            expires_at,
        })
    }

    async fn verify_password(&self, password: &str) -> Result<(), AuthFailure> {
        self.call(AUTH_BUS, AUTH_PATH, "VerifyPassword", &(password,))
            .await
            .map_err(|error| auth_failure(&error))
    }

    async fn recover_password(
        &self,
        recovery_key: &str,
        new_password: &str,
    ) -> Result<(), AuthFailure> {
        self.call(
            AUTH_BUS,
            AUTH_PATH,
            "RecoverPassword",
            &(recovery_key, new_password),
        )
        .await
        .map_err(|error| auth_failure(&error))
    }

    async fn platform(&self, action: Action) -> Result<(), PlatformFailure> {
        let member = match action {
            Action::Enable => "EnableRemoteManagement",
            Action::Disable => "DisableRemoteManagement",
            Action::Reenroll => "ReenrollRemoteManagement",
        };
        self.call(PLATFORM_BUS, PLATFORM_PATH, member, &())
            .await
            .map_err(|error| platform_failure(&error))
    }
}

fn error_code<'a>(error: &'a zbus::Error, prefix: &str) -> Option<&'a str> {
    match error {
        zbus::Error::MethodError(name, _, _) => name.as_str().strip_prefix(prefix),
        _ => None,
    }
}

fn auth_failure(error: &zbus::Error) -> AuthFailure {
    match error_code(error, "org.signallayer.Auth1.Error.") {
        Some("NotEnrolled") => AuthFailure::NotEnrolled,
        Some("EnrollmentUnconfirmed") => AuthFailure::EnrollmentUnconfirmed,
        Some("InvalidCredential") => AuthFailure::InvalidCredential,
        Some("PasswordRejected") => AuthFailure::PasswordRejected,
        Some("RateLimited") => AuthFailure::RateLimited,
        Some("Busy") => AuthFailure::Busy,
        Some("InvalidArgument") => AuthFailure::InvalidArgument,
        _ => AuthFailure::Unavailable,
    }
}

fn platform_failure(error: &zbus::Error) -> PlatformFailure {
    match error_code(error, "org.signallayer.Platform1.Error.") {
        Some("ResetIncomplete") => PlatformFailure::ResetIncomplete,
        Some("Busy") => PlatformFailure::Busy,
        _ => PlatformFailure::Unavailable,
    }
}

#[cfg(test)]
mod tests;
