//! Focused client for the local SignalLayer Platform 0.2 D-Bus API.

use sl_protocol::{PlatformProxy, Status, SCHEMA_VERSION};
use std::{error::Error as StdError, fmt, io, time::Duration};

pub const METHOD_TIMEOUT: Duration = Duration::from_secs(25);

#[derive(Debug, PartialEq, Eq)]
pub enum ClientError {
    SystemBusUnavailable,
    ServiceUnavailable,
    RemoteMethod { code: String, message: String },
    InvalidResponse,
    UnsupportedSchema,
    Unsupported,
    RebootOutcomeUnknown,
}

impl ClientError {
    pub fn code(&self) -> &str {
        match self {
            Self::SystemBusUnavailable | Self::ServiceUnavailable => "ServiceUnavailable",
            Self::RemoteMethod { code, .. } => code,
            Self::InvalidResponse => "InvalidResponse",
            Self::UnsupportedSchema => "UnsupportedSchema",
            Self::Unsupported => "Unsupported",
            Self::RebootOutcomeUnknown => "OutcomeUnknown",
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::SystemBusUnavailable => "The system D-Bus is unavailable",
            Self::ServiceUnavailable => "The local platform status service could not be reached",
            Self::RemoteMethod { message, .. } => message,
            Self::InvalidResponse => "The platform returned an invalid status response",
            Self::UnsupportedSchema => "The platform status schema is unsupported",
            Self::Unsupported => "The platform API version does not support this operation",
            Self::RebootOutcomeUnknown => {
                "Reboot request outcome unknown: connection closed while awaiting confirmation; \
                 the system may be rebooting."
            }
        }
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code(), self.message())
    }
}

impl StdError for ClientError {}

/// The Platform API version reported in status, as `major.minor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PlatformApiVersion {
    pub major: u32,
    pub minor: u32,
}

impl PlatformApiVersion {
    pub fn parse(value: &str) -> Option<Self> {
        let (major, minor) = value.split_once('.')?;
        Some(Self {
            major: version_component(major)?,
            minor: version_component(minor)?,
        })
    }

    /// True when this version is at least `major.minor`.
    pub fn supports(self, major: u32, minor: u32) -> bool {
        self >= Self { major, minor }
    }
}

fn version_component(value: &str) -> Option<u32> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

#[derive(Clone)]
pub struct PlatformClient {
    connection: zbus::Connection,
}

impl PlatformClient {
    pub async fn connect() -> Result<Self, ClientError> {
        let builder =
            zbus::connection::Builder::system().map_err(|_| ClientError::SystemBusUnavailable)?;
        let connection = builder
            .method_timeout(METHOD_TIMEOUT)
            .build()
            .await
            .map_err(|_| ClientError::SystemBusUnavailable)?;
        Ok(Self { connection })
    }

    async fn proxy(&self) -> Result<PlatformProxy<'_>, ClientError> {
        PlatformProxy::builder(&self.connection)
            .cache_properties(zbus::proxy::CacheProperties::No)
            .build()
            .await
            .map_err(map_bus_error)
    }

    pub async fn get_status(&self) -> Result<Status, ClientError> {
        let response = self
            .proxy()
            .await?
            .get_status()
            .await
            .map_err(map_bus_error)?;
        decode_status(&response)
    }

    pub async fn start_update(&self) -> Result<(), ClientError> {
        self.proxy()
            .await?
            .start_update()
            .await
            .map_err(map_bus_error)
    }

    pub async fn start_rollback(&self) -> Result<(), ClientError> {
        self.proxy()
            .await?
            .start_rollback()
            .await
            .map_err(map_bus_error)
    }

    /// Requests the fixed controlled reboot. A caller must not assume
    /// StartReboot exists below Platform API 0.2, so status is read first.
    pub async fn start_reboot(&self) -> Result<(), ClientError> {
        require_reboot_support(self.get_status().await)?;
        self.proxy()
            .await?
            .start_reboot()
            .await
            .map_err(map_reboot_error)
    }
}

fn require_reboot_support(status: Result<Status, ClientError>) -> Result<(), ClientError> {
    let status = status?;
    let version = PlatformApiVersion::parse(&status.platform_api_version)
        .ok_or(ClientError::InvalidResponse)?;
    if !version.supports(0, 2) {
        return Err(ClientError::Unsupported);
    }
    Ok(())
}

fn decode_status(response: &str) -> Result<Status, ClientError> {
    let status: Status =
        serde_json::from_str(response).map_err(|_| ClientError::InvalidResponse)?;
    if status.schema_version != SCHEMA_VERSION {
        return Err(ClientError::UnsupportedSchema);
    }
    Ok(status)
}

// The request has already been sent when the connection closes, or the method
// deadline expires, while its reply is pending, so a controlled reboot may be
// underway.
fn map_reboot_error(error: zbus::Error) -> ClientError {
    if let zbus::Error::InputOutput(io_error) = &error {
        if matches!(
            io_error.kind(),
            io::ErrorKind::BrokenPipe
                | io::ErrorKind::UnexpectedEof
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::TimedOut
        ) {
            return ClientError::RebootOutcomeUnknown;
        }
    }
    map_bus_error(error)
}

fn map_bus_error(error: zbus::Error) -> ClientError {
    if let zbus::Error::MethodError(name, message, _) = error {
        if let Some(code) = name
            .as_str()
            .strip_prefix("org.signallayer.Platform1.Error.")
        {
            return ClientError::RemoteMethod {
                code: code.into(),
                message: message
                    .as_deref()
                    .unwrap_or("Platform status query failed")
                    .into(),
            };
        }
    }
    ClientError::ServiceUnavailable
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status_json(schema_version: &str) -> String {
        serde_json::json!({
            "schema_version": schema_version,
            "product": "SignalLayerIT CoreOS",
            "version": "0.0.1",
            "platform_api_version": "0.2",
            "source_revision": null,
            "build_id": null,
            "machine": {
                "machine_id": "0123456789abcdef0123456789abcdef",
                "architecture": "x86_64",
                "boot_id": "01234567-89ab-cdef-0123-456789abcdef"
            },
            "network": {
                "state": "connected_global",
                "primary_connection": {
                    "interface": "enp0s2",
                    "addresses": ["10.0.2.15/24"],
                    "default_gateways": ["10.0.2.2"]
                }
            },
            "booted": {
                "deployment_id": "abc.0",
                "image_reference": "localhost/signallayer-coreos:0.0.1",
                "image_digest": "sha256:abc"
            },
            "retained_rollback": null,
            "update": {
                "state": "idle",
                "staged": null,
                "reboot_required": false,
                "failure": null
            },
            "rollback": {
                "state": "idle",
                "reboot_required": false,
                "failure": null
            },
            "health": {
                "state": "healthy",
                "system_state": "running",
                "failed_units": 0
            }
        })
        .to_string()
    }

    #[test]
    fn accepts_exact_phase_4c_schema() {
        let status = decode_status(&status_json("0.3")).expect("valid status");
        assert_eq!(status.schema_version, "0.3");
        assert_eq!(status.platform_api_version, "0.2");
        assert_eq!(status.machine.architecture, "x86_64");
        assert_eq!(
            status.network.primary_connection.unwrap().interface,
            "enp0s2"
        );
    }

    #[test]
    fn rejects_other_schema_versions() {
        assert_eq!(
            decode_status(&status_json("0.2")).unwrap_err(),
            ClientError::UnsupportedSchema
        );
        assert_eq!(
            decode_status(&status_json("0.4")).unwrap_err(),
            ClientError::UnsupportedSchema
        );
    }

    #[test]
    fn rejects_unknown_status_fields() {
        let mut value: serde_json::Value = serde_json::from_str(&status_json("0.3")).unwrap();
        value["future_field"] = serde_json::json!(true);
        assert_eq!(
            decode_status(&value.to_string()).unwrap_err(),
            ClientError::InvalidResponse
        );
    }

    #[test]
    fn rejects_missing_or_malformed_management_status() {
        let mut missing: serde_json::Value = serde_json::from_str(&status_json("0.3")).unwrap();
        missing.as_object_mut().unwrap().remove("machine");
        assert_eq!(
            decode_status(&missing.to_string()).unwrap_err(),
            ClientError::InvalidResponse
        );

        let mut malformed: serde_json::Value = serde_json::from_str(&status_json("0.3")).unwrap();
        malformed["network"]["primary_connection"]["addresses"] = serde_json::json!("10.0.2.15/24");
        assert_eq!(
            decode_status(&malformed.to_string()).unwrap_err(),
            ClientError::InvalidResponse
        );
    }

    #[test]
    fn client_errors_preserve_corectl_contract() {
        let remote = ClientError::RemoteMethod {
            code: "Busy".into(),
            message: "An update operation is already running".into(),
        };
        assert_eq!(remote.code(), "Busy");
        assert_eq!(remote.message(), "An update operation is already running");
        assert_eq!(
            ClientError::SystemBusUnavailable.code(),
            "ServiceUnavailable"
        );
    }

    fn status_with_api(version: &str) -> Status {
        let mut value: serde_json::Value = serde_json::from_str(&status_json("0.3")).unwrap();
        value["platform_api_version"] = serde_json::json!(version);
        decode_status(&value.to_string()).expect("status reads stay permissive")
    }

    #[test]
    fn platform_api_versions_parse_as_major_minor() {
        assert_eq!(
            PlatformApiVersion::parse("0.2"),
            Some(PlatformApiVersion { major: 0, minor: 2 })
        );
        assert_eq!(
            PlatformApiVersion::parse("1.10"),
            Some(PlatformApiVersion {
                major: 1,
                minor: 10
            })
        );
        for invalid in [
            "", "0", "0.", ".2", "0.2.1", "v0.2", " 0.2", "0.+2", "0.-1", "a.b",
        ] {
            assert_eq!(PlatformApiVersion::parse(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn platform_api_support_is_numeric() {
        let supports = |value| PlatformApiVersion::parse(value).unwrap().supports(0, 2);
        assert!(!supports("0.1"));
        assert!(supports("0.2"));
        assert!(supports("0.10"));
        assert!(supports("1.0"));
    }

    #[test]
    fn start_reboot_is_unsupported_below_platform_api_0_2() {
        assert_eq!(
            require_reboot_support(Ok(status_with_api("0.1"))).unwrap_err(),
            ClientError::Unsupported
        );
        assert_eq!(
            require_reboot_support(Ok(status_with_api("0.0"))).unwrap_err(),
            ClientError::Unsupported
        );
        assert!(require_reboot_support(Ok(status_with_api("0.2"))).is_ok());
        assert!(require_reboot_support(Ok(status_with_api("0.3"))).is_ok());
    }

    #[test]
    fn unparseable_platform_api_version_is_an_invalid_response() {
        assert_eq!(
            require_reboot_support(Ok(status_with_api("zero.two"))).unwrap_err(),
            ClientError::InvalidResponse
        );
    }

    #[test]
    fn failed_status_read_keeps_its_client_error() {
        for error in [
            ClientError::ServiceUnavailable,
            ClientError::SystemBusUnavailable,
            ClientError::UnsupportedSchema,
            ClientError::InvalidResponse,
        ] {
            let expected = format!("{error:?}");
            let actual = require_reboot_support(Err(error)).unwrap_err();
            assert_eq!(format!("{actual:?}"), expected);
        }
    }

    #[test]
    fn status_reads_accept_future_platform_api_versions() {
        assert_eq!(status_with_api("7.3").platform_api_version, "7.3");
        assert_eq!(
            status_with_api("not-a-version").platform_api_version,
            "not-a-version"
        );
    }

    #[test]
    fn closed_connection_during_reboot_is_an_unknown_outcome() {
        for kind in [
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::UnexpectedEof,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
        ] {
            let error = zbus::Error::InputOutput(io::Error::new(kind, "socket closed").into());
            assert_eq!(map_reboot_error(error), ClientError::RebootOutcomeUnknown);
        }
        let kind = io::ErrorKind::ConnectionRefused;
        let refused = zbus::Error::from(io::Error::new(kind, "refused"));
        assert_eq!(map_reboot_error(refused), ClientError::ServiceUnavailable);
        assert_eq!(
            ClientError::RebootOutcomeUnknown.message(),
            "Reboot request outcome unknown: connection closed while awaiting confirmation; \
             the system may be rebooting."
        );
    }

    #[test]
    fn timed_out_reboot_reply_is_an_unknown_outcome() {
        // zbus 5.19 reports an elapsed method timeout as an io::Error with
        // ErrorKind::TimedOut, converted through From.
        let timed_out = zbus::Error::from(io::Error::new(io::ErrorKind::TimedOut, "timed out"));
        assert_eq!(map_reboot_error(timed_out), ClientError::RebootOutcomeUnknown);
    }
}
