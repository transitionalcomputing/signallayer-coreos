//! Focused client for the local SignalLayer Platform 0.1 D-Bus API.

use sl_protocol::{PlatformProxy, Status, SCHEMA_VERSION};
use std::{error::Error as StdError, fmt, time::Duration};

pub const METHOD_TIMEOUT: Duration = Duration::from_secs(25);

#[derive(Debug, PartialEq, Eq)]
pub enum ClientError {
    SystemBusUnavailable,
    ServiceUnavailable,
    RemoteMethod { code: String, message: String },
    InvalidResponse,
    UnsupportedSchema,
}

impl ClientError {
    pub fn code(&self) -> &str {
        match self {
            Self::SystemBusUnavailable | Self::ServiceUnavailable => "ServiceUnavailable",
            Self::RemoteMethod { code, .. } => code,
            Self::InvalidResponse => "InvalidResponse",
            Self::UnsupportedSchema => "UnsupportedSchema",
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::SystemBusUnavailable => "The system D-Bus is unavailable",
            Self::ServiceUnavailable => "The local platform status service could not be reached",
            Self::RemoteMethod { message, .. } => message,
            Self::InvalidResponse => "The platform returned an invalid status response",
            Self::UnsupportedSchema => "The platform status schema is unsupported",
        }
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code(), self.message())
    }
}

impl StdError for ClientError {}

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
}

fn decode_status(response: &str) -> Result<Status, ClientError> {
    let status: Status =
        serde_json::from_str(response).map_err(|_| ClientError::InvalidResponse)?;
    if status.schema_version != SCHEMA_VERSION {
        return Err(ClientError::UnsupportedSchema);
    }
    Ok(status)
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
            "platform_api_version": "0.1",
            "source_revision": null,
            "build_id": null,
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
    fn accepts_exact_phase_4b_schema() {
        let status = decode_status(&status_json("0.2")).expect("valid status");
        assert_eq!(status.schema_version, "0.2");
        assert_eq!(status.platform_api_version, "0.1");
    }

    #[test]
    fn rejects_other_schema_versions() {
        assert_eq!(
            decode_status(&status_json("0.3")).unwrap_err(),
            ClientError::UnsupportedSchema
        );
    }

    #[test]
    fn rejects_unknown_status_fields() {
        let mut value: serde_json::Value = serde_json::from_str(&status_json("0.2")).unwrap();
        value["future_field"] = serde_json::json!(true);
        assert_eq!(
            decode_status(&value.to_string()).unwrap_err(),
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
}
