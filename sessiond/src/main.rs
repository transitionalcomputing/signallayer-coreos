use sl_platform_client::{ClientError, PlatformClient};
use std::future::pending;

const BUS: &str = "org.signallayer.Session1";
const PATH: &str = "/org/signallayer/Session1";

struct SessionService {
    platform: PlatformClient,
}

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.signallayer.Session1.Error")]
enum SessionError {
    PlatformUnavailable(String),
    InvalidPlatformStatus(String),
    UnsupportedPlatform(String),
    #[zbus(error)]
    ZBus(zbus::Error),
}

fn map_platform_error(error: ClientError) -> SessionError {
    match error {
        ClientError::InvalidResponse => SessionError::InvalidPlatformStatus(
            "The Platform service returned an invalid status response".into(),
        ),
        ClientError::UnsupportedSchema => {
            SessionError::UnsupportedPlatform("The Platform status schema is unsupported".into())
        }
        ClientError::SystemBusUnavailable
        | ClientError::ServiceUnavailable
        | ClientError::RemoteMethod { .. }
        | ClientError::Unsupported
        | ClientError::RebootOutcomeUnknown => {
            SessionError::PlatformUnavailable("Platform status is temporarily unavailable".into())
        }
    }
}

#[zbus::interface(name = "org.signallayer.Session1")]
impl SessionService {
    async fn get_platform_status(&self) -> Result<String, SessionError> {
        let status = self
            .platform
            .get_status()
            .await
            .map_err(map_platform_error)?;
        serde_json::to_string(&status).map_err(|_| {
            SessionError::InvalidPlatformStatus(
                "The Platform status response could not be serialized".into(),
            )
        })
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("sl-sessiond {}", env!("CARGO_PKG_VERSION"));
    let platform = PlatformClient::connect().await?;
    let _connection = zbus::connection::Builder::system()?
        .name(BUS)?
        .serve_at(PATH, SessionService { platform })?
        .build()
        .await?;
    pending::<()>().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_failures_are_bounded_and_hide_backend_details() {
        let error = map_platform_error(ClientError::RemoteMethod {
            code: "BackendUnavailable".into(),
            message: "sensitive backend output".into(),
        });
        match error {
            SessionError::PlatformUnavailable(message) => {
                assert_eq!(message, "Platform status is temporarily unavailable");
            }
            _ => panic!("wrong Session1 error"),
        }
    }

    #[test]
    fn schema_failure_has_a_distinct_bounded_error() {
        let error = map_platform_error(ClientError::UnsupportedSchema);
        assert!(matches!(error, SessionError::UnsupportedPlatform(_)));
    }
}
