use sl_platform_client::{ClientError, PlatformClient};
use sl_protocol::{RemoteManagementStatus, SessionStatus, Status};
use std::{future::pending, io, path::Path, time::Duration};

const BUS: &str = "org.signallayer.Session1";
const PATH: &str = "/org/signallayer/Session1";
/// Created by sl-remoted (5C-c) only while it accepts eligible connections.
const LISTENING_PATH: &str = "/run/sl-remoted/listening";
const AUTH_BUS: &str = "org.signallayer.Auth1";
const AUTH_PATH: &str = "/org/signallayer/Auth1";
const AUTH_INTERFACE: &str = "org.signallayer.Auth1";
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);

struct SessionService {
    platform: PlatformClient,
}

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.signallayer.Session1.Error")]
enum SessionError {
    PlatformUnavailable(String),
    InvalidPlatformStatus(String),
    UnsupportedPlatform(String),
    RemoteManagementUnavailable(String),
    AuthUnavailable(String),
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

/// Presence only: absent is false; any other failure to check is an error,
/// never a guessed value.
fn path_exists(path: &Path) -> Result<bool, ()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(()),
    }
}

/// Session1 aggregates schema 0.4 from its three owners without owning any.
fn compose(
    status: Status,
    enabled: Result<bool, ()>,
    listening: Result<bool, ()>,
    enrolled: Result<bool, ()>,
) -> Result<SessionStatus, SessionError> {
    let unavailable = || {
        SessionError::RemoteManagementUnavailable(
            "Remote-management state is temporarily unavailable".into(),
        )
    };
    let remote_management = RemoteManagementStatus {
        enabled: enabled.map_err(|()| unavailable())?,
        listening: listening.map_err(|()| unavailable())?,
        enrolled: enrolled.map_err(|()| {
            SessionError::AuthUnavailable(
                "The authentication service is temporarily unavailable".into(),
            )
        })?,
    };
    Ok(SessionStatus::from_platform(status, remote_management))
}

async fn enrolled(connection: &zbus::Connection) -> Result<bool, ()> {
    tokio::time::timeout(AUTH_TIMEOUT, async {
        let proxy = zbus::Proxy::new(connection, AUTH_BUS, AUTH_PATH, AUTH_INTERFACE).await?;
        proxy
            .call::<_, _, (bool, bool)>("GetEnrollmentState", &())
            .await
    })
    .await
    .map_err(|_| ())?
    .map(|(enrolled, _pairing_pending)| enrolled)
    .map_err(|_| ())
}

#[zbus::interface(name = "org.signallayer.Session1")]
impl SessionService {
    async fn get_platform_status(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<String, SessionError> {
        let status = self
            .platform
            .get_status()
            .await
            .map_err(map_platform_error)?;
        let enabled =
            path_exists(&Path::new(sl_remote_state::STATE_DIR).join(sl_remote_state::ENABLED));
        let listening = path_exists(Path::new(LISTENING_PATH));
        let status = compose(status, enabled, listening, enrolled(connection).await)?;
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

    const PLATFORM_STATUS: &str = r#"{
        "schema_version": "0.3",
        "product": "SignalLayerIT CoreOS",
        "version": "0.0.2",
        "platform_api_version": "0.3",
        "source_revision": null,
        "build_id": null,
        "machine": {"machine_id": "0123456789abcdef0123456789abcdef", "architecture": "x86_64",
            "boot_id": "01234567-89ab-cdef-0123-456789abcdef"},
        "network": {"state": "connected_global", "primary_connection": {"interface": "enp0s2",
            "addresses": ["10.0.2.15/24"], "default_gateways": ["10.0.2.2"]}},
        "booted": {"deployment_id": "a.0", "image_reference": null, "image_digest": null},
        "retained_rollback": null,
        "update": {"state": "idle", "staged": null, "reboot_required": false, "failure": null},
        "rollback": {"state": "idle", "reboot_required": false, "failure": null},
        "health": {"state": "healthy", "system_state": "running", "failed_units": 0}
    }"#;

    fn platform_status() -> Status {
        serde_json::from_str(PLATFORM_STATUS).unwrap()
    }

    #[test]
    fn schema_0_4_is_platform_0_3_plus_exactly_three_remote_management_facts() {
        for (enabled, listening, enrolled) in [
            (false, false, false),
            (true, false, false),
            (false, true, false),
            (false, false, true),
            (true, true, true),
        ] {
            let status =
                compose(platform_status(), Ok(enabled), Ok(listening), Ok(enrolled)).unwrap();
            let value = serde_json::to_value(&status).unwrap();
            assert_eq!(value["schema_version"], "0.4");
            assert_eq!(
                value["remote_management"],
                serde_json::json!({"enabled": enabled, "listening": listening, "enrolled": enrolled})
            );
            // Every other field is Platform's schema 0.3 value, unchanged.
            let platform: serde_json::Value = serde_json::from_str(PLATFORM_STATUS).unwrap();
            let mut session = value.clone();
            session.as_object_mut().unwrap().remove("remote_management");
            session["schema_version"] = "0.3".into();
            assert_eq!(session, platform);
            // The serialized form is exactly schema 0.4, and is not schema 0.3.
            let text = serde_json::to_string(&status).unwrap();
            assert!(serde_json::from_str::<SessionStatus>(&text).is_ok());
            assert!(serde_json::from_str::<Status>(&text).is_err());
        }
    }

    #[test]
    fn unreadable_remote_management_state_is_an_error_not_a_guess() {
        for (enabled, listening) in [(Err(()), Ok(false)), (Ok(false), Err(()))] {
            let error = compose(platform_status(), enabled, listening, Ok(false)).unwrap_err();
            assert!(matches!(
                error,
                SessionError::RemoteManagementUnavailable(_)
            ));
        }
    }

    #[test]
    fn sl_authd_unavailable_is_a_distinct_error_not_a_guess() {
        let error = compose(platform_status(), Ok(true), Ok(true), Err(())).unwrap_err();
        match error {
            SessionError::AuthUnavailable(message) => {
                assert_eq!(
                    message,
                    "The authentication service is temporarily unavailable"
                );
            }
            _ => panic!("wrong Session1 error"),
        }
    }

    #[test]
    fn presence_is_existence_only_and_absence_is_false() {
        let directory =
            std::env::temp_dir().join(format!("sl-sessiond-test-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let marker = directory.join("enabled");
        assert_eq!(path_exists(&marker), Ok(false));
        // Before sl-remoted exists, its runtime directory is absent too.
        assert_eq!(
            path_exists(&directory.join("sl-remoted").join("listening")),
            Ok(false)
        );
        std::fs::write(&marker, b"").unwrap();
        assert_eq!(path_exists(&marker), Ok(true));
        // Contents are ignored: presence only.
        std::fs::write(&marker, b"false").unwrap();
        assert_eq!(path_exists(&marker), Ok(true));
        // Anything but "not found" is an error (here, ENOTDIR).
        assert_eq!(path_exists(&marker.join("child")), Err(()));
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn platform_status_schema_stays_0_3() {
        assert_eq!(sl_protocol::SCHEMA_VERSION, "0.3");
        assert_eq!(sl_protocol::SESSION_SCHEMA_VERSION, "0.4");
        assert_eq!(platform_status().schema_version, "0.3");
    }
}
