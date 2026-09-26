mod checked_interface;
mod codes;
mod hash;
mod machine;
mod random;
mod service;
mod store;

use checked_interface::CheckedAuth;
use std::path::PathBuf;

const BUS: &str = "org.signallayer.Auth1";
const PATH: &str = "/org/signallayer/Auth1";
#[cfg(test)]
const INTERFACE: &str = "org.signallayer.Auth1";
const DEFAULT_STATE_DIRECTORY: &str = "/var/lib/sl-authd";

/// systemd passes StateDirectory= as STATE_DIRECTORY; only one is configured.
fn state_directory(environment: Option<std::ffi::OsString>) -> PathBuf {
    environment
        .and_then(|value| {
            value
                .to_str()
                .and_then(|value| value.split(':').next())
                .filter(|first| first.starts_with('/'))
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIRECTORY))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("sl-authd {}", env!("CARGO_PKG_VERSION"));
    let core = machine::Core::open(
        store::Store::new(state_directory(std::env::var_os("STATE_DIRECTORY"))),
        Box::new(machine::SystemClock),
        Box::new(random::KernelRandom),
        Box::new(hash::Argon2id::production()),
    );
    let connection = zbus::connection::Builder::system()?.build().await?;
    connection
        .object_server()
        .at(
            PATH,
            CheckedAuth(service::AuthService {
                shared: service::Shared::new(core),
            }),
        )
        .await?;
    connection.request_name(BUS).await?;
    std::future::pending::<()>().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_directory_comes_from_systemd_or_the_fixed_default() {
        assert_eq!(state_directory(None), PathBuf::from("/var/lib/sl-authd"));
        assert_eq!(
            state_directory(Some("/var/lib/sl-authd".into())),
            PathBuf::from("/var/lib/sl-authd")
        );
        assert_eq!(
            state_directory(Some("/var/lib/a:/var/lib/b".into())),
            PathBuf::from("/var/lib/a")
        );
        assert_eq!(
            state_directory(Some("relative".into())),
            PathBuf::from("/var/lib/sl-authd")
        );
    }
}
