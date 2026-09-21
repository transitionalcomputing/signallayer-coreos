use serde_json::Value;
use sl_protocol::{
    Deployment, Health, HealthState, PlatformError, Status, BUS, PATH, SCHEMA_VERSION,
};
use std::{collections::BTreeMap, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    sync::Semaphore,
    time::timeout,
};

mod checked_interface;
use checked_interface::CheckedPlatform;

const OUTPUT_LIMIT: u64 = 64 * 1024;
const BACKEND_TIMEOUT: Duration = Duration::from_secs(15);

struct Platform {
    connection: zbus::Connection,
    requests: Semaphore,
}

#[zbus::interface(name = "org.signallayer.Platform1")]
impl Platform {
    async fn get_status(&self) -> Result<String, PlatformError> {
        let _permit = self.requests.try_acquire().map_err(|_| {
            PlatformError::Busy("A status observation is already in progress".into())
        })?;
        let release = std::fs::read_to_string("/usr/lib/signallayer/release").map_err(|_| {
            PlatformError::MetadataUnavailable("Image release metadata is unreadable".into())
        })?;
        let backend =
            backend_command("/usr/bin/bootc", &["status", "--json"], BACKEND_TIMEOUT).await?;
        let manager = zbus::Proxy::new(
            &self.connection,
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
        )
        .await
        .map_err(|_| health_error())?;
        let health = timeout(Duration::from_secs(3), async {
            let state: String = manager.get_property("SystemState").await?;
            let failed: u32 = manager.get_property("NFailedUnits").await?;
            Ok::<_, zbus::Error>(observed_health(state, failed))
        })
        .await
        .map_err(|_| health_error())?
        .map_err(|_| health_error())?;
        let status = status_from_observations(&release, &backend, health)?;
        serde_json::to_string(&status).map_err(|_| invalid("Status serialization failed"))
    }
}

fn health_error() -> PlatformError {
    PlatformError::HealthUnavailable("Systemd health properties could not be observed".into())
}

fn observed_health(system_state: String, failed_units: u32) -> Health {
    let state = if system_state == "running" && failed_units == 0 {
        HealthState::Healthy
    } else {
        HealthState::Degraded
    };
    Health {
        state,
        system_state,
        failed_units,
    }
}

async fn backend_command(
    program: &str,
    args: &[&str],
    limit: Duration,
) -> Result<Vec<u8>, PlatformError> {
    let mut child = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        // The image copies Fedora's public configuration, keeping crypto policy
        // while avoiding cert_t file reads that would also expose TLS keys.
        .env("OPENSSL_CONF", "/usr/lib/signallayer/openssl.cnf")
        // Device metadata needs static public names, not privileged userdb IPC.
        .env("SYSTEMD_BYPASS_USERDB", "1")
        // Keep libmount's optional writable cache inside the service's PrivateTmp.
        .env("LIBMOUNT_UTAB", "/tmp/sl-platformd-utab")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| {
            eprintln!("bootc spawn: {error}");
            PlatformError::BackendUnavailable(
                "The bootc status backend could not be started".into(),
            )
        })?;
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let result = timeout(limit, async {
        // Stop at the first overflow instead of waiting for a blocked writer
        // after a truncated pipe read. Both streams are bounded independently.
        tokio::try_join!(bounded_output(stdout), bounded_output(stderr), async {
            child.wait().await.map_err(|error| {
                eprintln!("bootc wait: {error}");
                PlatformError::BackendUnavailable("bootc status could not be read".into())
            })
        })
    })
    .await;
    let (output, errors, exit) = match result {
        Err(_) => {
            // Explicitly kill and reap, in addition to kill_on_drop on cancellation.
            let _ = timeout(Duration::from_secs(2), child.kill()).await;
            return Err(PlatformError::BackendTimeout(
                "bootc status exceeded its deadline".into(),
            ));
        }
        Ok(Err(error)) => {
            let _ = timeout(Duration::from_secs(2), child.kill()).await;
            return Err(error);
        }
        Ok(Ok(result)) => result,
    };
    if !exit.success() {
        eprintln!(
            "bootc exited {exit}: {}",
            String::from_utf8_lossy(&errors[..errors.len().min(512)])
        );
        return Err(PlatformError::BackendUnavailable(
            "bootc status returned an unsuccessful exit status".into(),
        ));
    }
    Ok(output)
}

async fn bounded_output(stream: impl AsyncRead + Unpin) -> Result<Vec<u8>, PlatformError> {
    let mut output = Vec::new();
    stream
        .take(OUTPUT_LIMIT + 1)
        .read_to_end(&mut output)
        .await
        .map_err(|error| {
            eprintln!("bootc I/O: {error}");
            PlatformError::BackendUnavailable("bootc status could not be read".into())
        })?;
    if output.len() as u64 > OUTPUT_LIMIT {
        return Err(invalid("bootc status exceeded the output limit"));
    }
    Ok(output)
}

fn invalid(message: &str) -> PlatformError {
    PlatformError::InvalidBackendData(message.into())
}

fn hex_digest(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn deployment(value: &Value) -> Result<Deployment, PlatformError> {
    let checksum = value
        .pointer("/ostree/checksum")
        .and_then(Value::as_str)
        .filter(|value| hex_digest(value))
        .ok_or_else(|| invalid("Deployment identity is missing or invalid"))?;
    let serial = value
        .pointer("/ostree/deploySerial")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("Deployment serial is missing or invalid"))?;
    let image = value
        .get("image")
        .ok_or_else(|| invalid("Deployment image observation is missing"))?;
    let (image_reference, image_digest) = if image.is_null() {
        (None, None)
    } else {
        let reference = image
            .pointer("/image/image")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
            .ok_or_else(|| invalid("Image reference is missing or invalid"))?;
        let digest = image
            .get("imageDigest")
            .ok_or_else(|| invalid("Image digest observation is missing"))?;
        let digest = if digest.is_null() {
            None
        } else {
            Some(
                digest
                    .as_str()
                    .filter(|value| value.strip_prefix("sha256:").is_some_and(hex_digest))
                    .ok_or_else(|| invalid("Image digest is invalid"))?
                    .to_owned(),
            )
        };
        (Some(reference.to_owned()), digest)
    };
    Ok(Deployment {
        deployment_id: format!("{checksum}.{serial}"),
        image_reference,
        image_digest,
    })
}

fn status_from_observations(
    release: &str,
    backend: &[u8],
    health: Health,
) -> Result<Status, PlatformError> {
    let mut fields = BTreeMap::new();
    for line in release.lines().filter(|line| !line.trim().is_empty()) {
        let (key, value) = line.split_once('=').ok_or_else(|| {
            PlatformError::MetadataUnavailable("Invalid image release metadata".into())
        })?;
        let value = value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .filter(|value| {
                !value.is_empty() && !value.contains('"') && !value.chars().any(char::is_control)
            })
            .ok_or_else(|| {
                PlatformError::MetadataUnavailable("Invalid image release metadata value".into())
            })?;
        if fields.insert(key, value).is_some() {
            return Err(PlatformError::MetadataUnavailable(
                "Duplicate image release metadata field".into(),
            ));
        }
    }
    let required = |key| {
        fields.get(key).copied().ok_or_else(|| {
            PlatformError::MetadataUnavailable(format!("Image release field {key} is missing"))
        })
    };
    let optional = |key| {
        fields
            .get(key)
            .filter(|value| **value != "unknown")
            .map(|value| (*value).to_owned())
    };
    let value: Value =
        serde_json::from_slice(backend).map_err(|_| invalid("bootc status is not valid JSON"))?;
    if value.get("apiVersion").and_then(Value::as_str) != Some("org.containers.bootc/v1")
        || value.get("kind").and_then(Value::as_str) != Some("BootcHost")
    {
        return Err(invalid("Unsupported bootc status schema"));
    }
    let booted = value
        .pointer("/status/booted")
        .filter(|value| value.is_object())
        .ok_or_else(|| invalid("No booted deployment was observed"))?;
    let rollback = value
        .pointer("/status/rollback")
        .ok_or_else(|| invalid("Rollback observation is missing"))?;
    let retained_rollback = if rollback.is_null() {
        None
    } else {
        Some(deployment(rollback)?)
    };
    Ok(Status {
        schema_version: SCHEMA_VERSION.into(),
        product: required("NAME")?.into(),
        version: required("VERSION")?.into(),
        platform_api_version: required("PLATFORM_API_VERSION")?.into(),
        source_revision: optional("SOURCE_REVISION"),
        build_id: optional("BUILD_ID"),
        booted: deployment(booted)?,
        retained_rollback,
        health,
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let connection = zbus::connection::Builder::system()?.build().await?;
    connection
        .object_server()
        .at(
            PATH,
            CheckedPlatform(Platform {
                connection: connection.clone(),
                requests: Semaphore::new(1),
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
    const RELEASE: &str = "NAME=\"SignalLayerIT CoreOS\"\nVERSION=\"0.0.1\"\nPLATFORM_API_VERSION=\"0.1\"\nSOURCE_REVISION=\"unknown\"\nBUILD_ID=\"unknown\"\n";
    fn fixture() -> Value {
        serde_json::json!({"apiVersion":"org.containers.bootc/v1", "kind":"BootcHost", "status": {
            "booted": {"ostree":{"checksum":"a".repeat(64), "deploySerial":0},
                "image":{"image":{"image":"localhost/signallayer-coreos:0.0.1"}, "imageDigest":format!("sha256:{}", "b".repeat(64))}},
            "rollback":null}})
    }
    fn parse(value: Value) -> Result<Status, PlatformError> {
        status_from_observations(
            RELEASE,
            &serde_json::to_vec(&value).unwrap(),
            observed_health("running".into(), 0),
        )
    }
    #[test]
    fn retained_is_not_known_good_and_unknown_metadata_stays_unknown() {
        let mut value = fixture();
        value["status"]["rollback"] = value["status"]["booted"].clone();
        let status = parse(value).unwrap();
        assert!(status.retained_rollback.is_some());
        assert_eq!(status.source_revision, None);
        assert_eq!(status.build_id, None);
        assert_eq!(status.booted.deployment_id, format!("{}.0", "a".repeat(64)));
    }
    #[test]
    fn missing_or_invalid_observations_fail() {
        for path in ["booted", "rollback"] {
            let mut value = fixture();
            value["status"].as_object_mut().unwrap().remove(path);
            assert!(matches!(
                parse(value),
                Err(PlatformError::InvalidBackendData(_))
            ));
        }
        let mut value = fixture();
        value["status"]["booted"]["image"]["imageDigest"] = "invalid".into();
        assert!(parse(value).is_err());
        assert!(
            status_from_observations(RELEASE, b"broken", observed_health("running".into(), 0))
                .is_err()
        );
        assert!(status_from_observations(
            "",
            &serde_json::to_vec(&fixture()).unwrap(),
            observed_health("running".into(), 0)
        )
        .is_err());
    }
    #[test]
    fn health_is_only_healthy_for_running_without_failures() {
        assert_eq!(
            observed_health("running".into(), 0).state,
            HealthState::Healthy
        );
        assert_eq!(
            observed_health("running".into(), 1).state,
            HealthState::Degraded
        );
        assert_eq!(
            observed_health("starting".into(), 0).state,
            HealthState::Degraded
        );
        assert_eq!(
            observed_health("degraded".into(), 0).state,
            HealthState::Degraded
        );
    }
    #[tokio::test]
    async fn backend_unavailable_and_timeout_are_distinct() {
        assert!(matches!(
            backend_command("/nonexistent/sl-platform-test", &[], BACKEND_TIMEOUT).await,
            Err(PlatformError::BackendUnavailable(_))
        ));
        assert!(matches!(
            backend_command("/usr/bin/sleep", &["2"], Duration::from_millis(20)).await,
            Err(PlatformError::BackendTimeout(_))
        ));
        assert!(matches!(
            backend_command("/usr/bin/false", &[], BACKEND_TIMEOUT).await,
            Err(PlatformError::BackendUnavailable(_))
        ));
    }

    #[tokio::test]
    async fn output_bounds_accept_boundary_and_reject_blocked_writers() {
        let output = backend_command(
            "/usr/bin/head",
            &["-c", "65536", "/dev/zero"],
            BACKEND_TIMEOUT,
        )
        .await
        .unwrap();
        assert_eq!(output.len(), OUTPUT_LIMIT as usize);
        for (stream, script) in [
            (
                "stdout",
                "printf '%s' \"$$\" >\"$1\"; exec head -c 1048576 /dev/zero",
            ),
            (
                "stderr",
                "printf '%s' \"$$\" >\"$1\"; exec head -c 1048576 /dev/zero >&2",
            ),
        ] {
            let path = std::env::temp_dir().join(format!(
                "sl-platformd-overflow-{stream}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&path);
            assert!(matches!(
                backend_command(
                    "/usr/bin/bash",
                    &["-c", script, "sl-test", path.to_str().unwrap()],
                    Duration::from_secs(2)
                )
                .await,
                Err(PlatformError::InvalidBackendData(_))
            ));
            let pid = std::fs::read_to_string(&path).unwrap();
            std::fs::remove_file(path).unwrap();
            assert!(
                !std::path::Path::new(&format!("/proc/{pid}")).exists(),
                "{stream} overflow child remains running or unreaped"
            );
        }
    }

    #[tokio::test]
    async fn timeout_kills_and_reaps_the_actual_child() {
        let path =
            std::env::temp_dir().join(format!("sl-platformd-timeout-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let result = backend_command(
            "/usr/bin/bash",
            &[
                "-c",
                "printf '%s' \"$$\" >\"$1\"; exec sleep 30",
                "sl-test",
                path.to_str().unwrap(),
            ],
            Duration::from_secs(1),
        )
        .await;
        assert!(matches!(result, Err(PlatformError::BackendTimeout(_))));
        let pid = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "child remains running or unreaped"
        );
    }
}
