use serde_json::Value;
use sl_protocol::{
    Deployment, Health, HealthState, MachineStatus, NetworkStatus, PlatformError, RollbackFailure,
    RollbackState, RollbackStatus, Status, UpdateFailure, UpdateState, UpdateStatus, BUS, PATH,
    SCHEMA_VERSION,
};
use std::{collections::BTreeMap, ffi::CStr, net::IpAddr, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    sync::Semaphore,
    time::{sleep, timeout},
};

mod checked_interface;
use checked_interface::CheckedPlatform;

const OUTPUT_LIMIT: u64 = 64 * 1024;
const BACKEND_TIMEOUT: Duration = Duration::from_secs(15);
const SYSTEMD_TIMEOUT: Duration = Duration::from_secs(3);
const NETWORK_TIMEOUT: Duration = Duration::from_secs(3);
const SYSTEMD_BUS: &str = "org.freedesktop.systemd1";
const SYSTEMD_PATH: &str = "/org/freedesktop/systemd1";
const SYSTEMD_MANAGER: &str = "org.freedesktop.systemd1.Manager";
const SYSTEMD_UNIT: &str = "org.freedesktop.systemd1.Unit";
const SYSTEMD_SERVICE: &str = "org.freedesktop.systemd1.Service";
const UPDATE_UNIT: &str = "sl-update.service";
const ROLLBACK_UNIT: &str = "sl-rollback.service";
const REBOOT_UNIT: &str = "sl-reboot.service";
const NETWORK_OBSERVER_BUS: &str = "org.signallayer.NetworkObserver1";
const NETWORK_OBSERVER_PATH: &str = "/org/signallayer/NetworkObserver1";
const NETWORK_OBSERVER_INTERFACE: &str = "org.signallayer.NetworkObserver1";

struct Platform {
    connection: zbus::Connection,
    requests: Semaphore,
    mutation_starts: Semaphore,
}

#[derive(Debug, PartialEq, Eq)]
struct WorkerObservation {
    active_state: String,
    result: String,
    exit_status: i32,
}

#[zbus::interface(name = "org.signallayer.Platform1")]
impl Platform {
    async fn get_status(&self) -> Result<String, PlatformError> {
        let _permit = self.requests.try_acquire().map_err(|_| {
            PlatformError::Busy("A status observation is already in progress".into())
        })?;
        let update_worker = observe_worker(&self.connection, UPDATE_UNIT)
            .await
            .map_err(|_| update_unavailable())?;
        let rollback_worker = observe_worker(&self.connection, ROLLBACK_UNIT)
            .await
            .map_err(|_| rollback_unavailable())?;
        let release = std::fs::read_to_string("/usr/lib/signallayer/release").map_err(|_| {
            PlatformError::MetadataUnavailable("Image release metadata is unreadable".into())
        })?;
        let machine = observe_machine()?;
        let (backend, network) = tokio::try_join!(
            backend_command("/usr/bin/bootc", &["status", "--json"], BACKEND_TIMEOUT),
            observe_network(&self.connection)
        )?;
        let manager =
            zbus::Proxy::new(&self.connection, SYSTEMD_BUS, SYSTEMD_PATH, SYSTEMD_MANAGER)
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
        let status = status_from_observations(
            &release,
            &backend,
            machine,
            network,
            health,
            &update_worker,
            &rollback_worker,
        )?;
        serde_json::to_string(&status).map_err(|_| invalid("Status serialization failed"))
    }

    async fn start_update(&self) -> Result<(), PlatformError> {
        let _permit = self.mutation_starts.try_acquire().map_err(|_| {
            PlatformError::Busy("A deployment mutation start is already in progress".into())
        })?;
        let rollback = observe_worker(&self.connection, ROLLBACK_UNIT)
            .await
            .map_err(|_| rollback_unavailable())?;
        if worker_running(&rollback) {
            return Err(PlatformError::Busy(
                "The rollback worker is already running".into(),
            ));
        }
        let state = observe_mutation_state().await?;
        if state.rollback_queued {
            return Err(PlatformError::Conflict(
                "A rollback is already queued for the next boot".into(),
            ));
        }
        start_worker(&self.connection, UPDATE_UNIT, update_unavailable).await
    }

    async fn start_rollback(&self) -> Result<(), PlatformError> {
        let _permit = self.mutation_starts.try_acquire().map_err(|_| {
            PlatformError::Busy("A deployment mutation start is already in progress".into())
        })?;
        let update = observe_worker(&self.connection, UPDATE_UNIT)
            .await
            .map_err(|_| update_unavailable())?;
        if worker_running(&update) {
            return Err(PlatformError::Busy(
                "The update worker is already running".into(),
            ));
        }
        let state = observe_mutation_state().await?;
        if state.staged {
            return Err(PlatformError::Conflict(
                "An unapplied update is staged; rollback selection was not changed".into(),
            ));
        }
        if !state.retained_rollback {
            return Err(PlatformError::RollbackUnavailable(
                "No retained rollback deployment exists".into(),
            ));
        }
        if state.rollback_queued {
            return Err(PlatformError::Conflict(
                "A rollback is already queued for the next boot".into(),
            ));
        }
        start_worker(&self.connection, ROLLBACK_UNIT, rollback_unavailable).await
    }

    async fn start_reboot(&self) -> Result<(), PlatformError> {
        let connection = &self.connection;
        request_reboot(
            &self.mutation_starts,
            |unit| observe_worker(connection, unit),
            || start_worker(connection, REBOOT_UNIT, reboot_unavailable),
        )
        .await
    }
}

// Frozen 4D order: inspect update, inspect rollback, Conflict if either is
// active, inspect the reboot worker, Busy if it is active, otherwise start it.
// The mutation-start permit shared with StartUpdate and StartRollback is held
// for the whole evaluation. No retries and no deployment or boot-state changes.
async fn request_reboot<Observe, Observed, Start, Started>(
    mutation_starts: &Semaphore,
    observe: Observe,
    start: Start,
) -> Result<(), PlatformError>
where
    Observe: Fn(&'static str) -> Observed,
    Observed: std::future::Future<Output = Result<WorkerObservation, ()>>,
    Start: FnOnce() -> Started,
    Started: std::future::Future<Output = Result<(), PlatformError>>,
{
    let _permit = mutation_starts.try_acquire().map_err(|_| {
        PlatformError::Busy("A deployment mutation start is already in progress".into())
    })?;
    let update = observe(UPDATE_UNIT)
        .await
        .map_err(|_| reboot_unavailable())?;
    let rollback = observe(ROLLBACK_UNIT)
        .await
        .map_err(|_| reboot_unavailable())?;
    if worker_running(&update) {
        return Err(PlatformError::Conflict(
            "The update worker is running; reboot was not requested".into(),
        ));
    }
    if worker_running(&rollback) {
        return Err(PlatformError::Conflict(
            "The rollback worker is running; reboot was not requested".into(),
        ));
    }
    let reboot = observe(REBOOT_UNIT)
        .await
        .map_err(|_| reboot_unavailable())?;
    if worker_running(&reboot) {
        return Err(PlatformError::Busy(
            "The reboot worker is already running".into(),
        ));
    }
    start().await
}

fn machine_error(message: &str) -> PlatformError {
    PlatformError::MachineUnavailable(message.into())
}

fn network_error() -> PlatformError {
    PlatformError::NetworkUnavailable(
        "NetworkManager status could not be observed or was invalid".into(),
    )
}

fn validated_hex_id(value: &str, length: usize) -> Option<String> {
    let value = value.trim();
    (value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0'))
    .then(|| value.to_owned())
}

fn validated_boot_id(value: &str) -> Option<String> {
    let value = value.trim();
    let valid = value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
        && value.bytes().any(|byte| byte != b'0' && byte != b'-');
    valid.then(|| value.to_owned())
}

fn normalize_architecture(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return None;
    }
    Some(match value.as_str() {
        "amd64" => "x86_64".into(),
        "arm64" => "aarch64".into(),
        _ => value,
    })
}

fn observe_machine() -> Result<MachineStatus, PlatformError> {
    let machine_id = std::fs::read_to_string("/etc/machine-id")
        .ok()
        .and_then(|value| validated_hex_id(&value, 32))
        .ok_or_else(|| machine_error("The system machine ID is unavailable or invalid"))?;
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .and_then(|value| validated_boot_id(&value))
        .ok_or_else(|| machine_error("The kernel boot ID is unavailable or invalid"))?;
    let mut uts = std::mem::MaybeUninit::<libc::utsname>::uninit();
    // SAFETY: uname initializes the supplied utsname on success, and machine is
    // a kernel-provided NUL-terminated field in that initialized structure.
    let architecture = unsafe {
        if libc::uname(uts.as_mut_ptr()) != 0 {
            return Err(machine_error(
                "The running kernel architecture is unavailable",
            ));
        }
        let uts = uts.assume_init();
        CStr::from_ptr(uts.machine.as_ptr())
            .to_str()
            .ok()
            .and_then(normalize_architecture)
    }
    .ok_or_else(|| machine_error("The running kernel architecture is invalid"))?;
    Ok(MachineStatus {
        machine_id,
        architecture,
        boot_id,
    })
}

async fn observe_network(connection: &zbus::Connection) -> Result<NetworkStatus, PlatformError> {
    timeout(NETWORK_TIMEOUT, async {
        let observer = zbus::Proxy::new(
            connection,
            NETWORK_OBSERVER_BUS,
            NETWORK_OBSERVER_PATH,
            NETWORK_OBSERVER_INTERFACE,
        )
        .await?;
        let json: String = observer.call("GetNetworkStatus", &()).await?;
        let status: NetworkStatus = serde_json::from_str(&json)
            .map_err(|_| zbus::Error::Failure("Invalid network observer response".into()))?;
        validate_network_status(status)
            .ok_or_else(|| zbus::Error::Failure("Invalid network observer response".into()))
    })
    .await
    .map_err(|_| network_error())?
    .map_err(|_| network_error())
}

fn validate_network_status(status: NetworkStatus) -> Option<NetworkStatus> {
    let Some(primary) = status.primary_connection.as_ref() else {
        return Some(status);
    };
    if primary.interface.is_empty()
        || primary.interface.len() > 64
        || primary
            .interface
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || primary.addresses.len() > 256
        || primary.default_gateways.len() > 32
        || !strictly_sorted_unique(&primary.addresses)
        || !strictly_sorted_unique(&primary.default_gateways)
        || !primary.addresses.iter().all(|value| valid_address(value))
        || !primary.default_gateways.iter().all(|value| {
            value
                .parse::<IpAddr>()
                .is_ok_and(|parsed| parsed.to_string() == *value)
        })
    {
        return None;
    }
    Some(status)
}

fn strictly_sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn valid_address(value: &str) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    if prefix.contains('/') {
        return false;
    }
    let Ok(address) = address.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    let valid_prefix = if address.is_ipv4() {
        prefix <= 32
    } else {
        prefix <= 128
    };
    valid_prefix && format!("{address}/{prefix}") == value
}

fn update_unavailable() -> PlatformError {
    PlatformError::UpdateUnavailable("The fixed update worker could not be controlled".into())
}

fn rollback_unavailable() -> PlatformError {
    PlatformError::RollbackUnavailable("The fixed rollback worker could not be controlled".into())
}

fn reboot_unavailable() -> PlatformError {
    PlatformError::RebootUnavailable("The fixed reboot worker could not be controlled".into())
}

#[derive(Debug, PartialEq, Eq)]
struct MutationState {
    staged: bool,
    retained_rollback: bool,
    rollback_queued: bool,
}

async fn observe_mutation_state() -> Result<MutationState, PlatformError> {
    let backend = backend_command("/usr/bin/bootc", &["status", "--json"], BACKEND_TIMEOUT).await?;
    mutation_state_from_backend(&backend)
}

fn mutation_state_from_backend(backend: &[u8]) -> Result<MutationState, PlatformError> {
    let value: Value =
        serde_json::from_slice(backend).map_err(|_| invalid("bootc status is not valid JSON"))?;
    if value.get("apiVersion").and_then(Value::as_str) != Some("org.containers.bootc/v1")
        || value.get("kind").and_then(Value::as_str) != Some("BootcHost")
    {
        return Err(invalid("Unsupported bootc status schema"));
    }
    let status = value
        .get("status")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("Bootc deployment status is missing"))?;
    Ok(MutationState {
        staged: !status
            .get("staged")
            .ok_or_else(|| invalid("Staged deployment observation is missing"))?
            .is_null(),
        retained_rollback: !status
            .get("rollback")
            .ok_or_else(|| invalid("Rollback observation is missing"))?
            .is_null(),
        rollback_queued: status
            .get("rollbackQueued")
            .and_then(Value::as_bool)
            .ok_or_else(|| invalid("Rollback queue observation is missing or invalid"))?,
    })
}

async fn unit_path(
    manager: &zbus::Proxy<'_>,
    unit: &str,
) -> Result<zbus::zvariant::OwnedObjectPath, zbus::Error> {
    manager.call("LoadUnit", &(unit,)).await
}

async fn observe_worker(
    connection: &zbus::Connection,
    unit_name: &str,
) -> Result<WorkerObservation, ()> {
    timeout(SYSTEMD_TIMEOUT, async {
        let manager =
            zbus::Proxy::new(connection, SYSTEMD_BUS, SYSTEMD_PATH, SYSTEMD_MANAGER).await?;
        let path = unit_path(&manager, unit_name).await?;
        let unit = zbus::Proxy::new(connection, SYSTEMD_BUS, path.as_str(), SYSTEMD_UNIT).await?;
        let service =
            zbus::Proxy::new(connection, SYSTEMD_BUS, path.as_str(), SYSTEMD_SERVICE).await?;
        Ok::<_, zbus::Error>(WorkerObservation {
            active_state: unit.get_property("ActiveState").await?,
            result: service.get_property("Result").await?,
            exit_status: service.get_property("ExecMainStatus").await?,
        })
    })
    .await
    .map_err(|_| ())?
    .map_err(|_| ())
}

fn worker_running(worker: &WorkerObservation) -> bool {
    !matches!(worker.active_state.as_str(), "inactive" | "failed")
}

async fn start_worker(
    connection: &zbus::Connection,
    unit_name: &str,
    unavailable: fn() -> PlatformError,
) -> Result<(), PlatformError> {
    timeout(SYSTEMD_TIMEOUT, async {
        let manager =
            zbus::Proxy::new(connection, SYSTEMD_BUS, SYSTEMD_PATH, SYSTEMD_MANAGER).await?;
        let path = unit_path(&manager, unit_name).await?;
        let unit = zbus::Proxy::new(connection, SYSTEMD_BUS, path.as_str(), SYSTEMD_UNIT).await?;
        let active: String = unit.get_property("ActiveState").await?;
        if active != "inactive" && active != "failed" {
            return Err(PlatformError::Busy(
                "The requested deployment worker is already running".into(),
            ));
        }
        let previous_invocation: Vec<u8> = unit.get_property("InvocationID").await?;
        let _: zbus::zvariant::OwnedObjectPath =
            manager.call("StartUnit", &(unit_name, "fail")).await?;
        loop {
            let active: String = unit.get_property("ActiveState").await?;
            let invocation: Vec<u8> = unit.get_property("InvocationID").await?;
            if !matches!(active.as_str(), "inactive" | "failed")
                || invocation != previous_invocation
            {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        Ok::<_, PlatformError>(())
    })
    .await
    .map_err(|_| unavailable())?
    .map_err(|error| match error {
        PlatformError::Busy(_) => error,
        _ => unavailable(),
    })
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
    machine: MachineStatus,
    network: NetworkStatus,
    health: Health,
    update_worker: &WorkerObservation,
    rollback_worker: &WorkerObservation,
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
    let booted = deployment(booted)?;
    let staged_value = value
        .pointer("/status/staged")
        .ok_or_else(|| invalid("Staged deployment observation is missing"))?;
    let (staged, staged_queued) = if staged_value.is_null() {
        (None, false)
    } else {
        let download_only = staged_value
            .get("downloadOnly")
            .and_then(Value::as_bool)
            .ok_or_else(|| invalid("Staged deployment mode is missing or invalid"))?;
        (Some(deployment(staged_value)?), !download_only)
    };
    let rollback = value
        .pointer("/status/rollback")
        .ok_or_else(|| invalid("Rollback observation is missing"))?;
    let retained_rollback = if rollback.is_null() {
        None
    } else {
        Some(deployment(rollback)?)
    };
    let rollback_queued = value
        .pointer("/status/rollbackQueued")
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid("Rollback queue observation is missing or invalid"))?;
    let update = update_from_observations(&booted, staged, staged_queued, update_worker);
    let rollback = rollback_from_observations(rollback_queued, rollback_worker);
    Ok(Status {
        schema_version: SCHEMA_VERSION.into(),
        product: required("NAME")?.into(),
        version: required("VERSION")?.into(),
        platform_api_version: required("PLATFORM_API_VERSION")?.into(),
        source_revision: optional("SOURCE_REVISION"),
        build_id: optional("BUILD_ID"),
        machine,
        network,
        booted,
        retained_rollback,
        update,
        rollback,
        health,
    })
}

fn rollback_from_observations(rollback_queued: bool, worker: &WorkerObservation) -> RollbackStatus {
    let running = worker_running(worker);
    let failed = worker.active_state == "failed" || worker.result != "success";
    let (state, failure) = if running {
        (RollbackState::Running, None)
    } else if failed {
        let result = if worker
            .result
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            worker.result.as_str()
        } else {
            "failed"
        };
        (
            RollbackState::Failed,
            Some(RollbackFailure {
                code: "WorkerFailed".into(),
                message: format!(
                    "The rollback worker failed ({result}, status {})",
                    worker.exit_status
                ),
            }),
        )
    } else if rollback_queued {
        (RollbackState::Queued, None)
    } else {
        (RollbackState::Idle, None)
    };
    RollbackStatus {
        state,
        reboot_required: rollback_queued,
        failure,
    }
}

fn update_from_observations(
    booted: &Deployment,
    staged: Option<Deployment>,
    staged_queued: bool,
    worker: &WorkerObservation,
) -> UpdateStatus {
    let staged_differs = staged
        .as_ref()
        .is_some_and(|deployment| deployment.deployment_id != booted.deployment_id);
    let running = !matches!(worker.active_state.as_str(), "inactive" | "failed");
    let failed = worker.active_state == "failed" || worker.result != "success";
    let (state, failure) = if running {
        (UpdateState::Running, None)
    } else if failed {
        let result = if worker
            .result
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            worker.result.as_str()
        } else {
            "failed"
        };
        (
            UpdateState::Failed,
            Some(UpdateFailure {
                code: "WorkerFailed".into(),
                message: format!(
                    "The update worker failed ({result}, status {})",
                    worker.exit_status
                ),
            }),
        )
    } else if staged_differs && staged_queued {
        (UpdateState::Staged, None)
    } else {
        (UpdateState::Idle, None)
    };
    UpdateStatus {
        state,
        staged,
        reboot_required: staged_differs && staged_queued,
        failure,
    }
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
                mutation_starts: Semaphore::new(1),
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
    use sl_protocol::{NetworkState, PrimaryConnection};
    const RELEASE: &str = "NAME=\"SignalLayerIT CoreOS\"\nVERSION=\"0.0.1\"\nPLATFORM_API_VERSION=\"0.2\"\nSOURCE_REVISION=\"unknown\"\nBUILD_ID=\"unknown\"\n";
    fn fixture() -> Value {
        serde_json::json!({"apiVersion":"org.containers.bootc/v1", "kind":"BootcHost", "status": {
            "booted": {"ostree":{"checksum":"a".repeat(64), "deploySerial":0},
                "image":{"image":{"image":"localhost/signallayer-coreos:0.0.1"}, "imageDigest":format!("sha256:{}", "b".repeat(64))}},
            "staged":null,
            "rollback":null,
            "rollbackQueued":false}})
    }
    fn worker(active_state: &str, result: &str, exit_status: i32) -> WorkerObservation {
        WorkerObservation {
            active_state: active_state.into(),
            result: result.into(),
            exit_status,
        }
    }
    fn machine() -> MachineStatus {
        MachineStatus {
            machine_id: "0123456789abcdef0123456789abcdef".into(),
            architecture: "x86_64".into(),
            boot_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
        }
    }
    fn network() -> NetworkStatus {
        NetworkStatus {
            state: NetworkState::ConnectedGlobal,
            primary_connection: Some(PrimaryConnection {
                interface: "enp0s2".into(),
                addresses: vec!["10.0.2.15/24".into()],
                default_gateways: vec!["10.0.2.2".into()],
            }),
        }
    }
    fn parse(value: Value) -> Result<Status, PlatformError> {
        status_from_observations(
            RELEASE,
            &serde_json::to_vec(&value).unwrap(),
            machine(),
            network(),
            observed_health("running".into(), 0),
            &worker("inactive", "success", 0),
            &worker("inactive", "success", 0),
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
        assert_eq!(status.update.state, UpdateState::Idle);
        assert_eq!(status.rollback.state, RollbackState::Idle);
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
        assert!(status_from_observations(
            RELEASE,
            b"broken",
            machine(),
            network(),
            observed_health("running".into(), 0),
            &worker("inactive", "success", 0),
            &worker("inactive", "success", 0)
        )
        .is_err());
        assert!(status_from_observations(
            "",
            &serde_json::to_vec(&fixture()).unwrap(),
            machine(),
            network(),
            observed_health("running".into(), 0),
            &worker("inactive", "success", 0),
            &worker("inactive", "success", 0)
        )
        .is_err());
    }

    #[test]
    fn update_state_uses_worker_and_fresh_deployments() {
        let mut value = fixture();
        value["status"]["staged"] = serde_json::json!({
            "ostree":{"checksum":"c".repeat(64), "deploySerial":1},
            "image":{"image":{"image":"localhost/signallayer-coreos:0.0.1"},
                "imageDigest":format!("sha256:{}", "d".repeat(64))},
            "downloadOnly":false
        });
        let backend = serde_json::to_vec(&value).unwrap();
        let status = status_from_observations(
            RELEASE,
            &backend,
            machine(),
            network(),
            observed_health("running".into(), 0),
            &worker("inactive", "success", 0),
            &worker("inactive", "success", 0),
        )
        .unwrap();
        assert_eq!(status.update.state, UpdateState::Staged);
        assert!(status.update.reboot_required);
        assert_eq!(
            status.update.staged.unwrap().deployment_id,
            format!("{}.1", "c".repeat(64))
        );

        let running = status_from_observations(
            RELEASE,
            &backend,
            machine(),
            network(),
            observed_health("running".into(), 0),
            &worker("activating", "success", 0),
            &worker("inactive", "success", 0),
        )
        .unwrap();
        assert_eq!(running.update.state, UpdateState::Running);
        assert!(!running.update.failure.is_some());

        let failed = status_from_observations(
            RELEASE,
            &backend,
            machine(),
            network(),
            observed_health("running".into(), 0),
            &worker("failed", "exit-code", 1),
            &worker("inactive", "success", 0),
        )
        .unwrap();
        assert_eq!(failed.update.state, UpdateState::Failed);
        assert_eq!(failed.update.failure.unwrap().code, "WorkerFailed");
    }

    #[test]
    fn download_only_is_never_reboot_required() {
        let mut value = fixture();
        value["status"]["staged"] = serde_json::json!({
            "ostree":{"checksum":"c".repeat(64), "deploySerial":1},
            "image":{"image":{"image":"localhost/signallayer-coreos:0.0.1"},
                "imageDigest":format!("sha256:{}", "d".repeat(64))},
            "downloadOnly":true
        });
        let status = parse(value).unwrap();
        assert_eq!(status.update.state, UpdateState::Idle);
        assert!(!status.update.reboot_required);
        assert!(status.update.staged.is_some());
    }

    #[test]
    fn rollback_state_uses_authoritative_queue_and_worker() {
        let mut value = fixture();
        value["status"]["rollback"] = value["status"]["booted"].clone();
        value["status"]["rollbackQueued"] = true.into();
        let queued = parse(value.clone()).unwrap();
        assert_eq!(queued.rollback.state, RollbackState::Queued);
        assert!(queued.rollback.reboot_required);
        assert_eq!(queued.update.state, UpdateState::Idle);

        let backend = serde_json::to_vec(&value).unwrap();
        let running = status_from_observations(
            RELEASE,
            &backend,
            machine(),
            network(),
            observed_health("running".into(), 0),
            &worker("inactive", "success", 0),
            &worker("activating", "success", 0),
        )
        .unwrap();
        assert_eq!(running.rollback.state, RollbackState::Running);

        let failed = status_from_observations(
            RELEASE,
            &backend,
            machine(),
            network(),
            observed_health("running".into(), 0),
            &worker("inactive", "success", 0),
            &worker("failed", "exit-code", 1),
        )
        .unwrap();
        assert_eq!(failed.rollback.state, RollbackState::Failed);
        assert_eq!(failed.rollback.failure.unwrap().code, "WorkerFailed");
    }

    #[test]
    fn rollback_preconditions_are_derived_from_bootc() {
        let empty = mutation_state_from_backend(&serde_json::to_vec(&fixture()).unwrap()).unwrap();
        assert!(!empty.staged);
        assert!(!empty.retained_rollback);
        assert!(!empty.rollback_queued);

        let mut value = fixture();
        value["status"]["staged"] = value["status"]["booted"].clone();
        value["status"]["rollback"] = value["status"]["booted"].clone();
        value["status"]["rollbackQueued"] = true.into();
        let state = mutation_state_from_backend(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(state.staged);
        assert!(state.retained_rollback);
        assert!(state.rollback_queued);
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

    #[test]
    fn machine_observations_are_strict_and_normalized() {
        assert!(validated_hex_id("0123456789ABCDEF0123456789ABCDEF\n", 32).is_none());
        assert_eq!(
            validated_hex_id("0123456789abcdef0123456789abcdef\n", 32).as_deref(),
            Some("0123456789abcdef0123456789abcdef")
        );
        assert!(validated_hex_id("00000000000000000000000000000000", 32).is_none());
        assert!(validated_hex_id("not-a-machine-id", 32).is_none());
        assert!(validated_boot_id("01234567-89AB-CDEF-0123-456789ABCDEF\n").is_none());
        assert_eq!(
            validated_boot_id("01234567-89ab-cdef-0123-456789abcdef\n").as_deref(),
            Some("01234567-89ab-cdef-0123-456789abcdef")
        );
        assert!(validated_boot_id("00000000-0000-0000-0000-000000000000").is_none());
        assert!(validated_boot_id("0123456789abcdef0123456789abcdef").is_none());
        assert_eq!(normalize_architecture("AMD64\n").as_deref(), Some("x86_64"));
        assert_eq!(normalize_architecture("arm64").as_deref(), Some("aarch64"));
        assert!(normalize_architecture("x86 64").is_none());
    }

    #[test]
    fn helper_network_status_is_independently_validated() {
        assert!(validate_network_status(network()).is_some());

        let mut invalid = network();
        invalid.primary_connection.as_mut().unwrap().interface = "bad interface".into();
        assert!(validate_network_status(invalid).is_none());

        let mut invalid = network();
        invalid.primary_connection.as_mut().unwrap().addresses =
            vec!["192.0.2.2/24".into(), "10.0.2.15/24".into()];
        assert!(validate_network_status(invalid).is_none());

        let mut invalid = network();
        invalid.primary_connection.as_mut().unwrap().addresses = vec!["10.0.2.15/33".into()];
        assert!(validate_network_status(invalid).is_none());

        let mut invalid = network();
        invalid
            .primary_connection
            .as_mut()
            .unwrap()
            .default_gateways = vec!["2001:0db8::1".into()];
        assert!(validate_network_status(invalid).is_none());
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

    const ACTIVE_STATES: [&str; 4] = ["active", "activating", "deactivating", "reloading"];
    const IDLE_STATES: [&str; 2] = ["inactive", "failed"];

    async fn run_reboot(
        update: Result<&'static str, ()>,
        rollback: Result<&'static str, ()>,
        reboot: Result<&'static str, ()>,
        start: Result<(), PlatformError>,
    ) -> (Result<(), PlatformError>, Vec<&'static str>) {
        let calls = std::cell::RefCell::new(Vec::new());
        let mutation_starts = Semaphore::new(1);
        let result = request_reboot(
            &mutation_starts,
            |unit| {
                calls.borrow_mut().push(unit);
                let state = match unit {
                    UPDATE_UNIT => update,
                    ROLLBACK_UNIT => rollback,
                    REBOOT_UNIT => reboot,
                    _ => Err(()),
                };
                async move { state.map(|active_state| worker(active_state, "success", 0)) }
            },
            || {
                calls.borrow_mut().push("start");
                // The permit is still held when the reboot worker is started.
                assert!(mutation_starts.try_acquire().is_err());
                async move { start }
            },
        )
        .await;
        (result, calls.into_inner())
    }

    #[test]
    fn worker_activity_predicate_matches_contract() {
        for state in ACTIVE_STATES {
            assert!(worker_running(&worker(state, "success", 0)), "{state}");
        }
        for state in IDLE_STATES {
            assert!(!worker_running(&worker(state, "success", 0)), "{state}");
        }
    }

    #[tokio::test]
    async fn reboot_starts_fixed_worker_after_frozen_inspection_order() {
        let (result, calls) =
            run_reboot(Ok("inactive"), Ok("inactive"), Ok("inactive"), Ok(())).await;
        assert!(result.is_ok());
        assert_eq!(calls, [UPDATE_UNIT, ROLLBACK_UNIT, REBOOT_UNIT, "start"]);
    }

    #[tokio::test]
    async fn reboot_is_busy_while_reboot_worker_is_active() {
        for state in ACTIVE_STATES {
            let (result, calls) =
                run_reboot(Ok("inactive"), Ok("inactive"), Ok(state), Ok(())).await;
            assert!(matches!(result, Err(PlatformError::Busy(_))), "{state}");
            assert_eq!(calls, [UPDATE_UNIT, ROLLBACK_UNIT, REBOOT_UNIT], "{state}");
        }
    }

    #[tokio::test]
    async fn reboot_conflicts_with_active_deployment_workers() {
        for state in ACTIVE_STATES {
            let (result, calls) =
                run_reboot(Ok(state), Ok("inactive"), Ok("inactive"), Ok(())).await;
            assert!(
                matches!(result, Err(PlatformError::Conflict(_))),
                "update {state}"
            );
            assert_eq!(calls, [UPDATE_UNIT, ROLLBACK_UNIT], "update {state}");

            let (result, calls) =
                run_reboot(Ok("inactive"), Ok(state), Ok("inactive"), Ok(())).await;
            assert!(
                matches!(result, Err(PlatformError::Conflict(_))),
                "rollback {state}"
            );
            assert_eq!(calls, [UPDATE_UNIT, ROLLBACK_UNIT], "rollback {state}");
        }
    }

    #[tokio::test]
    async fn idle_deployment_workers_do_not_conflict() {
        for update in IDLE_STATES {
            for rollback in IDLE_STATES {
                let (result, calls) =
                    run_reboot(Ok(update), Ok(rollback), Ok("inactive"), Ok(())).await;
                assert!(result.is_ok(), "{update} {rollback}");
                assert_eq!(calls, [UPDATE_UNIT, ROLLBACK_UNIT, REBOOT_UNIT, "start"]);
            }
        }
    }

    #[tokio::test]
    async fn conflict_takes_precedence_over_busy() {
        for state in ACTIVE_STATES {
            let (result, calls) = run_reboot(Ok(state), Ok("inactive"), Ok(state), Ok(())).await;
            assert!(
                matches!(result, Err(PlatformError::Conflict(_))),
                "update {state}"
            );
            assert_eq!(calls, [UPDATE_UNIT, ROLLBACK_UNIT]);

            let (result, calls) = run_reboot(Ok("inactive"), Ok(state), Ok(state), Ok(())).await;
            assert!(
                matches!(result, Err(PlatformError::Conflict(_))),
                "rollback {state}"
            );
            assert_eq!(calls, [UPDATE_UNIT, ROLLBACK_UNIT]);
        }
    }

    #[tokio::test]
    async fn reboot_is_unavailable_when_any_required_unit_cannot_be_inspected() {
        let (result, calls) = run_reboot(Err(()), Ok("inactive"), Ok("inactive"), Ok(())).await;
        assert!(matches!(result, Err(PlatformError::RebootUnavailable(_))));
        assert_eq!(calls, [UPDATE_UNIT]);

        let (result, calls) = run_reboot(Ok("inactive"), Err(()), Ok("inactive"), Ok(())).await;
        assert!(matches!(result, Err(PlatformError::RebootUnavailable(_))));
        assert_eq!(calls, [UPDATE_UNIT, ROLLBACK_UNIT]);

        // Both deployment workers are inspected before the Conflict decision.
        let (result, _) = run_reboot(Ok("active"), Err(()), Ok("inactive"), Ok(())).await;
        assert!(matches!(result, Err(PlatformError::RebootUnavailable(_))));

        let (result, calls) = run_reboot(Ok("inactive"), Ok("inactive"), Err(()), Ok(())).await;
        assert!(matches!(result, Err(PlatformError::RebootUnavailable(_))));
        assert_eq!(calls, [UPDATE_UNIT, ROLLBACK_UNIT, REBOOT_UNIT]);
    }

    #[tokio::test]
    async fn reboot_start_failure_is_reboot_unavailable() {
        let (result, calls) = run_reboot(
            Ok("inactive"),
            Ok("inactive"),
            Ok("inactive"),
            Err(reboot_unavailable()),
        )
        .await;
        assert!(matches!(result, Err(PlatformError::RebootUnavailable(_))));
        assert_eq!(calls, [UPDATE_UNIT, ROLLBACK_UNIT, REBOOT_UNIT, "start"]);
    }

    #[tokio::test]
    async fn reboot_is_busy_while_a_mutation_start_is_in_progress() {
        let mutation_starts = Semaphore::new(1);
        let _held = mutation_starts.try_acquire().unwrap();
        let calls = std::cell::RefCell::new(Vec::new());
        let result = request_reboot(
            &mutation_starts,
            |unit| {
                calls.borrow_mut().push(unit);
                async move { Ok::<_, ()>(worker("inactive", "success", 0)) }
            },
            || {
                calls.borrow_mut().push("start");
                async move { Ok::<(), PlatformError>(()) }
            },
        )
        .await;
        assert!(matches!(result, Err(PlatformError::Busy(_))));
        assert!(calls.into_inner().is_empty());
    }
}
