//! Platform API 0.3 remote-management lifecycle, frozen in
//! docs/platform-api-0.3.md. Every step goes through [`Backend`], so the
//! sequences, failure points and permit are unit-tested without systemd,
//! sl-authd or the filesystem.
use sl_protocol::{NetworkStatus, PlatformError};
use std::{future::Future, net::IpAddr, path::Path, time::Duration};
use tokio::{
    sync::Semaphore,
    time::{sleep, timeout},
};

pub(crate) const ENABLE_UNIT: &str = "sl-rm-enable.service";
pub(crate) const DISABLE_UNIT: &str = "sl-rm-disable.service";
pub(crate) const ROTATE_UNIT: &str = "sl-rm-rotate.service";
pub(crate) const CLEAR_RESET_UNIT: &str = "sl-rm-clear-reset.service";
pub(crate) const REMOTED_UNIT: &str = "sl-remoted.service";
pub(crate) const PORT: u16 = 8443;
const WORKER_TIMEOUT: Duration = Duration::from_secs(30);
const REMOTED_TIMEOUT: Duration = Duration::from_secs(10);
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const AUTH_BUS: &str = "org.signallayer.Auth1";
const AUTH_PATH: &str = "/org/signallayer/Auth1";
const AUTH_INTERFACE: &str = "org.signallayer.Auth1";
const PAIRING_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Marker {
    Enabled,
    ResetPending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkerError {
    /// The worker unit was already running when this call tried to start it.
    Busy,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthCall {
    EnsurePendingPairing,
    CancelPendingPairing,
    ResetEnrollment,
}

impl AuthCall {
    fn member(self) -> &'static str {
        match self {
            Self::EnsurePendingPairing => "EnsurePendingPairing",
            Self::CancelPendingPairing => "CancelPendingPairing",
            Self::ResetEnrollment => "ResetEnrollment",
        }
    }
}

pub(crate) trait Backend: Sync {
    fn marker_exists(&self, marker: Marker) -> impl Future<Output = Result<bool, ()>> + Send;
    /// Starts a oneshot worker and waits for that invocation to finish.
    fn run_worker(
        &self,
        unit: &'static str,
    ) -> impl Future<Output = Result<(), WorkerError>> + Send;
    /// Starts sl-remoted if it is not active, and waits until it is.
    fn start_remoted(&self) -> impl Future<Output = Result<(), ()>> + Send;
    /// Stops sl-remoted if it is not idle, and waits until it is.
    fn stop_remoted(&self) -> impl Future<Output = Result<(), ()>> + Send;
    fn auth(&self, call: AuthCall) -> impl Future<Output = Result<(), ()>> + Send;
    fn pending_pairing(&self) -> impl Future<Output = Result<(bool, String, u64), ()>> + Send;
    fn network(&self) -> impl Future<Output = Result<NetworkStatus, ()>> + Send;
    fn fingerprint(&self) -> Result<Option<String>, ()>;
}

fn busy() -> PlatformError {
    PlatformError::Busy("A remote-management operation is already in progress".into())
}

fn unavailable() -> PlatformError {
    PlatformError::RemoteManagementUnavailable("Remote management could not be controlled".into())
}

fn auth_unavailable() -> PlatformError {
    PlatformError::AuthUnavailable("The authentication service is unavailable".into())
}

fn reset_incomplete() -> PlatformError {
    PlatformError::ResetIncomplete(
        "A previous remote-management reset did not complete; re-enroll to repair it".into(),
    )
}

fn worker_error(error: WorkerError) -> PlatformError {
    match error {
        WorkerError::Busy => {
            PlatformError::Busy("A remote-management worker is already running".into())
        }
        WorkerError::Failed => unavailable(),
    }
}

async fn marker(backend: &impl Backend, marker: Marker) -> Result<bool, PlatformError> {
    backend
        .marker_exists(marker)
        .await
        .map_err(|_| unavailable())
}

async fn auth(backend: &impl Backend, call: AuthCall) -> Result<(), PlatformError> {
    backend.auth(call).await.map_err(|_| auth_unavailable())
}

/// Each sequence holds the permit until it returns, whatever the outcome.
pub(crate) async fn enable(
    permit: &Semaphore,
    backend: &impl Backend,
) -> Result<(), PlatformError> {
    let _permit = permit.try_acquire().map_err(|_| busy())?;
    // Before any side effect.
    if marker(backend, Marker::ResetPending).await? {
        return Err(reset_incomplete());
    }
    backend
        .run_worker(ENABLE_UNIT)
        .await
        .map_err(worker_error)?;
    auth(backend, AuthCall::EnsurePendingPairing).await?;
    backend.start_remoted().await.map_err(|_| unavailable())
}

pub(crate) async fn disable(
    permit: &Semaphore,
    backend: &impl Backend,
) -> Result<(), PlatformError> {
    let _permit = permit.try_acquire().map_err(|_| busy())?;
    backend
        .run_worker(DISABLE_UNIT)
        .await
        .map_err(worker_error)?;
    backend.stop_remoted().await.map_err(|_| unavailable())?;
    auth(backend, AuthCall::CancelPendingPairing).await
}

/// Also the repair path for an incomplete boot reset. Never `ResetIncomplete`.
pub(crate) async fn reenroll(
    permit: &Semaphore,
    backend: &impl Backend,
) -> Result<(), PlatformError> {
    let _permit = permit.try_acquire().map_err(|_| busy())?;
    backend.stop_remoted().await.map_err(|_| unavailable())?;
    auth(backend, AuthCall::ResetEnrollment).await?;
    backend
        .run_worker(ROTATE_UNIT)
        .await
        .map_err(worker_error)?;
    let enabled = marker(backend, Marker::Enabled).await?;
    if enabled {
        auth(backend, AuthCall::EnsurePendingPairing).await?;
    }
    // Final durable step, after every durable security step converged.
    if marker(backend, Marker::ResetPending).await? {
        backend
            .run_worker(CLEAR_RESET_UNIT)
            .await
            .map_err(worker_error)?;
    }
    // Runtime convergence: sl-remoted cannot start while reset-pending exists.
    if enabled {
        backend.start_remoted().await.map_err(|_| unavailable())?;
    }
    Ok(())
}

pub(crate) async fn enrollment(
    permit: &Semaphore,
    backend: &impl Backend,
) -> Result<(String, String, String, u64), PlatformError> {
    let _permit = permit.try_acquire().map_err(|_| busy())?;
    let network = backend
        .network()
        .await
        .map_err(|_| super::network_error())?;
    let url = enrollment_url(&network);
    let fingerprint = backend
        .fingerprint()
        .map_err(|_| unavailable())?
        .unwrap_or_default();
    let (pending, code, expires_at) = backend
        .pending_pairing()
        .await
        .map_err(|_| auth_unavailable())?;
    let (code, expires_at) = if pending {
        if !valid_pairing_code(&code) || expires_at == 0 {
            return Err(auth_unavailable());
        }
        (code, expires_at)
    } else {
        (String::new(), 0)
    };
    Ok((url, fingerprint, code, expires_at))
}

fn valid_pairing_code(code: &str) -> bool {
    code.len() == 8 && code.bytes().all(|byte| PAIRING_ALPHABET.contains(&byte))
}

fn eligible(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !address.is_loopback()
                && !address.is_unspecified()
                && !address.is_multicast()
                && !address.is_link_local()
        }
        IpAddr::V6(address) => {
            !address.is_loopback()
                && !address.is_unspecified()
                && !address.is_multicast()
                && address.segments()[0] & 0xffc0 != 0xfe80
        }
    }
}

/// One URL: the first eligible IPv4 address in the observer's order, else the
/// first eligible IPv6 address; empty if none qualifies.
pub(crate) fn enrollment_url(network: &NetworkStatus) -> String {
    let Some(primary) = &network.primary_connection else {
        return String::new();
    };
    let addresses: Vec<IpAddr> = primary
        .addresses
        .iter()
        .filter_map(|value| value.split_once('/')?.0.parse().ok())
        .filter(eligible)
        .collect();
    let chosen = addresses
        .iter()
        .find(|address| address.is_ipv4())
        .or_else(|| addresses.iter().find(|address| address.is_ipv6()));
    match chosen {
        Some(IpAddr::V4(address)) => format!("https://{address}:{PORT}/"),
        Some(IpAddr::V6(address)) => format!("https://[{address}]:{PORT}/"),
        None => String::new(),
    }
}

/// A oneshot worker invocation succeeded only if it returned to `inactive`
/// with `Result=success`.
pub(crate) fn worker_succeeded(active_state: &str, result: &str) -> bool {
    active_state == "inactive" && result == "success"
}

fn idle(active_state: &str) -> bool {
    matches!(active_state, "inactive" | "failed")
}

type SystemdJob = (
    u32,
    String,
    String,
    String,
    zbus::zvariant::OwnedObjectPath,
    zbus::zvariant::OwnedObjectPath,
);

fn job_pending(jobs: &[SystemdJob], expected: &zbus::zvariant::OwnedObjectPath) -> bool {
    jobs.iter().any(|job| &job.4 == expected)
}

/// The production backend: systemd and sl-authd over the system bus, and the
/// read-only state directory.
pub(crate) struct SystemBackend<'a> {
    pub(crate) connection: &'a zbus::Connection,
}

impl SystemBackend<'_> {
    /// Property caching is disabled so every poll reads the current value.
    async fn uncached(
        &self,
        destination: &'static str,
        path: zbus::zvariant::OwnedObjectPath,
        interface: &'static str,
    ) -> zbus::Result<zbus::Proxy<'static>> {
        zbus::proxy::Builder::<zbus::Proxy<'static>>::new(self.connection)
            .destination(destination)?
            .path(path)?
            .interface(interface)?
            .cache_properties(zbus::proxy::CacheProperties::No)
            .build()
            .await
    }

    async fn unit(
        &self,
        name: &str,
    ) -> zbus::Result<(
        zbus::Proxy<'static>,
        zbus::Proxy<'static>,
        zbus::Proxy<'static>,
    )> {
        let manager = zbus::Proxy::new(
            self.connection,
            super::SYSTEMD_BUS,
            super::SYSTEMD_PATH,
            super::SYSTEMD_MANAGER,
        )
        .await?;
        let path: zbus::zvariant::OwnedObjectPath = manager.call("LoadUnit", &(name,)).await?;
        let unit = self
            .uncached(super::SYSTEMD_BUS, path.clone(), super::SYSTEMD_UNIT)
            .await?;
        let service = self
            .uncached(super::SYSTEMD_BUS, path, super::SYSTEMD_SERVICE)
            .await?;
        Ok((manager, unit, service))
    }
}

impl Backend for SystemBackend<'_> {
    async fn marker_exists(&self, marker: Marker) -> Result<bool, ()> {
        let name = match marker {
            Marker::Enabled => sl_remote_state::ENABLED,
            Marker::ResetPending => sl_remote_state::RESET_PENDING,
        };
        match std::fs::symlink_metadata(Path::new(sl_remote_state::STATE_DIR).join(name)) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(()),
        }
    }

    async fn run_worker(&self, name: &'static str) -> Result<(), WorkerError> {
        let outcome = timeout(WORKER_TIMEOUT, async {
            let (manager, unit, service) = self.unit(name).await?;
            let active: String = unit.get_property("ActiveState").await?;
            if !idle(&active) {
                return Ok(Err(WorkerError::Busy));
            }
            let job_path: zbus::zvariant::OwnedObjectPath =
                manager.call("StartUnit", &(name, "fail")).await?;
            loop {
                let jobs: Vec<SystemdJob> = manager.call("ListJobs", &()).await?;
                if !job_pending(&jobs, &job_path) {
                    break;
                }
                sleep(POLL_INTERVAL).await;
            }
            let active: String = unit.get_property("ActiveState").await?;
            let result: String = service.get_property("Result").await?;
            Ok::<_, zbus::Error>(if worker_succeeded(&active, &result) {
                Ok(())
            } else {
                Err(WorkerError::Failed)
            })
        })
        .await;
        match outcome {
            Ok(Ok(result)) => result,
            _ => Err(WorkerError::Failed),
        }
    }

    async fn start_remoted(&self) -> Result<(), ()> {
        timeout(REMOTED_TIMEOUT, async {
            let (manager, unit, _) = self.unit(REMOTED_UNIT).await?;
            let active: String = unit.get_property("ActiveState").await?;
            if active == "active" {
                return Ok(true);
            }
            let _: zbus::zvariant::OwnedObjectPath =
                manager.call("StartUnit", &(REMOTED_UNIT, "fail")).await?;
            loop {
                let active: String = unit.get_property("ActiveState").await?;
                match active.as_str() {
                    "active" => return Ok::<_, zbus::Error>(true),
                    "failed" => return Ok(false),
                    _ => sleep(POLL_INTERVAL).await,
                }
            }
        })
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?
        .then_some(())
        .ok_or(())
    }

    async fn stop_remoted(&self) -> Result<(), ()> {
        timeout(REMOTED_TIMEOUT, async {
            let (manager, unit, _) = self.unit(REMOTED_UNIT).await?;
            let active: String = unit.get_property("ActiveState").await?;
            if idle(&active) {
                return Ok(());
            }
            let _: zbus::zvariant::OwnedObjectPath =
                manager.call("StopUnit", &(REMOTED_UNIT, "replace")).await?;
            loop {
                let active: String = unit.get_property("ActiveState").await?;
                if idle(&active) {
                    return Ok::<_, zbus::Error>(());
                }
                sleep(POLL_INTERVAL).await;
            }
        })
        .await
        .map_err(|_| ())?
        .map_err(|_| ())
    }

    async fn auth(&self, call: AuthCall) -> Result<(), ()> {
        timeout(AUTH_TIMEOUT, async {
            let proxy =
                zbus::Proxy::new(self.connection, AUTH_BUS, AUTH_PATH, AUTH_INTERFACE).await?;
            proxy.call::<_, _, ()>(call.member(), &()).await
        })
        .await
        .map_err(|_| ())?
        .map_err(|_| ())
    }

    async fn pending_pairing(&self) -> Result<(bool, String, u64), ()> {
        timeout(AUTH_TIMEOUT, async {
            let proxy =
                zbus::Proxy::new(self.connection, AUTH_BUS, AUTH_PATH, AUTH_INTERFACE).await?;
            proxy
                .call::<_, _, (bool, String, u64)>("GetPendingPairing", &())
                .await
        })
        .await
        .map_err(|_| ())?
        .map_err(|_| ())
    }

    async fn network(&self) -> Result<NetworkStatus, ()> {
        super::observe_network(self.connection)
            .await
            .map_err(|_| ())
    }

    fn fingerprint(&self) -> Result<Option<String>, ()> {
        sl_remote_state::current_fingerprint(Path::new(sl_remote_state::STATE_DIR)).map_err(|_| ())
    }
}

#[cfg(test)]
mod tests;
