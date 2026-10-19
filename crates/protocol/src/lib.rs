//! The local Platform status contract. Backend storage details are deliberately absent.
use serde::{Deserialize, Serialize};

pub const BUS: &str = "org.signallayer.Platform1";
pub const PATH: &str = "/org/signallayer/Platform1";
pub const INTERFACE: &str = "org.signallayer.Platform1";
pub const SCHEMA_VERSION: &str = "0.3";
/// Session1's status schema: Platform's schema 0.3 plus `remote_management`.
/// Platform's own `GetStatus` stays at [`SCHEMA_VERSION`].
pub const SESSION_SCHEMA_VERSION: &str = "0.4";

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub schema_version: String,
    pub product: String,
    pub version: String,
    pub platform_api_version: String,
    pub source_revision: Option<String>,
    pub build_id: Option<String>,
    pub machine: MachineStatus,
    pub network: NetworkStatus,
    pub booted: Deployment,
    pub retained_rollback: Option<Deployment>,
    pub update: UpdateStatus,
    pub rollback: RollbackStatus,
    pub health: Health,
}

/// Exactly the three contract facts; no authentication internals.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemoteManagementStatus {
    pub enabled: bool,
    pub listening: bool,
    pub enrolled: bool,
}

/// Session1 status schema 0.4, aggregated by Session1 without owning any of
/// it: every Platform schema 0.3 field, plus `remote_management`.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionStatus {
    pub schema_version: String,
    pub product: String,
    pub version: String,
    pub platform_api_version: String,
    pub source_revision: Option<String>,
    pub build_id: Option<String>,
    pub machine: MachineStatus,
    pub network: NetworkStatus,
    pub booted: Deployment,
    pub retained_rollback: Option<Deployment>,
    pub update: UpdateStatus,
    pub rollback: RollbackStatus,
    pub health: Health,
    pub remote_management: RemoteManagementStatus,
}

impl SessionStatus {
    pub fn from_platform(status: Status, remote_management: RemoteManagementStatus) -> Self {
        Self {
            schema_version: SESSION_SCHEMA_VERSION.into(),
            product: status.product,
            version: status.version,
            platform_api_version: status.platform_api_version,
            source_revision: status.source_revision,
            build_id: status.build_id,
            machine: status.machine,
            network: status.network,
            booted: status.booted,
            retained_rollback: status.retained_rollback,
            update: status.update,
            rollback: status.rollback,
            health: status.health,
            remote_management,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MachineStatus {
    pub machine_id: String,
    pub architecture: String,
    pub boot_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkStatus {
    pub state: NetworkState,
    pub primary_connection: Option<PrimaryConnection>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkState {
    Unknown,
    Disconnected,
    Connecting,
    ConnectedLocal,
    ConnectedSite,
    ConnectedGlobal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PrimaryConnection {
    pub interface: String,
    pub addresses: Vec<String>,
    pub default_gateways: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    /// Opaque identifier: clients must not infer a storage path from this value.
    pub deployment_id: String,
    pub image_reference: Option<String>,
    pub image_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UpdateStatus {
    pub state: UpdateState,
    pub staged: Option<Deployment>,
    pub reboot_required: bool,
    pub failure: Option<UpdateFailure>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpdateState {
    Idle,
    Running,
    Staged,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UpdateFailure {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RollbackStatus {
    pub state: RollbackState,
    pub reboot_required: bool,
    pub failure: Option<RollbackFailure>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RollbackState {
    Idle,
    Running,
    Queued,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RollbackFailure {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Health {
    pub state: HealthState,
    pub system_state: String,
    pub failed_units: u32,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    Healthy,
    Degraded,
}

#[derive(Debug, Clone, zbus::DBusError)]
#[zbus(prefix = "org.signallayer.Platform1.Error")]
pub enum PlatformError {
    BackendUnavailable(String),
    BackendTimeout(String),
    InvalidBackendData(String),
    MetadataUnavailable(String),
    HealthUnavailable(String),
    MachineUnavailable(String),
    NetworkUnavailable(String),
    UpdateUnavailable(String),
    RollbackUnavailable(String),
    RebootUnavailable(String),
    Conflict(String),
    Busy(String),
    RemoteManagementUnavailable(String),
    AuthUnavailable(String),
    ResetIncomplete(String),
    #[zbus(error)]
    ZBus(zbus::Error),
}

#[zbus::proxy(
    interface = "org.signallayer.Platform1",
    default_service = "org.signallayer.Platform1",
    default_path = "/org/signallayer/Platform1"
)]
pub trait Platform {
    fn get_status(&self) -> zbus::Result<String>;
    fn start_update(&self) -> zbus::Result<()>;
    fn start_rollback(&self) -> zbus::Result<()>;
    fn start_reboot(&self) -> zbus::Result<()>;
    fn enable_remote_management(&self) -> zbus::Result<()>;
    fn disable_remote_management(&self) -> zbus::Result<()>;
    fn reenroll_remote_management(&self) -> zbus::Result<()>;
    /// (url, fingerprint, pairing_code, expires_at); the pairing fields are
    /// "" and 0 when no pairing is pending.
    fn get_remote_management_enrollment(&self) -> zbus::Result<(String, String, String, u64)>;
}
