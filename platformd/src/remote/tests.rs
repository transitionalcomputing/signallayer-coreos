use super::*;
use sl_protocol::{NetworkState, PrimaryConnection};
use std::sync::{Arc, Mutex};

const FINGERPRINT: &str = "20:E5:0B:A7:F0:9C:9E:C6:4C:02:2C:81:EE:01:1C:5C:A5:1C:60:12:0C:39:BD:43:D0:CB:50:C4:DD:5E:78:00";

/// Records every call in order, fails the named step, and checks on every call
/// that the remote-management permit is held.
struct Fake {
    permit: Arc<Semaphore>,
    calls: Mutex<Vec<&'static str>>,
    permit_held_at: Mutex<Vec<(&'static str, bool)>>,
    enabled: bool,
    reset_pending: bool,
    fail: Option<&'static str>,
    worker_busy: bool,
    network: Result<NetworkStatus, ()>,
    fingerprint: Result<Option<String>, ()>,
    pairing: Result<(bool, String, u64), ()>,
}

impl Fake {
    fn new() -> Self {
        Self {
            permit: Arc::new(Semaphore::new(1)),
            calls: Mutex::default(),
            permit_held_at: Mutex::default(),
            enabled: true,
            reset_pending: false,
            fail: None,
            worker_busy: false,
            network: Ok(network(&["192.0.2.10/24"])),
            fingerprint: Ok(Some(FINGERPRINT.into())),
            pairing: Ok((true, "04HMASW9".into(), 1_800_000_600)),
        }
    }

    fn step(&self, name: &'static str) -> Result<(), ()> {
        self.calls.lock().unwrap().push(name);
        // A concurrent remote-management call would be Busy here.
        self.permit_held_at
            .lock()
            .unwrap()
            .push((name, self.permit.try_acquire().is_err()));
        if self.fail == Some(name) {
            Err(())
        } else {
            Ok(())
        }
    }

    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }

    fn assert_permit_held_throughout(&self) {
        for (step, held) in self.permit_held_at.lock().unwrap().iter() {
            assert!(held, "the permit was not held at {step}");
        }
        assert_eq!(
            self.permit.available_permits(),
            1,
            "the permit was released"
        );
    }
}

impl Backend for Fake {
    async fn marker_exists(&self, marker: Marker) -> Result<bool, ()> {
        match marker {
            Marker::Enabled => self.step("marker:enabled").map(|()| self.enabled),
            Marker::ResetPending => self
                .step("marker:reset-pending")
                .map(|()| self.reset_pending),
        }
    }

    async fn run_worker(&self, unit: &'static str) -> Result<(), WorkerError> {
        self.step(unit).map_err(|()| WorkerError::Failed)?;
        if self.worker_busy {
            return Err(WorkerError::Busy);
        }
        Ok(())
    }

    async fn start_remoted(&self) -> Result<(), ()> {
        self.step("start")
    }

    async fn stop_remoted(&self) -> Result<(), ()> {
        self.step("stop")
    }

    async fn auth(&self, call: AuthCall) -> Result<(), ()> {
        self.step(match call {
            AuthCall::EnsurePendingPairing => "auth:EnsurePendingPairing",
            AuthCall::CancelPendingPairing => "auth:CancelPendingPairing",
            AuthCall::ResetEnrollment => "auth:ResetEnrollment",
        })
    }

    async fn pending_pairing(&self) -> Result<(bool, String, u64), ()> {
        self.step("auth:GetPendingPairing")?;
        self.pairing.clone()
    }

    async fn network(&self) -> Result<NetworkStatus, ()> {
        self.step("network")?;
        self.network.clone()
    }

    fn fingerprint(&self) -> Result<Option<String>, ()> {
        self.step("fingerprint")?;
        self.fingerprint.clone()
    }
}

fn network(addresses: &[&str]) -> NetworkStatus {
    NetworkStatus {
        state: NetworkState::ConnectedGlobal,
        primary_connection: Some(PrimaryConnection {
            interface: "enp0s2".into(),
            addresses: addresses.iter().map(|value| value.to_string()).collect(),
            default_gateways: Vec::new(),
        }),
    }
}

#[derive(Debug, Clone, Copy)]
enum Op {
    Enable,
    Disable,
    Reenroll,
}

/// Runs one lifecycle method and checks the permit was held at every step and
/// released on return.
async fn call(fake: &Fake, op: Op) -> Result<(), PlatformError> {
    let permit = Arc::clone(&fake.permit);
    let result = match op {
        Op::Enable => enable(&permit, fake).await,
        Op::Disable => disable(&permit, fake).await,
        Op::Reenroll => reenroll(&permit, fake).await,
    };
    fake.assert_permit_held_throughout();
    result
}

async fn call_enrollment(fake: &Fake) -> Result<(String, String, String, u64), PlatformError> {
    let permit = Arc::clone(&fake.permit);
    let result = enrollment(&permit, fake).await;
    fake.assert_permit_held_throughout();
    result
}

macro_rules! assert_error {
    ($result:expr, $variant:ident) => {
        assert!(
            matches!($result, Err(PlatformError::$variant(_))),
            "expected {}, got {:?}",
            stringify!($variant),
            $result
        )
    };
}

const ENABLE: [&str; 4] = [
    "marker:reset-pending",
    ENABLE_UNIT,
    "auth:EnsurePendingPairing",
    "start",
];

// Enable.

#[tokio::test]
async fn enable_runs_the_frozen_steps_in_order() {
    let fake = Fake::new();
    assert!(call(&fake, Op::Enable).await.is_ok());
    assert_eq!(fake.calls(), ENABLE);
}

#[tokio::test]
async fn enable_refuses_a_pending_reset_before_any_side_effect() {
    let mut fake = Fake::new();
    fake.reset_pending = true;
    let result = call(&fake, Op::Enable).await;
    assert_error!(result, ResetIncomplete);
    assert_eq!(fake.calls(), ["marker:reset-pending"]);
}

#[tokio::test]
async fn enable_stops_at_each_failure_point() {
    let cases: [(&str, fn(&Result<(), PlatformError>)); 4] = [
        ("marker:reset-pending", |result| {
            assert_error!(result, RemoteManagementUnavailable)
        }),
        (ENABLE_UNIT, |result| {
            assert_error!(result, RemoteManagementUnavailable)
        }),
        ("auth:EnsurePendingPairing", |result| {
            assert_error!(result, AuthUnavailable)
        }),
        ("start", |result| {
            assert_error!(result, RemoteManagementUnavailable)
        }),
    ];
    for (index, (step, check)) in cases.into_iter().enumerate() {
        let mut fake = Fake::new();
        fake.fail = Some(step);
        let result = call(&fake, Op::Enable).await;
        check(&result);
        assert_eq!(fake.calls(), ENABLE[..=index], "{step}");
    }
}

#[tokio::test]
async fn a_running_worker_is_busy() {
    let mut fake = Fake::new();
    fake.worker_busy = true;
    let result = call(&fake, Op::Enable).await;
    assert_error!(result, Busy);
    assert_eq!(fake.calls(), ENABLE[..2]);
}

// Disable.

const DISABLE: [&str; 3] = [DISABLE_UNIT, "stop", "auth:CancelPendingPairing"];

#[tokio::test]
async fn disable_runs_the_frozen_steps_and_stops_at_each_failure() {
    let fake = Fake::new();
    assert!(call(&fake, Op::Disable).await.is_ok());
    assert_eq!(fake.calls(), DISABLE);
    let cases: [(&str, fn(&Result<(), PlatformError>)); 3] = [
        (DISABLE_UNIT, |result| {
            assert_error!(result, RemoteManagementUnavailable)
        }),
        ("stop", |result| {
            assert_error!(result, RemoteManagementUnavailable)
        }),
        ("auth:CancelPendingPairing", |result| {
            assert_error!(result, AuthUnavailable)
        }),
    ];
    for (index, (step, check)) in cases.into_iter().enumerate() {
        let mut fake = Fake::new();
        fake.fail = Some(step);
        let result = call(&fake, Op::Disable).await;
        check(&result);
        assert_eq!(fake.calls(), DISABLE[..=index], "{step}");
    }
}

#[tokio::test]
async fn disable_is_allowed_while_a_reset_is_pending() {
    let mut fake = Fake::new();
    fake.reset_pending = true;
    assert!(call(&fake, Op::Disable).await.is_ok());
    assert_eq!(fake.calls(), DISABLE);
}

// Reenroll.

const REENROLL_ENABLED: [&str; 7] = [
    "stop",
    "auth:ResetEnrollment",
    ROTATE_UNIT,
    "marker:enabled",
    "auth:EnsurePendingPairing",
    "marker:reset-pending",
    "start",
];

const REENROLL_REPAIR: [&str; 8] = [
    "stop",
    "auth:ResetEnrollment",
    ROTATE_UNIT,
    "marker:enabled",
    "auth:EnsurePendingPairing",
    "marker:reset-pending",
    CLEAR_RESET_UNIT,
    "start",
];

#[tokio::test]
async fn reenroll_on_an_enabled_machine() {
    let fake = Fake::new();
    assert!(call(&fake, Op::Reenroll).await.is_ok());
    assert_eq!(fake.calls(), REENROLL_ENABLED);
}

#[tokio::test]
async fn reenroll_on_a_disabled_machine_creates_no_pairing_and_starts_nothing() {
    let mut fake = Fake::new();
    fake.enabled = false;
    assert!(call(&fake, Op::Reenroll).await.is_ok());
    assert_eq!(
        fake.calls(),
        [
            "stop",
            "auth:ResetEnrollment",
            ROTATE_UNIT,
            "marker:enabled",
            "marker:reset-pending"
        ]
    );
    fake.reset_pending = true;
    fake.calls.lock().unwrap().clear();
    assert!(call(&fake, Op::Reenroll).await.is_ok());
    assert_eq!(
        fake.calls(),
        [
            "stop",
            "auth:ResetEnrollment",
            ROTATE_UNIT,
            "marker:enabled",
            "marker:reset-pending",
            CLEAR_RESET_UNIT
        ]
    );
}

#[tokio::test]
async fn reenroll_repairs_a_pending_reset_clearing_it_last_before_the_start() {
    let mut fake = Fake::new();
    fake.reset_pending = true;
    assert!(call(&fake, Op::Reenroll).await.is_ok());
    assert_eq!(fake.calls(), REENROLL_REPAIR);
}

#[tokio::test]
async fn reenroll_holds_the_permit_through_the_clear_and_the_start_even_when_it_fails() {
    let mut fake = Fake::new();
    fake.reset_pending = true;
    fake.fail = Some("start");
    let result = call(&fake, Op::Reenroll).await;
    assert_error!(result, RemoteManagementUnavailable);
    let held = fake.permit_held_at.lock().unwrap().clone();
    assert!(held.contains(&(CLEAR_RESET_UNIT, true)));
    assert!(held.contains(&("start", true)));
    // Released on return, including after the failed start.
    assert_eq!(fake.permit.available_permits(), 1);
}

#[tokio::test]
async fn reenroll_stops_at_each_failure_point_and_never_reports_reset_incomplete() {
    type Check = fn(&Result<(), PlatformError>);
    let unavailable: Check = |result| assert_error!(result, RemoteManagementUnavailable);
    let auth: Check = |result| assert_error!(result, AuthUnavailable);
    let cases: [(&str, Check); 8] = [
        ("stop", unavailable),
        ("auth:ResetEnrollment", auth),
        (ROTATE_UNIT, unavailable),
        ("marker:enabled", unavailable),
        ("auth:EnsurePendingPairing", auth),
        ("marker:reset-pending", unavailable),
        (CLEAR_RESET_UNIT, unavailable),
        ("start", unavailable),
    ];
    for (index, (step, check)) in cases.into_iter().enumerate() {
        let mut fake = Fake::new();
        fake.reset_pending = true;
        fake.fail = Some(step);
        let result = call(&fake, Op::Reenroll).await;
        check(&result);
        assert_eq!(fake.calls(), REENROLL_REPAIR[..=index], "{step}");
        // sl-remoted is never started after a failed reset, rotation, pairing
        // or clear.
        if index < 7 {
            assert!(!fake.calls().contains(&"start"), "{step}");
        }
    }
}

// Enrollment.

#[tokio::test]
async fn enrollment_composes_url_fingerprint_and_pairing() {
    let fake = Fake::new();
    let result = call_enrollment(&fake).await;
    assert_eq!(
        result.unwrap(),
        (
            "https://192.0.2.10:8443/".into(),
            FINGERPRINT.into(),
            "04HMASW9".into(),
            1_800_000_600
        )
    );
    // Reads only: no credential-creating or state-changing call.
    assert_eq!(
        fake.calls(),
        ["network", "fingerprint", "auth:GetPendingPairing"]
    );
}

#[tokio::test]
async fn enrollment_reports_absent_values_as_empty() {
    let mut fake = Fake::new();
    fake.network = Ok(NetworkStatus {
        state: NetworkState::Disconnected,
        primary_connection: None,
    });
    fake.fingerprint = Ok(None);
    fake.pairing = Ok((false, "ignored".into(), 7));
    let result = call_enrollment(&fake).await;
    assert_eq!(
        result.unwrap(),
        (String::new(), String::new(), String::new(), 0)
    );
}

#[tokio::test]
async fn enrollment_errors_are_named() {
    let mut fake = Fake::new();
    fake.network = Err(());
    assert_error!(call_enrollment(&fake).await, NetworkUnavailable);
    let mut fake = Fake::new();
    fake.fingerprint = Err(());
    assert_error!(call_enrollment(&fake).await, RemoteManagementUnavailable);
    for pairing in [
        Err(()),
        Ok((true, "04hmasw9".into(), 1)),
        Ok((true, "04HMASWU".into(), 1)),
        Ok((true, "04HM-ASW9".into(), 1)),
        Ok((true, "04HMASW9".into(), 0)),
    ] {
        let mut fake = Fake::new();
        fake.pairing = pairing.clone();
        assert_error!(call_enrollment(&fake).await, AuthUnavailable);
    }
}

#[test]
fn enrollment_url_formats_and_selects_one_address() {
    let url = |addresses: &[&str]| enrollment_url(&network(addresses));
    assert_eq!(url(&["192.0.2.10/24"]), "https://192.0.2.10:8443/");
    assert_eq!(url(&["2001:db8::10/64"]), "https://[2001:db8::10]:8443/");
    // IPv4 is preferred; within a family, the observer's order decides.
    assert_eq!(
        url(&["10.0.0.5/8", "192.0.2.10/24", "2001:db8::10/64"]),
        "https://10.0.0.5:8443/"
    );
    assert_eq!(
        url(&["2001:db8::10/64", "2001:db8::2/64"]),
        "https://[2001:db8::10]:8443/"
    );
    // Exclusions.
    for excluded in [
        "127.0.0.1/8",
        "0.0.0.0/0",
        "224.0.0.1/4",
        "169.254.1.2/16",
        "::1/128",
        "::/0",
        "ff02::1/16",
        "fe80::1/64",
        "febf::1/64",
    ] {
        assert_eq!(url(&[excluded]), "", "{excluded}");
    }
    assert_eq!(
        url(&["169.254.1.2/16", "fe80::1/64", "2001:db8::10/64"]),
        "https://[2001:db8::10]:8443/"
    );
    assert_eq!(url(&["fec0::1/64"]), "https://[fec0::1]:8443/");
    assert_eq!(url(&[]), "");
}

// Permit.

#[tokio::test]
async fn every_method_is_busy_while_the_permit_is_held() {
    let fake = Fake::new();
    let held = fake.permit.try_acquire().unwrap();
    assert_error!(enable(&fake.permit, &fake).await, Busy);
    assert_error!(disable(&fake.permit, &fake).await, Busy);
    assert_error!(reenroll(&fake.permit, &fake).await, Busy);
    assert_error!(enrollment(&fake.permit, &fake).await, Busy);
    assert!(fake.calls().is_empty(), "no step ran");
    drop(held);
    assert!(enable(&fake.permit, &fake).await.is_ok());
}

#[tokio::test]
async fn the_permit_is_released_after_every_outcome() {
    for fail in [
        None,
        Some("start"),
        Some("stop"),
        Some("auth:ResetEnrollment"),
    ] {
        let mut fake = Fake::new();
        fake.fail = fail;
        let _ = call(&fake, Op::Enable).await;
        let _ = call(&fake, Op::Disable).await;
        let _ = call(&fake, Op::Reenroll).await;
        let _ = call_enrollment(&fake).await;
    }
}

#[tokio::test]
async fn the_remote_management_permit_is_independent_of_mutation_starts() {
    let mutation_starts = Semaphore::new(1);
    let _update = mutation_starts.try_acquire().unwrap();
    let fake = Fake::new();
    assert!(enable(&fake.permit, &fake).await.is_ok());
    let _remote = fake.permit.try_acquire().unwrap();
    let other = Semaphore::new(1);
    assert!(
        other.try_acquire().is_ok(),
        "a separate permit is unaffected"
    );
    assert!(mutation_starts.try_acquire().is_err());
}

#[test]
fn a_worker_succeeds_only_when_inactive_with_result_success() {
    assert!(worker_succeeded("inactive", "success"));
    for (active, result) in [
        ("failed", "exit-code"),
        ("failed", "success"),
        ("inactive", "exit-code"),
        ("inactive", "timeout"),
        ("active", "success"),
    ] {
        assert!(!worker_succeeded(active, result), "{active} {result}");
    }
}

#[test]
fn a_worker_waits_only_while_the_exact_start_job_is_listed() {
    let expected =
        zbus::zvariant::OwnedObjectPath::try_from("/org/freedesktop/systemd1/job/7").unwrap();
    let other =
        zbus::zvariant::OwnedObjectPath::try_from("/org/freedesktop/systemd1/job/8").unwrap();
    let unit = zbus::zvariant::OwnedObjectPath::try_from(
        "/org/freedesktop/systemd1/unit/sl_2drm_2denable_2eservice",
    )
    .unwrap();
    let jobs = vec![(
        7,
        ENABLE_UNIT.into(),
        "start".into(),
        "running".into(),
        expected.clone(),
        unit.clone(),
    )];
    assert!(job_pending(&jobs, &expected));
    assert!(!job_pending(&jobs, &other));
    assert!(!job_pending(&[], &expected));
}

#[test]
fn the_worker_completion_bound_remains_thirty_seconds() {
    assert_eq!(WORKER_TIMEOUT, Duration::from_secs(30));
}
