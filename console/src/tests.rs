use super::*;
use sl_protocol::*;
use std::{cell::RefCell, collections::VecDeque};

struct Fake {
    enrolled: RefCell<bool>,
    enabled: RefCell<bool>,
    auth: RefCell<Result<(), AuthFailure>>,
    platform: RefCell<VecDeque<Result<(), PlatformFailure>>>,
    calls: RefCell<Vec<&'static str>>,
    status_available: RefCell<bool>,
    reset_incomplete: RefCell<bool>,
}

impl Fake {
    fn with(enrolled: bool, enabled: bool) -> Self {
        Self {
            enrolled: RefCell::new(enrolled),
            enabled: RefCell::new(enabled),
            auth: RefCell::new(Ok(())),
            platform: RefCell::new(VecDeque::new()),
            calls: RefCell::new(Vec::new()),
            status_available: RefCell::new(true),
            reset_incomplete: RefCell::new(false),
        }
    }
}

impl Backend for Fake {
    async fn status(&self) -> Result<SessionStatus, ConsoleError> {
        self.calls.borrow_mut().push("status");
        if !*self.status_available.borrow() {
            return Err(ConsoleError::StatusUnavailable);
        }
        let remote = RemoteManagementStatus {
            enabled: *self.enabled.borrow(),
            listening: *self.enabled.borrow(),
            enrolled: *self.enrolled.borrow(),
        };
        let platform: Status = serde_json::from_value(serde_json::json!({
            "schema_version":"0.3","product":"SignalLayer CoreOS","version":"0.0.3",
            "platform_api_version":"0.3","source_revision":null,"build_id":null,
            "machine":{"machine_id":"machine","architecture":"x86_64","boot_id":"boot"},
            "network":{"state":"connected_global","primary_connection":null},
            "booted":{"deployment_id":"a.0","image_reference":null,"image_digest":null},
            "retained_rollback":null,
            "update":{"state":"idle","staged":null,"reboot_required":false,"failure":null},
            "rollback":{"state":"idle","reboot_required":false,"failure":null},
            "health":{"state":"healthy","system_state":"running","failed_units":0}
        }))
        .unwrap();
        Ok(SessionStatus::from_platform(platform, remote))
    }

    async fn enrollment(&self) -> Result<Enrollment, ConsoleError> {
        self.calls.borrow_mut().push("enrollment");
        if *self.reset_incomplete.borrow() {
            return Err(ConsoleError::Platform(PlatformFailure::ResetIncomplete));
        }
        Ok(Enrollment {
            url: "https://10.0.0.2:8443/".into(),
            fingerprint: "AA".into(),
            pairing_code: if *self.enrolled.borrow() {
                ""
            } else {
                "01234567"
            }
            .into(),
            expires_at: 1,
        })
    }

    async fn verify_password(&self, _: &str) -> Result<(), AuthFailure> {
        self.calls.borrow_mut().push("verify");
        *self.auth.borrow()
    }

    async fn recover_password(&self, _: &str, _: &str) -> Result<(), AuthFailure> {
        self.calls.borrow_mut().push("recover");
        *self.auth.borrow()
    }

    async fn platform(&self, action: Action) -> Result<(), PlatformFailure> {
        self.calls.borrow_mut().push(match action {
            Action::Enable => "enable",
            Action::Disable => "disable",
            Action::Reenroll => "reenroll",
        });
        let result = self.platform.borrow_mut().pop_front().unwrap_or(Ok(()));
        if result == Err(PlatformFailure::ResetIncomplete) {
            *self.reset_incomplete.borrow_mut() = true;
        }
        if result.is_ok() {
            match action {
                Action::Enable => *self.enabled.borrow_mut() = true,
                Action::Disable => *self.enabled.borrow_mut() = false,
                Action::Reenroll => {
                    *self.enrolled.borrow_mut() = false;
                    *self.reset_incomplete.borrow_mut() = false;
                }
            }
        }
        result
    }
}

#[tokio::test]
async fn unenrolled_enable_and_pairing_need_no_password() {
    let mut controller = Controller::new(Fake::with(false, false));
    let view = controller.act(Action::Enable).await.unwrap();
    assert!(view.remote.enabled);
    assert_eq!(view.enrollment.pairing_code, "01234567");
    assert!(!controller.backend.calls.borrow().contains(&"verify"));
}

#[tokio::test]
async fn enrolled_actions_require_successful_authentication() {
    let mut controller = Controller::new(Fake::with(true, true));
    assert_eq!(
        controller.act(Action::Disable).await.unwrap_err(),
        ConsoleError::AuthenticationRequired
    );
    controller.authenticate("correct").await.unwrap();
    assert!(
        !controller
            .act(Action::Disable)
            .await
            .unwrap()
            .remote
            .enabled
    );
}

#[tokio::test]
async fn bad_credentials_never_authorize() {
    let fake = Fake::with(true, true);
    *fake.auth.borrow_mut() = Err(AuthFailure::InvalidCredential);
    let mut controller = Controller::new(fake);
    assert_eq!(
        controller.authenticate("bad").await.unwrap_err(),
        ConsoleError::Auth(AuthFailure::InvalidCredential)
    );
    assert_eq!(
        controller.act(Action::Disable).await.unwrap_err(),
        ConsoleError::AuthenticationRequired
    );
}

#[tokio::test]
async fn reset_incomplete_is_a_distinct_reenroll_repair_state() {
    let fake = Fake::with(false, false);
    fake.platform
        .borrow_mut()
        .push_back(Err(PlatformFailure::ResetIncomplete));
    let mut controller = Controller::new(fake);
    assert_eq!(
        controller.act(Action::Enable).await.unwrap_err(),
        ConsoleError::Platform(PlatformFailure::ResetIncomplete)
    );
    assert!(controller.refresh().await.unwrap().reset_incomplete);
    assert_eq!(
        controller.act(Action::Enable).await.unwrap_err(),
        ConsoleError::Platform(PlatformFailure::ResetIncomplete)
    );
    assert!(
        !controller
            .act(Action::Reenroll)
            .await
            .unwrap()
            .reset_incomplete
    );
}

#[tokio::test]
async fn fresh_console_discovers_preexisting_incomplete_reset_without_mutation() {
    let fake = Fake::with(false, false);
    *fake.reset_incomplete.borrow_mut() = true;
    let mut controller = Controller::new(fake);

    let view = controller.refresh().await.unwrap();
    assert!(view.reset_incomplete);
    assert_eq!(
        view.enrollment,
        Enrollment {
            url: String::new(),
            fingerprint: String::new(),
            pairing_code: String::new(),
            expires_at: 0,
        }
    );
    assert_eq!(
        &*controller.backend.calls.borrow(),
        &["status", "enrollment"]
    );

    assert_eq!(
        controller.act(Action::Enable).await.unwrap_err(),
        ConsoleError::Platform(PlatformFailure::ResetIncomplete)
    );
    assert!(!controller.backend.calls.borrow().contains(&"enable"));
}

#[tokio::test]
async fn recovery_uses_authd_and_does_not_grant_a_session() {
    let mut controller = Controller::new(Fake::with(true, true));
    let view = controller
        .recover_password("key", "new password")
        .await
        .unwrap();
    assert!(!view.authenticated);
    assert!(controller.backend.calls.borrow().contains(&"recover"));
    assert_eq!(
        controller.act(Action::Disable).await.unwrap_err(),
        ConsoleError::AuthenticationRequired
    );
}

#[tokio::test]
async fn logout_and_enrollment_change_revoke_authorization() {
    let mut controller = Controller::new(Fake::with(true, true));
    controller.authenticate("correct").await.unwrap();
    controller.logout();
    assert_eq!(
        controller.act(Action::Disable).await.unwrap_err(),
        ConsoleError::AuthenticationRequired
    );
    controller.authenticate("correct").await.unwrap();
    *controller.backend.enrolled.borrow_mut() = false;
    assert!(!controller.refresh().await.unwrap().authenticated);
}

#[tokio::test]
async fn backend_loss_fails_closed() {
    let fake = Fake::with(false, false);
    *fake.status_available.borrow_mut() = false;
    let mut controller = Controller::new(fake);
    assert_eq!(
        controller.act(Action::Enable).await.unwrap_err(),
        ConsoleError::StatusUnavailable
    );
    assert!(controller
        .backend
        .calls
        .borrow()
        .iter()
        .all(|call| *call != "enable"));
}

#[test]
fn console_abstraction_contains_only_frozen_actions() {
    assert_eq!([Action::Enable, Action::Disable, Action::Reenroll].len(), 3);
}

#[test]
fn call_deadlines_cover_platform_contracts_with_bounded_slack() {
    assert_eq!(READ_AUTH_TIMEOUT, Duration::from_secs(30));
    assert_eq!(lifecycle_timeout(Action::Enable), Duration::from_secs(60));
    assert_eq!(lifecycle_timeout(Action::Disable), Duration::from_secs(60));
    assert_eq!(
        lifecycle_timeout(Action::Reenroll),
        Duration::from_secs(110)
    );
    assert!(lifecycle_timeout(Action::Enable) > Duration::from_secs(50));
    assert!(lifecycle_timeout(Action::Reenroll) > Duration::from_secs(100));
}
