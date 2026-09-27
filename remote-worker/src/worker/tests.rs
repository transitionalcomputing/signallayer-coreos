use super::*;
use std::{
    cell::RefCell,
    os::unix::fs::MetadataExt,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "sl-remote-worker-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    /// The worker's state directory, not yet created.
    fn state(&self) -> PathBuf {
        self.0.join("sl-remote-management")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    Req,
    Fingerprint,
    Reset,
}

/// Records calls; a fake openssl writes the files the real one would.
#[derive(Default)]
struct FakeTools {
    calls: Vec<Call>,
    arguments: Vec<Vec<OsString>>,
    counter: u8,
    fail_req: bool,
    fingerprint_output: Option<Vec<u8>>,
    skip_key: bool,
    fail_reset: bool,
    fail_random: bool,
    /// Called when reset_enrollment runs, to snapshot the filesystem.
    on_reset: Option<Box<dyn FnMut()>>,
}

fn fingerprint_for(counter: u8) -> String {
    let mut parts = Vec::new();
    for index in 0..32u8 {
        parts.push(format!("{:02X}", index.wrapping_add(counter)));
    }
    parts.join(":")
}

impl Tools for FakeTools {
    fn openssl(&mut self, arguments: &[OsString]) -> Result<Vec<u8>, ()> {
        self.arguments.push(arguments.to_vec());
        let position = |flag: &str| {
            arguments
                .iter()
                .position(|argument| argument == flag)
                .map(|index| PathBuf::from(&arguments[index + 1]))
        };
        if arguments[0] == "req" {
            self.calls.push(Call::Req);
            if self.fail_req {
                return Err(());
            }
            if !self.skip_key {
                fs::write(position("-keyout").unwrap(), b"key").unwrap();
            }
            fs::write(position("-out").unwrap(), b"cert").unwrap();
            Ok(Vec::new())
        } else {
            self.calls.push(Call::Fingerprint);
            Ok(self.fingerprint_output.clone().unwrap_or_else(|| {
                format!("sha256 Fingerprint={}\n", fingerprint_for(self.counter)).into_bytes()
            }))
        }
    }

    fn reset_enrollment(&mut self) -> Result<(), ()> {
        self.calls.push(Call::Reset);
        if let Some(hook) = self.on_reset.as_mut() {
            hook();
        }
        if self.fail_reset {
            Err(())
        } else {
            Ok(())
        }
    }

    fn random(&mut self, buffer: &mut [u8]) -> Result<(), ()> {
        if self.fail_random {
            return Err(());
        }
        self.counter += 1;
        buffer.fill(self.counter);
        Ok(())
    }
}

fn worker(directory: &TempDir) -> Worker<FakeTools> {
    Worker::new(directory.state(), FakeTools::default(), Ownership::Skip)
}

fn mode_of(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

fn exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn generations(state: &Path) -> Vec<String> {
    let mut names: Vec<String> = match fs::read_dir(state.join(TLS_DIR)) {
        Ok(entries) => entries
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.starts_with("gen-"))
            .collect(),
        Err(_) => Vec::new(),
    };
    names.sort();
    names
}

fn current(state: &Path) -> Option<String> {
    layout::current_generation(state).unwrap()
}

// Fixed argv.

#[test]
fn openssl_path_and_argv_are_the_frozen_fixed_lists() {
    assert_eq!(OPENSSL, "/usr/bin/openssl");
    let generation = Path::new("/var/lib/sl-remote-management/tls/gen-0000000000000001");
    let req: Vec<String> = req_arguments(generation)
        .into_iter()
        .map(|argument| argument.into_string().unwrap())
        .collect();
    assert_eq!(
        req,
        [
            "req",
            "-x509",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-pkeyopt",
            "ec_param_enc:named_curve",
            "-noenc",
            "-keyout",
            "/var/lib/sl-remote-management/tls/gen-0000000000000001/key.pem",
            "-out",
            "/var/lib/sl-remote-management/tls/gen-0000000000000001/cert.pem",
            "-subj",
            "/CN=SignalLayer CoreOS remote management",
            "-not_after",
            "99991231235959Z",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-addext",
            "keyUsage=critical,digitalSignature",
            "-addext",
            "extendedKeyUsage=serverAuth",
        ]
    );
    let fingerprint: Vec<String> = fingerprint_arguments(generation)
        .into_iter()
        .map(|argument| argument.into_string().unwrap())
        .collect();
    assert_eq!(
        fingerprint,
        [
            "x509",
            "-in",
            "/var/lib/sl-remote-management/tls/gen-0000000000000001/cert.pem",
            "-noout",
            "-fingerprint",
            "-sha256",
        ]
    );
}

// Enable.

#[test]
fn enable_generates_an_identity_then_commits_the_marker() {
    let directory = TempDir::new();
    let state = directory.state();
    let mut worker = worker(&directory);
    worker.run(Mode::Enable).unwrap();
    assert_eq!(worker.tools().calls, [Call::Req, Call::Fingerprint]);
    let generation = current(&state).unwrap();
    assert_eq!(generation, "gen-0101010101010101");
    assert_eq!(generations(&state), [generation.clone()]);
    let generation_directory = state.join(TLS_DIR).join(&generation);
    assert_eq!(mode_of(&state), 0o755);
    assert_eq!(mode_of(&state.join(TLS_DIR)), 0o750);
    assert_eq!(mode_of(&generation_directory), 0o750);
    assert_eq!(mode_of(&generation_directory.join(KEY_FILE)), 0o640);
    assert_eq!(mode_of(&generation_directory.join(CERT_FILE)), 0o644);
    assert_eq!(mode_of(&generation_directory.join(FINGERPRINT_FILE)), 0o644);
    assert_eq!(
        fs::read_to_string(generation_directory.join(FINGERPRINT_FILE)).unwrap(),
        format!("{}\n", fingerprint_for(1))
    );
    assert_eq!(mode_of(&state.join(ENABLED)), 0o644);
    assert_eq!(fs::read(state.join(ENABLED)).unwrap(), b"");
    // The argv used the generation directory it created.
    assert_eq!(
        worker.tools().arguments[0],
        req_arguments(&generation_directory)
    );
}

#[test]
fn enable_never_rotates_an_existing_identity() {
    let directory = TempDir::new();
    let state = directory.state();
    let mut worker = worker(&directory);
    worker.run(Mode::Enable).unwrap();
    let before = current(&state);
    worker.run(Mode::Enable).unwrap();
    worker.run(Mode::Disable).unwrap();
    worker.run(Mode::Enable).unwrap();
    assert_eq!(current(&state), before);
    assert_eq!(worker.tools().calls, [Call::Req, Call::Fingerprint]);
    assert!(exists(&state.join(ENABLED)));
}

#[test]
fn enable_refuses_while_a_reset_is_pending() {
    let directory = TempDir::new();
    let state = directory.state();
    fs::create_dir(&state).unwrap();
    fs::write(state.join(RESET_PENDING), b"").unwrap();
    let mut worker = worker(&directory);
    assert!(worker.run(Mode::Enable).is_err());
    assert!(worker.tools().calls.is_empty());
    assert!(!exists(&state.join(ENABLED)));
    assert!(!exists(&state.join(TLS_DIR)));
}

#[test]
fn enable_fails_closed_on_an_invalid_identity() {
    let directory = TempDir::new();
    let state = directory.state();
    let mut worker = worker(&directory);
    worker.run(Mode::Enable).unwrap();
    worker.run(Mode::Disable).unwrap();
    let generation = current(&state).unwrap();
    fs::write(
        state.join(TLS_DIR).join(&generation).join(FINGERPRINT_FILE),
        b"malformed\n",
    )
    .unwrap();
    assert_eq!(
        worker.run(Mode::Enable),
        Err(Failed("the existing TLS identity is invalid"))
    );
    assert!(!exists(&state.join(ENABLED)));
    assert_eq!(current(&state), Some(generation.clone()));
    assert_eq!(worker.tools().calls, [Call::Req, Call::Fingerprint]);
    // A dangling current is invalid too, and is not replaced.
    fs::remove_dir_all(state.join(TLS_DIR).join(&generation)).unwrap();
    assert!(worker.run(Mode::Enable).is_err());
    assert!(!exists(&state.join(ENABLED)));
    // Rotation (Reenroll) repairs it.
    worker.run(Mode::RotateTls).unwrap();
    worker.run(Mode::Enable).unwrap();
    assert!(exists(&state.join(ENABLED)));
}

#[test]
fn a_failed_generation_leaves_no_identity_and_no_marker() {
    let directory = TempDir::new();
    let state = directory.state();
    let mut worker = worker(&directory);
    worker.tools().fail_req = true;
    assert!(worker.run(Mode::Enable).is_err());
    assert_eq!(current(&state), None);
    assert!(generations(&state).is_empty());
    assert!(!exists(&state.join(ENABLED)));
    worker.tools().fail_req = false;
    worker.tools().fingerprint_output = Some(b"sha256 Fingerprint=nonsense\n".to_vec());
    assert_eq!(
        worker.run(Mode::Enable),
        Err(Failed("openssl returned a malformed fingerprint"))
    );
    assert!(generations(&state).is_empty());
    assert!(!exists(&state.join(ENABLED)));
    worker.tools().fingerprint_output = None;
    worker.tools().skip_key = true;
    assert!(worker.run(Mode::Enable).is_err());
    assert!(generations(&state).is_empty());
    worker.tools().skip_key = false;
    worker.tools().fail_random = true;
    assert!(worker.run(Mode::Enable).is_err());
    worker.tools().fail_random = false;
    worker.run(Mode::Enable).unwrap();
    assert!(current(&state).is_some());
    assert!(exists(&state.join(ENABLED)));
}

#[test]
fn a_failed_swap_leaves_no_identity_and_no_marker() {
    let directory = TempDir::new();
    let state = directory.state();
    let mut worker = worker(&directory).with_faults(|point| point == Point::SwapCurrent);
    assert!(worker.run(Mode::Enable).is_err());
    assert_eq!(current(&state), None);
    assert!(!exists(&state.join(ENABLED)));
}

// Disable and clear-reset-pending.

#[test]
fn disable_removes_only_the_enabled_marker() {
    let directory = TempDir::new();
    let state = directory.state();
    let mut worker = worker(&directory);
    worker.run(Mode::Disable).unwrap();
    worker.run(Mode::Enable).unwrap();
    let identity = current(&state);
    worker.run(Mode::Disable).unwrap();
    assert!(!exists(&state.join(ENABLED)));
    assert_eq!(current(&state), identity);
    worker.run(Mode::Disable).unwrap();
}

#[test]
fn clear_reset_pending_removes_only_that_marker() {
    let directory = TempDir::new();
    let state = directory.state();
    let mut worker = worker(&directory);
    worker.run(Mode::ClearResetPending).unwrap();
    worker.run(Mode::Enable).unwrap();
    fs::write(state.join(RESET_PENDING), b"").unwrap();
    worker.run(Mode::ClearResetPending).unwrap();
    assert!(!exists(&state.join(RESET_PENDING)));
    assert!(exists(&state.join(ENABLED)));
    assert!(current(&state).is_some());
    worker.run(Mode::ClearResetPending).unwrap();
}

#[test]
fn marker_removal_failure_keeps_the_marker() {
    let directory = TempDir::new();
    let state = directory.state();
    let mut worker = worker(&directory).with_faults(|point| point == Point::RemoveMarker(ENABLED));
    worker.run(Mode::Enable).unwrap();
    assert!(worker.run(Mode::Disable).is_err());
    assert!(exists(&state.join(ENABLED)));
}

#[test]
fn marker_creation_failure_leaves_no_marker_or_temporary() {
    let directory = TempDir::new();
    let state = directory.state();
    let mut worker = worker(&directory).with_faults(|point| point == Point::CreateMarker(ENABLED));
    assert!(worker.run(Mode::Enable).is_err());
    assert!(!exists(&state.join(ENABLED)));
    assert!(!exists(&state.join("enabled.tmp")));
}

// Rotation and cleanup.

#[test]
fn rotation_installs_a_new_identity_and_removes_the_old() {
    let directory = TempDir::new();
    let state = directory.state();
    let mut worker = worker(&directory);
    worker.run(Mode::Enable).unwrap();
    let old = current(&state).unwrap();
    let old_fingerprint = layout::current_fingerprint(&state).unwrap();
    worker.run(Mode::RotateTls).unwrap();
    let new = current(&state).unwrap();
    assert_ne!(new, old);
    assert_ne!(
        layout::current_fingerprint(&state).unwrap(),
        old_fingerprint
    );
    assert_eq!(generations(&state), [new]);
    assert!(
        exists(&state.join(ENABLED)),
        "rotation does not touch the marker"
    );
}

#[test]
fn a_failed_rotation_keeps_the_previous_identity() {
    let directory = TempDir::new();
    let state = directory.state();
    let mut worker = worker(&directory);
    worker.run(Mode::Enable).unwrap();
    let old = current(&state).unwrap();
    worker.tools().fail_req = true;
    assert!(worker.run(Mode::RotateTls).is_err());
    assert_eq!(current(&state), Some(old.clone()));
    assert_eq!(generations(&state), [old.clone()]);
    worker.tools().fail_req = false;
    let mut failing_swap = Worker::new(state.clone(), FakeTools::default(), Ownership::Skip)
        .with_faults(|point| point == Point::SwapCurrent);
    failing_swap.tools().counter = 50;
    assert!(failing_swap.run(Mode::RotateTls).is_err());
    assert_eq!(current(&state), Some(old.clone()));
    // The unreferenced generation is removed by the next run that writes TLS.
    assert_eq!(generations(&state).len(), 2);
    worker.run(Mode::RotateTls).unwrap();
    assert_eq!(generations(&state), [current(&state).unwrap()]);
}

#[test]
fn a_new_generation_never_collides_with_a_leftover() {
    let directory = TempDir::new();
    let state = directory.state();
    // gen-0101010101010101 is left unreferenced, as after a failed reset.
    fs::create_dir_all(state.join(TLS_DIR).join("gen-0101010101010101")).unwrap();
    let mut worker = worker(&directory);
    worker.run(Mode::RotateTls).unwrap();
    assert_eq!(current(&state).as_deref(), Some("gen-0101010101010101"));
    assert_eq!(generations(&state), ["gen-0101010101010101"]);
}

#[test]
fn stale_temporaries_are_removed_by_the_next_run() {
    let directory = TempDir::new();
    let state = directory.state();
    let mut worker = worker(&directory);
    worker.run(Mode::Enable).unwrap();
    fs::write(state.join("enabled.tmp"), b"").unwrap();
    fs::write(state.join("reset-pending.tmp"), b"").unwrap();
    symlink(
        "gen-ffffffffffffffff",
        state.join(TLS_DIR).join("current.tmp"),
    )
    .unwrap();
    worker.run(Mode::Disable).unwrap();
    assert!(!exists(&state.join("enabled.tmp")));
    assert!(!exists(&state.join("reset-pending.tmp")));
    assert!(!exists(&state.join(TLS_DIR).join("current.tmp")));
}

#[test]
fn only_generation_entries_are_cleaned_up() {
    let directory = TempDir::new();
    let state = directory.state();
    let mut worker = worker(&directory);
    worker.run(Mode::Enable).unwrap();
    fs::create_dir(state.join(TLS_DIR).join("gen-00000000000000aa")).unwrap();
    fs::write(state.join(TLS_DIR).join("gen-00000000000000bb"), b"").unwrap();
    fs::write(state.join(TLS_DIR).join("unrelated"), b"").unwrap();
    worker.run(Mode::RotateTls).unwrap();
    assert_eq!(generations(&state), [current(&state).unwrap()]);
    assert!(exists(&state.join(TLS_DIR).join("unrelated")));
}

// Boot reset.

#[test]
fn boot_reset_follows_the_frozen_order() {
    let directory = TempDir::new();
    let state = directory.state();
    let mut worker = worker(&directory);
    worker.run(Mode::Enable).unwrap();
    let old = current(&state).unwrap();
    let observed = Rc::new(RefCell::new(None));
    let snapshot = Rc::clone(&observed);
    let at_reset = state.clone();
    let old_generation = old.clone();
    worker.tools().on_reset = Some(Box::new(move || {
        // At the sl-authd call: reset-pending is committed, current is gone,
        // and the old generation is still present.
        *snapshot.borrow_mut() = Some((
            exists(&at_reset.join(RESET_PENDING)),
            exists(&at_reset.join(TLS_DIR).join(CURRENT)),
            exists(&at_reset.join(TLS_DIR).join(&old_generation)),
        ));
    }));
    worker.run(Mode::BootReset).unwrap();
    assert_eq!(*observed.borrow(), Some((true, false, true)));
    assert_eq!(current(&state), None);
    assert!(generations(&state).is_empty());
    assert!(!exists(&state.join(RESET_PENDING)));
    assert!(
        exists(&state.join(ENABLED)),
        "the enabled marker is untouched"
    );
    assert_eq!(
        worker.tools().calls,
        [Call::Req, Call::Fingerprint, Call::Reset]
    );
}

#[test]
fn boot_reset_on_a_fresh_machine_completes() {
    let directory = TempDir::new();
    let state = directory.state();
    let mut worker = worker(&directory);
    worker.run(Mode::BootReset).unwrap();
    assert!(!exists(&state.join(RESET_PENDING)));
    assert_eq!(worker.tools().calls, [Call::Reset]);
}

/// Runs a boot reset with a failure at one point, then checks the state and
/// that rerunning the reset completes it.
fn boot_reset_failing_at(point: Option<Point>, fail_reset: bool) -> (TempDir, String, Vec<Call>) {
    let directory = TempDir::new();
    let state = directory.state();
    let mut setup = worker(&directory);
    setup.run(Mode::Enable).unwrap();
    let old = current(&state).unwrap();
    let mut failing = Worker::new(state.clone(), FakeTools::default(), Ownership::Skip)
        .with_faults(move |candidate| Some(candidate) == point);
    failing.tools().fail_reset = fail_reset;
    assert!(failing.run(Mode::BootReset).is_err());
    let calls = failing.tools().calls.clone();
    (directory, old, calls)
}

fn rerun_completes(directory: &TempDir) {
    let state = directory.state();
    let mut rerun = worker(directory);
    rerun.run(Mode::BootReset).unwrap();
    assert!(!exists(&state.join(RESET_PENDING)));
    assert_eq!(current(&state), None);
    assert!(generations(&state).is_empty());
}

#[test]
fn boot_reset_failure_creating_the_marker_is_not_destructive() {
    let (directory, old, calls) =
        boot_reset_failing_at(Some(Point::CreateMarker(RESET_PENDING)), false);
    let state = directory.state();
    assert!(calls.is_empty(), "sl-authd was not called");
    assert!(!exists(&state.join(RESET_PENDING)));
    assert_eq!(current(&state), Some(old.clone()));
    assert_eq!(generations(&state), [old]);
    rerun_completes(&directory);
}

#[test]
fn boot_reset_failures_after_the_marker_commit_keep_it() {
    // Step 1: removing current.
    let (directory, old, calls) = boot_reset_failing_at(Some(Point::RemoveCurrent), false);
    let state = directory.state();
    assert!(exists(&state.join(RESET_PENDING)));
    assert_eq!(current(&state), Some(old));
    assert!(calls.is_empty());
    rerun_completes(&directory);

    // Step 2: sl-authd.
    let (directory, old, calls) = boot_reset_failing_at(None, true);
    let state = directory.state();
    assert!(exists(&state.join(RESET_PENDING)));
    assert_eq!(current(&state), None);
    assert_eq!(generations(&state), [old]);
    assert_eq!(calls, [Call::Reset]);
    rerun_completes(&directory);

    // Step 3: removing generations.
    let (directory, old, _) = boot_reset_failing_at(Some(Point::RemoveGenerations), false);
    let state = directory.state();
    assert!(exists(&state.join(RESET_PENDING)));
    assert_eq!(current(&state), None);
    assert_eq!(generations(&state), [old]);
    rerun_completes(&directory);

    // Step 4: clearing the marker after every step succeeded.
    let (directory, _, _) = boot_reset_failing_at(Some(Point::RemoveMarker(RESET_PENDING)), false);
    let state = directory.state();
    assert!(exists(&state.join(RESET_PENDING)));
    assert_eq!(current(&state), None);
    assert!(generations(&state).is_empty());
    rerun_completes(&directory);
}

#[test]
fn an_existing_reset_pending_marker_is_kept_and_completed() {
    let directory = TempDir::new();
    let state = directory.state();
    let mut worker = worker(&directory);
    worker.run(Mode::Enable).unwrap();
    fs::write(state.join(RESET_PENDING), b"").unwrap();
    worker.run(Mode::BootReset).unwrap();
    assert!(!exists(&state.join(RESET_PENDING)));
    assert_eq!(current(&state), None);
}

#[test]
fn a_pending_reset_blocks_enable_until_cleared() {
    let (directory, _, _) = boot_reset_failing_at(None, true);
    let state = directory.state();
    let mut worker = worker(&directory);
    assert!(worker.run(Mode::Enable).is_err());
    assert_eq!(current(&state), None, "no identity was generated");
    // Reenroll's worker steps: rotate, then clear.
    worker.run(Mode::RotateTls).unwrap();
    worker.run(Mode::ClearResetPending).unwrap();
    worker.run(Mode::Enable).unwrap();
}
