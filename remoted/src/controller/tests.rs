use super::*;
use std::{
    path::Path,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Mutex,
    },
};
use tokio::{sync::mpsc, time::advance};

fn status(addresses: &[&str]) -> String {
    serde_json::json!({"schema_version": "0.4", "network": {"state": "connected_global",
        "primary_connection": {"interface": "enp0s2", "addresses": addresses, "default_gateways": []}}})
    .to_string()
}

struct FakeStatus {
    current: Mutex<Result<String, ()>>,
    calls: AtomicUsize,
    /// While set, a refresh captures its result, then waits to be released.
    gate: Mutex<Option<Arc<tokio::sync::Notify>>>,
}

#[async_trait]
impl StatusSource for FakeStatus {
    async fn status(&self) -> Result<String, ()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let result = self.current.lock().unwrap().clone();
        let gate = self.gate.lock().unwrap().clone();
        if let Some(gate) = gate {
            gate.notified().await;
        }
        result
    }
}

#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<String>>>);

impl Log {
    fn push(&self, entry: String) {
        self.0.lock().unwrap().push(entry);
    }
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut self.0.lock().unwrap())
    }
}

struct FakeListeners {
    log: Log,
    failing: Arc<Mutex<Vec<IpAddr>>>,
}

impl Listeners for FakeListeners {
    fn bind(&mut self, addresses: &[IpAddr]) -> Vec<SocketAddr> {
        let failing = self.failing.lock().unwrap().clone();
        addresses
            .iter()
            .filter(|address| {
                let ok = !failing.contains(address);
                self.log.push(format!(
                    "bind {address} {}",
                    if ok { "ok" } else { "failed" }
                ));
                ok
            })
            .map(|address| SocketAddr::new(*address, 8443))
            .collect()
    }

    fn serve(&mut self, generation: u64) {
        self.log.push(format!("serve {generation}"));
    }

    fn close(&mut self) {
        self.log.push("close".into());
    }
}

struct FakeEvents(mpsc::UnboundedReceiver<io::Result<()>>);

#[async_trait]
impl Events for FakeEvents {
    async fn changed(&mut self) -> io::Result<()> {
        match self.0.recv().await {
            Some(result) => result,
            None => std::future::pending().await,
        }
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "sl-remoted-controller-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Harness {
    status: Arc<FakeStatus>,
    log: Log,
    failing: Arc<Mutex<Vec<IpAddr>>>,
    shared: Arc<Shared>,
    marker: PathBuf,
    events: mpsc::UnboundedSender<io::Result<()>>,
    session_events: mpsc::UnboundedSender<io::Result<()>>,
    task: tokio::task::JoinHandle<io::Error>,
    _directory: TempDir,
}

impl Harness {
    async fn start(initial: Result<String, ()>) -> Self {
        Self::start_with(initial, None, None).await
    }

    async fn start_with_marker(initial: Result<String, ()>, marker: Option<PathBuf>) -> Self {
        Self::start_with(initial, marker, None).await
    }

    async fn start_with(
        initial: Result<String, ()>,
        marker: Option<PathBuf>,
        gate: Option<Arc<tokio::sync::Notify>>,
    ) -> Self {
        let directory = TempDir::new();
        let marker = marker.unwrap_or_else(|| directory.0.join("listening"));
        let status = Arc::new(FakeStatus {
            current: Mutex::new(initial),
            calls: AtomicUsize::new(0),
            gate: Mutex::new(gate),
        });
        let log = Log::default();
        let failing = Arc::new(Mutex::new(Vec::new()));
        let shared = Shared::new();
        let (events, receiver) = mpsc::unbounded_channel();
        let (session_events, session_receiver) = mpsc::unbounded_channel();
        let controller = Controller::new(
            status.clone(),
            FakeListeners {
                log: log.clone(),
                failing: failing.clone(),
            },
            Marker {
                path: marker.clone(),
            },
            shared.clone(),
        );
        let invalidations = Invalidations::new(FakeEvents(session_receiver), FakeEvents(receiver));
        let task = tokio::spawn(controller.run(invalidations));
        let harness = Self {
            status,
            log,
            failing,
            shared,
            marker,
            events,
            session_events,
            task,
            _directory: directory,
        };
        harness.settle().await;
        harness
    }

    async fn settle(&self) {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
    }

    async fn advance(&self, duration: Duration) {
        advance(duration).await;
        self.settle().await;
    }

    fn set_status(&self, value: Result<String, ()>) {
        *self.status.current.lock().unwrap() = value;
    }

    fn calls(&self) -> usize {
        self.status.calls.load(Ordering::SeqCst)
    }

    fn generation(&self) -> u64 {
        *self.shared.subscribe().borrow()
    }

    fn admits(&self, source: &str) -> bool {
        self.shared
            .admits(self.generation(), source.parse().unwrap())
    }

    fn listening(&self) -> bool {
        Path::new(&self.marker).exists()
    }

    async fn event(&self) {
        self.events.send(Ok(())).unwrap();
        self.settle().await;
    }

    async fn session_owner_change(&self) {
        self.session_events.send(Ok(())).unwrap();
        self.settle().await;
    }
}

#[tokio::test(start_paused = true)]
async fn session_owner_loss_withdraws_until_a_fresh_status_fetch_succeeds() {
    let harness = Harness::start(Ok(status(&["192.0.2.10/24"]))).await;
    harness.log.take();
    let old_generation = harness.generation();
    harness.set_status(Err(()));

    harness.session_owner_change().await;
    assert!(!harness.listening(), "withdrawn without waiting for timers");
    assert!(!harness
        .shared
        .admits(old_generation, "192.0.2.77".parse().unwrap()));
    assert!(!harness.shared.is_current(old_generation));
    assert_eq!(harness.log.take(), ["close"]);

    harness.advance(DEBOUNCE).await;
    assert!(!harness.listening(), "failed fresh fetch stays withdrawn");
    harness.set_status(Ok(status(&["198.51.100.20/24"])));
    harness.settle().await;
    assert!(!harness.listening(), "old state is never reused");
    harness.advance(RETRY).await;
    assert!(harness.listening());
    assert!(harness.admits("198.51.100.99"));
    assert!(!harness.admits("192.0.2.77"));
}

#[tokio::test(start_paused = true)]
async fn startup_publishes_a_view_then_the_marker() {
    let harness = Harness::start(Ok(status(&["192.0.2.10/24"]))).await;
    let generation = harness.generation();
    assert_eq!(
        harness.log.take(),
        [
            "close",
            "bind 192.0.2.10 ok",
            &format!("serve {generation}")
        ]
    );
    assert!(harness.listening());
    assert!(harness.admits("192.0.2.77"));
    assert!(!harness.admits("198.51.100.7"));
    // An earlier generation is never admitted.
    assert!(!harness
        .shared
        .admits(generation - 1, "192.0.2.77".parse().unwrap()));
}

#[tokio::test(start_paused = true)]
async fn a_stale_marker_from_an_earlier_run_is_removed_first() {
    let directory = TempDir::new();
    let marker = directory.0.join("listening");
    std::fs::write(&marker, b"").unwrap();
    let harness = Harness::start_with_marker(Err(()), Some(marker)).await;
    assert!(!harness.listening());
}

#[tokio::test(start_paused = true)]
async fn a_change_event_withdraws_immediately_and_bursts_coalesce() {
    let harness = Harness::start(Ok(status(&["192.0.2.10/24"]))).await;
    harness.log.take();
    let calls = harness.calls();
    harness.set_status(Ok(status(&["198.51.100.20/24"])));
    harness.event().await;
    // Withdrawn before any refresh.
    assert!(!harness.listening());
    assert!(!harness.admits("192.0.2.77"));
    assert_eq!(harness.log.take(), ["close"]);
    assert_eq!(harness.calls(), calls);
    // More events inside the debounce window extend it.
    harness.advance(Duration::from_millis(300)).await;
    harness.event().await;
    harness.advance(Duration::from_millis(300)).await;
    harness.event().await;
    harness.advance(Duration::from_millis(400)).await;
    assert_eq!(harness.calls(), calls, "still debouncing");
    assert!(!harness.listening());
    harness.advance(Duration::from_millis(200)).await;
    assert_eq!(harness.calls(), calls + 1, "one refresh for the burst");
    let generation = harness.generation();
    assert_eq!(
        harness.log.take(),
        [
            "close",
            "bind 198.51.100.20 ok",
            &format!("serve {generation}")
        ]
    );
    assert!(harness.listening());
    assert!(harness.admits("198.51.100.99"));
    assert!(!harness.admits("192.0.2.77"), "the old prefix is gone");
}

#[tokio::test(start_paused = true)]
async fn a_failed_refresh_after_an_event_stays_withdrawn_until_success() {
    let harness = Harness::start(Ok(status(&["192.0.2.10/24"]))).await;
    harness.set_status(Err(()));
    harness.event().await;
    harness.advance(DEBOUNCE).await;
    assert!(!harness.listening());
    assert!(!harness.admits("192.0.2.77"));
    harness.set_status(Ok(status(&["192.0.2.10/24"])));
    harness.advance(RETRY).await;
    assert!(harness.listening());
    assert!(harness.admits("192.0.2.77"));
}

#[tokio::test(start_paused = true)]
async fn periodic_reconcile_leaves_an_unchanged_view_undisturbed() {
    let harness = Harness::start(Ok(status(&["192.0.2.10/24"]))).await;
    harness.log.take();
    let generation = harness.generation();
    let calls = harness.calls();
    harness.advance(RECONCILE).await;
    assert_eq!(harness.calls(), calls + 1);
    assert!(harness.log.take().is_empty(), "no close, no rebind");
    assert_eq!(harness.generation(), generation);
    assert!(harness.listening());
}

#[tokio::test(start_paused = true)]
async fn periodic_reconcile_withdraws_before_publishing_a_changed_view() {
    let harness = Harness::start(Ok(status(&["192.0.2.10/24"]))).await;
    harness.log.take();
    harness.set_status(Ok(status(&["192.0.2.10/25"])));
    harness.advance(RECONCILE).await;
    let generation = harness.generation();
    assert_eq!(
        harness.log.take(),
        [
            "close",
            "bind 192.0.2.10 ok",
            &format!("serve {generation}")
        ]
    );
    assert!(harness.admits("192.0.2.100"));
    assert!(!harness.admits("192.0.2.200"), "outside the new /25");
}

#[tokio::test(start_paused = true)]
async fn a_view_becomes_stale_after_120_seconds_without_confirmation() {
    let harness = Harness::start(Ok(status(&["192.0.2.10/24"]))).await;
    harness.set_status(Err(()));
    harness.advance(RECONCILE).await;
    assert!(harness.listening(), "one failed refresh is not yet stale");
    assert!(harness.admits("192.0.2.77"));
    for _ in 0..11 {
        harness.advance(RETRY).await;
        assert!(harness.listening(), "still within 120 s");
    }
    harness.advance(RETRY).await;
    assert!(!harness.listening(), "stale at 120 s");
    assert!(!harness.admits("192.0.2.77"));
    harness.set_status(Ok(status(&["192.0.2.10/24"])));
    harness.advance(RETRY).await;
    assert!(harness.listening());
}

#[tokio::test(start_paused = true)]
async fn missing_or_ambiguous_state_never_listens() {
    let no_primary = serde_json::json!({"schema_version": "0.4",
        "network": {"state": "disconnected", "primary_connection": null}})
    .to_string();
    for initial in [
        Ok(no_primary),
        Ok(status(&["192.0.2.10/0"])),
        Ok(status(&["192.0.2.10/24"]).replace("\"0.4\"", "\"0.3\"")),
        Ok(status(&["169.254.1.1/16", "fe80::1/64"])),
        Err(()),
    ] {
        let harness = Harness::start(initial.clone()).await;
        assert!(!harness.listening(), "{initial:?}");
        assert!(!harness.admits("192.0.2.77"), "{initial:?}");
        assert!(!harness.admits("169.254.1.2"), "{initial:?}");
        assert!(!harness
            .log
            .take()
            .iter()
            .any(|entry| entry.starts_with("serve")));
    }
}

#[tokio::test(start_paused = true)]
async fn the_marker_tracks_bound_listeners() {
    let harness = Harness::start(Ok(status(&["192.0.2.10/24"]))).await;
    harness
        .failing
        .lock()
        .unwrap()
        .push("192.0.2.10".parse().unwrap());
    harness.event().await;
    harness.advance(DEBOUNCE).await;
    assert!(!harness.listening(), "no listener could be bound");
    assert!(!harness.admits("192.0.2.77"));
    // One of two addresses bound: listening, and retried at the next reconcile.
    harness.set_status(Ok(status(&["192.0.2.10/24", "198.51.100.20/24"])));
    harness.event().await;
    harness.advance(DEBOUNCE).await;
    assert!(harness.listening());
    harness.log.take();
    harness.failing.lock().unwrap().clear();
    harness.advance(RECONCILE).await;
    let generation = harness.generation();
    assert_eq!(
        harness.log.take(),
        [
            "close",
            "bind 192.0.2.10 ok",
            "bind 198.51.100.20 ok",
            &format!("serve {generation}")
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn a_marker_that_cannot_be_written_withdraws_everything() {
    let directory = TempDir::new();
    let unwritable = directory.0.join("missing-directory").join("listening");
    let harness =
        Harness::start_with_marker(Ok(status(&["192.0.2.10/24"])), Some(unwritable)).await;
    assert!(!harness.admits("192.0.2.77"));
    assert_eq!(harness.log.take().last().map(String::as_str), Some("close"));
}

#[tokio::test(start_paused = true)]
async fn a_failed_event_source_withdraws_and_ends_the_controller() {
    let harness = Harness::start(Ok(status(&["192.0.2.10/24"]))).await;
    assert!(harness.listening());
    harness
        .events
        .send(Err(io::Error::other("netlink failed")))
        .unwrap();
    harness.settle().await;
    assert!(harness.task.is_finished());
    assert!(!harness.listening());
    assert!(!harness.admits("192.0.2.77"));
}

// Invalidation during each await (docs/remote-api-0.0.3.md, "Controller
// concurrency"). Idle and debounce waits are covered above.

fn gate(harness: &Harness) -> Arc<tokio::sync::Notify> {
    let gate = Arc::new(tokio::sync::Notify::new());
    *harness.status.gate.lock().unwrap() = Some(gate.clone());
    gate
}

fn release(harness: &Harness, gate: &tokio::sync::Notify) {
    *harness.status.gate.lock().unwrap() = None;
    gate.notify_waiters();
}

#[tokio::test(start_paused = true)]
async fn invalidation_during_a_periodic_refresh_withdraws_at_once_and_drops_it() {
    let harness = Harness::start(Ok(status(&["192.0.2.10/24"]))).await;
    harness.log.take();
    let gate = gate(&harness);
    // The in-flight refresh has already captured a view that is now stale.
    harness.set_status(Ok(status(&["203.0.113.10/24"])));
    harness.advance(RECONCILE).await;
    let calls = harness.calls();
    assert!(harness.listening(), "refresh in flight");
    harness.set_status(Ok(status(&["198.51.100.20/24"])));
    harness.event().await;
    assert!(
        !harness.listening(),
        "withdrawn without waiting for the refresh"
    );
    assert!(!harness.admits("192.0.2.77"));
    assert_eq!(harness.log.take(), ["close"]);
    release(&harness, &gate);
    harness.settle().await;
    assert!(
        harness.log.take().is_empty(),
        "the stale result is not applied"
    );
    harness.advance(DEBOUNCE).await;
    assert_eq!(
        harness.calls(),
        calls + 1,
        "a fresh refresh after the debounce"
    );
    let log = harness.log.take();
    assert!(log.contains(&"bind 198.51.100.20 ok".to_owned()), "{log:?}");
    assert!(
        !log.iter().any(|entry| entry.contains("203.0.113.10")),
        "{log:?}"
    );
    assert!(harness.admits("198.51.100.99"));
    assert!(!harness.admits("203.0.113.99"));
}

#[tokio::test(start_paused = true)]
async fn invalidation_during_the_first_refresh_drops_it() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let harness =
        Harness::start_with(Ok(status(&["203.0.113.10/24"])), None, Some(gate.clone())).await;
    assert_eq!(harness.calls(), 1, "first refresh in flight");
    harness.set_status(Ok(status(&["198.51.100.20/24"])));
    harness.event().await;
    release(&harness, &gate);
    harness.settle().await;
    assert!(!harness.listening());
    assert!(
        !harness.admits("203.0.113.99"),
        "the stale view is never published"
    );
    harness.advance(DEBOUNCE).await;
    assert!(harness.listening());
    assert!(harness.admits("198.51.100.99"));
    assert!(!harness
        .log
        .take()
        .iter()
        .any(|entry| entry.contains("203.0.113.10")));
}

#[tokio::test(start_paused = true)]
async fn a_failing_event_source_during_a_refresh_withdraws_and_ends() {
    let harness = Harness::start(Ok(status(&["192.0.2.10/24"]))).await;
    let _gate = gate(&harness);
    harness.advance(RECONCILE).await;
    harness
        .events
        .send(Err(io::Error::other("netlink failed")))
        .unwrap();
    harness.settle().await;
    assert!(harness.task.is_finished());
    assert!(!harness.listening());
    assert!(!harness.admits("192.0.2.77"));
}

// Ties: invalidation and a competing future ready in the same poll.

#[tokio::test(start_paused = true)]
async fn session_owner_loss_beats_a_refresh_result_ready_in_the_same_poll() {
    let harness = Harness::start(Ok(status(&["192.0.2.10/24"]))).await;
    harness.log.take();
    let gate = gate(&harness);
    harness.set_status(Ok(status(&["203.0.113.10/24"])));
    harness.advance(RECONCILE).await;
    let calls = harness.calls();
    harness.set_status(Ok(status(&["198.51.100.20/24"])));
    // Both become ready before the controller runs again.
    release(&harness, &gate);
    harness.session_events.send(Ok(())).unwrap();
    harness.settle().await;
    assert!(!harness.listening());
    assert!(!harness.admits("192.0.2.77"), "old eligibility withdrawn");
    assert!(!harness.admits("203.0.113.99"), "stale refresh not applied");
    assert_eq!(harness.log.take(), ["close"], "nothing bound or served");
    harness.advance(DEBOUNCE).await;
    assert_eq!(harness.calls(), calls + 1);
    let log = harness.log.take();
    assert!(log.contains(&"bind 198.51.100.20 ok".to_owned()), "{log:?}");
    assert!(
        !log.iter().any(|entry| entry.contains("203.0.113.10")),
        "{log:?}"
    );
    assert!(harness.admits("198.51.100.99"));
}

#[tokio::test(start_paused = true)]
async fn invalidation_beats_a_reconcile_timer_ready_in_the_same_poll() {
    let harness = Harness::start(Ok(status(&["192.0.2.10/24"]))).await;
    harness.log.take();
    let calls = harness.calls();
    harness.set_status(Ok(status(&["203.0.113.10/24"])));
    // The event is queued, then the reconcile deadline arrives: both ready.
    harness.events.send(Ok(())).unwrap();
    harness.advance(RECONCILE).await;
    assert_eq!(
        harness.calls(),
        calls,
        "no refresh started before invalidation"
    );
    assert!(!harness.listening());
    assert!(!harness.admits("192.0.2.77"));
    assert_eq!(harness.log.take(), ["close"]);
    harness.set_status(Ok(status(&["198.51.100.20/24"])));
    harness.advance(DEBOUNCE).await;
    assert_eq!(harness.calls(), calls + 1);
    let log = harness.log.take();
    assert!(
        !log.iter().any(|entry| entry.contains("203.0.113.10")),
        "{log:?}"
    );
    assert!(harness.admits("198.51.100.99"));
}
