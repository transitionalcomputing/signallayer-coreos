//! Listener and eligibility lifecycle (docs/remote-api-0.0.3.md, "Network
//! exposure"). Session1 is the only network truth; change notifications only
//! invalidate. Every withdrawal happens before any new state is exposed.
use crate::{
    network::{on_link, view_from_status, View},
    peers::StatusSource,
};
use std::{
    fs::OpenOptions,
    io,
    net::{IpAddr, SocketAddr},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::{
    sync::watch,
    time::{sleep, sleep_until, Instant},
};
use zbus::export::async_trait::async_trait;

pub const DEBOUNCE: Duration = Duration::from_millis(500);
pub const RECONCILE: Duration = Duration::from_secs(60);
pub const STALE_AFTER: Duration = Duration::from_secs(120);
pub const RETRY: Duration = Duration::from_secs(5);

struct Published {
    generation: u64,
    view: View,
}

/// What every accept and every open connection is checked against.
pub struct Shared {
    current: RwLock<Option<Published>>,
    generation: watch::Sender<u64>,
}

impl Shared {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            current: RwLock::new(None),
            generation: watch::channel(0).0,
        })
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.generation.subscribe()
    }

    /// No source is eligible afterwards, and every listener and connection of
    /// an earlier generation ends.
    pub(crate) fn withdraw(&self) {
        if let Ok(mut current) = self.current.write() {
            *current = None;
        }
        self.generation.send_modify(|generation| *generation += 1);
    }

    pub(crate) fn publish(&self, view: View) -> u64 {
        let generation = *self.generation.borrow();
        if let Ok(mut current) = self.current.write() {
            *current = Some(Published { generation, view });
        }
        generation
    }

    /// A connection is admitted only under the current published generation,
    /// and only from an on-link source.
    pub fn admits(&self, generation: u64, source: IpAddr) -> bool {
        self.current.read().is_ok_and(|current| {
            current.as_ref().is_some_and(|published| {
                published.generation == generation && on_link(&published.view, source)
            })
        })
    }

    pub fn is_current(&self, generation: u64) -> bool {
        *self.generation.borrow() == generation
    }
}

/// Binding and serving, injected so the lifecycle is testable.
pub trait Listeners: Send {
    /// Binds one listener per address; returns the endpoints that were bound.
    /// Nothing is accepted until `serve`.
    fn bind(&mut self, addresses: &[IpAddr]) -> Vec<SocketAddr>;
    fn serve(&mut self, generation: u64);
    /// Stops accepting and closes every listener.
    fn close(&mut self);
}

#[async_trait]
pub trait Events: Send {
    async fn changed(&mut self) -> io::Result<()>;
}

/// Combines independent invalidation sources. The first source is polled
/// first so Session1 ownership changes win scheduler ties.
pub struct Invalidations<A, B> {
    first: A,
    second: B,
}

impl<A, B> Invalidations<A, B> {
    pub fn new(first: A, second: B) -> Self {
        Self { first, second }
    }
}

#[async_trait]
impl<A: Events, B: Events> Events for Invalidations<A, B> {
    async fn changed(&mut self) -> io::Result<()> {
        tokio::select! {
            biased;
            changed = self.first.changed() => changed,
            changed = self.second.changed() => changed,
        }
    }
}

#[async_trait]
impl Events for crate::netlink::Netlink {
    async fn changed(&mut self) -> io::Result<()> {
        crate::netlink::Netlink::changed(self).await
    }
}

#[async_trait]
impl Events for crate::peers::SessionOwnerEvents {
    async fn changed(&mut self) -> io::Result<()> {
        crate::peers::SessionOwnerEvents::changed(self).await
    }
}

/// `/run/sl-remoted/listening`: present only while listening.
pub struct Marker {
    pub path: PathBuf,
}

impl Marker {
    fn create(&self) -> io::Result<()> {
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o644)
            .open(&self.path)
            .map(drop)
    }

    fn remove(&self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub struct Controller<L> {
    status: Arc<dyn StatusSource>,
    listeners: L,
    marker: Marker,
    shared: Arc<Shared>,
    /// The published view, and whether every listen address was bound.
    published: Option<(View, bool)>,
    confirmed_at: Option<Instant>,
}

impl<L: Listeners> Controller<L> {
    pub fn new(
        status: Arc<dyn StatusSource>,
        listeners: L,
        marker: Marker,
        shared: Arc<Shared>,
    ) -> Self {
        // A marker left by an earlier run is never trusted.
        marker.remove();
        Self {
            status,
            listeners,
            marker,
            shared,
            published: None,
            confirmed_at: None,
        }
    }

    /// Immediate and synchronous: marker, eligibility, then listeners.
    fn withdraw(&mut self) {
        self.marker.remove();
        self.shared.withdraw();
        self.listeners.close();
        self.published = None;
        self.confirmed_at = None;
    }

    /// Precondition: withdrawn.
    fn establish(&mut self, view: View, now: Instant) {
        let bound = self.listeners.bind(&view.listen);
        let complete = bound.len() == view.listen.len();
        self.confirmed_at = Some(now);
        if bound.is_empty() {
            self.listeners.close();
            self.published = Some((view, complete));
            return;
        }
        let generation = self.shared.publish(view.clone());
        self.listeners.serve(generation);
        if self.marker.create().is_err() {
            // Without the marker the service must not claim to listen.
            self.withdraw();
            return;
        }
        self.published = Some((view, complete));
    }

    /// Applies a completed Session1 refresh. Never called with a refresh that
    /// an invalidation interrupted: that future is dropped instead.
    fn apply(&mut self, view: Result<View, ()>, now: Instant) -> Result<(), ()> {
        match view {
            Ok(view) => {
                let unchanged = self
                    .published
                    .as_ref()
                    .is_some_and(|(published, complete)| *complete && *published == view);
                if unchanged {
                    self.confirmed_at = Some(now);
                } else {
                    self.withdraw();
                    self.establish(view, now);
                }
                Ok(())
            }
            Err(()) => {
                let stale = self
                    .confirmed_at
                    .is_none_or(|confirmed| now.duration_since(confirmed) >= STALE_AFTER);
                if stale {
                    self.withdraw();
                }
                Err(())
            }
        }
    }

    /// Withdraws at once, then coalesces a burst of notifications.
    async fn invalidate(
        &mut self,
        changed: io::Result<()>,
        events: &mut impl Events,
    ) -> Result<(), io::Error> {
        self.withdraw();
        changed?;
        loop {
            tokio::select! {
                biased;
                changed = events.changed() => changed?,
                _ = sleep(DEBOUNCE) => return Ok(()),
            }
        }
    }

    /// Runs until the change-event source fails; everything is withdrawn
    /// before returning. Every await is raced against the next notification.
    pub async fn run(mut self, mut events: impl Events) -> io::Error {
        let mut next = Instant::now();
        loop {
            // `biased`: when both are ready, invalidation always wins.
            let changed = tokio::select! {
                biased;
                changed = events.changed() => changed,
                _ = sleep_until(next) => {
                    let refresh = fetch(Arc::clone(&self.status));
                    tokio::select! {
                        biased;
                        // The in-flight refresh is dropped here, so its
                        // result can never be published.
                        changed = events.changed() => changed,
                        view = refresh => {
                            let now = Instant::now();
                            next = match self.apply(view, now) {
                                Ok(()) => now + RECONCILE,
                                Err(()) => now + RETRY,
                            };
                            continue;
                        }
                    }
                }
            };
            if let Err(error) = self.invalidate(changed, &mut events).await {
                return error;
            }
            next = Instant::now();
        }
    }
}

async fn fetch(status: Arc<dyn StatusSource>) -> Result<View, ()> {
    status
        .status()
        .await
        .and_then(|status| view_from_status(&status))
}

#[cfg(test)]
mod tests;
