//! Concurrent callers share one in-flight observation instead of being refused.
//! Nothing is cached: a call that starts after the observation has completed
//! runs a new one.
use std::{
    future::Future,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};
use tokio::sync::watch;

type Flight<T> = watch::Receiver<Option<T>>;
type Slot<T> = Arc<Mutex<Option<Flight<T>>>>;

pub(crate) struct SharedRead<T> {
    in_flight: Slot<T>,
}

impl<T: Clone + Send + Sync + 'static> SharedRead<T> {
    pub(crate) fn new() -> Self {
        Self {
            in_flight: Arc::default(),
        }
    }

    /// Joins the observation in progress, or starts `observe` as a new one.
    /// The observation runs in its own task, so a caller that goes away
    /// cannot strand the others. `None` only if that task panicked.
    pub(crate) async fn run<F>(&self, observe: impl FnOnce() -> F) -> Option<T>
    where
        F: Future<Output = T> + Send + 'static,
    {
        let mut flight = {
            let mut in_flight = lock(&self.in_flight);
            match &*in_flight {
                Some(flight) => flight.clone(),
                None => {
                    let (sender, flight) = watch::channel(None);
                    *in_flight = Some(flight.clone());
                    let end = EndFlight {
                        slot: Arc::clone(&self.in_flight),
                        flight: flight.clone(),
                    };
                    let observation = observe();
                    tokio::spawn(async move {
                        let value = observation.await;
                        // Ended and published under the lock, so a later
                        // caller never joins a completed observation.
                        let mut in_flight = lock(&end.slot);
                        end.clear(&mut in_flight);
                        let _ = sender.send(Some(value));
                    });
                    flight
                }
            }
        };
        let value = flight.wait_for(Option::is_some).await.ok()?.clone();
        value
    }
}

fn lock<T>(slot: &Slot<T>) -> MutexGuard<'_, Option<Flight<T>>> {
    slot.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Ends the flight even if the observation panics, so later calls start anew.
struct EndFlight<T> {
    slot: Slot<T>,
    flight: Flight<T>,
}

impl<T> EndFlight<T> {
    fn clear(&self, in_flight: &mut Option<Flight<T>>) {
        if in_flight
            .as_ref()
            .is_some_and(|current| current.same_channel(&self.flight))
        {
            *in_flight = None;
        }
    }
}

impl<T> Drop for EndFlight<T> {
    fn drop(&mut self) {
        let mut in_flight = lock(&self.slot);
        self.clear(&mut in_flight);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    #[tokio::test]
    async fn concurrent_callers_share_one_observation_and_nothing_is_cached() {
        let reads = SharedRead::new();
        let started = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Notify::new());
        let observe = || {
            let started = Arc::clone(&started);
            let release = Arc::clone(&release);
            move || async move {
                let n = started.fetch_add(1, Ordering::SeqCst) + 1;
                release.notified().await;
                n
            }
        };
        let first = reads.run(observe());
        let second = reads.run(observe());
        let third = reads.run(observe());
        let releaser = async {
            while started.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
            release.notify_one();
        };
        let (a, b, c, ()) = tokio::join!(first, second, third, releaser);
        assert_eq!((a, b, c), (Some(1), Some(1), Some(1)));
        assert_eq!(started.load(Ordering::SeqCst), 1);

        release.notify_one();
        assert_eq!(reads.run(observe()).await, Some(2));
    }

    #[tokio::test]
    async fn a_panicked_observation_fails_its_callers_and_the_next_call_runs_anew() {
        let reads: SharedRead<u8> = SharedRead::new();
        assert_eq!(reads.run(|| async { panic!("observation") }).await, None);
        assert_eq!(reads.run(|| async { 7 }).await, Some(7));
    }
}
