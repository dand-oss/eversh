//! Network-change driven noq endpoint rebinding for a live association.

use crate::ClientEndpoint;
use everssh::transport::{RouteIdentity, UdpBindPolicy};
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;

const FALLBACK_POLL: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub enum RouteError {
    RuntimeUnavailable,
    ExplicitPolicy,
}

impl fmt::Display for RouteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RuntimeUnavailable => "everudp route watcher requires an active Tokio runtime",
            Self::ExplicitPolicy => "everudp route watcher requires route-selected UDP binding",
        })
    }
}

impl std::error::Error for RouteError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteTrigger {
    NetworkChange,
    FallbackPoll,
    ProcessWake,
    PathFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteSnapshot {
    pub local_addr: SocketAddr,
    pub route: Option<RouteIdentity>,
    pub observations: u64,
    pub rebinds: u64,
    pub failures: u64,
    pub last_trigger: Option<RouteTrigger>,
    pub finished: bool,
}

pub struct RouteSupervisor {
    cancel: watch::Sender<bool>,
    triggers: mpsc::Sender<RouteTrigger>,
    handle: Option<JoinHandle<()>>,
    snapshot: Arc<Mutex<RouteSnapshot>>,
}

impl RouteSupervisor {
    pub fn spawn(
        endpoint: ClientEndpoint,
        peer: SocketAddr,
        policy: UdpBindPolicy,
    ) -> Result<Self, RouteError> {
        tokio::runtime::Handle::try_current().map_err(|_| RouteError::RuntimeUnavailable)?;
        if matches!(policy, UdpBindPolicy::Explicit(_)) {
            return Err(RouteError::ExplicitPolicy);
        }
        let local_addr = endpoint
            .local_addr()
            .map_err(|_| RouteError::RuntimeUnavailable)?;
        let snapshot = Arc::new(Mutex::new(RouteSnapshot {
            local_addr,
            route: endpoint.route_identity(),
            observations: 0,
            rebinds: 0,
            failures: 0,
            last_trigger: None,
            finished: false,
        }));
        let (cancel, cancel_rx) = watch::channel(false);
        let (triggers, trigger_rx) = mpsc::channel(1);
        let task_snapshot = Arc::clone(&snapshot);
        let handle = tokio::spawn(async move {
            let _finished = Finished(Arc::clone(&task_snapshot));
            run(endpoint, peer, policy, cancel_rx, trigger_rx, task_snapshot).await;
        });
        Ok(Self {
            cancel,
            triggers,
            handle: Some(handle),
            snapshot,
        })
    }

    pub fn notify_path_failure(&self) {
        let _ = self.triggers.try_send(RouteTrigger::PathFailure);
    }

    pub fn snapshot(&self) -> RouteSnapshot {
        *lock_unpoisoned(&self.snapshot)
    }

    pub fn stop(&self) {
        let _ = self.cancel.send(true);
    }

    pub async fn join(mut self) {
        self.stop();
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

impl fmt::Debug for RouteSupervisor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RouteSupervisor")
            .field("snapshot", &self.snapshot())
            .finish_non_exhaustive()
    }
}

impl Drop for RouteSupervisor {
    fn drop(&mut self) {
        let _ = self.cancel.send(true);
        if let Some(handle) = self.handle.as_ref() {
            handle.abort();
        }
    }
}

struct Finished(Arc<Mutex<RouteSnapshot>>);

impl Drop for Finished {
    fn drop(&mut self) {
        lock_unpoisoned(&self.0).finished = true;
    }
}

enum Event {
    Cancelled,
    Trigger(RouteTrigger),
    Notification(std::io::Result<()>),
    Timer,
}

async fn run(
    endpoint: ClientEndpoint,
    peer: SocketAddr,
    policy: UdpBindPolicy,
    mut cancel: watch::Receiver<bool>,
    mut triggers: mpsc::Receiver<RouteTrigger>,
    snapshot: Arc<Mutex<RouteSnapshot>>,
) {
    let mut notifications = open_notifications();
    let mut expected = Instant::now() + FALLBACK_POLL;
    loop {
        if *cancel.borrow() {
            break;
        }
        let timer = tokio::time::sleep_until(expected);
        tokio::pin!(timer);
        let event = tokio::select! {
            biased;
            changed = cancel.changed() => {
                if changed.is_err() || *cancel.borrow() {
                    Event::Cancelled
                } else {
                    continue;
                }
            }
            requested = triggers.recv() => match requested {
                Some(trigger) => Event::Trigger(trigger),
                None => Event::Cancelled,
            },
            changed = wait_for_notification(&notifications) => Event::Notification(changed),
            _ = &mut timer => Event::Timer,
        };
        let trigger = match event {
            Event::Cancelled => break,
            Event::Trigger(trigger) => trigger,
            Event::Notification(Ok(())) => RouteTrigger::NetworkChange,
            Event::Notification(Err(_)) => {
                notifications = open_notifications();
                continue;
            }
            Event::Timer => {
                let now = Instant::now();
                let trigger = classify_timer(now, expected);
                expected = now + FALLBACK_POLL;
                trigger
            }
        };
        {
            let mut state = lock_unpoisoned(&snapshot);
            state.observations = state.observations.saturating_add(1);
            state.last_trigger = Some(trigger);
        }
        let force = trigger == RouteTrigger::PathFailure;
        match endpoint.rebind_routed(peer, policy, force) {
            Ok(outcome) => {
                let mut state = lock_unpoisoned(&snapshot);
                state.local_addr = outcome.local_addr;
                state.route = outcome.route;
                if outcome.rebound {
                    state.rebinds = state.rebinds.saturating_add(1);
                }
            }
            Err(_) => {
                let mut state = lock_unpoisoned(&snapshot);
                state.failures = state.failures.saturating_add(1);
            }
        }
    }
}

fn classify_timer(now: Instant, expected: Instant) -> RouteTrigger {
    if now > expected + FALLBACK_POLL {
        RouteTrigger::ProcessWake
    } else {
        RouteTrigger::FallbackPoll
    }
}

#[cfg(target_os = "linux")]
type Notifications = everssh::transport::RouteChangeNotifications;

#[cfg(target_os = "linux")]
fn open_notifications() -> Option<Notifications> {
    Notifications::open().ok()
}

#[cfg(not(target_os = "linux"))]
struct Notifications;

#[cfg(not(target_os = "linux"))]
fn open_notifications() -> Option<Notifications> {
    None
}

#[cfg(target_os = "linux")]
async fn wait_for_notification(notifications: &Option<Notifications>) -> std::io::Result<()> {
    match notifications {
        Some(notifications) => notifications.changed().await,
        None => std::future::pending().await,
    }
}

#[cfg(not(target_os = "linux"))]
async fn wait_for_notification(_notifications: &Option<Notifications>) -> std::io::Result<()> {
    std::future::pending().await
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(value) => value,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_timer, RouteTrigger, FALLBACK_POLL};
    use tokio::time::Instant;

    #[test]
    fn late_fallback_tick_is_classified_as_process_wake() {
        let expected = Instant::now();
        assert_eq!(
            classify_timer(expected, expected),
            RouteTrigger::FallbackPoll
        );
        assert_eq!(
            classify_timer(expected + FALLBACK_POLL + FALLBACK_POLL, expected),
            RouteTrigger::ProcessWake
        );
    }
}
