//! A small scheduling witness for the delivery-handoff experiment.
//!
//! The noQ driver can wake a blocked application reader and then wake itself
//! before returning `Pending`.  This test keeps the two possible application
//! placements separate: a `block_on` root future is not a Tokio task, while a
//! `tokio::spawn` application is.  The distinction matters when deciding
//! whether the driver's next transmit poll can run before the reader handles
//! the notification.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use tokio::sync::oneshot;
use tokio::time::{timeout, Duration};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    WakeReader,
    Consume,
    Transmit,
}

#[derive(Default)]
struct Shared {
    app_waker: Option<Waker>,
    blocked: bool,
    notified: bool,
    intervened: bool,
    events: Vec<Event>,
}

type State = Arc<Mutex<Shared>>;

struct App {
    state: State,
    first_poll: bool,
    ready: Option<oneshot::Sender<()>>,
}

impl Future for App {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.first_poll {
            self.first_poll = false;
            let ready = self.ready.take();
            let mut state = self.state.lock().expect("state lock");
            state.blocked = true;
            state.app_waker = Some(cx.waker().clone());
            drop(state);
            if let Some(ready) = ready {
                ready.send(()).expect("driver is alive");
            }
            return Poll::Pending;
        }

        let mut state = self.state.lock().expect("state lock");
        assert!(state.notified, "reader was polled without a driver wake");
        state.events.push(Event::Consume);
        Poll::Ready(())
    }
}

struct Driver {
    state: State,
    done: Option<oneshot::Sender<()>>,
}

impl Future for Driver {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.state.lock().expect("state lock");
        if !state.intervened {
            assert!(state.blocked, "driver woke before the reader blocked");
            let app_waker = state.app_waker.clone().expect("blocked reader waker");
            state.intervened = true;
            state.notified = true;
            state.events.push(Event::WakeReader);
            // Wake the reader first, then the driver.  `wake_by_ref` does not
            // poll either future while this state lock is held.
            app_waker.wake_by_ref();
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        state.events.push(Event::Transmit);
        drop(state);
        if let Some(done) = self.done.take() {
            let _ = done.send(());
        }
        Poll::Ready(())
    }
}

async fn driver_task(state: State, ready: oneshot::Receiver<()>, done: oneshot::Sender<()>) {
    ready.await.expect("application is alive");
    Driver {
        state,
        done: Some(done),
    }
    .await;
}

fn events(state: &State) -> Vec<Event> {
    state.lock().expect("state lock").events.clone()
}

async fn root_application_case() -> Vec<Event> {
    let state = Arc::new(Mutex::new(Shared::default()));
    let (ready_tx, ready_rx) = oneshot::channel();
    let (done_tx, done_rx) = oneshot::channel();
    tokio::spawn(driver_task(Arc::clone(&state), ready_rx, done_tx));

    // This future is the root of `Runtime::block_on`; it has a parker waker,
    // not a Tokio task queue entry.
    let app = App {
        state: Arc::clone(&state),
        first_poll: true,
        ready: Some(ready_tx),
    };
    app.await;
    timeout(Duration::from_secs(1), done_rx)
        .await
        .expect("driver watchdog")
        .expect("driver completion");
    events(&state)
}

async fn spawned_application_case() -> Vec<Event> {
    let state = Arc::new(Mutex::new(Shared::default()));
    let (ready_tx, ready_rx) = oneshot::channel();
    let (done_tx, done_rx) = oneshot::channel();
    tokio::spawn(driver_task(Arc::clone(&state), ready_rx, done_tx));
    let app = App {
        state: Arc::clone(&state),
        first_poll: true,
        ready: Some(ready_tx),
    };
    let app_task = tokio::spawn(app);
    timeout(Duration::from_secs(1), async {
        app_task.await.expect("app task");
        done_rx.await.expect("driver completion");
    })
    .await
    .expect("spawned case watchdog");
    events(&state)
}

#[tokio::test(flavor = "current_thread")]
async fn spawned_reader_consumes_before_driver_transmit() {
    let observed = spawned_application_case().await;
    assert_eq!(
        observed,
        vec![Event::WakeReader, Event::Consume, Event::Transmit]
    );
}

#[test]
fn root_block_on_reader_is_not_polled_before_driver_transmit() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("runtime");
    let observed = runtime.block_on(async {
        timeout(Duration::from_secs(1), root_application_case())
            .await
            .expect("root case watchdog")
    });
    assert_eq!(
        observed,
        vec![Event::WakeReader, Event::Transmit, Event::Consume]
    );
}
