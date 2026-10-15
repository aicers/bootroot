//! A process-wide subscriber that keeps thread-scoped log captures whole.
//!
//! `tracing` caches each callsite's interest once for the whole process,
//! computed on whichever thread reaches the callsite first. While a
//! capture is the only live dispatcher, that interest is asked of the
//! registering thread's default alone, so a parallel test thread with no
//! subscriber caches the callsite as `Interest::never()` and every
//! thread, the capturing one included, loses its events. Rebuilding the
//! interest cache after installing a capture repairs callsites cached
//! before it, but not one another thread registers for the first time
//! while the capture is running.
//!
//! The global default installed here answers `Interest::sometimes()` for
//! every callsite. Combined with any other subscriber's answer that
//! stays `sometimes`, so no callsite can be cached `never`, and each
//! event asks the current thread's default whether it is enabled. A
//! capturing thread still sees exactly its own events; every other
//! thread reaches this subscriber, which enables nothing.

use std::sync::Once;

use tracing::level_filters::LevelFilter;
use tracing::subscriber::Interest;
use tracing::{Event, Metadata, Subscriber, span};

/// A subscriber that enables nothing yet never lets a callsite be
/// cached as disabled.
struct Undecided;

impl Subscriber for Undecided {
    fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
        Interest::sometimes()
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(LevelFilter::OFF)
    }

    fn enabled(&self, _: &Metadata<'_>) -> bool {
        false
    }

    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }

    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}

    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}

    fn event(&self, _: &Event<'_>) {}

    fn enter(&self, _: &span::Id) {}

    fn exit(&self, _: &span::Id) {}
}

/// Installs [`Undecided`] as the process's global default subscriber,
/// once per test process.
///
/// Every thread-scoped log capture calls this before it installs its own
/// subscriber.
///
/// # Panics
///
/// Panics if another global default subscriber was already set, which a
/// lib test must not do.
pub(crate) fn install_undecided_global_subscriber() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        tracing::subscriber::set_global_default(Undecided)
            .expect("no other lib test sets a global default subscriber");
    });
}

/// Emits from a callsite no other test reaches, so this test alone
/// decides which thread registers it first.
fn emit_from_a_callsite_of_its_own() {
    tracing::error!("reached from a callsite of its own");
}

#[test]
fn a_callsite_first_reached_on_a_bare_thread_still_reaches_a_capture() {
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    install_undecided_global_subscriber();
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = Captured(Arc::clone(&buffer));
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        std::thread::spawn(emit_from_a_callsite_of_its_own)
            .join()
            .unwrap();
        emit_from_a_callsite_of_its_own();
    });
    let captured = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
    assert!(
        captured.contains("reached from a callsite of its own"),
        "{captured}"
    );
}
