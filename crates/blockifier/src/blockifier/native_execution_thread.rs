//! Stack-sized execution threads whose thread-local Native caches survive sequential batches.

use std::cell::Cell;
use std::io;
use std::thread::{self, JoinHandle};

thread_local! {
    // Only threads allocated by this module may advertise their stack size.
    static NATIVE_STACK_SIZE: Cell<usize> = const { Cell::new(0) };
}

/// Starts a long-lived execution loop with a stack suitable for Native execution.
///
/// Use the same stack size as `TransactionExecutorConfig::stack_size`. Sequential executors
/// on this thread can reuse it, including across block transitions. Ordinary callers retain
/// the scoped-thread fallback; a larger requested stack also falls back rather than trusting
/// an undersized worker. This does not change the concurrent executor's worker pool.
pub fn spawn_native_execution_thread<F, T>(
    name: String,
    stack_size: usize,
    run: F,
) -> io::Result<JoinHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    thread::Builder::new().name(name).stack_size(stack_size).spawn(move || {
        NATIVE_STACK_SIZE.set(stack_size);
        run()
    })
}

#[cfg(feature = "cairo_native")]
pub(crate) fn on_native_stack<F, T>(stack_size: usize, run: F) -> T
where
    F: FnOnce() -> T + Send,
    T: Send,
{
    if NATIVE_STACK_SIZE.get() >= stack_size && NATIVE_STACK_SIZE.get() != 0 {
        return run();
    }
    // Preserve the existing protection for RPC/validation and other unregistered callers.
    // This temporary thread is deliberately not registered as a reusable execution loop.
    thread::scope(|scope| {
        thread::Builder::new()
            .stack_size(stack_size)
            .spawn_scoped(scope, run)
            .expect("Failed to spawn Native execution thread")
            .join()
            .expect("Failed to join Native execution thread")
    })
}

#[cfg(all(test, feature = "cairo_native"))]
mod tests {
    use super::*;

    const STACK: usize = 2 * 1024 * 1024;
    thread_local! {
        static BATCHES: Cell<usize> = const { Cell::new(0) };
    }

    #[test]
    fn registered_worker_reuses_thread_and_locals_across_batches() {
        spawn_native_execution_thread("native-test".into(), STACK, || {
            let worker = thread::current().id();
            for expected in 1..=3 {
                on_native_stack(STACK, || {
                    assert_eq!(thread::current().id(), worker);
                    BATCHES.set(BATCHES.get() + 1);
                    assert_eq!(BATCHES.get(), expected);
                });
            }
            assert_eq!(BATCHES.get(), 3);
        })
        .unwrap()
        .join()
        .unwrap();
    }

    #[test]
    fn unregistered_caller_keeps_scoped_thread_fallback() {
        let caller = thread::current().id();
        let mut result = 0;
        for _ in 0..2 {
            on_native_stack(STACK, || {
                assert_ne!(thread::current().id(), caller);
                assert_eq!(BATCHES.get(), 0);
                BATCHES.set(1);
                result += 1;
            });
        }
        assert_eq!(result, 2);
        assert_eq!(NATIVE_STACK_SIZE.get(), 0);
    }

    #[test]
    fn larger_stack_request_falls_back_without_losing_worker_locals() {
        spawn_native_execution_thread("native-small".into(), STACK, || {
            let worker = thread::current().id();
            BATCHES.set(7);
            on_native_stack(STACK * 2, || {
                assert_ne!(thread::current().id(), worker);
                assert_eq!(BATCHES.get(), 0);
            });
            on_native_stack(STACK, || assert_eq!(BATCHES.get(), 7));
        })
        .unwrap()
        .join()
        .unwrap();
    }

    #[test]
    fn registration_is_not_inherited_by_unregistered_child_threads() {
        spawn_native_execution_thread("native-parent".into(), STACK, || {
            thread::spawn(|| {
                assert_eq!(NATIVE_STACK_SIZE.get(), 0);
                let child = thread::current().id();
                on_native_stack(STACK, || assert_ne!(thread::current().id(), child));
            })
            .join()
            .unwrap();
        })
        .unwrap()
        .join()
        .unwrap();
    }

    #[test]
    fn worker_panic_reaches_joiner_and_replacement_starts_cold() {
        let failed = spawn_native_execution_thread("native-panic".into(), STACK, || {
            on_native_stack(STACK, || {
                BATCHES.set(9);
                panic!("execution failed");
            });
        })
        .unwrap()
        .join();
        assert!(failed.is_err());
        spawn_native_execution_thread("native-replacement".into(), STACK, || {
            on_native_stack(STACK, || assert_eq!(BATCHES.get(), 0));
        })
        .unwrap()
        .join()
        .unwrap();
    }

    #[test]
    fn fallback_panic_reaches_caller() {
        assert!(std::panic::catch_unwind(|| on_native_stack(STACK, || panic!("failed"))).is_err());
    }
}
