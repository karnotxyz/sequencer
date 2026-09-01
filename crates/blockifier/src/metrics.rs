use apollo_metrics::define_metrics;
use apollo_metrics::metrics::{MetricCounter, MetricDetails, MetricScope};
use std::sync::atomic::{AtomicU64, Ordering};

define_metrics!(
    Blockifier => {
        MetricCounter {
            NATIVE_CLASS_RETURNED,
            "native_class_returned",
            "Counter of the number of times that the state reader returned Native class",
            init=0},
        MetricCounter { NATIVE_COMPILATION_ERROR,
            "native_compilation_error",
            "Counter of Native compilation failures in the blockifier",
            init=0 },
        MetricCounter {
            CALLS_RUNNING_NATIVE,
            "calls_running_native",
            "Counter of the number of calls running native",
            init=0
        },
        MetricCounter {
            TOTAL_CALLS,
            "number_of_total_calls",
            "Counter of the total number of calls",
            init=0
        }
    }
);

pub const BLOCKIFIER_METRIC_RATE_DURATION: &str = "5m";

/// Process-lifetime transaction execution counters.
///
/// These mirror the per-chunk counters emitted by Blockifier's concurrent
/// executor while also covering sequential `execute_txs` calls. They are kept
/// as relaxed atomics so downstream nodes can export them without adding a
/// metrics dependency to the execution hot path.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TransactionExecutorMetrics {
    pub transactions: u64,
    pub committed_transactions: u64,
    pub execution_attempts: u64,
    pub validation_attempts: u64,
    pub aborts: u64,
    pub commit_phase_aborts: u64,
}

static TRANSACTIONS: AtomicU64 = AtomicU64::new(0);
static COMMITTED_TRANSACTIONS: AtomicU64 = AtomicU64::new(0);
static EXECUTION_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static VALIDATION_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static ABORTS: AtomicU64 = AtomicU64::new(0);
static COMMIT_PHASE_ABORTS: AtomicU64 = AtomicU64::new(0);

pub fn transaction_executor_metrics() -> TransactionExecutorMetrics {
    TransactionExecutorMetrics {
        transactions: TRANSACTIONS.load(Ordering::Relaxed),
        committed_transactions: COMMITTED_TRANSACTIONS.load(Ordering::Relaxed),
        execution_attempts: EXECUTION_ATTEMPTS.load(Ordering::Relaxed),
        validation_attempts: VALIDATION_ATTEMPTS.load(Ordering::Relaxed),
        aborts: ABORTS.load(Ordering::Relaxed),
        commit_phase_aborts: COMMIT_PHASE_ABORTS.load(Ordering::Relaxed),
    }
}

pub(crate) fn record_transaction_executor_metrics(metrics: TransactionExecutorMetrics) {
    TRANSACTIONS.fetch_add(metrics.transactions, Ordering::Relaxed);
    COMMITTED_TRANSACTIONS.fetch_add(metrics.committed_transactions, Ordering::Relaxed);
    EXECUTION_ATTEMPTS.fetch_add(metrics.execution_attempts, Ordering::Relaxed);
    VALIDATION_ATTEMPTS.fetch_add(metrics.validation_attempts, Ordering::Relaxed);
    ABORTS.fetch_add(metrics.aborts, Ordering::Relaxed);
    COMMIT_PHASE_ABORTS.fetch_add(metrics.commit_phase_aborts, Ordering::Relaxed);
}

pub struct CacheMetrics {
    misses: MetricCounter,
    hits: MetricCounter,
}

impl CacheMetrics {
    pub const fn new(misses: MetricCounter, hits: MetricCounter) -> Self {
        Self { misses, hits }
    }

    pub fn misses(&self) -> &MetricCounter {
        &self.misses
    }

    pub fn hits(&self) -> &MetricCounter {
        &self.hits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_executor_metrics_accumulate_monotonically() {
        let before = transaction_executor_metrics();
        let increment = TransactionExecutorMetrics {
            transactions: 50,
            committed_transactions: 48,
            execution_attempts: 73,
            validation_attempts: 81,
            aborts: 23,
            commit_phase_aborts: 4,
        };

        record_transaction_executor_metrics(increment);
        let after = transaction_executor_metrics();

        assert!(after.transactions >= before.transactions + increment.transactions);
        assert!(
            after.committed_transactions
                >= before.committed_transactions + increment.committed_transactions
        );
        assert!(
            after.execution_attempts >= before.execution_attempts + increment.execution_attempts
        );
        assert!(
            after.validation_attempts >= before.validation_attempts + increment.validation_attempts
        );
        assert!(after.aborts >= before.aborts + increment.aborts);
        assert!(
            after.commit_phase_aborts >= before.commit_phase_aborts + increment.commit_phase_aborts
        );
    }
}

impl CacheMetrics {
    pub fn register(&self) {
        self.misses.register();
        self.hits.register();
    }

    pub fn increment_miss(&self) {
        self.misses.increment(1);
    }

    pub fn increment_hit(&self) {
        self.hits.increment(1);
    }

    pub fn get_scope(&self) -> MetricScope {
        assert_eq!(
            self.misses.get_scope(),
            self.hits.get_scope(),
            "Scope of misses and hits must be the same"
        );

        self.misses.get_scope()
    }
}
