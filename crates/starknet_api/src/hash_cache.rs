use std::{
    borrow::Borrow,
    hash::Hash,
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};

use dashmap::DashMap;
use starknet_types_core::felt::Felt;

pub const DEFAULT_SN_KECCAK_CACHE_CAPACITY: usize = 8 * 1024;
pub const DEFAULT_PEDERSEN_PAIR_CACHE_CAPACITY: usize = 8 * 1024;
pub const DEFAULT_PEDERSEN_ARRAY_CACHE_CAPACITY: usize = 2 * 1024;
pub const DEFAULT_POSEIDON_ARRAY_CACHE_CAPACITY: usize = 2 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HashCacheConfig {
    pub enabled: bool,
    pub sn_keccak_capacity: usize,
    pub pedersen_pair_capacity: usize,
    pub pedersen_array_capacity: usize,
    pub poseidon_array_capacity: usize,
}

impl Default for HashCacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            sn_keccak_capacity: DEFAULT_SN_KECCAK_CACHE_CAPACITY,
            pedersen_pair_capacity: DEFAULT_PEDERSEN_PAIR_CACHE_CAPACITY,
            pedersen_array_capacity: DEFAULT_PEDERSEN_ARRAY_CACHE_CAPACITY,
            poseidon_array_capacity: DEFAULT_POSEIDON_ARRAY_CACHE_CAPACITY,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashCacheKind {
    SnKeccak,
    PedersenPair,
    PedersenArray,
    PoseidonArray,
}

impl HashCacheKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SnKeccak => "starknet_keccak",
            Self::PedersenPair => "pedersen_pair",
            Self::PedersenArray => "pedersen_array",
            Self::PoseidonArray => "poseidon_array",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HashCacheMetrics {
    pub kind: HashCacheKind,
    pub total_calls: u64,
    pub hits: u64,
    pub misses: u64,
    pub capacity_clears: u64,
    pub entries: usize,
    pub capacity: usize,
}

struct CacheCounters {
    hits: AtomicU64,
    misses: AtomicU64,
    capacity_clears: AtomicU64,
}

impl CacheCounters {
    const fn new() -> Self {
        Self {
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            capacity_clears: AtomicU64::new(0),
        }
    }
}

static HASH_CACHE_ENABLED: AtomicBool = AtomicBool::new(false);
static SN_KECCAK_CACHE_CAPACITY: AtomicUsize = AtomicUsize::new(DEFAULT_SN_KECCAK_CACHE_CAPACITY);
static PEDERSEN_PAIR_CACHE_CAPACITY: AtomicUsize =
    AtomicUsize::new(DEFAULT_PEDERSEN_PAIR_CACHE_CAPACITY);
static PEDERSEN_ARRAY_CACHE_CAPACITY: AtomicUsize =
    AtomicUsize::new(DEFAULT_PEDERSEN_ARRAY_CACHE_CAPACITY);
static POSEIDON_ARRAY_CACHE_CAPACITY: AtomicUsize =
    AtomicUsize::new(DEFAULT_POSEIDON_ARRAY_CACHE_CAPACITY);
static SN_KECCAK_CACHE: LazyLock<DashMap<Vec<u8>, Felt>> = LazyLock::new(DashMap::new);
static PEDERSEN_PAIR_CACHE: LazyLock<DashMap<(Felt, Felt), Felt>> = LazyLock::new(DashMap::new);
static PEDERSEN_ARRAY_CACHE: LazyLock<DashMap<Vec<Felt>, Felt>> = LazyLock::new(DashMap::new);
static POSEIDON_ARRAY_CACHE: LazyLock<DashMap<Vec<Felt>, Felt>> = LazyLock::new(DashMap::new);
static SN_KECCAK_CACHE_COUNTERS: CacheCounters = CacheCounters::new();
static PEDERSEN_PAIR_CACHE_COUNTERS: CacheCounters = CacheCounters::new();
static PEDERSEN_ARRAY_CACHE_COUNTERS: CacheCounters = CacheCounters::new();
static POSEIDON_ARRAY_CACHE_COUNTERS: CacheCounters = CacheCounters::new();

/// Configures process-wide Starknet hash memoization.
///
/// Configure this once during process startup, before execution workers begin
/// handling transactions. A capacity of zero disables that individual cache.
pub fn configure_hash_cache(config: HashCacheConfig) {
    HASH_CACHE_ENABLED.store(false, Ordering::Relaxed);
    clear_caches();
    SN_KECCAK_CACHE_CAPACITY.store(config.sn_keccak_capacity, Ordering::Relaxed);
    PEDERSEN_PAIR_CACHE_CAPACITY.store(config.pedersen_pair_capacity, Ordering::Relaxed);
    PEDERSEN_ARRAY_CACHE_CAPACITY.store(config.pedersen_array_capacity, Ordering::Relaxed);
    POSEIDON_ARRAY_CACHE_CAPACITY.store(config.poseidon_array_capacity, Ordering::Relaxed);
    HASH_CACHE_ENABLED.store(config.enabled, Ordering::Relaxed);
}

/// Enables or disables process-wide Starknet hash memoization.
///
/// Configure this once during process startup, before execution workers begin
/// handling transactions.
pub fn set_hash_cache_enabled(enabled: bool) {
    HASH_CACHE_ENABLED.store(enabled, Ordering::Relaxed);
    if !enabled {
        clear_caches();
    }
}

pub fn hash_cache_metrics() -> [HashCacheMetrics; 4] {
    [
        snapshot(
            HashCacheKind::SnKeccak,
            &SN_KECCAK_CACHE,
            &SN_KECCAK_CACHE_CAPACITY,
            &SN_KECCAK_CACHE_COUNTERS,
        ),
        snapshot(
            HashCacheKind::PedersenPair,
            &PEDERSEN_PAIR_CACHE,
            &PEDERSEN_PAIR_CACHE_CAPACITY,
            &PEDERSEN_PAIR_CACHE_COUNTERS,
        ),
        snapshot(
            HashCacheKind::PedersenArray,
            &PEDERSEN_ARRAY_CACHE,
            &PEDERSEN_ARRAY_CACHE_CAPACITY,
            &PEDERSEN_ARRAY_CACHE_COUNTERS,
        ),
        snapshot(
            HashCacheKind::PoseidonArray,
            &POSEIDON_ARRAY_CACHE,
            &POSEIDON_ARRAY_CACHE_CAPACITY,
            &POSEIDON_ARRAY_CACHE_COUNTERS,
        ),
    ]
}

fn snapshot<K, V>(
    kind: HashCacheKind,
    cache: &DashMap<K, V>,
    capacity: &AtomicUsize,
    counters: &CacheCounters,
) -> HashCacheMetrics
where
    K: Eq + Hash,
{
    let hits = counters.hits.load(Ordering::Relaxed);
    let misses = counters.misses.load(Ordering::Relaxed);
    HashCacheMetrics {
        kind,
        total_calls: hits.saturating_add(misses),
        hits,
        misses,
        capacity_clears: counters.capacity_clears.load(Ordering::Relaxed),
        entries: cache.len(),
        capacity: capacity.load(Ordering::Relaxed),
    }
}

fn clear_caches() {
    SN_KECCAK_CACHE.clear();
    PEDERSEN_PAIR_CACHE.clear();
    PEDERSEN_ARRAY_CACHE.clear();
    POSEIDON_ARRAY_CACHE.clear();
}

fn enabled() -> bool {
    HASH_CACHE_ENABLED.load(Ordering::Relaxed)
}

fn get<K, Q, V>(cache: &DashMap<K, V>, key: &Q, counters: &CacheCounters) -> Option<V>
where
    K: Borrow<Q> + Eq + Hash,
    Q: Eq + Hash + ?Sized,
    V: Copy,
{
    if !enabled() {
        return None;
    }
    match cache.get(key) {
        Some(value) => {
            counters.hits.fetch_add(1, Ordering::Relaxed);
            Some(*value)
        }
        None => {
            counters.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

fn insert<K, V>(
    cache: &DashMap<K, V>,
    capacity: &AtomicUsize,
    counters: &CacheCounters,
    key: K,
    value: V,
) where
    K: Eq + Hash,
{
    if !enabled() {
        return;
    }
    let capacity = capacity.load(Ordering::Relaxed);
    if capacity == 0 {
        return;
    }
    if cache.len() >= capacity {
        cache.clear();
        counters.capacity_clears.fetch_add(1, Ordering::Relaxed);
    }
    cache.insert(key, value);
}

pub(crate) fn sn_keccak_get(data: &[u8]) -> Option<Felt> {
    get(&SN_KECCAK_CACHE, data, &SN_KECCAK_CACHE_COUNTERS)
}

pub(crate) fn sn_keccak_insert(data: &[u8], value: Felt) {
    insert(
        &SN_KECCAK_CACHE,
        &SN_KECCAK_CACHE_CAPACITY,
        &SN_KECCAK_CACHE_COUNTERS,
        data.to_vec(),
        value,
    );
}

pub(crate) fn pedersen_pair_get(left: Felt, right: Felt) -> Option<Felt> {
    get(&PEDERSEN_PAIR_CACHE, &(left, right), &PEDERSEN_PAIR_CACHE_COUNTERS)
}

pub(crate) fn pedersen_pair_insert(left: Felt, right: Felt, value: Felt) {
    insert(
        &PEDERSEN_PAIR_CACHE,
        &PEDERSEN_PAIR_CACHE_CAPACITY,
        &PEDERSEN_PAIR_CACHE_COUNTERS,
        (left, right),
        value,
    );
}

pub(crate) fn pedersen_array_get(values: &[Felt]) -> Option<Felt> {
    get(&PEDERSEN_ARRAY_CACHE, values, &PEDERSEN_ARRAY_CACHE_COUNTERS)
}

pub(crate) fn pedersen_array_insert(values: &[Felt], value: Felt) {
    insert(
        &PEDERSEN_ARRAY_CACHE,
        &PEDERSEN_ARRAY_CACHE_CAPACITY,
        &PEDERSEN_ARRAY_CACHE_COUNTERS,
        values.to_vec(),
        value,
    );
}

pub(crate) fn poseidon_array_get(values: &[Felt]) -> Option<Felt> {
    get(&POSEIDON_ARRAY_CACHE, values, &POSEIDON_ARRAY_CACHE_COUNTERS)
}

pub(crate) fn poseidon_array_insert(values: &[Felt], value: Felt) {
    insert(
        &POSEIDON_ARRAY_CACHE,
        &POSEIDON_ARRAY_CACHE_CAPACITY,
        &POSEIDON_ARRAY_CACHE_COUNTERS,
        values.to_vec(),
        value,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn cache_is_bypassed_when_disabled_and_reused_when_enabled() {
        let _guard = TEST_MUTEX.lock().unwrap();
        let key = Felt::from(1_u8);
        let value = Felt::from(2_u8);

        configure_hash_cache(HashCacheConfig::default());
        pedersen_pair_insert(key, key, value);
        assert_eq!(pedersen_pair_get(key, key), None);

        set_hash_cache_enabled(true);
        pedersen_pair_insert(key, key, value);
        assert_eq!(pedersen_pair_get(key, key), Some(value));

        set_hash_cache_enabled(false);
    }

    #[test]
    fn capacity_and_metrics_are_configurable() {
        let _guard = TEST_MUTEX.lock().unwrap();
        let before = hash_cache_metrics()[1];
        configure_hash_cache(HashCacheConfig {
            enabled: true,
            pedersen_pair_capacity: 1,
            ..Default::default()
        });

        let first = Felt::from(1_u8);
        let second = Felt::from(2_u8);
        let value = Felt::from(3_u8);
        assert_eq!(pedersen_pair_get(first, first), None);
        pedersen_pair_insert(first, first, value);
        assert_eq!(pedersen_pair_get(first, first), Some(value));
        pedersen_pair_insert(second, second, value);

        let after = hash_cache_metrics()[1];
        assert_eq!(after.capacity, 1);
        assert_eq!(after.entries, 1);
        assert_eq!(after.total_calls, before.total_calls + 2);
        assert_eq!(after.hits, before.hits + 1);
        assert_eq!(after.misses, before.misses + 1);
        assert_eq!(after.capacity_clears, before.capacity_clears + 1);
        assert_eq!(pedersen_pair_get(first, first), None);
        assert_eq!(pedersen_pair_get(second, second), Some(value));

        configure_hash_cache(HashCacheConfig::default());
    }
}
