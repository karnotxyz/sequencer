pub const ALIASES_TEST_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/aliases_test_bytes"));

/// Standalone verifier entrypoints retained even when production dispatch uses shared reads.
pub const COMMITTED_DATA_TEST_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/committed_data_test_bytes"));
