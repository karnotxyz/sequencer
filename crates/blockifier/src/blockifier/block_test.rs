use starknet_api::block::{BlockHash, BlockHashAndNumber, BlockNumber};
use starknet_api::felt;
use starknet_api::state::StorageKey;

use crate::abi::constants;
use crate::blockifier::block::pre_process_block;
use crate::blockifier_versioned_constants::VersionedConstants;
use crate::state::cached_state::CachedState;
use crate::state::state_api::StateReader;
use crate::test_utils::dict_state_reader::DictStateReader;

#[test]
fn test_pre_process_block() {
    let mut state = CachedState::new(DictStateReader::default());
    let os_constants = VersionedConstants::create_for_testing().os_constants;

    // Test the positive flow of pre_process_block inside the allowed block number interval
    let block_number = BlockNumber(constants::STORED_BLOCK_HASH_BUFFER);
    let block_hash = felt!(20_u8);
    pre_process_block(
        &mut state,
        Some(BlockHashAndNumber { hash: BlockHash(block_hash), number: block_number }),
        block_number,
        &os_constants,
    )
    .unwrap();

    let written_hash = state.get_storage_at(
        os_constants.os_contract_addresses.block_hash_contract_address(),
        StorageKey::from(block_number.0),
    );
    assert_eq!(written_hash.unwrap(), block_hash);

    // Test that block pre-process with block hash None is successful only within the allowed
    // block number interval.
    let block_number = BlockNumber(constants::STORED_BLOCK_HASH_BUFFER - 1);
    assert!(pre_process_block(&mut state, None, block_number, &os_constants).is_ok());

    let block_number = BlockNumber(constants::STORED_BLOCK_HASH_BUFFER);
    let error = pre_process_block(&mut state, None, block_number, &os_constants);
    assert_eq!(
        format!(
            "A block hash must be provided for block number > {}.",
            constants::STORED_BLOCK_HASH_BUFFER
        ),
        format!("{}", error.unwrap_err())
    );
}

#[test]
fn pre_process_block_uses_configured_hash_window() {
    use crate::state::cached_state::CachedState;
    use crate::state::errors::StateError;
    use crate::test_utils::dict_state_reader::DictStateReader;

    let mut state = CachedState::new(DictStateReader::default());
    let mut os_constants = VersionedConstants::create_for_testing().os_constants;
    // Use a non-default window to exercise the custom-buffer error path.
    std::sync::Arc::make_mut(&mut os_constants).stored_block_hash_buffer = 51;
    assert!(pre_process_block(&mut state, None, BlockNumber(50), &os_constants).is_ok());
    assert!(matches!(
        pre_process_block(&mut state, None, BlockNumber(51), &os_constants),
        Err(StateError::OldBlockHashNotProvidedForBuffer { buffer: 51 })
    ));
    let hash = felt!(66_u64);
    pre_process_block(
        &mut state,
        Some(BlockHashAndNumber { number: BlockNumber(0), hash: BlockHash(hash) }),
        BlockNumber(51),
        &os_constants,
    )
    .unwrap();
    assert_eq!(
        state
            .get_storage_at(
                os_constants.os_contract_addresses.block_hash_contract_address(),
                StorageKey::from(0_u64),
            )
            .unwrap(),
        hash
    );
}
