use blockifier_test_utils::cairo_versions::{CairoVersion, RunnableCairo1};
use blockifier_test_utils::contracts::FeatureContract;
use expect_test::expect;
use pretty_assertions::assert_eq;
use starknet_api::abi::abi_utils::selector_from_name;
use starknet_api::block::{BlockHash, BlockNumber};
use starknet_api::execution_utils::format_panic_data;
use starknet_api::state::StorageKey;
use starknet_api::test_utils::CURRENT_BLOCK_NUMBER;
use starknet_api::{calldata, felt};
use starknet_types_core::felt::Felt;
use test_case::test_case;

use crate::abi::constants;
use crate::blockifier_versioned_constants::VersionedConstants;
use crate::context::ChainInfo;
use crate::execution::entry_point::CallEntryPoint;
use crate::retdata;
use crate::state::cached_state::CachedState;
use crate::state::state_api::State;
use crate::test_utils::dict_state_reader::DictStateReader;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{trivial_external_entry_point_new, BALANCE};

pub fn initialize_state(
    test_contract: FeatureContract,
) -> (CachedState<DictStateReader>, Felt, Felt) {
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(test_contract, 1)]);

    // Initialize block number -> block hash entry.
    let upper_bound_block_number = CURRENT_BLOCK_NUMBER - constants::STORED_BLOCK_HASH_BUFFER;
    let block_number = felt!(upper_bound_block_number);
    let block_hash = felt!(66_u64);
    let key = StorageKey::try_from(block_number).unwrap();
    let block_hash_contract_address = VersionedConstants::create_for_testing()
        .os_constants
        .os_contract_addresses
        .block_hash_contract_address();
    state.set_storage_at(block_hash_contract_address, key, block_hash).unwrap();

    (state, block_number, block_hash)
}

#[cfg_attr(feature = "cairo_native", test_case(RunnableCairo1::Native;"Native"))]
#[test_case(RunnableCairo1::Casm;"VM")]
fn positive_flow(runnable_version: RunnableCairo1) {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1(runnable_version));
    let (mut state, block_number, block_hash) = initialize_state(test_contract);

    let calldata = calldata![block_number, block_hash];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_get_block_hash"),
        calldata,
        ..trivial_external_entry_point_new(test_contract)
    };

    let mut call_info = entry_point_call.clone().execute_directly(&mut state).unwrap();

    assert_eq!(call_info.storage_access_tracker.accessed_blocks.len(), 1);
    assert!(
        call_info
            .storage_access_tracker
            .accessed_blocks
            .contains(&BlockNumber(block_number.try_into().unwrap()))
    );
    assert_eq!(
        call_info.storage_access_tracker.read_block_hash_values,
        vec![BlockHash(block_hash)]
    );

    assert_eq!(call_info.execution.cairo_native, runnable_version.is_cairo_native());
    call_info.execution.cairo_native = false;

    expect![[r#"
        CallExecution {
            retdata: Retdata(
                [
                    0x42,
                ],
            ),
            events: [],
            l2_to_l1_messages: [],
            cairo_native: false,
            failed: false,
            gas_consumed: 15620,
        }
    "#]]
    .assert_debug_eq(&call_info.execution);
    assert_eq!(call_info.execution.retdata, retdata![block_hash]);
}

#[cfg_attr(feature = "cairo_native", test_case(RunnableCairo1::Native;"Native"))]
#[test_case(RunnableCairo1::Casm;"VM")]
fn negative_flow_block_number_out_of_range(runnable_version: RunnableCairo1) {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1(runnable_version));
    let (mut state, _, _) = initialize_state(test_contract);

    let requested_block_number = CURRENT_BLOCK_NUMBER - constants::STORED_BLOCK_HASH_BUFFER + 1;
    let block_number = felt!(requested_block_number);
    let dummy_block_hash = felt!(66_u64);
    let calldata = calldata![block_number, dummy_block_hash];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_get_block_hash"),
        calldata,
        ..trivial_external_entry_point_new(test_contract)
    };

    let call_info = entry_point_call.clone().execute_directly(&mut state).unwrap();
    assert!(call_info.execution.failed);
    assert_eq!(
        format_panic_data(&call_info.execution.retdata.0),
        "0x426c6f636b206e756d626572206f7574206f662072616e6765 ('Block number out of range')"
    );

    let error = entry_point_call.execute_directly_in_validate_mode(&mut state).unwrap_err();
    assert!(error.to_string().contains(
        "Unauthorized syscall get_block_hash on recent blocks in execution mode Validate."
    ));
}

#[cfg_attr(feature = "cairo_native", test_case(RunnableCairo1::Native, 49, 0, false; "native_before_window"))]
#[cfg_attr(feature = "cairo_native", test_case(RunnableCairo1::Native, 50, 0, true; "native_at_window"))]
#[cfg_attr(feature = "cairo_native", test_case(RunnableCairo1::Native, 100, 50, true; "native_last_allowed"))]
#[cfg_attr(feature = "cairo_native", test_case(RunnableCairo1::Native, 100, 51, false; "native_too_recent"))]
#[cfg_attr(feature = "cairo_native", test_case(RunnableCairo1::Native, 100, 90, false; "native_old_policy_key"))]
#[test_case(RunnableCairo1::Casm, 49, 0, false; "vm_before_window")]
#[test_case(RunnableCairo1::Casm, 50, 0, true; "vm_at_window")]
#[test_case(RunnableCairo1::Casm, 100, 50, true; "vm_last_allowed")]
#[test_case(RunnableCairo1::Casm, 100, 51, false; "vm_too_recent")]
#[test_case(RunnableCairo1::Casm, 100, 90, false; "vm_old_policy_key")]
fn configured_hash_window(
    runnable_version: RunnableCairo1,
    current: u64,
    requested: u64,
    allowed: bool,
) {
    use std::sync::Arc;

    use crate::context::BlockContext;
    use crate::execution::common_hints::ExecutionMode;
    use crate::transaction::objects::{DeprecatedTransactionInfo, TransactionInfo};

    let contract = FeatureContract::TestContract(CairoVersion::Cairo1(runnable_version));
    let (mut state, _, hash) = initialize_state(contract);
    let mut context = BlockContext::create_for_testing();
    context.block_info.block_number = BlockNumber(current);
    Arc::make_mut(&mut context.versioned_constants.os_constants).stored_block_hash_buffer = 50;
    // An old-policy key may already exist after a window change. The syscall must
    // reject it by age, not return its stored hash or silently replace it with zero.
    state
        .set_storage_at(
            context
                .versioned_constants
                .os_constants
                .os_contract_addresses
                .block_hash_contract_address(),
            StorageKey::from(requested),
            hash,
        )
        .unwrap();
    let call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_get_block_hash"),
        calldata: calldata![Felt::from(requested), hash],
        ..trivial_external_entry_point_new(contract)
    };
    let result =
        call.clone().execute_directly_given_block_context(&mut state, context.clone()).unwrap();
    assert_eq!(result.execution.cairo_native, runnable_version.is_cairo_native());
    assert_eq!(result.execution.failed, !allowed);
    if allowed {
        assert_eq!(result.execution.retdata, retdata![hash]);
    } else {
        assert_eq!(
            format_panic_data(&result.execution.retdata.0),
            "0x426c6f636b206e756d626572206f7574206f662072616e6765 ('Block number out of range')"
        );
        let error = call
            .execute_directly_given_tx_info(
                &mut state,
                TransactionInfo::Deprecated(DeprecatedTransactionInfo::default()),
                Some(Arc::new(context)),
                false,
                ExecutionMode::Validate,
            )
            .unwrap_err();
        assert!(error.to_string().contains(
            "Unauthorized syscall get_block_hash on recent blocks in execution mode Validate."
        ));
    }
}
