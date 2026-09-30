use std::sync::Arc;

use blockifier::execution::syscalls::committed_data::{
    CommittedDataWitness,
    CommittedDataWitnesses,
};
use blockifier::test_utils::dict_state_reader::DictStateReader;
use blockifier_test_utils::cairo_versions::{CairoVersion, RunnableCairo1};
use blockifier_test_utils::calldata::create_calldata;
use blockifier_test_utils::contracts::FeatureContract;
use starknet_api::{calldata, invoke_tx_args};
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Poseidon, StarkHash};

use crate::test_manager::{TestBuilder, TestRunner};

fn witness(publisher: Felt, value: Felt) -> CommittedDataWitness {
    let index = 499999_u32;
    let siblings = std::array::from_fn(|i| Felt::from(i + 100));
    let mut root = Poseidon::hash_array(&[
        Felt::from_hex_unchecked("0x434f4d4d49545445445f444154415f5631"),
        publisher,
        Felt::from(index),
        value,
    ]);
    for (depth, sibling) in siblings.iter().enumerate() {
        root = if (index >> depth) & 1 == 0 {
            Poseidon::hash(&root, sibling)
        } else {
            Poseidon::hash(sibling, &root)
        };
    }
    CommittedDataWitness { root, publisher, index, value, siblings }
}

async fn prepare() -> TestRunner<DictStateReader> {
    let contract = FeatureContract::TestContract(CairoVersion::Cairo1(RunnableCairo1::Casm));
    let (mut builder, [publisher]) =
        TestBuilder::create_standard([(contract, calldata![Felt::ZERO, Felt::ZERO])]).await;
    builder.os_hints_config.full_output = true;
    let witnesses =
        vec![witness(**publisher, Felt::MAX), witness(**publisher, Felt::from(54321_u32))];
    builder.initial_state.block_context.committed_data_activation_block = Some(0);
    builder.os_hints_config.committed_data_activation_block = Some(0);
    let readers = starknet_api::committed_data::CommittedDataReaders::new(vec![publisher]).unwrap();
    builder.initial_state.block_context.committed_data_readers = readers.clone();
    builder.os_hints_config.committed_data_readers = readers;
    builder.initial_state.block_context.committed_data_witnesses =
        Arc::new(CommittedDataWitnesses::new(witnesses.clone()).unwrap());
    builder.os_hints_config.committed_data_witnesses = witnesses.clone();
    // Both roots are published and consumed in order in one block. Only one root storage slot
    // and one result slot change; private value/path data does not become storage/DA.
    for w in &witnesses {
        let calldata = create_calldata(publisher, "test_storage_write", &[Felt::from(45), w.root]);
        builder.add_funded_account_invoke(invoke_tx_args! { calldata });
        let calldata =
            create_calldata(publisher, "test_committed_data_read", &[Felt::from(w.index), w.value]);
        builder.add_funded_account_invoke(invoke_tx_args! { calldata });
    }
    builder.build().await
}

#[tokio::test]
async fn committed_data_root_rotation_full_os_pie() {
    let output = prepare().await.run();
    output.perform_default_validations();
    output.runner_output.cairo_pie.run_validity_checks().unwrap();
    if let Some(path) = std::env::var_os("COMMITTED_DATA_POC_PIE_PATH") {
        output.runner_output.cairo_pie.write_zip_file(std::path::Path::new(&path), true).unwrap();
    }
    eprintln!(
        "CommittedData full OS PIE resources: {:?}",
        output.runner_output.cairo_pie.execution_resources
    );
}

#[tokio::test]
async fn committed_data_bad_witness_fails_inside_os() {
    let mut runner = prepare().await;
    // Execution already succeeded with a valid host cache. Corrupt only SNOS's private hint input.
    runner.os_hints.os_hints_config.committed_data_witnesses[1].siblings[0] += Felt::ONE;
    let error = starknet_os::runner::run_os_stateless(
        starknet_os::runner::DEFAULT_OS_LAYOUT,
        runner.os_hints,
    )
    .expect_err("Cairo must reject a corrupt membership proof");
    let error = error.to_string();
    assert!(error.contains("An ASSERT_EQ instruction failed"), "unexpected error: {error}");
    assert!(error.contains("assert calculated_root = root"), "wrong failing constraint: {error}");
}

/// Opt-in integration sample: actually hash all 500,000 leaves for each of two publications.
#[tokio::test]
#[ignore = "builds two complete 500k-value trees"]
async fn committed_data_full_500k_snapshot_os_pie() {
    use blockifier::execution::syscalls::committed_data::CommittedDataSet;
    let contract = FeatureContract::TestContract(CairoVersion::Cairo1(RunnableCairo1::Casm));
    let (mut builder, [publisher]) =
        TestBuilder::create_standard([(contract, calldata![Felt::ZERO, Felt::ZERO])]).await;
    let mut witnesses = Vec::new();
    let started = std::time::Instant::now();
    for epoch in 0..2_u128 {
        let tree = CommittedDataSet::new(
            **publisher,
            (0..500_000_u128).map(|index| Felt::from(100_000_000 + index * 100 + epoch)).collect(),
        )
        .unwrap();
        let root = tree.root();
        eprintln!("500k epoch {epoch}: root={root:#x}, elapsed={:?}", started.elapsed());
        assert!(tree.witness(500_000).is_none());
        let calldata = create_calldata(publisher, "test_storage_write", &[Felt::from(45), root]);
        builder.add_funded_account_invoke(invoke_tx_args! { calldata });
        for index in [0_u32, 17, 249999, 499999] {
            let w = tree.witness(index).unwrap();
            assert!(w.verify());
            let calldata = create_calldata(
                publisher,
                "test_committed_data_read",
                &[Felt::from(index), w.value],
            );
            builder.add_funded_account_invoke(invoke_tx_args! { calldata });
            witnesses.push(w);
        }
    }
    builder.initial_state.block_context.committed_data_activation_block = Some(0);
    builder.os_hints_config.committed_data_activation_block = Some(0);
    let readers = starknet_api::committed_data::CommittedDataReaders::new(vec![publisher]).unwrap();
    builder.initial_state.block_context.committed_data_readers = readers.clone();
    builder.os_hints_config.committed_data_readers = readers;
    builder.initial_state.block_context.committed_data_witnesses =
        Arc::new(CommittedDataWitnesses::new(witnesses.clone()).unwrap());
    builder.os_hints_config.committed_data_witnesses = witnesses;
    let output = builder.build().await.run();
    output.perform_default_validations();
    output.runner_output.cairo_pie.run_validity_checks().unwrap();
    if let Some(path) = std::env::var_os("COMMITTED_DATA_POC_PIE_PATH") {
        output.runner_output.cairo_pie.write_zip_file(std::path::Path::new(&path), true).unwrap();
    }
    eprintln!(
        "500k full OS resources: {:?}; wall={:?}",
        output.runner_output.cairo_pie.execution_resources,
        started.elapsed()
    );
}

#[tokio::test]
async fn committed_data_activation_mismatch_cannot_replay_a_successful_read() {
    let mut runner = prepare().await;
    runner.os_hints.os_hints_config.committed_data_activation_block = None;
    let result = starknet_os::runner::run_os_stateless(
        starknet_os::runner::DEFAULT_OS_LAYOUT,
        runner.os_hints,
    );
    assert!(result.is_err(), "disabled OS must not authenticate a host-only special call");
}

#[tokio::test]
async fn committed_data_missing_witness_cannot_replay_a_successful_read() {
    let mut runner = prepare().await;
    runner.os_hints.os_hints_config.committed_data_witnesses.clear();
    let result = starknet_os::runner::run_os_stateless(
        starknet_os::runner::DEFAULT_OS_LAYOUT,
        runner.os_hints,
    );
    assert!(result.is_err(), "missing input must not authenticate a host-only value");
}

#[tokio::test]
async fn committed_data_full_os_output_aggregates_only_with_matching_activation() {
    use starknet_os::hint_processor::aggregator_hint_processor::{
        AggregatorInput,
        DataAvailability,
    };
    let runner = prepare().await;
    let chain_info = runner.os_hints.os_hints_config.chain_info.clone();
    let public_keys = runner.os_hints.os_hints_config.public_keys.clone();
    let readers = runner.os_hints.os_hints_config.committed_data_readers.clone();
    let output = runner.run();
    output.perform_default_validations();
    let child = output.runner_output.raw_os_output;
    let mut bootloader =
        vec![Felt::ONE, Felt::from(child.len() + 2), apollo_starknet_os_program::PROGRAM_HASHES.os];
    bootloader.extend(child);
    for (activation, readers) in [
        (Some(0), readers.clone()),
        (None, readers.clone()),
        (Some(1), readers),
        (Some(0), Default::default()),
    ] {
        let should_succeed = activation == Some(0) && !readers.as_slice().is_empty();
        let input = AggregatorInput {
            bootloader_output: Some(bootloader.clone()),
            full_output: true,
            debug_mode: false,
            chain_id: (&chain_info.chain_id).try_into().unwrap(),
            fee_token_address: chain_info.strk_fee_token_address.into(),
            public_keys: public_keys.clone(),
            da: DataAvailability::CallData,
            committed_data_activation_block: activation,
            committed_data_readers: readers,
        };
        let result = starknet_os::runner::run_aggregator(
            cairo_vm::types::layout_name::LayoutName::all_cairo,
            input,
        );
        if should_succeed {
            result.unwrap().cairo_pie.run_validity_checks().unwrap();
        } else {
            assert!(result.is_err(), "aggregator must reject mismatching activation configuration");
        }
    }
}

#[tokio::test]
async fn committed_data_invalid_requests_produce_provable_reverts_without_witnesses() {
    use blockifier::execution::syscalls::committed_data::{
        COMMITTED_DATA_ADDRESS,
        MAX_COMMITTED_DATA_VALUES,
    };
    use starknet_api::abi::abi_utils::selector_from_name;
    let contract = FeatureContract::TestContract(CairoVersion::Cairo1(RunnableCairo1::Casm));
    let (mut builder, [publisher]) =
        TestBuilder::create_standard([(contract, calldata![Felt::ZERO, Felt::ZERO])]).await;
    builder.initial_state.block_context.committed_data_activation_block = Some(0);
    builder.os_hints_config.committed_data_activation_block = Some(0);
    let readers = starknet_api::committed_data::CommittedDataReaders::new(vec![publisher]).unwrap();
    builder.initial_state.block_context.committed_data_readers = readers.clone();
    builder.os_hints_config.committed_data_readers = readers;
    for (selector, args) in [
        (Felt::ZERO, vec![Felt::ZERO, Felt::ZERO]),
        (selector_from_name("get_value").0, vec![Felt::ZERO]),
        (
            selector_from_name("get_value").0,
            vec![Felt::ZERO, Felt::from(MAX_COMMITTED_DATA_VALUES)],
        ),
    ] {
        let mut raw = vec![COMMITTED_DATA_ADDRESS, selector, Felt::from(args.len())];
        raw.extend(args);
        let calldata = create_calldata(publisher, "test_call_contract", &raw);
        let tx = builder.create_funded_account_invoke(invoke_tx_args! { calldata });
        builder.add_invoke_tx(tx, Some(String::new()), None);
    }
    let output = builder.build().await.run();
    output.perform_default_validations();
    output.runner_output.cairo_pie.run_validity_checks().unwrap();
}

#[tokio::test]
async fn committed_data_reader_policy_mismatch_cannot_replay_a_successful_read() {
    let mut runner = prepare().await;
    runner.os_hints.os_hints_config.committed_data_readers = Default::default();
    assert!(
        starknet_os::runner::run_os_stateless(
            starknet_os::runner::DEFAULT_OS_LAYOUT,
            runner.os_hints,
        )
        .is_err(),
        "OS admission policy must match the executed call"
    );
}

#[tokio::test]
async fn committed_data_unapproved_reader_produces_provable_revert_without_witness() {
    let contract = FeatureContract::TestContract(CairoVersion::Cairo1(RunnableCairo1::Casm));
    let (mut builder, [publisher]) =
        TestBuilder::create_standard([(contract, calldata![Felt::ZERO, Felt::ZERO])]).await;
    builder.initial_state.block_context.committed_data_activation_block = Some(0);
    builder.os_hints_config.committed_data_activation_block = Some(0);
    // Empty reader policy denies before data lookup, so no private witness is needed.
    let calldata = create_calldata(publisher, "test_committed_data_read", &[Felt::ZERO, Felt::MAX]);
    let tx = builder.create_funded_account_invoke(invoke_tx_args! { calldata });
    builder.add_invoke_tx(tx, Some(String::new()), None);
    let output = builder.build().await.run();
    output.perform_default_validations();
    output.runner_output.cairo_pie.run_validity_checks().unwrap();
}

#[tokio::test]
async fn committed_data_virtual_os_binds_adapter_policy() {
    let contract = FeatureContract::TestContract(CairoVersion::Cairo1(RunnableCairo1::Casm));
    let (mut builder, [publisher]) =
        TestBuilder::create_standard_virtual([(contract, calldata![Felt::ZERO, Felt::ZERO])]).await;
    let readers = starknet_api::committed_data::CommittedDataReaders::new(vec![publisher]).unwrap();
    builder.initial_state.block_context.committed_data_activation_block = Some(0);
    builder.initial_state.block_context.committed_data_readers = readers.clone();
    builder.os_hints_config.committed_data_activation_block = Some(0);
    builder.os_hints_config.committed_data_readers = readers;
    // Virtual OS accepts a single invoke. Its output must bind the configured policy even
    // when this particular transaction only performs an ordinary storage read.
    let calldata = create_calldata(publisher, "test_storage_read", &[Felt::from(45)]);
    builder.add_funded_account_invoke(invoke_tx_args! { calldata });
    builder.build().await.run_virtual_and_validate();
}
