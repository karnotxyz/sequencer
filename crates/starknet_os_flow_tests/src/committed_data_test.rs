use std::sync::Arc;

use blockifier::execution::syscalls::committed_data::{
    CommittedDataWitness,
    CommittedDataWitnesses,
    read_os_resources,
};
use blockifier::execution::syscalls::vm_syscall_utils::SyscallSelector;
use blockifier::test_utils::dict_state_reader::DictStateReader;
use blockifier::test_utils::get_const_syscall_resources;
use blockifier_test_utils::cairo_versions::{CairoVersion, RunnableCairo1};
use blockifier_test_utils::calldata::create_calldata;
use blockifier_test_utils::contracts::FeatureContract;
use starknet_api::{calldata, invoke_tx_args};
use starknet_types_core::felt::Felt;

use crate::test_manager::{TestBuilder, TestRunner};

fn witness(value: Felt, index: u32, height: usize) -> CommittedDataWitness {
    witness_for_key(value, Felt::from(index), height)
}

fn witness_for_key(value: Felt, key: Felt, height: usize) -> CommittedDataWitness {
    use blockifier::execution::syscalls::committed_data::{
        CommittedDataSibling,
        branch,
        key_bit,
        leaf,
    };
    let siblings: Vec<_> = (0..height)
        .map(|i| CommittedDataSibling { bit: i as u8, hash: Felt::from(i + 100) })
        .collect();
    let mut root = leaf(key, value);
    for step in &siblings {
        root = if key_bit(key, step.bit) {
            branch(step.bit, step.hash, root)
        } else {
            branch(step.bit, root, step.hash)
        };
    }
    CommittedDataWitness { root, key, value, siblings }
}

async fn prepare() -> TestRunner<DictStateReader> {
    let contract = FeatureContract::TestContract(CairoVersion::Cairo1(RunnableCairo1::Casm));
    let (mut builder, readers) = TestBuilder::create_standard([
        (contract, calldata![Felt::ZERO, Felt::ZERO]),
        (contract, calldata![Felt::ZERO, Felt::ZERO]),
    ])
    .await;
    assert_ne!(readers[0], readers[1]);
    builder.os_hints_config.full_output = true;
    let mut witnesses = vec![
        witness(Felt::MAX, 499_999, 19),
        witness(Felt::from(54_321_u32), 17_777, 15),
        witness(Felt::from(42_u32), 0, 0),
        witness(Felt::from(150_u32), 0, 15),
        witness(Felt::from(190_u32), 0, 19),
    ];
    witnesses.extend(
        (1..=19).map(|height| witness(Felt::from(1000 + height), (1_u32 << height) - 1, height)),
    );
    witnesses.extend(
        [31, 64, 127, 128, 251, 252].map(|height| witness(Felt::from(2000 + height), 0, height)),
    );
    witnesses.push(witness_for_key(Felt::ZERO, Felt::MAX, 252));
    builder.initial_state.block_context.use_committed_data = true;
    builder.os_hints_config.use_committed_data = true;
    builder.initial_state.block_context.committed_data_witnesses =
        Arc::new(CommittedDataWitnesses::new(witnesses.clone()).unwrap());
    builder.os_hints_config.committed_data_witnesses = witnesses.clone();
    // Both contracts consume the same roots and witnesses without reader configuration.
    // Each stores its trusted root and result; private value/path data does not become storage/DA.
    for w in &witnesses {
        for reader in readers {
            let calldata = create_calldata(reader, "test_storage_write", &[Felt::from(45), w.root]);
            builder.add_funded_account_invoke(invoke_tx_args! { calldata });
            let calldata = create_calldata(reader, "test_committed_data_read", &[w.key, w.value]);
            builder.add_funded_account_invoke(invoke_tx_args! { calldata });
        }
    }
    builder.build().await
}

fn collect_profiled_committed_data_calls<'a>(
    trace: &'a serde_json::Value,
    calls: &mut Vec<&'a serde_json::Value>,
) {
    match trace {
        serde_json::Value::Array(values) => {
            for value in values {
                collect_profiled_committed_data_calls(value, calls);
            }
        }
        serde_json::Value::Object(object) => {
            let is_leaf_call = object.get("selector").and_then(serde_json::Value::as_str)
                == Some("CallContract")
                && object
                    .get("inner_syscalls")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(Vec::is_empty);
            let uses_poseidon = object
                .get("resources")
                .and_then(|resources| {
                    resources.pointer("/builtin_instance_counter/poseidon_builtin")
                })
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|count| count > 0);
            if is_leaf_call && uses_poseidon {
                calls.push(&object["resources"]);
            }
            for value in object.values() {
                collect_profiled_committed_data_calls(value, calls);
            }
        }
        _ => {}
    }
}

/// Compare the executed OS syscall, including its wrapper, with the same resources the
/// sequencer charges and reserves. Keep the ordinary CallContract allowance in both totals.
fn validate_read_resources(
    output: &starknet_os::io::os_output::StarknetOsRunnerOutput,
) -> Vec<usize> {
    use blockifier::blockifier_versioned_constants::VersionedConstants;
    use blockifier::bouncer::BuiltinWeights;
    use blockifier::utils::get_gas_cost_from_vm_resources;
    use starknet_api::versioned_constants_logic::VersionedConstantsTrait;
    let costs = &VersionedConstants::latest_constants().os_constants.gas_costs;
    let proving_costs = BuiltinWeights::default().gas_costs;
    let trace = serde_json::to_value(&output.txs_trace).unwrap();
    let mut measured_calls = Vec::new();
    collect_profiled_committed_data_calls(&trace, &mut measured_calls);
    let mut report = Vec::new();
    let mut heights = Vec::new();
    for measured in measured_calls {
        let poseidons =
            measured["builtin_instance_counter"]["poseidon_builtin"].as_u64().unwrap() as usize;
        let height = poseidons.checked_sub(2).unwrap() / 2;
        let expected = &get_const_syscall_resources(SyscallSelector::CallContract)
            + &read_os_resources(height);
        heights.push(height);
        let steps = usize::try_from(measured["n_steps"].as_u64().unwrap()).unwrap();
        let range_checks = usize::try_from(
            measured["builtin_instance_counter"]["range_check_builtin"].as_u64().unwrap(),
        )
        .unwrap();
        assert!(
            steps <= expected.n_steps,
            "OS steps {steps} exceed bouncer bound {} at height {height}",
            expected.n_steps
        );
        assert!(
            range_checks
                <= expected.builtin_instance_counter
                    [&cairo_vm::types::builtin_name::BuiltinName::range_check],
            "OS range checks {range_checks} exceed bouncer bound at height {height}"
        );
        // OsLogger does not attribute holes per syscall. Check the whole PIE below,
        // rather than interpreting its placeholder zero as a measurement.
        assert_eq!(
            usize::try_from(
                measured["builtin_instance_counter"]["poseidon_builtin"].as_u64().unwrap()
            )
            .unwrap(),
            expected.builtin_instance_counter
                [&cairo_vm::types::builtin_name::BuiltinName::poseidon]
        );
        let actual: cairo_vm::vm::runners::cairo_runner::ExecutionResources =
            serde_json::from_value(measured.clone()).unwrap();
        let sierra = get_gas_cost_from_vm_resources(&actual, &costs.base, &costs.builtins);
        let sierra_bound = get_gas_cost_from_vm_resources(&expected, &costs.base, &costs.builtins);
        let proving = get_gas_cost_from_vm_resources(&actual, &costs.base, &proving_costs);
        let proving_bound = get_gas_cost_from_vm_resources(&expected, &costs.base, &proving_costs);
        assert!(sierra <= sierra_bound, "Sierra resource allowance at height {height}");
        assert!(proving <= proving_bound, "proving resource allowance at height {height}");
        report.push(serde_json::json!({
            "height": height, "actual": actual, "reserved": expected,
            "sierra": sierra, "sierra_bound": sierra_bound,
            "extra_sierra_charged": blockifier::execution::syscalls::committed_data::read_gas(height),
            "proving": proving, "proving_bound": proving_bound,
        }));
    }
    // Conservatively charge *all* PIE holes, including unrelated transaction/state work,
    // against this fixture's read headroom. This avoids relying on per-syscall hole attribution.
    let hole_gas = output.cairo_pie.execution_resources.n_memory_holes as u64
        * costs.base.memory_hole_gas_cost;
    for (actual, bound) in [("sierra", "sierra_bound"), ("proving", "proving_bound")] {
        let used: u64 = report.iter().map(|row| row[actual].as_u64().unwrap()).sum();
        let reserved: u64 = report.iter().map(|row| row[bound].as_u64().unwrap()).sum();
        assert!(used + hole_gas <= reserved, "read budget including all PIE holes: {actual}");
    }
    if let Some(path) = std::env::var_os("COMMITTED_DATA_RESOURCE_REPORT") {
        let report = serde_json::json!({
            "reads": report, "whole_pie": output.cairo_pie.execution_resources,
            "whole_pie_hole_gas": hole_gas,
        });
        std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }
    heights
}

#[tokio::test]
async fn committed_data_root_rotation_and_shared_reads_full_os_pie() {
    let output = prepare().await.run();
    output.perform_default_validations();
    output.runner_output.cairo_pie.run_validity_checks().unwrap();
    let mut heights = validate_read_resources(&output.runner_output);
    assert_eq!(heights.len(), 62, "profile every committed-data read in the fixture");
    heights.sort_unstable();
    let mut expected_heights: Vec<_> = (0..=19).flat_map(|height| [height, height]).collect();
    expected_heights.extend([15, 15, 15, 15, 19, 19, 19, 19]);
    expected_heights.extend([31, 64, 127, 128, 251, 252].into_iter().flat_map(|h| [h, h]));
    expected_heights.extend([252, 252]);
    expected_heights.sort_unstable();
    assert_eq!(heights, expected_heights);
    if let Some(path) = std::env::var_os("COMMITTED_DATA_POC_PIE_PATH") {
        output.runner_output.cairo_pie.write_zip_file(std::path::Path::new(&path), true).unwrap();
    }
    eprintln!(
        "CommittedData full OS PIE resources: {:?}",
        output.runner_output.cairo_pie.execution_resources
    );
}

#[tokio::test]
async fn committed_data_optional_witnesses_do_not_change_ordinary_execution() {
    let contract = FeatureContract::TestContract(CairoVersion::Cairo1(RunnableCairo1::Casm));
    let mut outputs = Vec::new();
    for (enabled, include_unused_witness) in
        [(false, false), (false, true), (true, false), (true, true)]
    {
        let (mut builder, [reader]) =
            TestBuilder::create_standard([(contract, calldata![Felt::ZERO, Felt::ZERO])]).await;
        builder.initial_state.block_context.use_committed_data = enabled;
        builder.os_hints_config.use_committed_data = enabled;
        // Neither execution permission nor unused private inputs may alter ordinary blocks.
        if include_unused_witness {
            let witnesses = vec![witness(Felt::MAX, 0, 0)];
            builder.initial_state.block_context.committed_data_witnesses =
                Arc::new(CommittedDataWitnesses::new(witnesses.clone()).unwrap());
            builder.os_hints_config.committed_data_witnesses = witnesses;
        }
        let calldata =
            create_calldata(reader, "test_storage_write", &[Felt::from(45), Felt::from(123)]);
        builder.add_funded_account_invoke(invoke_tx_args! { calldata });
        let output = builder.build().await.run();
        output.perform_default_validations();
        output.runner_output.cairo_pie.run_validity_checks().unwrap();
        outputs.push(output.runner_output.raw_os_output);
    }
    for output in &outputs[1..] {
        assert_eq!(&outputs[0], output, "optional inputs must not change ordinary public output");
    }
}

#[tokio::test]
async fn committed_data_bad_witness_fails_inside_os() {
    let mut runner = prepare().await;
    // Execution already succeeded with a valid host cache. Corrupt only SNOS's private hint input.
    runner.os_hints.os_hints_config.committed_data_witnesses[1].siblings[0].hash += Felt::ONE;
    let error = starknet_os::runner::run_os_stateless(
        starknet_os::runner::DEFAULT_OS_LAYOUT,
        runner.os_hints,
    )
    .expect_err("Cairo must reject a corrupt membership proof");
    let error = error.to_string();
    assert!(error.contains("An ASSERT_EQ instruction failed"), "unexpected error: {error}");
    assert!(error.contains("assert calculated_root = root"), "wrong failing constraint: {error}");
}

/// Opt-in integration: complete 30k/500k maps, hashed felt keys and two root publications each.
#[tokio::test]
#[ignore = "builds complete 30k and 500k maps with two root publications each"]
async fn committed_data_full_500k_snapshot_os_pie() {
    use blockifier::execution::syscalls::committed_data::CommittedDataSet;
    let contract = FeatureContract::TestContract(CairoVersion::Cairo1(RunnableCairo1::Casm));
    let (mut builder, [reader]) =
        TestBuilder::create_standard([(contract, calldata![Felt::ZERO, Felt::ZERO])]).await;
    let mut witnesses = Vec::new();
    let started = std::time::Instant::now();
    let mut expected_heights = Vec::new();
    use starknet_types_core::hash::{Poseidon, StarkHash};
    let key = |index: u128| Poseidon::hash_array(&[Felt::from(index)]);
    for size in [30_000_u128, 500_000] {
        for epoch in 0..2_u128 {
            let tree = CommittedDataSet::new(
                (0..size)
                    .map(|index| (key(index), Felt::from(100_000_000 + index * 100 + epoch)))
                    .collect(),
            )
            .unwrap();
            let root = tree.root();
            eprintln!(
                "{size} entries, epoch {epoch}: root={root:#x}, elapsed={:?}",
                started.elapsed()
            );
            assert!(tree.witness(key(size)).is_none());
            let calldata = create_calldata(reader, "test_storage_write", &[Felt::from(45), root]);
            builder.add_funded_account_invoke(invoke_tx_args! { calldata });
            for index in [0_u128, 17, size / 2, size - 1] {
                let w = tree.witness(key(index)).unwrap();
                assert!(w.verify());
                let calldata =
                    create_calldata(reader, "test_committed_data_read", &[key(index), w.value]);
                builder.add_funded_account_invoke(invoke_tx_args! { calldata });
                expected_heights.push(w.siblings.len());
                witnesses.push(w);
            }
        }
    }
    builder.initial_state.block_context.use_committed_data = true;
    builder.os_hints_config.use_committed_data = true;
    builder.initial_state.block_context.committed_data_witnesses =
        Arc::new(CommittedDataWitnesses::new(witnesses.clone()).unwrap());
    builder.os_hints_config.committed_data_witnesses = witnesses;
    let output = builder.build().await.run();
    output.perform_default_validations();
    output.runner_output.cairo_pie.run_validity_checks().unwrap();
    let mut heights = validate_read_resources(&output.runner_output);
    heights.sort_unstable();
    expected_heights.sort_unstable();
    assert_eq!(heights, expected_heights, "profile every full-map read");
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
async fn committed_data_disabled_input_cannot_prove_a_successful_read() {
    let mut runner = prepare().await;
    runner.os_hints.os_hints_config.use_committed_data = false;
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
async fn committed_data_full_os_output_aggregates_with_standard_config_hash() {
    use starknet_os::hint_processor::aggregator_hint_processor::{
        AggregatorInput,
        DataAvailability,
    };
    let runner = prepare().await;
    let chain_info = runner.os_hints.os_hints_config.chain_info.clone();
    let public_keys = runner.os_hints.os_hints_config.public_keys.clone();
    let output = runner.run();
    output.perform_default_validations();
    let child_config_hash =
        output.runner_output.get_os_output(None).unwrap().common_os_output.starknet_os_config_hash;
    let child = output.runner_output.raw_os_output;
    let mut bootloader =
        vec![Felt::ONE, Felt::from(child.len() + 2), apollo_starknet_os_program::PROGRAM_HASHES.os];
    bootloader.extend(child);
    let standard_config_hash = chain_info.compute_os_config_hash(public_keys.as_ref()).unwrap();
    assert_eq!(child_config_hash, standard_config_hash);
    let input = AggregatorInput {
        bootloader_output: Some(bootloader),
        full_output: true,
        debug_mode: false,
        chain_id: (&chain_info.chain_id).try_into().unwrap(),
        fee_token_address: chain_info.strk_fee_token_address.into(),
        public_keys,
        da: DataAvailability::CallData,
    };
    let result = starknet_os::runner::run_aggregator(
        cairo_vm::types::layout_name::LayoutName::all_cairo,
        input,
    )
    .unwrap();
    result.cairo_pie.run_validity_checks().unwrap();
}

#[tokio::test]
async fn committed_data_invalid_requests_produce_provable_reverts_without_witnesses() {
    use blockifier::execution::syscalls::committed_data::COMMITTED_DATA_ADDRESS;
    use starknet_api::abi::abi_utils::selector_from_name;
    let contract = FeatureContract::TestContract(CairoVersion::Cairo1(RunnableCairo1::Casm));
    let (mut builder, [reader]) =
        TestBuilder::create_standard([(contract, calldata![Felt::ZERO, Felt::ZERO])]).await;
    builder.initial_state.block_context.use_committed_data = true;
    builder.os_hints_config.use_committed_data = true;
    for (selector, args) in [
        (Felt::ZERO, vec![Felt::ZERO, Felt::ZERO]),
        (selector_from_name("get_value").0, vec![Felt::ZERO]),
    ] {
        let mut raw = vec![COMMITTED_DATA_ADDRESS, selector, Felt::from(args.len())];
        raw.extend(args);
        let calldata = create_calldata(reader, "test_call_contract", &raw);
        let tx = builder.create_funded_account_invoke(invoke_tx_args! { calldata });
        builder.add_invoke_tx(tx, Some(String::new()), None);
    }
    let output = builder.build().await.run();
    output.perform_default_validations();
    output.runner_output.cairo_pie.run_validity_checks().unwrap();
}

#[tokio::test]
async fn committed_data_virtual_os_uses_standard_config_hash() {
    let contract = FeatureContract::TestContract(CairoVersion::Cairo1(RunnableCairo1::Casm));
    let (mut builder, [reader]) =
        TestBuilder::create_standard_virtual([(contract, calldata![Felt::ZERO, Felt::ZERO])]).await;
    builder.initial_state.block_context.use_committed_data = true;
    builder.os_hints_config.use_committed_data = true;
    // Virtual OS accepts a single invoke and must use the ordinary config hash.
    let calldata = create_calldata(reader, "test_storage_read", &[Felt::from(45)]);
    builder.add_funded_account_invoke(invoke_tx_args! { calldata });
    builder.build().await.run_virtual_and_validate();
}
