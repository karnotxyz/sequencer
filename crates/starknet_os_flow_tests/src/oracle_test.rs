use std::sync::Arc;

use blockifier::execution::syscalls::oracle::{ORACLE_TREE_HEIGHT, OracleWitness, OracleWitnesses};
use blockifier::test_utils::dict_state_reader::DictStateReader;
use blockifier_test_utils::cairo_versions::{CairoVersion, RunnableCairo1};
use blockifier_test_utils::calldata::create_calldata;
use blockifier_test_utils::contracts::FeatureContract;
use starknet_api::{calldata, invoke_tx_args};
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Poseidon, StarkHash};

use crate::test_manager::{TestBuilder, TestRunner};

fn witness(publisher: Felt, price: u128) -> OracleWitness {
    let asset = 499999_u32;
    let siblings: Vec<_> = (0..ORACLE_TREE_HEIGHT).map(|i| Felt::from(i + 100)).collect();
    let mut root = Poseidon::hash_array(&[
        Felt::from_hex_unchecked("0x4f5241434c455f5631"),
        publisher,
        Felt::from(asset),
        Felt::from(price),
    ]);
    for (depth, sibling) in siblings.iter().enumerate() {
        root = if (asset >> depth) & 1 == 0 {
            Poseidon::hash(&root, sibling)
        } else {
            Poseidon::hash(sibling, &root)
        };
    }
    OracleWitness { root, publisher, asset, price, siblings }
}

async fn prepare() -> TestRunner<DictStateReader> {
    let contract = FeatureContract::TestContract(CairoVersion::Cairo1(RunnableCairo1::Casm));
    let (mut builder, [publisher]) =
        TestBuilder::create_standard([(contract, calldata![Felt::ZERO, Felt::ZERO])]).await;
    let witnesses = vec![witness(**publisher, 12345), witness(**publisher, 54321)];
    builder.initial_state.block_context.oracle_witnesses =
        Arc::new(OracleWitnesses::new(witnesses.clone()).unwrap());
    builder.os_hints_config.oracle_witnesses = witnesses.clone();
    // Both roots are published and consumed in order in one block. Only one root storage slot
    // and one result slot change; private price/path data does not become storage/DA.
    for w in &witnesses {
        let calldata = create_calldata(publisher, "test_storage_write", &[Felt::from(45), w.root]);
        builder.add_funded_account_invoke(invoke_tx_args! { calldata });
        let calldata = create_calldata(
            publisher,
            "test_oracle_read",
            &[Felt::from(w.asset), Felt::from(w.price)],
        );
        builder.add_funded_account_invoke(invoke_tx_args! { calldata });
    }
    builder.build().await
}

#[tokio::test]
async fn oracle_root_rotation_full_os_pie() {
    let output = prepare().await.run();
    output.perform_default_validations();
    output.runner_output.cairo_pie.run_validity_checks().unwrap();
    if let Some(path) = std::env::var_os("ORACLE_POC_PIE_PATH") {
        output.runner_output.cairo_pie.write_zip_file(std::path::Path::new(&path), true).unwrap();
    }
    eprintln!(
        "Oracle full OS PIE resources: {:?}",
        output.runner_output.cairo_pie.execution_resources
    );
}

#[tokio::test]
async fn oracle_bad_witness_fails_inside_os() {
    let mut runner = prepare().await;
    // Execution already succeeded with a valid host cache. Corrupt only SNOS's private hint input.
    runner.os_hints.os_hints_config.oracle_witnesses[1].siblings[0] += Felt::ONE;
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
#[ignore = "builds two complete 500k-price trees"]
async fn oracle_full_500k_snapshot_os_pie() {
    use blockifier::execution::syscalls::oracle::OracleSnapshot;
    let contract = FeatureContract::TestContract(CairoVersion::Cairo1(RunnableCairo1::Casm));
    let (mut builder, [publisher]) =
        TestBuilder::create_standard([(contract, calldata![Felt::ZERO, Felt::ZERO])]).await;
    let mut witnesses = Vec::new();
    let started = std::time::Instant::now();
    for epoch in 0..2_u128 {
        let tree = OracleSnapshot::new(
            **publisher,
            (0..500_000_u128).map(|asset| 100_000_000 + asset * 100 + epoch).collect(),
        )
        .unwrap();
        let root = tree.root();
        eprintln!("500k epoch {epoch}: root={root:#x}, elapsed={:?}", started.elapsed());
        assert!(tree.witness(500_000).is_none());
        let calldata = create_calldata(publisher, "test_storage_write", &[Felt::from(45), root]);
        builder.add_funded_account_invoke(invoke_tx_args! { calldata });
        for asset in [0_u32, 17, 249999, 499999] {
            let w = tree.witness(asset).unwrap();
            assert!(w.verify());
            let calldata = create_calldata(
                publisher,
                "test_oracle_read",
                &[Felt::from(asset), Felt::from(w.price)],
            );
            builder.add_funded_account_invoke(invoke_tx_args! { calldata });
            witnesses.push(w);
        }
    }
    builder.initial_state.block_context.oracle_witnesses =
        Arc::new(OracleWitnesses::new(witnesses.clone()).unwrap());
    builder.os_hints_config.oracle_witnesses = witnesses;
    let output = builder.build().await.run();
    output.perform_default_validations();
    output.runner_output.cairo_pie.run_validity_checks().unwrap();
    if let Some(path) = std::env::var_os("ORACLE_POC_PIE_PATH") {
        output.runner_output.cairo_pie.write_zip_file(std::path::Path::new(&path), true).unwrap();
    }
    eprintln!(
        "500k full OS resources: {:?}; wall={:?}",
        output.runner_output.cairo_pie.execution_resources,
        started.elapsed()
    );
}
