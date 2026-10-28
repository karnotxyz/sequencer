//! Manual paired benchmark using the complete archived trading state, not a price-read surrogate.
//! The external fixture contains application contracts and state and is deliberately not bundled.
//! Run explicitly with CD_SHARING_HARNESS, CD_SHARING_VARIANT and CD_SHARING_BLOCK.
use std::path::{Path, PathBuf};
use std::sync::Arc;

use blockifier::blockifier::config::TransactionExecutorConfig;
use blockifier::blockifier::transaction_executor::TransactionExecutor;
use blockifier::execution::contract_class::RunnableCompiledClass;
use blockifier::execution::syscalls::committed_data::{
    CommittedDataWitness,
    CommittedDataWitnesses,
};
use cairo_lang_starknet_classes::casm_contract_class::CasmContractClass;
use serde_json::{Value, json};
use starknet_api::block::{BlockTimestamp, GasPrice, GasPrices, StarknetVersion};
use starknet_api::execution_resources::GasAmount;
use starknet_api::transaction::fields::{
    AllResourceBounds,
    ResourceBounds,
    TransactionSignature,
    ValidResourceBounds,
};
use starknet_api::versioned_constants_logic::VersionedConstantsTrait;

use super::*;
use crate::initial_state::{InitialState, InitialStateData, commit_initial_state_diff};

fn felt(value: &Value) -> Felt {
    Felt::from_hex(value.as_str().unwrap()).unwrap()
}
fn address(value: &Value) -> ContractAddress {
    felt(value).try_into().unwrap()
}
fn read(path: impl AsRef<Path>) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[tokio::test]
#[ignore = "requires an independently prepared complete application snapshot"]
async fn committed_data_full_trade_snapshot() {
    let root = PathBuf::from(std::env::var("CD_SHARING_HARNESS").unwrap());
    let variant = std::env::var("CD_SHARING_VARIANT").unwrap();
    let block: u64 = std::env::var("CD_SHARING_BLOCK").unwrap().parse().unwrap();
    let data = read(root.join(format!("fixtures/{block}.json")));
    let step = &data["step"];
    assert_eq!(data["benchmark_scope"]["existing_positions"], 400);
    let maker: std::collections::HashSet<_> =
        data["benchmark_scope"]["maker_symbols"].as_array().unwrap().iter().map(felt).collect();
    let taker: std::collections::HashSet<_> =
        data["benchmark_scope"]["taker_symbols"].as_array().unwrap().iter().map(felt).collect();
    assert_eq!((maker.len(), taker.len()), (400, 400));
    assert!(maker.is_disjoint(&taker));
    let new_symbol = felt(&data["benchmark_scope"]["new_symbol"]);
    assert!(!maker.contains(&new_symbol) && !taker.contains(&new_symbol));
    let sender = address(&data["account"]);
    let fee_token = address(&data["fee_token"]);
    let mut state = DictStateReader::default();
    let mut maps = StateMaps::default();
    for row in data["storage"].as_array().unwrap() {
        maps.storage.insert((address(&row[0]), felt(&row[1]).try_into().unwrap()), felt(&row[2]));
    }
    // Both arms use exactly the same test signing key, account code and original caller address.
    // Application state, contracts, calldata and timestamps are preserved from the audited run.
    maps.storage.insert(
        (sender, felt(&data["signer_storage_key"]).try_into().unwrap()),
        starknet_crypto::get_public_key(&Felt::ONE),
    );
    for row in data["nonces"].as_array().unwrap() {
        maps.nonces.insert(address(&row[0]), Nonce(felt(&row[1])));
    }
    for row in data["deployed"].as_array().unwrap() {
        maps.class_hashes.insert(address(&row[0]), ClassHash(felt(&row[1])));
    }
    for row in data["declared"].as_array().unwrap() {
        maps.compiled_class_hashes
            .insert(ClassHash(felt(&row[0])), starknet_api::core::CompiledClassHash(felt(&row[1])));
    }
    let mut contracts = OsExecutionContracts::default();
    let mut runnable = HashMap::new();
    for class in data["classes"].as_array().unwrap() {
        let source = read(class["sierra"].as_str().unwrap());
        let sierra: SierraContractClass = serde_json::from_value(source).unwrap();
        let hash = sierra.calculate_class_hash();
        assert_eq!(hash.0, felt(&class["class_hash"]));
        let casm: CasmContractClass =
            serde_json::from_value(read(class["casm"].as_str().unwrap())).unwrap();
        let compiled = casm.hash(&HashVersion::V2);
        if let Some(expected) = maps.compiled_class_hashes.get(&hash) {
            assert_eq!(*expected, compiled);
        }
        let run = RunnableCompiledClass::try_from(ContractClass::V1((
            casm.clone(),
            sierra.get_sierra_version().unwrap(),
        )))
        .unwrap();
        state.class_hash_to_sierra.insert(hash, sierra.clone());
        state.class_hash_to_compiled_class_hash_v2.lock().unwrap().insert(hash, compiled);
        contracts.add_cairo1_contract(casm, &sierra);
        runnable.insert(hash, run);
    }
    eprintln!("Loaded exact classes and {} storage values", maps.storage.len());
    state.apply_writes(&maps, &runnable);
    let cache = root.join("fixtures").join(format!("{block}.facts"));
    let roots_path = root.join("fixtures").join(format!("{block}.roots.json"));
    let (roots, commitment_storage) = if cache.exists() && roots_path.exists() {
        use std::io::Read;

        use starknet_patricia_storage::map_storage::MapStorage;
        use starknet_patricia_storage::storage_trait::{DbKey, DbValue};
        let roots: StateRoots = serde_json::from_value(read(&roots_path)).unwrap();
        let mut bytes = std::io::Cursor::new(std::fs::read(&cache).unwrap());
        let mut facts = HashMap::new();
        while bytes.position() < bytes.get_ref().len() as u64 {
            let mut length = [0u8; 4];
            bytes.read_exact(&mut length).unwrap();
            let mut key = vec![0; u32::from_le_bytes(length) as usize];
            bytes.read_exact(&mut key).unwrap();
            bytes.read_exact(&mut length).unwrap();
            let mut value = vec![0; u32::from_le_bytes(length) as usize];
            bytes.read_exact(&mut value).unwrap();
            facts.insert(DbKey(key), DbValue(value));
        }
        (roots, MapStorage(facts))
    } else {
        use std::io::Write;
        let (roots, storage) =
            commit_initial_state_diff(state_maps_to_committer_state_diff(maps.clone())).await;
        let mut bytes = Vec::new();
        for (key, value) in &storage.0 {
            bytes.write_all(&(key.0.len() as u32).to_le_bytes()).unwrap();
            bytes.write_all(&key.0).unwrap();
            bytes.write_all(&(value.0.len() as u32).to_le_bytes()).unwrap();
            bytes.write_all(&value.0).unwrap();
        }
        std::fs::write(&cache, bytes).unwrap();
        std::fs::write(&roots_path, serde_json::to_vec(&roots).unwrap()).unwrap();
        (roots, storage)
    };
    eprintln!("Initial snapshot committed");
    let mut witnesses: Vec<CommittedDataWitness> = Vec::new();
    for file in std::fs::read_dir(data["witness_directory"].as_str().unwrap()).unwrap() {
        let path = file.unwrap().path();
        // macOS archive metadata is not a witness; malformed witness JSON must still fail.
        if path.file_name().unwrap().to_string_lossy().starts_with("._") {
            continue;
        }
        witnesses.push(serde_json::from_value(read(path)).unwrap());
    }
    if let Ok(extra) = std::env::var("CD_EXTRA_WITNESSES") {
        for entry in std::fs::read_dir(extra).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e == "json") {
                let witness: CommittedDataWitness = serde_json::from_value(read(path)).unwrap();
                if let Some(prior) =
                    witnesses.iter().find(|w| w.root == witness.root && w.key == witness.key)
                {
                    assert_eq!(prior, &witness);
                } else {
                    witnesses.push(witness);
                }
            }
        }
    }
    let mut context = BlockContext::new(
        BlockInfo {
            block_number: BlockNumber(block - 1), block_timestamp: BlockTimestamp(step["block"]["timestamp"].as_u64().unwrap()),
            starknet_version: StarknetVersion::V0_14_2, sequencer_address: Felt::from(0x123u32).try_into().unwrap(),
            gas_prices: GasPrices::default(), use_kzg_da: true,
        },
        ChainInfo { chain_id: ChainId::Other("COMMITTED_DATA_COST".into()), fee_token_addresses: FeeTokenAddresses { strk_fee_token_address: fee_token, eth_fee_token_address: fee_token }, ..Default::default() },
        VersionedConstants::get(&StarknetVersion::V0_14_2).unwrap().clone(),
        serde_json::from_value(json!({"block_max_capacity":{"sierra_gas":6000000000u64,"message_segment_length":3700,"n_events":5000,"state_diff_size":22000,"l1_gas":2500000,"n_txs":500,"proving_gas":6000000000u64,"receipt_l2_gas":10800000000u64},"builtin_weights":{"gas_costs":read(root.join("resource-costs.json"))["proving_builtin_costs"]}})).unwrap(),
    );
    context.use_committed_data = true;
    context.committed_data_witnesses =
        Arc::new(CommittedDataWitnesses::new(witnesses.clone()).unwrap());
    let pair = std::env::var_os("CD_SHARING_PAIR").is_some();
    let steps = if pair {
        vec![data.clone(), read(root.join(format!("fixtures/{}.json", block + 1)))]
    } else {
        vec![data.clone()]
    };
    let mut transactions = Vec::new();
    for snapshot in &steps {
        let calldata: Vec<Felt> = snapshot["step"]["trace"]["execute_invocation"]["calldata"]
            .as_array()
            .unwrap()
            .iter()
            .map(felt)
            .collect();
        let bound = |amount| ResourceBounds {
            max_amount: GasAmount(amount),
            max_price_per_unit: GasPrice(2),
        };
        let nonce = snapshot["nonces"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| address(&row[0]) == sender)
            .unwrap();
        let mut args = invoke_tx_args! {
            sender_address: sender, nonce: Nonce(felt(&nonce[1])), calldata: Calldata(Arc::new(calldata)),
            resource_bounds: ValidResourceBounds::AllResources(AllResourceBounds { l1_gas: bound(100000), l1_data_gas: bound(1000000), l2_gas: bound(7000000000) }),
        };
        let tx = InvokeTransaction::create(invoke_tx(args.clone()), &context.chain_info().chain_id)
            .unwrap();
        let signature = starknet_core::crypto::ecdsa_sign(&Felt::ONE, &tx.tx_hash.0).unwrap();
        args.signature = TransactionSignature(Arc::new(vec![signature.r, signature.s]));
        let tx =
            InvokeTransaction::create(invoke_tx(args), &context.chain_info().chain_id).unwrap();
        transactions.push(BlockifierTransaction::new_for_sequencing(
            ExecutableTransaction::Account(AccountTransaction::Invoke(tx)),
        ));
    }
    let block_context = BlockContext::from_base_context(&context, 0, true);
    let mut executor = TransactionExecutor::pre_process_and_create(
        state.clone(),
        block_context,
        crate::utils::maybe_dummy_block_hash_and_number(BlockNumber(block))
            .map(|(number, hash)| starknet_api::block::BlockHashAndNumber { number, hash }),
        TransactionExecutorConfig::default(),
    )
    .unwrap();
    let mut infos = Vec::new();
    let mut measured_storage = std::collections::HashMap::new();
    let mut flows = Vec::new();
    for (tx, snapshot) in transactions.into_iter().zip(&steps) {
        let (info, writes) = executor.execute(&tx).unwrap();
        measured_storage.extend(writes.storage);
        let boundary = data["positions_per_side"].as_u64().is_some_and(|n| n >= 400);
        assert!(info.revert_error.is_none(), "full trade must succeed: {:?}", info.revert_error);
        let events = info.accumulated_sorted_events();
        let business_events: Vec<_> =
            events.iter().filter(|event| event.from_address != fee_token).collect();
        let expected_events: Vec<_> = snapshot["step"]["receipt"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|event| address(&event["from_address"]) != fee_token)
            .collect();
        if !boundary {
            assert_eq!(business_events.len(), expected_events.len());
            for (actual, expected) in business_events.into_iter().zip(expected_events) {
                assert_eq!(actual.from_address, address(&expected["from_address"]));
                assert_eq!(
                    actual.content.keys.iter().map(|key| key.0).collect::<Vec<_>>(),
                    expected["keys"].as_array().unwrap().iter().map(felt).collect::<Vec<_>>()
                );
                assert_eq!(
                    actual.content.data.0,
                    expected["data"].as_array().unwrap().iter().map(felt).collect::<Vec<_>>()
                );
            }
        } else if info.revert_error.is_none() {
            use starknet_api::abi::abi_utils::selector_from_name;
            let traded = selector_from_name("TradeSettled").0;
            assert_eq!(
                business_events
                    .iter()
                    .filter(|e| e.content.keys.iter().any(|k| k.0 == traded))
                    .count(),
                1,
                "400-position trade did not settle"
            );
            assert!(!business_events.iter().any(|e| e.content.keys.iter().any(|k| {
                ["SettleTradeFailedV3", "BlockTradeFailed"]
                    .iter()
                    .any(|s| k.0 == selector_from_name(s).0)
            })));
        }
        let expected_revert_reason = info.revert_error.as_ref().map(ToString::to_string);
        let event_expectations = events
            .into_iter()
            .map(|expected| EventPredicateExpectation {
                description: "same independently executed event".into(),
                predicate: Box::new(move |actual| actual == &expected),
            })
            .collect();
        flows.push(FlowTestTx { tx, expected_revert_reason, event_expectations });
        infos.push(info);
    }
    let reservation = executor.finalize().unwrap().bouncer_weights;
    if let Ok(path) = std::env::var("CD_RECEIPT_ONLY") {
        let receipt = json!({"transactions":infos.iter().map(|i|json!({"revert_error":i.revert_error.as_ref().map(ToString::to_string),"sierra_gas":i.receipt.resources.computation.sierra_gas.0,"reverted_sierra_gas":i.receipt.resources.computation.reverted_sierra_gas.0,"total_sierra_gas":i.receipt.resources.computation.sierra_gas.0+i.receipt.resources.computation.reverted_sierra_gas.0,"receipt_gas":i.receipt.gas})).collect::<Vec<_>>()});
        std::fs::write(path, serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();
        return;
    }
    let mut builder = TestBuilder::new_with_initial_state_data(
        InitialStateData {
            initial_state: InitialState {
                updatable_state: state,
                commitment_storage,
                contracts_trie_root_hash: roots.contracts_trie_root_hash,
                classes_trie_root_hash: roots.classes_trie_root_hash,
                block_context: context,
            },
            nonce_manager: NonceManager::default(),
            execution_contracts: contracts,
        },
        TestBuilderConfig { use_kzg_da: true, full_output: true, private_keys: None },
        false,
    );
    builder.os_hints_config.use_committed_data = true;
    builder.os_hints_config.committed_data_witnesses = witnesses.clone();
    builder.last_block_txs_mut().extend(flows);
    eprintln!("Building full OS input");
    let runner = builder.build().await;
    eprintln!("Executing full SNOS");
    let output = runner.run();
    output.perform_default_validations();
    let pie = &output.runner_output.cairo_pie;
    pie.run_validity_checks().unwrap();
    let folder = root.join("evidence").join(&variant);
    std::fs::create_dir_all(&folder).unwrap();
    pie.write_zip_file(&folder.join(format!("{block}.zip")), true).unwrap();
    let costs =
        VersionedConstants::get(&StarknetVersion::V0_14_2).unwrap().os_constants.gas_costs.clone();
    let weights: blockifier::bouncer::BuiltinWeights = serde_json::from_value(
        json!({"gas_costs":read(root.join("resource-costs.json"))["proving_builtin_costs"]}),
    )
    .unwrap();
    let mut charged = pie.execution_resources.clone();
    charged.builtin_instance_counter.remove(&BuiltinName::output);
    let proving = blockifier::utils::get_gas_cost_from_vm_resources(
        &charged,
        &costs.base,
        &weights.gas_costs,
    );
    let sierra =
        blockifier::utils::get_gas_cost_from_vm_resources(&charged, &costs.base, &costs.builtins);
    assert!(
        proving <= reservation.proving_gas.0,
        "proving underreserved: {proving} > {:?}",
        reservation
    );
    assert!(
        sierra <= reservation.sierra_gas.0,
        "Sierra underreserved: {sierra} > {:?}",
        reservation
    );
    // Inspect the special-call work itself as well as the whole-block reservation. The logger
    // cannot attribute holes per call; whole-block checks above include every PIE memory hole.
    let mut call_profiles = Vec::new();
    if step["label"].as_str().unwrap().contains("committed")
        && step["label"].as_str().unwrap().contains("trade")
    {
        fn collect<'a>(value: &'a Value, out: &mut Vec<&'a Value>) {
            match value {
                Value::Array(values) => {
                    for value in values {
                        collect(value, out);
                    }
                }
                Value::Object(object) => {
                    if object.get("committed_request").is_some_and(|request| !request.is_null()) {
                        out.push(value);
                    }
                    for value in object.values() {
                        collect(value, out);
                    }
                }
                _ => {}
            }
        }
        let trace = serde_json::to_value(&output.runner_output.txs_trace).unwrap();
        let mut calls = Vec::new();
        collect(&trace, &mut calls);
        if infos.iter().any(|i| i.revert_error.is_none()) {
            assert!(!calls.is_empty(), "successful full trade must exercise committed reads");
        }
        let witnesses = CommittedDataWitnesses::new(witnesses).unwrap();
        use blockifier::execution::syscalls::committed_data::{
            CommittedDataReadSet,
            read_values_shared,
        };
        let read_set = CommittedDataReadSet::default();
        let mut actual = cairo_vm::vm::runners::cairo_runner::ExecutionResources::default();
        let mut reserved = actual.clone();
        for call in calls {
            let (root, keys): (Felt, Vec<Felt>) =
                serde_json::from_value(call["committed_request"].clone()).unwrap();
            let mut calldata = vec![root, Felt::from(keys.len())];
            calldata.extend_from_slice(&keys);
            let (_, extra) = read_values_shared(
                true,
                &witnesses,
                &read_set,
                selector_from_name("get_values").0,
                &calldata,
                &mut u64::MAX,
                &mut None,
            )
            .unwrap();
            let used: cairo_vm::vm::runners::cairo_runner::ExecutionResources =
                serde_json::from_value(call["resources"].clone()).unwrap();
            let paid = &blockifier::test_utils::get_const_syscall_resources(
                blockifier::execution::syscalls::vm_syscall_utils::SyscallSelector::CallContract,
            ) + &extra;
            actual += &used;
            reserved += &paid;
            call_profiles.push(json!({"root":root,"keys":keys,"actual":used,"reserved":paid}));
        }
        for finalization in &output.runner_output.committed_data_finalizations {
            actual += finalization;
        }
        // This deliberately overattributes holes; the whole-block check above also includes them.
        actual.n_memory_holes = pie.execution_resources.n_memory_holes;
        for builtin_costs in [&costs.builtins, &weights.gas_costs] {
            let used = blockifier::utils::get_gas_cost_from_vm_resources(
                &actual,
                &costs.base,
                builtin_costs,
            );
            let paid = blockifier::utils::get_gas_cost_from_vm_resources(
                &reserved,
                &costs.base,
                builtin_costs,
            );
            assert!(
                used <= paid,
                "shared verification undercharged: {used} > {paid}; actual={actual:?}; \
                 reserved={reserved:?}"
            );
        }
    }
    let info = &infos[0];
    let result = json!({"storage_updates":measured_storage.iter().map(|((a,k),v)|json!([a.0.key(),k.0.key(),v])).collect::<Vec<_>>(),"transactions":infos.iter().map(|i|json!({"revert_error":i.revert_error.as_ref().map(ToString::to_string),"sierra_gas":i.receipt.resources.computation.sierra_gas.0,"reverted_sierra_gas":i.receipt.resources.computation.reverted_sierra_gas.0,"total_sierra_gas":i.receipt.resources.computation.sierra_gas.0+i.receipt.resources.computation.reverted_sierra_gas.0,"receipt_gas":i.receipt.gas})).collect::<Vec<_>>(),"label":step["label"],"block":block,"implementation":variant,"sierra_gas":info.receipt.resources.computation.sierra_gas.0,"receipt_gas":info.receipt.gas,"reservation":reservation,"actual_proving_gas":proving,"actual_sierra_resources":sierra,"snos_resources":pie.execution_resources,"call_profiles":call_profiles,"finalization_profiles":output.runner_output.committed_data_finalizations});
    std::fs::write(
        folder.join(format!("{block}.json")),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
    eprintln!("SHARED_TRADE_RESULT {result}");
}
