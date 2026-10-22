//! Manual paired benchmark using the complete archived trading state, not a price-read surrogate.
//! Included temporarily as a child of the flow-test manager; never enabled in ordinary CI.
use super::*;
use crate::initial_state::{commit_initial_state_diff, InitialState, InitialStateData};
use blockifier::blockifier::{config::TransactionExecutorConfig, transaction_executor::TransactionExecutor};
use blockifier::execution::contract_class::RunnableCompiledClass;
use blockifier::execution::syscalls::committed_data::{CommittedDataWitness, CommittedDataWitnesses};
use cairo_lang_starknet_classes::casm_contract_class::CasmContractClass;
use starknet_api::block::{BlockTimestamp, GasPrices, GasPrice, StarknetVersion};
use starknet_api::transaction::fields::{AllResourceBounds, ResourceBounds, TransactionSignature, ValidResourceBounds};
use starknet_api::versioned_constants_logic::VersionedConstantsTrait;
use serde_json::{json, Value};
use starknet_api::execution_resources::GasAmount;
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn felt(value: &Value) -> Felt { Felt::from_hex(value.as_str().unwrap()).unwrap() }
fn address(value: &Value) -> ContractAddress { felt(value).try_into().unwrap() }
fn read(path: impl AsRef<Path>) -> Value { serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap() }

#[tokio::test]
async fn paired_full_trade_snapshot() {
    let root = PathBuf::from(std::env::var("CD_SHARING_HARNESS").unwrap());
    let variant = std::env::var("CD_SHARING_VARIANT").unwrap();
    let block: u64 = std::env::var("CD_SHARING_BLOCK").unwrap().parse().unwrap();
    let data = read(root.join(format!("fixtures/{block}.json")));
    let step = &data["step"];
    let sender = address(&data["account"]);
    let fee_token = address(&data["fee_token"]);
    let mut state = DictStateReader::default();
    let mut maps = StateMaps::default();
    for row in data["storage"].as_array().unwrap() {
        maps.storage.insert((address(&row[0]), felt(&row[1]).try_into().unwrap()), felt(&row[2]));
    }
    // Both arms use exactly the same test signing key, account code and original caller address.
    // Application state, contracts, calldata and timestamps are preserved from the audited run.
    maps.storage.insert((sender, felt(&data["signer_storage_key"]).try_into().unwrap()), starknet_crypto::get_public_key(&Felt::ONE));
    for row in data["nonces"].as_array().unwrap() { maps.nonces.insert(address(&row[0]), Nonce(felt(&row[1]))); }
    for row in data["deployed"].as_array().unwrap() { maps.class_hashes.insert(address(&row[0]), ClassHash(felt(&row[1]))); }
    for row in data["declared"].as_array().unwrap() { maps.compiled_class_hashes.insert(ClassHash(felt(&row[0])), starknet_api::core::CompiledClassHash(felt(&row[1]))); }
    let mut contracts = OsExecutionContracts::default();
    let mut runnable = HashMap::new();
    for class in data["classes"].as_array().unwrap() {
        let source = read(class["sierra"].as_str().unwrap());
        let sierra: SierraContractClass = serde_json::from_value(source).unwrap();
        let hash = sierra.calculate_class_hash();
        assert_eq!(hash.0, felt(&class["class_hash"]));
        let casm: CasmContractClass = serde_json::from_value(read(class["casm"].as_str().unwrap())).unwrap();
        let compiled = casm.hash(&HashVersion::V2);
        if let Some(expected) = maps.compiled_class_hashes.get(&hash) { assert_eq!(*expected, compiled); }
        let run = RunnableCompiledClass::try_from(ContractClass::V1((casm.clone(), sierra.get_sierra_version().unwrap()))).unwrap();
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
        use starknet_patricia_storage::{map_storage::MapStorage, storage_trait::{DbKey, DbValue}};
        let roots: StateRoots = serde_json::from_value(read(&roots_path)).unwrap();
        let mut bytes = std::io::Cursor::new(std::fs::read(&cache).unwrap());
        let mut facts = HashMap::new();
        while bytes.position() < bytes.get_ref().len() as u64 {
            let mut length = [0u8; 4]; bytes.read_exact(&mut length).unwrap();
            let mut key = vec![0; u32::from_le_bytes(length) as usize]; bytes.read_exact(&mut key).unwrap();
            bytes.read_exact(&mut length).unwrap();
            let mut value = vec![0; u32::from_le_bytes(length) as usize]; bytes.read_exact(&mut value).unwrap();
            facts.insert(DbKey(key), DbValue(value));
        }
        (roots, MapStorage(facts))
    } else {
        use std::io::Write;
        let (roots, storage) = commit_initial_state_diff(state_maps_to_committer_state_diff(maps.clone())).await;
        let mut bytes = Vec::new();
        for (key, value) in &storage.0 {
            bytes.write_all(&(key.0.len() as u32).to_le_bytes()).unwrap(); bytes.write_all(&key.0).unwrap();
            bytes.write_all(&(value.0.len() as u32).to_le_bytes()).unwrap(); bytes.write_all(&value.0).unwrap();
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
        if path.file_name().unwrap().to_string_lossy().starts_with("._") { continue; }
        witnesses.push(serde_json::from_value(read(path)).unwrap());
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
    context.committed_data_witnesses = Arc::new(CommittedDataWitnesses::new(witnesses.clone()).unwrap());
    let pair = std::env::var_os("CD_SHARING_PAIR").is_some();
    let steps = if pair { vec![data.clone(), read(root.join(format!("fixtures/{}.json", block + 1)))] } else { vec![data.clone()] };
    let mut transactions = Vec::new();
    for snapshot in &steps {
        let calldata: Vec<Felt> = snapshot["step"]["trace"]["execute_invocation"]["calldata"].as_array().unwrap().iter().map(felt).collect();
        let bound = |amount| ResourceBounds { max_amount: GasAmount(amount), max_price_per_unit: GasPrice(2) };
        let nonce = snapshot["nonces"].as_array().unwrap().iter().find(|row| address(&row[0])==sender).unwrap();
        let mut args = invoke_tx_args! {
            sender_address: sender, nonce: Nonce(felt(&nonce[1])), calldata: Calldata(Arc::new(calldata)),
            resource_bounds: ValidResourceBounds::AllResources(AllResourceBounds { l1_gas: bound(100000), l1_data_gas: bound(1000000), l2_gas: bound(7000000000) }),
        };
        let tx = InvokeTransaction::create(invoke_tx(args.clone()), &context.chain_info().chain_id).unwrap();
        let signature = starknet_core::crypto::ecdsa_sign(&Felt::ONE, &tx.tx_hash.0).unwrap();
        args.signature = TransactionSignature(Arc::new(vec![signature.r, signature.s]));
        let tx = InvokeTransaction::create(invoke_tx(args), &context.chain_info().chain_id).unwrap();
        transactions.push(BlockifierTransaction::new_for_sequencing(ExecutableTransaction::Account(AccountTransaction::Invoke(tx))));
    }
    let block_context = BlockContext::from_base_context(&context, 0, true);
    let mut executor = TransactionExecutor::pre_process_and_create(state.clone(), block_context, crate::utils::maybe_dummy_block_hash_and_number(BlockNumber(block)).map(|(number, hash)| starknet_api::block::BlockHashAndNumber { number, hash }), TransactionExecutorConfig::default()).unwrap();
    let mut infos = Vec::new();
    let mut flows = Vec::new();
    for (tx, snapshot) in transactions.into_iter().zip(&steps) {
        let (info, _) = executor.execute(&tx).unwrap();
        assert!(info.revert_error.is_none(), "{:?}", info.revert_error);
        let events = info.accumulated_sorted_events();
        let business_events: Vec<_> = events.iter().filter(|event| event.from_address != fee_token).collect();
        let expected_events: Vec<_> = snapshot["step"]["receipt"]["events"].as_array().unwrap().iter().filter(|event| address(&event["from_address"]) != fee_token).collect();
        assert_eq!(business_events.len(), expected_events.len());
        for (actual, expected) in business_events.into_iter().zip(expected_events) {
            assert_eq!(actual.from_address, address(&expected["from_address"]));
            assert_eq!(actual.content.keys.iter().map(|key| key.0).collect::<Vec<_>>(), expected["keys"].as_array().unwrap().iter().map(felt).collect::<Vec<_>>());
            assert_eq!(actual.content.data.0, expected["data"].as_array().unwrap().iter().map(felt).collect::<Vec<_>>());
        }
        let event_expectations = events.into_iter().map(|expected| EventPredicateExpectation { description: "same independently executed event".into(), predicate: Box::new(move |actual| actual == &expected) }).collect();
        flows.push(FlowTestTx { tx, expected_revert_reason: None, event_expectations });
        infos.push(info);
    }
    let reservation = executor.finalize().unwrap().bouncer_weights;
    let mut builder = TestBuilder::new_with_initial_state_data(InitialStateData {
        initial_state: InitialState { updatable_state: state, commitment_storage, contracts_trie_root_hash: roots.contracts_trie_root_hash, classes_trie_root_hash: roots.classes_trie_root_hash, block_context: context },
        nonce_manager: NonceManager::default(), execution_contracts: contracts,
    }, TestBuilderConfig { use_kzg_da: true, full_output: true, private_keys: None }, false);
    builder.os_hints_config.use_committed_data = true;
    builder.os_hints_config.committed_data_witnesses = witnesses;
    builder.last_block_txs_mut().extend(flows);
    eprintln!("Building full OS input");
    let runner = builder.build().await;
    eprintln!("Executing full SNOS");
    let output = runner.run();
    output.perform_default_validations();
    let pie = &output.runner_output.cairo_pie;
    pie.run_validity_checks().unwrap();
    let folder = root.join("evidence").join(&variant); std::fs::create_dir_all(&folder).unwrap();
    pie.write_zip_file(&folder.join(format!("{block}.zip")), true).unwrap();
    let costs = VersionedConstants::get(&StarknetVersion::V0_14_2).unwrap().os_constants.gas_costs.clone();
    let weights: blockifier::bouncer::BuiltinWeights = serde_json::from_value(json!({"gas_costs":read(root.join("resource-costs.json"))["proving_builtin_costs"]})).unwrap();
    let mut charged = pie.execution_resources.clone();
    charged.builtin_instance_counter.remove(&BuiltinName::output);
    let proving = blockifier::utils::get_gas_cost_from_vm_resources(&charged, &costs.base, &weights.gas_costs);
    let sierra = blockifier::utils::get_gas_cost_from_vm_resources(&charged, &costs.base, &costs.builtins);
    assert!(proving <= reservation.proving_gas.0, "proving underreserved: {proving} > {:?}", reservation);
    assert!(sierra <= reservation.sierra_gas.0, "Sierra underreserved: {sierra} > {:?}", reservation);
    // Inspect the special-call work itself as well as the whole-block reservation. The logger
    // cannot attribute holes per call; whole-block checks above include every PIE memory hole.
    let mut call_profiles = Vec::new();
    if false && step["label"].as_str().unwrap().contains("committed") && step["label"].as_str().unwrap().contains("trade") {
        fn collect<'a>(value: &'a Value, out: &mut Vec<&'a Value>) {
            match value {
                Value::Array(values) => for value in values { collect(value,out); },
                Value::Object(object) => {
                    if object.get("selector").and_then(Value::as_str)==Some("CallContract")
                        && object.get("inner_syscalls").and_then(Value::as_array).is_some_and(Vec::is_empty)
                        && object.get("resources").and_then(|r|r.pointer("/builtin_instance_counter/poseidon_builtin")).and_then(Value::as_u64).is_some_and(|n|n>0) {
                            out.push(&object["resources"]);
                        }
                    for value in object.values(){ collect(value,out); }
                }, _ => {}
            }
        }
        let trace=serde_json::to_value(&output.runner_output.txs_trace).unwrap();
        let mut calls=Vec::new();collect(&trace,&mut calls);
        let batches=read(root.join("evidence/shared-trade-batches-release.json"));
        let batches:Vec<_>=batches.as_array().unwrap().iter().filter(|c|c["block"]==block).collect();
        assert_eq!(calls.len(),batches.len());
        for (call,batch) in calls.into_iter().zip(batches) {
            let n=batch["keys"].as_array().unwrap().len();let u=batch["unique_leaves"].as_u64().unwrap() as usize;let b=batch["new_branches"].as_u64().unwrap() as usize;
            let used:cairo_vm::vm::runners::cairo_runner::ExecutionResources=serde_json::from_value(call.clone()).unwrap();
            let reserved = &blockifier::test_utils::get_const_syscall_resources(blockifier::execution::syscalls::vm_syscall_utils::SyscallSelector::CallContract)
                + &blockifier::execution::syscalls::committed_data::batch_os_resources(n, u, b);
            assert_eq!(used.builtin_instance_counter[&BuiltinName::poseidon],reserved.builtin_instance_counter[&BuiltinName::poseidon]);
            assert!(used.n_steps<=reserved.n_steps);
            for (name,count) in &used.builtin_instance_counter {assert!(*count<=reserved.builtin_instance_counter.get(name).copied().unwrap_or(0));}
            let sierra_used=blockifier::utils::get_gas_cost_from_vm_resources(&used,&costs.base,&costs.builtins);
            let sierra_bound=blockifier::utils::get_gas_cost_from_vm_resources(&reserved,&costs.base,&costs.builtins);
            let proving_used=blockifier::utils::get_gas_cost_from_vm_resources(&used,&costs.base,&weights.gas_costs);
            let proving_bound=blockifier::utils::get_gas_cost_from_vm_resources(&reserved,&costs.base,&weights.gas_costs);
            call_profiles.push(json!({"outputs":n,"unique":u,"branches":b,"actual":used,"reserved":reserved,"sierra_used":sierra_used,"sierra_bound":sierra_bound,"proving_used":proving_used,"proving_bound":proving_bound}));
        }

    }
    let info = &infos[0];
    let result = json!({"transactions":infos.iter().map(|i|json!({"sierra_gas":i.receipt.resources.computation.sierra_gas.0,"receipt_gas":i.receipt.gas})).collect::<Vec<_>>(),"label":step["label"],"block":block,"implementation":variant,"sierra_gas":info.receipt.resources.computation.sierra_gas.0,"receipt_gas":info.receipt.gas,"reservation":reservation,"actual_proving_gas":proving,"actual_sierra_resources":sierra,"snos_resources":pie.execution_resources,"call_profiles":call_profiles});
    std::fs::write(folder.join(format!("{block}.json")), serde_json::to_vec_pretty(&result).unwrap()).unwrap();
    eprintln!("SHARED_TRADE_RESULT {result}");
}
