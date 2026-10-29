//! Run the Cairo verifier directly so malformed hints cannot be rejected only by the Rust builder.
use std::collections::HashMap;

use apollo_starknet_os_program::test_programs::COMMITTED_DATA_TEST_BYTES;
use blockifier::execution::syscalls::committed_data::{
    branch,
    leaf,
    CommittedDataBatchProof,
    CommittedDataSet,
    CommittedDataSibling,
    CommittedDataWitness,
};
use blockifier::test_utils::dict_state_reader::DictStateReader;
use cairo_vm::types::builtin_name::BuiltinName;
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::vm::runners::cairo_runner::CairoArg;
use starknet_os::hint_processor::snos_hint_processor::SnosHintProcessor;
use starknet_os::test_utils::cairo_runner::{
    initialize_cairo_runner,
    EntryPointRunnerConfig,
    ImplicitArg,
    EMPTY_BLOCK_INPUT,
};
use starknet_types_core::felt::Felt;

fn verify(
    root: Felt,
    keys: &[Felt],
    proof: &CommittedDataBatchProof,
) -> Result<(), Box<dyn std::error::Error>> {
    let entrypoint =
        "starkware.starknet.core.os.execution.committed_data.verify_committed_data_batch";
    let (mut runner, program, _) = initialize_cairo_runner(
        &EntryPointRunnerConfig {
            layout: LayoutName::all_cairo,
            add_main_prefix_to_entrypoint: false,
            ..Default::default()
        },
        COMMITTED_DATA_TEST_BYTES,
        entrypoint,
        &[
            ImplicitArg::Builtin(BuiltinName::range_check),
            ImplicitArg::Builtin(BuiltinName::bitwise),
            ImplicitArg::Builtin(BuiltinName::poseidon),
        ],
        HashMap::new(),
    )?;
    // The program's builtin order is canonical; the function takes poseidon before bitwise.
    let mut args: Vec<_> = [BuiltinName::range_check, BuiltinName::poseidon, BuiltinName::bitwise]
        .into_iter()
        .map(|name| {
            CairoArg::Single(
                runner
                    .vm
                    .get_builtin_runners()
                    .iter()
                    .find(|b| b.name() == name)
                    .unwrap()
                    .initial_stack()[0]
                    .clone(),
            )
        })
        .collect();
    let array = |values: Vec<Felt>| CairoArg::Array(values.into_iter().map(Into::into).collect());
    let values =
        keys.iter().enumerate().map(|(i, _)| proof.leaves[2 * proof.indices[i] + 1]).collect();
    args.extend([
        CairoArg::Single(root.into()),
        array(keys.to_vec()),
        CairoArg::Single(Felt::from(keys.len()).into()),
        array(proof.proof.clone()),
        array(proof.leaves.clone()),
        array(proof.indices.iter().copied().map(Felt::from).collect()),
        CairoArg::Single(Felt::from(proof.branches).into()),
        CairoArg::Single(Felt::from(proof.unique_leaves()).into()),
        array(values),
    ]);
    let mut hints = SnosHintProcessor::<DictStateReader>::new_for_testing(
        None,
        &program,
        None,
        &EMPTY_BLOCK_INPUT,
    )?;
    runner.run_from_entrypoint(
        program.get_identifier(entrypoint).unwrap().pc.unwrap(),
        &args.iter().collect::<Vec<_>>(),
        true,
        None,
        &mut hints,
    )?;
    Ok(())
}

#[test]
fn batch_verifier_accepts_repeated_hashes_as_opaque_siblings() {
    let mut root = leaf(Felt::ZERO, Felt::ONE);
    let mut siblings = Vec::new();
    for bit in 0..252_u8 {
        siblings.push(CommittedDataSibling { bit, hash: root });
        root = branch(bit, root, root);
    }
    let witness = CommittedDataWitness { root, key: Felt::ZERO, value: Felt::ONE, siblings };
    let keys = [Felt::ZERO];
    let proof = CommittedDataBatchProof::new(root, &keys, |_| Ok(Some(witness.clone()))).unwrap();
    assert_eq!(proof.branches, 252);
    verify(root, &keys, &proof).unwrap();
}

#[test]
fn batch_verifier_authenticates_values_order_and_exact_work_counts() {
    let tree = CommittedDataSet::new(vec![
        (Felt::ZERO, Felt::MAX),
        (Felt::ONE, Felt::ZERO),
        (Felt::MAX, Felt::TWO),
    ])
    .unwrap();
    let keys = [Felt::MAX, Felt::ZERO, Felt::MAX, Felt::ONE];
    let fresh = || CommittedDataBatchProof::from_dataset(&tree, &keys).unwrap();
    verify(tree.root(), &keys, &fresh()).unwrap();
    let mut proof = fresh();
    proof.leaves[1] += Felt::ONE;
    assert!(verify(tree.root(), &keys, &proof).is_err());
    let mut proof = fresh();
    proof.indices.swap(0, 1);
    assert!(verify(tree.root(), &keys, &proof).is_err());
    for delta in [-1_i32, 1] {
        let mut proof = fresh();
        proof.branches = (proof.branches as i32 + delta) as usize;
        assert!(verify(tree.root(), &keys, &proof).is_err());
    }
    let mut proof = fresh();
    proof.leaves.extend([Felt::TWO, Felt::ONE]);
    assert!(verify(tree.root(), &keys, &proof).is_err());
}

#[test]
fn batch_verifier_rejects_wrong_routing_even_when_the_hash_matches() {
    // The claimed root really hashes these leaves, but its left leaf has bit zero set.
    // Root equality alone would incorrectly accept this malformed trie.
    let left = leaf(Felt::ONE, Felt::from(10));
    let right = leaf(Felt::ZERO, Felt::from(20));
    let root = branch(0, left, right);
    let proof = CommittedDataBatchProof {
        branch_hashes: Vec::new(),
        proof: vec![Felt::TWO, Felt::ZERO, Felt::ONE, Felt::ZERO, Felt::ZERO, right],
        leaves: vec![Felt::ONE, Felt::from(10)],
        indices: vec![0],
        branches: 1,
    };
    assert!(verify(root, &[Felt::ONE], &proof).is_err());
}

#[test]
fn batch_verifier_cannot_inflate_work_by_expanding_an_unrequested_subtree() {
    let entries: Vec<_> = (0..4).map(|i| (Felt::from(i), Felt::from(i + 10))).collect();
    let tree = CommittedDataSet::new(entries.clone()).unwrap();
    let keys = [Felt::ZERO];
    verify(tree.root(), &keys, &CommittedDataBatchProof::from_dataset(&tree, &keys).unwrap())
        .unwrap();
    // All hashes and keys are correct. Only the right subtree was unnecessarily expanded.
    let proof = CommittedDataBatchProof {
        branch_hashes: Vec::new(),
        proof: vec![
            Felt::TWO,
            Felt::ONE,
            Felt::TWO,
            Felt::ZERO,
            Felt::ONE,
            Felt::ZERO,
            Felt::ZERO,
            leaf(entries[1].0, entries[1].1),
            Felt::TWO,
            Felt::ZERO,
            Felt::ZERO,
            leaf(entries[2].0, entries[2].1),
            Felt::ZERO,
            leaf(entries[3].0, entries[3].1),
        ],
        leaves: vec![entries[0].0, entries[0].1],
        indices: vec![0],
        branches: 3,
    };
    assert!(verify(tree.root(), &keys, &proof).is_err());
}
