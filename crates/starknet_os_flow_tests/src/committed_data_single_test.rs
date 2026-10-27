//! Exercise the Cairo entrypoint directly: Rust validation must not hide unconstrained hints.
use std::collections::HashMap;

use apollo_starknet_os_program::OS_PROGRAM_BYTES;
use blockifier::execution::syscalls::committed_data::{
    read_gas,
    CommittedDataSet,
    CommittedDataSibling,
    CommittedDataWitness,
};
use blockifier::execution::syscalls::hint_processor::OUT_OF_GAS_ERROR_FELT;
use blockifier::test_utils::dict_state_reader::DictStateReader;
use cairo_vm::types::builtin_name::BuiltinName;
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::types::relocatable::MaybeRelocatable;
use cairo_vm::vm::runners::cairo_runner::CairoArg;
use starknet_os::hint_processor::snos_hint_processor::SnosHintProcessor;
use starknet_os::io::os_input::OsHintsConfig;
use starknet_os::test_utils::cairo_runner::{
    initialize_cairo_runner,
    EntryPointRunnerConfig,
    ImplicitArg,
    EMPTY_BLOCK_INPUT,
};
use starknet_types_core::felt::Felt;

fn read_one(
    witness: CommittedDataWitness,
    gas: u64,
) -> Result<Vec<MaybeRelocatable>, Box<dyn std::error::Error>> {
    let entrypoint = "starkware.starknet.core.os.execution.committed_data.committed_data_read_one";
    let builtins = [BuiltinName::range_check, BuiltinName::poseidon];
    let (mut runner, program, _) = initialize_cairo_runner(
        &EntryPointRunnerConfig {
            layout: LayoutName::all_cairo,
            add_main_prefix_to_entrypoint: false,
            ..Default::default()
        },
        OS_PROGRAM_BYTES,
        entrypoint,
        &builtins.map(ImplicitArg::Builtin),
        HashMap::new(),
    )?;
    let mut args: Vec<_> = runner
        .vm
        .get_builtin_runners()
        .iter()
        .map(|builtin| CairoArg::Single(builtin.initial_stack()[0].clone()))
        .collect();
    args.extend([witness.root, witness.key, Felt::from(gas)].map(|x| CairoArg::Single(x.into())));
    let mut hints = SnosHintProcessor::<DictStateReader>::new_for_testing(
        None,
        &program,
        Some(OsHintsConfig {
            use_committed_data: true,
            committed_data_witnesses: vec![witness],
            ..Default::default()
        }),
        &EMPTY_BLOCK_INPUT,
    )?;
    runner.run_from_entrypoint(
        program.get_identifier(entrypoint).unwrap().pc.unwrap(),
        &args.iter().collect::<Vec<_>>(),
        true,
        None,
        &mut hints,
    )?;
    Ok(runner.vm.get_return_values(3)?)
}

#[test]
fn single_read_authenticates_height_before_selecting_out_of_gas() {
    let tree = CommittedDataSet::new(vec![(Felt::ZERO, Felt::ONE)]).unwrap();
    let witness = tree.witness(Felt::ZERO).unwrap();
    let gas = 100_000;
    assert_eq!(
        read_one(witness.clone(), gas).unwrap(),
        [Felt::ONE, Felt::from(gas - read_gas(0)), Felt::ZERO].map(MaybeRelocatable::from)
    );
    assert_eq!(
        read_one(witness.clone(), 0).unwrap(),
        [Felt::ZERO, Felt::ZERO, OUT_OF_GAS_ERROR_FELT].map(MaybeRelocatable::from)
    );
    let forged = CommittedDataWitness {
        siblings: (0..252_u8).map(|bit| CommittedDataSibling { bit, hash: Felt::ZERO }).collect(),
        ..witness
    };
    assert!(!forged.verify());
    assert!(read_one(forged, gas).is_err());
}
