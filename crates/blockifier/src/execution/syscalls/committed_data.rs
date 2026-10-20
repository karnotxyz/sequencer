//! Authenticated reads from immutable, application-owned datasets.
//!
//! The application supplies a root read from its own authenticated storage. Values and paths
//! are private execution input; the Cairo OS independently proves membership and the response.
//! Any contract may read a dataset by root and key. Roots and witnesses are independent of
//! the caller; applications enforce root authorization and freshness in their own contracts.
//! `use_committed_data` is execution permission, not a consensus activation policy. When false,
//! reads reject the account transaction or proof instead of producing a provable revert. The
//! address is always reserved and the permission does not affect the OS configuration hash.
//!
//! Supported usage is through account transactions. L1 handlers do not check the sticky
//! committed-data failure and can record disabled or missing data as a transaction revert.
//! Committed-data reads, including reads through adapters, must therefore stay out of L1-handler
//! execution. This limitation concerns reading the dataset, not publishing its root to storage.
use std::collections::HashMap;
use std::sync::Arc;

use starknet_api::abi::abi_utils::selector_from_name;
use starknet_types_core::felt::Felt;

use super::hint_processor::{INVALID_ARGUMENT_FELT, OUT_OF_GAS_ERROR_FELT};
use super::vm_syscall_utils::SyscallExecutorBaseError;

/// `starknet_keccak("committed_data_v1")`. Permanently reserved by this OS version.
pub const COMMITTED_DATA_ADDRESS: Felt =
    Felt::from_hex_unchecked("0x6c5f4559c7041984537bc078c71443fdc58b2e1bab302b341ec12b3d2cec44");
mod mpt;
pub use mpt::*;
/// Bound on distinct witnesses supplied to one replay request.
pub const MAX_COMMITTED_DATA_WITNESSES: usize = 65_536;
// Conservative bounds include full-key bit extraction and two Poseidon permutations per node.
// The OS flow test profiles short, long and high-bit paths against these same bounds.
const READ_STEPS_BASE: usize = 600;
const READ_STEPS_PER_LEVEL: usize = 300;
const READ_RANGE_CHECKS_BASE: usize = 40;
const READ_RANGE_CHECKS_PER_LEVEL: usize = 20;
// The ordinary CallContract entry is already counted by the syscall accounting.
const CALL_CONTRACT_STEPS: usize = 903;
const CALL_CONTRACT_RANGE_CHECKS: usize = 18;
const STEP_SIERRA_GAS: u64 = 100;
const RANGE_CHECK_SIERRA_GAS: u64 = 70;
const POSEIDON_SIERRA_GAS: u64 = 491;

fn read_steps(height: usize) -> usize {
    (READ_STEPS_BASE + READ_STEPS_PER_LEVEL * height).saturating_sub(CALL_CONTRACT_STEPS)
}

fn read_range_checks(height: usize) -> usize {
    READ_RANGE_CHECKS_BASE + READ_RANGE_CHECKS_PER_LEVEL * height - CALL_CONTRACT_RANGE_CHECKS
}

/// Extra OS resources beyond the already-counted CallContract entry.
/// OS flow tests check short, high-bit and maximum-length paths against these bounds.
pub fn read_os_resources(height: usize) -> cairo_vm::vm::runners::cairo_runner::ExecutionResources {
    use cairo_vm::types::builtin_name::BuiltinName;
    use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
    assert!(height <= COMMITTED_DATA_TREE_HEIGHT);
    ExecutionResources {
        n_steps: read_steps(height),
        n_memory_holes: 0,
        builtin_instance_counter: std::collections::BTreeMap::from([
            (BuiltinName::range_check, read_range_checks(height)),
            (BuiltinName::poseidon, 2 * height + 2),
        ]),
    }
}

pub fn read_gas(height: usize) -> u64 {
    assert!(height <= COMMITTED_DATA_TREE_HEIGHT);
    read_steps(height) as u64 * STEP_SIERRA_GAS
        + read_range_checks(height) as u64 * RANGE_CHECK_SIERRA_GAS
        + (2 * height + 2) as u64 * POSEIDON_SIERRA_GAS
}

/// Bounded batch ABI: [root, number_of_keys, key_0, ...], returning [count, value_0, ...].
pub const MAX_COMMITTED_DATA_READ_KEYS: usize = 1024;
const BATCH_STEPS_PER_KEY: usize = 200;
const BATCH_RANGE_CHECKS_PER_KEY: usize = 20;

/// Decode both entrypoints before any witness retrieval. Order and duplicate keys are preserved.
pub fn read_keys(
    selector: Felt,
    calldata: &[Felt],
) -> Result<(&[Felt], bool), SyscallExecutorBaseError> {
    if selector == selector_from_name("get_value").0 && calldata.len() == 2 {
        return Ok((&calldata[1..], false));
    }
    if selector == selector_from_name("get_values").0
        && (3..=MAX_COMMITTED_DATA_READ_KEYS + 2).contains(&calldata.len())
        && calldata[1] == Felt::from(calldata.len() - 2)
    {
        return Ok((&calldata[2..], true));
    }
    Err(SyscallExecutorBaseError::Revert { error_data: vec![INVALID_ARGUMENT_FELT] })
}

/// Restore the ordinary-call allowance subtracted by each single-key charge except the first.
/// Reserve additional loop/return-copy work. Batches still verify independent membership paths.
pub fn batch_overhead_resources(
    count: usize,
) -> cairo_vm::vm::runners::cairo_runner::ExecutionResources {
    use cairo_vm::types::builtin_name::BuiltinName;
    cairo_vm::vm::runners::cairo_runner::ExecutionResources {
        n_steps: count.saturating_sub(1) * CALL_CONTRACT_STEPS + count * BATCH_STEPS_PER_KEY,
        n_memory_holes: 0,
        builtin_instance_counter: std::collections::BTreeMap::from([(
            BuiltinName::range_check,
            count.saturating_sub(1) * CALL_CONTRACT_RANGE_CHECKS
                + count * BATCH_RANGE_CHECKS_PER_KEY,
        )]),
    }
}

/// Sierra charge for the batch wrapper, matching the reserved OS resources.
pub fn batch_overhead_gas(count: usize) -> u64 {
    let resources = batch_overhead_resources(count);
    resources.n_steps as u64 * STEP_SIERRA_GAS
        + resources.builtin_instance_counter
            [&cairo_vm::types::builtin_name::BuiltinName::range_check] as u64
            * RANGE_CHECK_SIERRA_GAS
}

/// Shared VM/native dispatch. A batch fails as a whole; no partial values are returned.
pub fn read_values(
    use_committed_data: bool,
    witnesses: &CommittedDataWitnesses,
    selector: Felt,
    calldata: &[Felt],
    remaining_gas: &mut u64,
    availability_failure: &mut Option<CommittedDataError>,
) -> Result<
    (Vec<Felt>, cairo_vm::vm::runners::cairo_runner::ExecutionResources),
    SyscallExecutorBaseError,
> {
    // Preserve disabled-read rejection even for malformed calls to the reserved address.
    if !use_committed_data {
        return read_value(
            false,
            witnesses,
            selector,
            calldata,
            remaining_gas,
            availability_failure,
        )
        .map(|(value, height)| (vec![value], read_os_resources(height)));
    }
    let (keys, batch) = read_keys(selector, calldata)?;
    let mut resources =
        if batch { batch_overhead_resources(keys.len()) } else { Default::default() };
    if batch {
        *remaining_gas =
            remaining_gas.checked_sub(batch_overhead_gas(keys.len())).ok_or_else(|| {
                SyscallExecutorBaseError::Revert { error_data: vec![OUT_OF_GAS_ERROR_FELT] }
            })?;
    }
    let mut values = Vec::with_capacity(keys.len() + usize::from(batch));
    if batch {
        values.push(Felt::from(keys.len()));
    }
    for key in keys {
        let (value, height) = read_value(
            true,
            witnesses,
            selector_from_name("get_value").0,
            &[calldata[0], *key],
            remaining_gas,
            availability_failure,
        )?;
        resources += &read_os_resources(height);
        values.push(value);
    }
    Ok((values, resources))
}

/// Failed calls reserve the bounded worst case, including work before an out-of-gas failure.
pub fn failed_read_resources(
    selector: Felt,
    calldata: &[Felt],
) -> cairo_vm::vm::runners::cairo_runner::ExecutionResources {
    let (count, batch) =
        read_keys(selector, calldata).map_or((1, false), |(keys, batch)| (keys.len(), batch));
    let mut resources = if batch { batch_overhead_resources(count) } else { Default::default() };
    for _ in 0..count {
        resources += &read_os_resources(COMMITTED_DATA_TREE_HEIGHT);
    }
    resources
}

/// Failures of execution permission, dataset authentication or witness lookup.
#[derive(Debug, thiserror::Error)]
pub enum CommittedDataError {
    #[error("Committed-data reads require use_committed_data=true")]
    Disabled,
    #[error("Dataset must contain 1..={MAX_COMMITTED_DATA_VALUES} values")]
    InvalidLength,
    #[error("Duplicate committed-data key")]
    DuplicateKey,
    #[error("Committed-data witness does not match its root")]
    InvalidWitness,
    #[error("Duplicate committed-data witness")]
    DuplicateWitness,
    #[error("At most {MAX_COMMITTED_DATA_WITNESSES} witnesses are accepted per replay")]
    TooManyWitnesses,
    #[error("Committed-data witness unavailable for exact root and key")]
    Unavailable,
    #[error("Committed-data provider failed: {0}")]
    Provider(String),
}

/// Indexed witnesses authenticated before execution; shared immutably by replay workers.
#[derive(Clone, Debug, Default)]
pub struct CommittedDataWitnesses {
    witnesses: HashMap<(Felt, Felt), CommittedDataWitness>,
    provider: Option<Arc<dyn CommittedDataProvider>>,
}

/// Providers authenticate immutable datasets against the exact root before returning values.
/// The OS never trusts this trait: it separately constrains the witness and syscall response.
pub trait CommittedDataProvider: std::fmt::Debug + Send + Sync {
    fn value(&self, root: Felt, key: Felt) -> Result<Option<(Felt, usize)>, CommittedDataError>;
}

impl CommittedDataWitnesses {
    /// Validates every path and rejects duplicate tuples, even identical duplicates.
    pub fn new(witnesses: Vec<CommittedDataWitness>) -> Result<Self, CommittedDataError> {
        if witnesses.len() > MAX_COMMITTED_DATA_WITNESSES {
            return Err(CommittedDataError::TooManyWitnesses);
        }
        let mut values = HashMap::with_capacity(witnesses.len());
        for witness in witnesses {
            if !witness.verify() {
                return Err(CommittedDataError::InvalidWitness);
            }
            let key = (witness.root, witness.key);
            if values.insert(key, witness).is_some() {
                return Err(CommittedDataError::DuplicateWitness);
            }
        }
        Ok(Self { witnesses: values, provider: None })
    }

    pub fn from_provider(provider: Arc<dyn CommittedDataProvider>) -> Self {
        Self { witnesses: HashMap::new(), provider: Some(provider) }
    }

    pub fn value(
        &self,
        root: Felt,
        index: Felt,
    ) -> Result<Option<(Felt, usize)>, CommittedDataError> {
        if let Some(witness) = self.get(root, index) {
            return Ok(Some((witness.value, witness.siblings.len())));
        }
        let value = match &self.provider {
            Some(provider) => provider.value(root, index),
            None => Ok(None),
        }?;
        if value.is_some_and(|(_, height)| height > COMMITTED_DATA_TREE_HEIGHT) {
            return Err(CommittedDataError::InvalidWitness);
        }
        Ok(value)
    }

    pub fn get(&self, root: Felt, index: Felt) -> Option<&CommittedDataWitness> {
        self.witnesses.get(&(root, index))
    }
}

/// Shared VM/Native fast path. Missing data aborts execution instead of inventing a value.
pub fn read_value(
    use_committed_data: bool,
    witnesses: &CommittedDataWitnesses,
    selector: Felt,
    calldata: &[Felt],
    remaining_gas: &mut u64,
    availability_failure: &mut Option<CommittedDataError>,
) -> Result<(Felt, usize), SyscallExecutorBaseError> {
    let invalid = |info: &str| SyscallExecutorBaseError::InvalidSyscallInput {
        input: selector,
        info: info.into(),
    };
    if !use_committed_data {
        let error = CommittedDataError::Disabled;
        let syscall_error = invalid(&error.to_string());
        availability_failure.get_or_insert(error);
        return Err(syscall_error);
    }
    validate_read_request(selector, calldata, *remaining_gas)?;
    let (value, height) = match witnesses.value(calldata[0], calldata[1]) {
        Ok(Some(value)) => value,
        result => {
            let error = result.err().unwrap_or(CommittedDataError::Unavailable);
            let syscall_error = invalid(&error.to_string());
            // This marker survives nested-call error handling. The transaction boundary must
            // reject unavailable data rather than commit an unprovable reverted receipt.
            availability_failure.get_or_insert(error);
            return Err(syscall_error);
        }
    };
    let gas = read_gas(height);
    if *remaining_gas < gas {
        return Err(SyscallExecutorBaseError::Revert { error_data: vec![OUT_OF_GAS_ERROR_FELT] });
    }
    *remaining_gas -= gas;
    Ok((value, height))
}

/// Deterministic contract-input failures are ordinary syscall reverts in VM, Native and OS.
/// Missing private data is intentionally excluded: it is a node/prover availability failure.
pub fn validate_read_request(
    selector: Felt,
    calldata: &[Felt],
    _remaining_gas: u64,
) -> Result<(), SyscallExecutorBaseError> {
    if selector != selector_from_name("get_value").0 || calldata.len() != 2 {
        return Err(SyscallExecutorBaseError::Revert { error_data: vec![INVALID_ARGUMENT_FELT] });
    }
    Ok(())
}

/// Decodes a bounded witness list without trusting a JSON length or allocating without a cap.
pub fn deserialize_witnesses<'de, D>(deserializer: D) -> Result<Vec<CommittedDataWitness>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct WitnessVisitor;
    impl<'de> serde::de::Visitor<'de> for WitnessVisitor {
        type Value = Vec<CommittedDataWitness>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a bounded list of committed-data witnesses")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> Result<Self::Value, A::Error> {
            let mut witnesses = Vec::new();
            while let Some(witness) = sequence.next_element()? {
                if witnesses.len() == MAX_COMMITTED_DATA_WITNESSES {
                    return Err(serde::de::Error::custom(CommittedDataError::TooManyWitnesses));
                }
                witnesses.push(witness);
            }
            Ok(witnesses)
        }
    }
    deserializer.deserialize_seq(WitnessVisitor)
}

#[cfg(test)]
mod tests {
    use starknet_api::versioned_constants_logic::VersionedConstantsTrait;

    use super::*;
    use crate::blockifier_versioned_constants::VersionedConstants;
    use crate::utils::get_gas_cost_from_vm_resources;

    #[test]
    fn batch_reads_preserve_order_charge_resources_and_reject_partial_success() {
        use crate::utils::get_gas_cost_from_vm_resources;
        let tree =
            CommittedDataSet::new(vec![(Felt::ZERO, Felt::MAX), (Felt::MAX, Felt::ZERO)]).unwrap();
        let witnesses = CommittedDataWitnesses::new(vec![
            tree.witness(Felt::ZERO).unwrap(),
            tree.witness(Felt::MAX).unwrap(),
        ])
        .unwrap();
        let selector = selector_from_name("get_values").0;
        let calldata = [tree.root(), Felt::from(3), Felt::MAX, Felt::ZERO, Felt::MAX];
        let charge = batch_overhead_gas(3) + 3 * read_gas(1);
        let mut gas = charge;
        let mut failure = None;
        let (values, resources) =
            read_values(true, &witnesses, selector, &calldata, &mut gas, &mut failure).unwrap();
        assert_eq!(values, vec![Felt::from(3), Felt::ZERO, Felt::MAX, Felt::ZERO]);
        assert_eq!(gas, 0);
        let costs = &VersionedConstants::latest_constants().os_constants.gas_costs;
        assert_eq!(
            get_gas_cost_from_vm_resources(&resources, &costs.base, &costs.builtins),
            charge
        );
        gas = charge - 1;
        assert!(
            read_values(true, &witnesses, selector, &calldata, &mut gas, &mut failure).is_err()
        );
        assert!(failure.is_none()); // OOG is a contract revert, not missing private data.
        gas = charge;
        assert!(
            read_values(
                true,
                &witnesses,
                selector,
                &[tree.root(), Felt::TWO, Felt::ZERO, Felt::ONE],
                &mut gas,
                &mut failure
            )
            .is_err()
        );
        assert!(matches!(failure, Some(CommittedDataError::Unavailable)));
        for args in [
            vec![],
            vec![tree.root(), Felt::ZERO],
            vec![tree.root(), Felt::TWO, Felt::ZERO],
            vec![Felt::ZERO; MAX_COMMITTED_DATA_READ_KEYS + 3],
        ] {
            assert!(read_keys(selector, &args).is_err());
        }
        let mut args = vec![tree.root(), Felt::from(MAX_COMMITTED_DATA_READ_KEYS)];
        args.extend(std::iter::repeat_n(Felt::ZERO, MAX_COMMITTED_DATA_READ_KEYS));
        assert_eq!(read_keys(selector, &args).unwrap().0.len(), MAX_COMMITTED_DATA_READ_KEYS);
        failure = None;
        assert!(
            read_values(false, &witnesses, selector, &calldata, &mut gas, &mut failure).is_err()
        );
        assert!(matches!(failure, Some(CommittedDataError::Disabled)));
    }

    #[test]
    fn address_matches_versioned_namespace() {
        assert_eq!(COMMITTED_DATA_ADDRESS, selector_from_name("committed_data_v1").0);
        assert_ne!(COMMITTED_DATA_ADDRESS, selector_from_name("paradox_oracle_tick").0);
    }

    #[test]
    fn resource_delta_matches_additional_gas_charge_at_every_depth() {
        let gas_costs = &VersionedConstants::latest_constants().os_constants.gas_costs;
        let call_contract = crate::test_utils::get_const_syscall_resources(
            crate::execution::syscalls::vm_syscall_utils::SyscallSelector::CallContract,
        );
        assert_eq!(call_contract.n_steps, CALL_CONTRACT_STEPS);
        assert_eq!(
            call_contract.builtin_instance_counter
                [&cairo_vm::types::builtin_name::BuiltinName::range_check],
            CALL_CONTRACT_RANGE_CHECKS
        );
        for height in 0..=COMMITTED_DATA_TREE_HEIGHT {
            assert_eq!(
                get_gas_cost_from_vm_resources(
                    &read_os_resources(height),
                    &gas_costs.base,
                    &gas_costs.builtins,
                ),
                read_gas(height),
                "resource charge at height {height}"
            );
        }
    }

    #[test]
    fn compact_tree_authenticates_every_occupied_key() {
        for count in [1_u32, 2, 3, 7, 8, 9, 31] {
            let tree =
                CommittedDataSet::new((0..count).map(|i| (Felt::from(i), Felt::from(i))).collect())
                    .unwrap();
            for index in 0..count {
                assert!(tree.witness(Felt::from(index)).unwrap().verify());
            }
            assert!(tree.witness(Felt::from(count)).is_none());
            assert_eq!(tree.branches().len(), count as usize - 1);
        }
    }

    #[test]
    fn witness_binds_all_fields_and_supports_full_felt_values() {
        let tree = CommittedDataSet::new(vec![(Felt::ZERO, Felt::MAX)]).unwrap();
        let witness = tree.witness(Felt::ZERO).unwrap();
        assert!(witness.verify());
        // Independent Python cairo-lang Poseidon reference vector (key=0, value=p-1).
        assert_eq!(
            tree.root(),
            Felt::from_hex_unchecked(
                "0x31fd3f11a98d38bff2d70429c78b0acca48029a9a3eade958f9950911b0b3e6"
            )
        );
        let mut bad = witness.clone();
        bad.value -= Felt::ONE;
        assert!(!bad.verify());
        let mut bad = witness.clone();
        bad.key += Felt::ONE;
        assert!(!bad.verify());
        let mut bad = witness.clone();
        bad.root += Felt::ONE;
        assert!(!bad.verify());
        let mut bad = witness.clone();
        bad.siblings.push(CommittedDataSibling { bit: 0, hash: Felt::ONE });
        assert!(!bad.verify());
        assert!(matches!(
            CommittedDataWitnesses::new(vec![witness.clone(), witness.clone()]),
            Err(CommittedDataError::DuplicateWitness)
        ));
        let json = serde_json::to_string(&witness).unwrap();
        assert_eq!(serde_json::from_str::<CommittedDataWitness>(&json).unwrap(), witness);
        let oversized = CommittedDataWitness {
            siblings: vec![
                CommittedDataSibling { bit: 0, hash: Felt::ZERO };
                COMMITTED_DATA_TREE_HEIGHT + 1
            ],
            ..witness
        };
        assert!(!oversized.verify());
        assert!(
            serde_json::from_str::<CommittedDataWitness>(
                &serde_json::to_string(&oversized).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn reads_require_exact_tuple_and_charge_only_successful_reads() {
        let tree = CommittedDataSet::new(vec![(Felt::ZERO, Felt::from(42_u32))]).unwrap();
        let cache = CommittedDataWitnesses::new(vec![tree.witness(Felt::ZERO).unwrap()]).unwrap();
        let mut gas = read_gas(0);
        let selector = selector_from_name("get_value").0;
        let mut failure = None;
        assert!(
            read_value(
                true,
                &cache,
                selector,
                &[tree.root() + Felt::ONE, Felt::ZERO],
                &mut gas,
                &mut failure
            )
            .is_err()
        );
        assert_eq!(gas, read_gas(0));
        assert!(matches!(failure, Some(CommittedDataError::Unavailable)));
        assert_eq!(
            read_value(true, &cache, selector, &[tree.root(), Felt::ZERO], &mut gas, &mut failure)
                .unwrap(),
            (Felt::from(42_u32), 0)
        );
        assert_eq!(gas, 0);
        assert!(
            read_value(true, &cache, selector, &[tree.root(), Felt::ZERO], &mut gas, &mut failure)
                .is_err()
        );
        assert!(cache.value(tree.root(), Felt::MAX).unwrap().is_none());
        assert!(cache.value(tree.root(), Felt::from(MAX_COMMITTED_DATA_VALUES)).unwrap().is_none());
    }
}
