//! Authenticated reads from immutable, application-owned datasets.
//!
//! The application supplies a root read from its own authenticated storage. Values and paths
//! are private execution input; the Cairo OS independently proves membership and the response.
//! Any contract may read a dataset by root and index. Roots and witnesses are independent of
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

use serde::{Deserialize, Serialize};
use starknet_api::abi::abi_utils::selector_from_name;
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Poseidon, StarkHash};

use super::hint_processor::{INVALID_ARGUMENT_FELT, OUT_OF_GAS_ERROR_FELT};
use super::vm_syscall_utils::SyscallExecutorBaseError;

/// `starknet_keccak("committed_data_v1")`. Permanently reserved by this OS version.
pub const COMMITTED_DATA_ADDRESS: Felt =
    Felt::from_hex_unchecked("0x6c5f4559c7041984537bc078c71443fdc58b2e1bab302b341ec12b3d2cec44");
/// Maximum supported tree height; trees use the minimum height for their value count.
pub const COMMITTED_DATA_TREE_HEIGHT: usize = 19;
/// Maximum number of values in one dataset.
pub const MAX_COMMITTED_DATA_VALUES: usize = 1 << COMMITTED_DATA_TREE_HEIGHT;
/// Bound on distinct witnesses supplied to one replay request.
pub const MAX_COMMITTED_DATA_WITNESSES: usize = 65_536;
// A successful OS call measured 306 + 44*height steps and 14 + 3*height range checks.
// These bounds add headroom for the changed gas calculation and future OS instruction changes.
const READ_STEPS_BASE: usize = 400;
const READ_STEPS_PER_LEVEL: usize = 50;
const READ_RANGE_CHECKS_BASE: usize = 20;
const READ_RANGE_CHECKS_PER_LEVEL: usize = 4;
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
/// Proof traces check these bounds at every supported tree depth.
pub fn read_os_resources(height: usize) -> cairo_vm::vm::runners::cairo_runner::ExecutionResources {
    use cairo_vm::types::builtin_name::BuiltinName;
    use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
    assert!(height <= COMMITTED_DATA_TREE_HEIGHT);
    ExecutionResources {
        n_steps: read_steps(height),
        n_memory_holes: 0,
        builtin_instance_counter: std::collections::BTreeMap::from([
            (BuiltinName::range_check, read_range_checks(height)),
            (BuiltinName::poseidon, height + 2),
        ]),
    }
}

pub fn read_gas(height: usize) -> u64 {
    assert!(height <= COMMITTED_DATA_TREE_HEIGHT);
    read_steps(height) as u64 * STEP_SIERRA_GAS
        + read_range_checks(height) as u64 * RANGE_CHECK_SIERRA_GAS
        + (height + 2) as u64 * POSEIDON_SIERRA_GAS
}

/// Domain separation for version-one leaves, also encoded in Cairo OS.
pub const COMMITTED_DATA_LEAF_DOMAIN: Felt =
    Felt::from_hex_unchecked("0x434f4d4d49545445445f444154415f5631");

/// Failures of execution permission, dataset authentication or witness lookup.
#[derive(Debug, thiserror::Error)]
pub enum CommittedDataError {
    #[error("Committed-data reads require use_committed_data=true")]
    Disabled,
    #[error("Dataset must contain 1..={MAX_COMMITTED_DATA_VALUES} values")]
    InvalidLength,
    #[error("Committed-data index is outside the version-one tree")]
    InvalidIndex,
    #[error("Committed-data witness does not match its root")]
    InvalidWitness,
    #[error("Duplicate committed-data witness")]
    DuplicateWitness,
    #[error("At most {MAX_COMMITTED_DATA_WITNESSES} witnesses are accepted per replay")]
    TooManyWitnesses,
    #[error("Committed-data witness unavailable for exact root and index")]
    Unavailable,
    #[error("Committed-data provider failed: {0}")]
    Provider(String),
}

/// Private witness for one field element, reusable by every caller of the same root.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedDataWitness {
    pub root: Felt,
    pub index: u32,
    pub value: Felt,
    /// A bounded path; its length is the authenticated tree height (0..=19).
    #[serde(deserialize_with = "deserialize_siblings")]
    pub siblings: Vec<Felt>,
}

fn deserialize_siblings<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<Felt>, D::Error> {
    struct Siblings;
    impl<'de> serde::de::Visitor<'de> for Siblings {
        type Value = Vec<Felt>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("at most 19 committed-data siblings")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut siblings = Vec::new();
            while let Some(sibling) = seq.next_element()? {
                if siblings.len() == COMMITTED_DATA_TREE_HEIGHT {
                    return Err(serde::de::Error::custom("Too many committed-data siblings"));
                }
                siblings.push(sibling);
            }
            Ok(siblings)
        }
    }
    deserializer.deserialize_seq(Siblings)
}

impl CommittedDataWitness {
    /// Checks index, value and ordered path against the requested root.
    pub fn verify(&self) -> bool {
        if self.siblings.len() > COMMITTED_DATA_TREE_HEIGHT
            || usize::try_from(self.index).expect("u32 fits supported usize")
                >= 1_usize << self.siblings.len()
        {
            return false;
        }
        let mut node = leaf(self.index, self.value);
        for (level, sibling) in self.siblings.iter().enumerate() {
            node = if (self.index >> level) & 1 == 0 {
                Poseidon::hash(&node, sibling)
            } else {
                Poseidon::hash(sibling, &node)
            };
        }
        node == self.root
    }
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
    fn value(&self, root: Felt, index: u32) -> Result<Option<(Felt, usize)>, CommittedDataError>;
}

/// Indexed tree with zero-hash padding. Unused leaves are not valid zero-value entries.
/// Only occupied prefixes are allocated, so tiny datasets do not allocate a full 19-level tree.
#[derive(Debug)]
pub struct CommittedDataSet {
    values: Vec<Felt>,
    levels: Vec<Vec<Felt>>,
    empty: [Felt; COMMITTED_DATA_TREE_HEIGHT],
    height: usize,
}

impl CommittedDataSet {
    /// Builds the unique minimum-height tree for these values.
    pub fn new(values: Vec<Felt>) -> Result<Self, CommittedDataError> {
        if values.is_empty() || values.len() > MAX_COMMITTED_DATA_VALUES {
            return Err(CommittedDataError::InvalidLength);
        }
        let height = (values.len() - 1).checked_ilog2().map_or(0, |log| log as usize + 1);
        let leaves = values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                leaf(
                    u32::try_from(index).expect("dataset length is bounded below u32::MAX"),
                    *value,
                )
            })
            .collect();
        let mut levels: Vec<Vec<Felt>> = vec![leaves];
        let mut empty = [Felt::ZERO; COMMITTED_DATA_TREE_HEIGHT];
        for depth in 0..height {
            if depth > 0 {
                empty[depth] = Poseidon::hash(&empty[depth - 1], &empty[depth - 1]);
            }
            let parents = levels[depth]
                .chunks(2)
                .map(|pair| Poseidon::hash(&pair[0], pair.get(1).unwrap_or(&empty[depth])))
                .collect();
            levels.push(parents);
        }
        Ok(Self { values, levels, empty, height })
    }

    pub fn root(&self) -> Felt {
        self.levels[self.height][0]
    }
    pub fn height(&self) -> usize {
        self.height
    }
    pub fn values(&self) -> &[Felt] {
        &self.values
    }

    /// Occupied internal-node prefixes in ascending height, excluding the root.
    /// Persisting these permits bounded path reads without reconstructing an entire dataset.
    pub fn internal_levels(&self) -> impl Iterator<Item = &[Felt]> {
        self.levels[1..self.height.max(1)].iter().map(Vec::as_slice)
    }
    pub fn value(&self, index: u32) -> Option<Felt> {
        self.values.get(usize::try_from(index).expect("u32 fits supported usize")).copied()
    }

    /// Returns no witness for an unoccupied leaf, even when its padding hash is known.
    pub fn witness(&self, index: u32) -> Option<CommittedDataWitness> {
        let value = self.value(index)?;
        let siblings = (0..self.height)
            .map(|depth| {
                self.levels[depth]
                    .get(((usize::try_from(index).expect("u32 fits supported usize")) >> depth) ^ 1)
                    .copied()
                    .unwrap_or(self.empty[depth])
            })
            .collect();
        Some(CommittedDataWitness { root: self.root(), index, value, siblings })
    }
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
            let key = (witness.root, Felt::from(witness.index));
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
        let checked_index: u32 = index.try_into().map_err(|_| CommittedDataError::InvalidIndex)?;
        if usize::try_from(checked_index).expect("u32 fits supported usize")
            >= MAX_COMMITTED_DATA_VALUES
        {
            return Err(CommittedDataError::InvalidIndex);
        }
        if let Some(witness) = self.get(root, index) {
            return Ok(Some((witness.value, witness.siblings.len())));
        }
        let value = match &self.provider {
            Some(provider) => provider.value(root, checked_index),
            None => Ok(None),
        }?;
        if value.is_some_and(|(_, height)| {
            height > COMMITTED_DATA_TREE_HEIGHT || (checked_index as usize) >= 1_usize << height
        }) {
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
    if selector != selector_from_name("get_value").0
        || calldata.len() != 2
        || calldata.get(1).is_some_and(|index| *index >= Felt::from(MAX_COMMITTED_DATA_VALUES))
    {
        return Err(SyscallExecutorBaseError::Revert { error_data: vec![INVALID_ARGUMENT_FELT] });
    }
    Ok(())
}

/// Domain-separated leaf shared with authenticated dataset persistence.
pub fn leaf(index: u32, value: Felt) -> Felt {
    Poseidon::hash_array(&[COMMITTED_DATA_LEAF_DOMAIN, Felt::from(index), value])
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
    fn compact_tree_authenticates_every_occupied_leaf() {
        for count in [1_u32, 2, 3, 7, 8, 9, 31] {
            let values: Vec<_> = (0..count).map(Felt::from).collect();
            let tree = CommittedDataSet::new(values.clone()).unwrap();
            assert_eq!(
                tree.height(),
                (count - 1).checked_ilog2().map_or(0, |log| log as usize + 1)
            );
            for index in 0..count {
                assert!(tree.witness(index).unwrap().verify());
            }
            assert!(tree.witness(count).is_none());
            assert_eq!(tree.levels[0].len(), count as usize);
        }
        let tree = CommittedDataSet::new((0..30_000_u32).map(Felt::from).collect()).unwrap();
        assert_eq!(tree.height(), 15);
        assert!(tree.witness(29_999).unwrap().verify());
    }

    #[test]
    fn witness_binds_all_fields_and_supports_full_felt_values() {
        let tree = CommittedDataSet::new(vec![Felt::MAX]).unwrap();
        let witness = tree.witness(0).unwrap();
        assert!(witness.verify());
        // Independent Python cairo-lang Poseidon reference vector (index=0, value=p-1).
        assert_eq!(tree.root(), leaf(0, Felt::MAX));
        let mut bad = witness.clone();
        bad.value -= Felt::ONE;
        assert!(!bad.verify());
        let mut bad = witness.clone();
        bad.index += 1;
        assert!(!bad.verify());
        let mut bad = witness.clone();
        bad.root += Felt::ONE;
        assert!(!bad.verify());
        let mut bad = witness.clone();
        bad.siblings.push(Felt::ONE);
        assert!(!bad.verify());
        assert!(matches!(
            CommittedDataWitnesses::new(vec![witness.clone(), witness.clone()]),
            Err(CommittedDataError::DuplicateWitness)
        ));
        let json = serde_json::to_string(&witness).unwrap();
        assert_eq!(serde_json::from_str::<CommittedDataWitness>(&json).unwrap(), witness);
        let oversized = CommittedDataWitness {
            siblings: vec![Felt::ZERO; COMMITTED_DATA_TREE_HEIGHT + 1],
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
        let tree = CommittedDataSet::new(vec![Felt::from(42_u32)]).unwrap();
        let cache = CommittedDataWitnesses::new(vec![tree.witness(0).unwrap()]).unwrap();
        let mut gas = read_gas(tree.height());
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
        assert_eq!(gas, read_gas(tree.height()));
        assert!(matches!(failure, Some(CommittedDataError::Unavailable)));
        assert_eq!(
            read_value(true, &cache, selector, &[tree.root(), Felt::ZERO], &mut gas, &mut failure)
                .unwrap(),
            (Felt::from(42_u32), tree.height())
        );
        assert_eq!(gas, 0);
        assert!(
            read_value(true, &cache, selector, &[tree.root(), Felt::ZERO], &mut gas, &mut failure)
                .is_err()
        );
        assert!(cache.value(tree.root(), Felt::MAX).is_err());
        assert!(cache.value(tree.root(), Felt::from(MAX_COMMITTED_DATA_VALUES)).is_err());
    }
}
