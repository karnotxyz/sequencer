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
/// Version-one trees have 524,288 indexed leaves.
pub const COMMITTED_DATA_TREE_HEIGHT: usize = 19;
/// Maximum number of values in one dataset.
pub const MAX_COMMITTED_DATA_VALUES: usize = 1 << COMMITTED_DATA_TREE_HEIGHT;
/// Bound on distinct witnesses supplied to one replay request.
pub const MAX_COMMITTED_DATA_WITNESSES: usize = 65_536;
/// Additional charge for a 19-level read after the normal `CallContract` cost is deducted.
/// Together they charge the measured complete special-call cost of 124,701 gas.
pub const COMMITTED_DATA_READ_GAS: u64 = 33_141;
/// Measured OS resource delta beyond the normal `CallContract` resource entry.
pub fn read_os_resources() -> &'static cairo_vm::vm::runners::cairo_runner::ExecutionResources {
    use cairo_vm::types::builtin_name::BuiltinName;
    use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
    static RESOURCES: std::sync::LazyLock<ExecutionResources> =
        std::sync::LazyLock::new(|| ExecutionResources {
            n_steps: 194,
            n_memory_holes: 0,
            builtin_instance_counter: std::collections::BTreeMap::from([
                (BuiltinName::range_check, 49),
                (BuiltinName::poseidon, 21),
            ]),
        });
    &RESOURCES
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
    /// Fixed-length paths bound decoding and avoid malformed path allocation.
    pub siblings: [Felt; COMMITTED_DATA_TREE_HEIGHT],
}

impl CommittedDataWitness {
    /// Checks index, value and ordered path against the requested root.
    pub fn verify(&self) -> bool {
        if usize::try_from(self.index).expect("u32 fits supported usize")
            >= MAX_COMMITTED_DATA_VALUES
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
    fn value(&self, root: Felt, index: u32) -> Result<Option<Felt>, CommittedDataError>;
}

/// Indexed tree with zero-hash padding. Unused leaves are not valid zero-value entries.
/// Only occupied prefixes are allocated, so tiny datasets do not allocate a full 19-level tree.
#[derive(Debug)]
pub struct CommittedDataSet {
    values: Vec<Felt>,
    levels: Vec<Vec<Felt>>,
    empty: [Felt; COMMITTED_DATA_TREE_HEIGHT],
}

impl CommittedDataSet {
    /// Builds a version-one tree; rejects empty or oversized datasets before hashing.
    pub fn new(values: Vec<Felt>) -> Result<Self, CommittedDataError> {
        if values.is_empty() || values.len() > MAX_COMMITTED_DATA_VALUES {
            return Err(CommittedDataError::InvalidLength);
        }
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
        for depth in 0..COMMITTED_DATA_TREE_HEIGHT {
            if depth > 0 {
                empty[depth] = Poseidon::hash(&empty[depth - 1], &empty[depth - 1]);
            }
            let parents = levels[depth]
                .chunks(2)
                .map(|pair| Poseidon::hash(&pair[0], pair.get(1).unwrap_or(&empty[depth])))
                .collect();
            levels.push(parents);
        }
        Ok(Self { values, levels, empty })
    }

    pub fn root(&self) -> Felt {
        self.levels[COMMITTED_DATA_TREE_HEIGHT][0]
    }
    pub fn values(&self) -> &[Felt] {
        &self.values
    }

    /// Occupied internal-node prefixes in ascending height, excluding the root.
    /// Persisting these permits bounded path reads without reconstructing an entire dataset.
    pub fn internal_levels(&self) -> impl Iterator<Item = &[Felt]> {
        self.levels[1..COMMITTED_DATA_TREE_HEIGHT].iter().map(Vec::as_slice)
    }
    pub fn value(&self, index: u32) -> Option<Felt> {
        self.values.get(usize::try_from(index).expect("u32 fits supported usize")).copied()
    }

    /// Returns no witness for an unoccupied leaf, even when its padding hash is known.
    pub fn witness(&self, index: u32) -> Option<CommittedDataWitness> {
        let value = self.value(index)?;
        let siblings = std::array::from_fn(|depth| {
            self.levels[depth]
                .get(((usize::try_from(index).expect("u32 fits supported usize")) >> depth) ^ 1)
                .copied()
                .unwrap_or(self.empty[depth])
        });
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

    pub fn value(&self, root: Felt, index: Felt) -> Result<Option<Felt>, CommittedDataError> {
        let checked_index: u32 = index.try_into().map_err(|_| CommittedDataError::InvalidIndex)?;
        if usize::try_from(checked_index).expect("u32 fits supported usize")
            >= MAX_COMMITTED_DATA_VALUES
        {
            return Err(CommittedDataError::InvalidIndex);
        }
        if let Some(witness) = self.get(root, index) {
            return Ok(Some(witness.value));
        }
        match &self.provider {
            Some(provider) => provider.value(root, checked_index),
            None => Ok(None),
        }
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
) -> Result<Felt, SyscallExecutorBaseError> {
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
    let gas = *remaining_gas - COMMITTED_DATA_READ_GAS;
    let value = match witnesses.value(calldata[0], calldata[1]) {
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
    *remaining_gas = gas;
    Ok(value)
}

/// Deterministic contract-input failures are ordinary syscall reverts in VM, Native and OS.
/// Missing private data is intentionally excluded: it is a node/prover availability failure.
pub fn validate_read_request(
    selector: Felt,
    calldata: &[Felt],
    remaining_gas: u64,
) -> Result<(), SyscallExecutorBaseError> {
    if selector != selector_from_name("get_value").0
        || calldata.len() != 2
        || calldata.get(1).is_some_and(|index| *index >= Felt::from(MAX_COMMITTED_DATA_VALUES))
    {
        return Err(SyscallExecutorBaseError::Revert { error_data: vec![INVALID_ARGUMENT_FELT] });
    }
    if remaining_gas < COMMITTED_DATA_READ_GAS {
        return Err(SyscallExecutorBaseError::Revert { error_data: vec![OUT_OF_GAS_ERROR_FELT] });
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
    fn measured_resource_delta_matches_additional_gas_charge() {
        let gas_costs = &VersionedConstants::latest_constants().os_constants.gas_costs;
        assert_eq!(
            get_gas_cost_from_vm_resources(
                read_os_resources(),
                &gas_costs.base,
                &gas_costs.builtins,
            ),
            COMMITTED_DATA_READ_GAS
        );
    }

    #[test]
    fn compact_tree_authenticates_every_occupied_leaf() {
        for count in [1, 2, 3, 7, 8, 9, 31] {
            let values = (0..count).map(Felt::from).collect();
            let tree = CommittedDataSet::new(values).unwrap();
            for index in 0..count {
                assert!(tree.witness(index).unwrap().verify());
            }
            assert!(tree.witness(count).is_none());
            assert_eq!(tree.levels[0].len(), count as usize);
        }
    }

    #[test]
    fn witness_binds_all_fields_and_supports_full_felt_values() {
        let tree = CommittedDataSet::new(vec![Felt::MAX]).unwrap();
        let witness = tree.witness(0).unwrap();
        assert!(witness.verify());
        // Independent Python cairo-lang Poseidon reference vector (index=0, value=p-1).
        assert_eq!(
            tree.root(),
            Felt::from_hex_unchecked(
                "0x37d41acbaf910cb2e20f1e3995e1c1cdc875b58c1f4ae31a5079999e29fa29c"
            )
        );
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
        bad.siblings[0] += Felt::ONE;
        assert!(!bad.verify());
        assert!(matches!(
            CommittedDataWitnesses::new(vec![witness.clone(), witness.clone()]),
            Err(CommittedDataError::DuplicateWitness)
        ));
        let json = serde_json::to_string(&witness).unwrap();
        assert_eq!(serde_json::from_str::<CommittedDataWitness>(&json).unwrap(), witness);
    }

    #[test]
    fn reads_require_exact_tuple_and_charge_only_successful_reads() {
        let tree = CommittedDataSet::new(vec![Felt::from(42_u32)]).unwrap();
        let cache = CommittedDataWitnesses::new(vec![tree.witness(0).unwrap()]).unwrap();
        let mut gas = COMMITTED_DATA_READ_GAS;
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
        assert_eq!(gas, COMMITTED_DATA_READ_GAS);
        assert!(matches!(failure, Some(CommittedDataError::Unavailable)));
        assert_eq!(
            read_value(true, &cache, selector, &[tree.root(), Felt::ZERO], &mut gas, &mut failure)
                .unwrap(),
            Felt::from(42_u32)
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
