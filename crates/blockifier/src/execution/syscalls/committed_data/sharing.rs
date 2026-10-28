//! Block-local accounting for the read set authenticated by Cairo at block finalization.
//!
//! A transaction works on a fork. Only admitted work may discount later reads; rejected
//! transactions, failed fee probes and execution omitted by SNOS must discard their changes.
//! Root identity is part of every key: publishing a new root never inherits the old discount.
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use cairo_vm::vm::runners::cairo_runner::ExecutionResources;

use super::*;

#[derive(Clone, Debug, Default)]
struct ReadSet {
    leaves: HashSet<(Felt, Felt)>,
    branches: HashSet<(Felt, Felt)>,
}

/// One ordered block's charged leaves and expanded branch commitments.
/// Clone shares state within a transaction; `fork` isolates speculative execution.
#[derive(Clone, Debug, Default)]
pub struct CommittedDataReadSet(Arc<Mutex<ReadSet>>);

impl CommittedDataReadSet {
    pub fn fork(&self) -> Self {
        Self(Arc::new(Mutex::new(self.0.lock().expect("Committed-data read set poisoned").clone())))
    }

    /// Publish an accepted fork, or restore a checkpoint when execution is omitted by SNOS.
    pub fn replace_with(&self, other: &Self) {
        let replacement = other.0.lock().expect("Committed-data read set poisoned").clone();
        *self.0.lock().expect("Committed-data read set poisoned") = replacement;
    }
}

/// Per-call dictionary accesses, response copying and amortized dictionary finalization.
/// Membership work is charged separately for newly observed leaves and branches.
pub fn shared_request_resources(count: usize) -> ExecutionResources {
    use cairo_vm::types::builtin_name::BuiltinName;
    ExecutionResources {
        n_steps: 800 + 80 * count,
        n_memory_holes: 0,
        builtin_instance_counter: std::collections::BTreeMap::from([(
            BuiltinName::range_check,
            20 + 4 * count,
        )]),
    }
}

pub fn resources_gas(resources: &ExecutionResources) -> u64 {
    use cairo_vm::types::builtin_name::BuiltinName;
    let count = |name| resources.builtin_instance_counter.get(&name).copied().unwrap_or(0) as u64;
    resources.n_steps as u64 * STEP_SIERRA_GAS
        + count(BuiltinName::range_check) * RANGE_CHECK_SIERRA_GAS
        + count(BuiltinName::poseidon) * POSEIDON_SIERRA_GAS
        + count(BuiltinName::bitwise) * BITWISE_SIERRA_GAS
}

/// Authenticate first, price only new membership work, and warm only after payment succeeds.
/// The legacy single-key selector retains its existing independently verified gas schedule.
pub fn read_values_shared(
    enabled: bool,
    witnesses: &CommittedDataWitnesses,
    read_set: &CommittedDataReadSet,
    selector: Felt,
    calldata: &[Felt],
    remaining_gas: &mut u64,
    failure: &mut Option<CommittedDataError>,
) -> Result<(Vec<Felt>, ExecutionResources), SyscallExecutorBaseError> {
    let Ok((keys, true)) = read_keys(selector, calldata) else {
        return read_values(enabled, witnesses, selector, calldata, remaining_gas, failure);
    };
    // Preserve permission checks and authenticate every supplied value even on a warm hit.
    let (values, _) = read_values(enabled, witnesses, selector, calldata, &mut u64::MAX, failure)?;
    let root = calldata[0];
    let mut seen = read_set.0.lock().expect("Committed-data read set poisoned");
    let mut distinct = HashSet::new();
    let cold: Vec<_> = keys
        .iter()
        .copied()
        .filter(|key| !seen.leaves.contains(&(root, *key)) && distinct.insert(*key))
        .collect();
    // This is also the OS input's bound. Reject before publishing discounts or a receipt,
    // rather than admitting a read set that cannot be represented by the replay witness list.
    if seen.leaves.len() + cold.len() > MAX_COMMITTED_DATA_WITNESSES {
        let error = CommittedDataError::TooManyWitnesses;
        let info = error.to_string();
        failure.get_or_insert(error);
        return Err(SyscallExecutorBaseError::InvalidSyscallInput { input: selector, info });
    }
    let mut resources = shared_request_resources(keys.len());
    let mut new_branches = Vec::new();
    if !cold.is_empty() {
        let proof = witnesses.batch(root, &cold).map_err(|error| {
            let result = SyscallExecutorBaseError::InvalidSyscallInput {
                input: selector,
                info: error.to_string(),
            };
            failure.get_or_insert(error);
            result
        })?;
        new_branches.extend(
            proof.branch_hashes.into_iter().filter(|hash| !seen.branches.contains(&(root, *hash))),
        );
        resources += &batch_os_resources(cold.len(), cold.len(), new_branches.len());
    }
    charge_authenticated_read(selector, resources_gas(&resources), remaining_gas, failure)?;
    seen.leaves.extend(cold.into_iter().map(|key| (root, key)));
    seen.branches.extend(new_branches.into_iter().map(|hash| (root, hash)));
    Ok((values, resources))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only paid, admitted work may warm a block; roots and block boundaries are independent.
    #[test]
    fn shared_reads_charge_union_and_discard_rejected_forks() {
        let tree = CommittedDataSet::new(
            (0..16).map(|key| (Felt::from(key), Felt::from(key + 20))).collect(),
        )
        .unwrap();
        let witnesses = CommittedDataWitnesses::new(
            tree.entries().iter().map(|(key, _)| tree.witness(*key).unwrap()).collect(),
        )
        .unwrap();
        let block = CommittedDataReadSet::default();
        let selector = selector_from_name("get_values").0;
        let call = |cache: &CommittedDataReadSet, keys: &[Felt], mut gas: u64| {
            let mut calldata = vec![tree.root(), Felt::from(keys.len())];
            calldata.extend_from_slice(keys);
            read_values_shared(true, &witnesses, cache, selector, &calldata, &mut gas, &mut None)
        };
        let first_keys = [Felt::ZERO, Felt::ONE, Felt::ZERO];
        let expected = &shared_request_resources(3) + &batch_os_resources(2, 2, 4);
        let discarded = block.fork();
        let (_, cold) = call(&discarded, &first_keys, u64::MAX).unwrap();
        assert_eq!(cold, expected);
        // A rejected admission doesn't publish its fork.
        let accepted = block.fork();
        assert_eq!(call(&accepted, &first_keys, u64::MAX).unwrap().1, cold);
        block.replace_with(&accepted);
        assert_eq!(call(&block, &first_keys, u64::MAX).unwrap().1, shared_request_resources(3));
        // An underfunded cold read does not warm even the current transaction.
        let next_keys = [Felt::TWO, Felt::THREE];
        let before = block.fork();
        assert!(call(&block, &next_keys, 0).is_err());
        assert_eq!(
            call(&block, &next_keys, u64::MAX).unwrap().1,
            call(&before, &next_keys, u64::MAX).unwrap().1
        );
        assert_eq!(call(&CommittedDataReadSet::default(), &first_keys, u64::MAX).unwrap().1, cold);
    }
}
