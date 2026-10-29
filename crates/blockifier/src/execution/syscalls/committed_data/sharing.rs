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
    witnesses: HashSet<(Felt, Felt)>,
    leaves: HashSet<(Felt, Felt)>,
    branches: HashSet<(Felt, Felt)>,
}

/// One ordered block's charged leaves and expanded branch commitments.
/// Clone shares state within a transaction; `fork` isolates speculative execution.
#[derive(Clone, Debug, Default)]
pub struct CommittedDataReadSet(Arc<Mutex<ReadSet>>);

impl CommittedDataReadSet {
    /// Witnesses required by admitted execution, including the independently charged single-key
    /// ABI.
    pub fn witness_keys(&self) -> Vec<(Felt, Felt)> {
        let mut keys: Vec<_> = self
            .0
            .lock()
            .expect("Committed-data read set poisoned")
            .witnesses
            .iter()
            .copied()
            .collect();
        keys.sort_unstable();
        keys
    }

    pub fn is_empty(&self) -> bool {
        self.0.lock().expect("Committed-data read set poisoned").witnesses.is_empty()
    }

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
    let Ok((keys, batch)) = read_keys(selector, calldata) else {
        return read_values(enabled, witnesses, selector, calldata, remaining_gas, failure);
    };
    // Preserve permission checks and authenticate every supplied value even on a warm hit.
    let mut verification_gas = u64::MAX;
    let (values, single_resources) =
        read_values(enabled, witnesses, selector, calldata, &mut verification_gas, failure)?;
    let root = calldata[0];
    let mut seen = read_set.0.lock().expect("Committed-data read set poisoned");
    let mut distinct = HashSet::new();
    let cold: Vec<_> = keys
        .iter()
        .copied()
        .filter(|key| !seen.leaves.contains(&(root, *key)) && distinct.insert(*key))
        .collect();
    // Count both ABIs without giving single reads the batch ABI's deferred-proof discount.
    let requested: HashSet<_> = keys.iter().map(|key| (root, *key)).collect();
    if seen.witnesses.len() + requested.difference(&seen.witnesses).count()
        > MAX_COMMITTED_DATA_WITNESSES
    {
        let error = CommittedDataError::TooManyWitnesses;
        let info = error.to_string();
        failure.get_or_insert(error);
        return Err(SyscallExecutorBaseError::InvalidSyscallInput { input: selector, info });
    }
    if !batch {
        charge_authenticated_read(
            selector,
            resources_gas(&single_resources),
            remaining_gas,
            failure,
        )?;
        seen.witnesses.extend(requested);
        return Ok((values, single_resources));
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
    seen.witnesses.extend(requested);
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

    /// Both selectors consume the same block allowance; single reads keep their original gas.
    #[rstest::rstest]
    #[case::single("get_value", false)]
    #[case::batch("get_values", true)]
    fn witness_capacity_defers_a_transaction_without_consuming_its_nonce(
        #[case] selector: &str,
        #[case] batch: bool,
    ) {
        use blockifier_test_utils::cairo_versions::{CairoVersion, RunnableCairo1};
        use blockifier_test_utils::calldata::create_calldata;
        use starknet_api::invoke_tx_args;

        use crate::blockifier::config::TransactionExecutorConfig;
        use crate::blockifier::transaction_executor::{
            TransactionExecutor,
            TransactionExecutorError,
        };
        use crate::context::BlockContext;
        use crate::state::state_api::StateReader;
        use crate::transaction::test_utils::{
            create_test_init_data,
            default_all_resource_bounds,
            invoke_tx_with_default_flags,
        };
        use crate::transaction::transaction_execution::Transaction;

        let tree = CommittedDataSet::new(vec![(Felt::ZERO, Felt::TWO)]).unwrap();
        let mut context = BlockContext::create_for_testing();
        context.use_committed_data = true;
        context.committed_data_witnesses =
            Arc::new(CommittedDataWitnesses::new(vec![tree.witness(Felt::ZERO).unwrap()]).unwrap());
        let data =
            create_test_init_data(&context.chain_info, CairoVersion::Cairo1(RunnableCairo1::Casm));
        let args = if batch {
            vec![tree.root(), Felt::ONE, Felt::ZERO]
        } else {
            vec![tree.root(), Felt::ZERO]
        };
        let transaction = Transaction::Account(invoke_tx_with_default_flags(invoke_tx_args! {
            sender_address: data.account_address,
            resource_bounds: default_all_resource_bounds(),
            calldata: create_calldata(COMMITTED_DATA_ADDRESS.try_into().unwrap(), selector, &args),
        }));
        let mut executor = TransactionExecutor::new(
            data.state,
            context.clone(),
            TransactionExecutorConfig::default(),
        );
        // Model the distinct keys admitted before this transaction without executing 65k calls.
        executor
            .block_context
            .committed_data_read_set
            .0
            .lock()
            .unwrap()
            .witnesses
            .extend((0..MAX_COMMITTED_DATA_WITNESSES).map(|key| (Felt::ONE, Felt::from(key))));
        let nonce =
            executor.block_state.as_ref().unwrap().get_nonce_at(data.account_address).unwrap();
        assert!(matches!(executor.execute(&transaction), Err(TransactionExecutorError::BlockFull)));
        assert_eq!(
            executor.block_state.as_ref().unwrap().get_nonce_at(data.account_address).unwrap(),
            nonce
        );
        assert_eq!(
            executor.block_context.committed_data_read_set.witness_keys().len(),
            MAX_COMMITTED_DATA_WITNESSES
        );
        let state = executor.block_state.take().unwrap();
        let mut next =
            TransactionExecutor::new(state, context, TransactionExecutorConfig::default());
        let (execution, _) = next.execute(&transaction).unwrap();
        assert!(execution.revert_error.is_none());
        assert_eq!(
            next.block_context.committed_data_read_set.witness_keys(),
            vec![(tree.root(), Felt::ZERO)]
        );
        assert_ne!(
            next.block_state.as_ref().unwrap().get_nonce_at(data.account_address).unwrap(),
            nonce
        );
    }

    #[test]
    fn single_reads_share_witness_identity_without_warming_batch_proof_discounts() {
        let tree = CommittedDataSet::new(vec![(Felt::ZERO, Felt::TWO)]).unwrap();
        let witnesses =
            CommittedDataWitnesses::new(vec![tree.witness(Felt::ZERO).unwrap()]).unwrap();
        let seen = CommittedDataReadSet::default();
        let single = selector_from_name("get_value").0;
        for _ in 0..2 {
            let mut gas = u64::MAX;
            let (_, resources) = read_values_shared(
                true,
                &witnesses,
                &seen,
                single,
                &[tree.root(), Felt::ZERO],
                &mut gas,
                &mut None,
            )
            .unwrap();
            assert_eq!(u64::MAX - gas, read_gas(0));
            assert_eq!(resources, read_os_resources(0));
        }
        assert_eq!(seen.witness_keys(), vec![(tree.root(), Felt::ZERO)]);
        let mut gas = u64::MAX;
        let (_, resources) = read_values_shared(
            true,
            &witnesses,
            &seen,
            selector_from_name("get_values").0,
            &[tree.root(), Felt::TWO, Felt::ZERO, Felt::ZERO],
            &mut gas,
            &mut None,
        )
        .unwrap();
        assert_eq!(resources, &shared_request_resources(2) + &batch_os_resources(1, 1, 0));
        assert_eq!(seen.witness_keys().len(), 1);
    }
}
