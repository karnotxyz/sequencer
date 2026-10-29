use blockifier::state::state_api::StateReader;
use cairo_vm::types::relocatable::MaybeRelocatable;

use crate::hint_processor::snos_hint_processor::SnosHintProcessor;
use crate::hints::error::{OsHintError, OsHintResult};
use crate::hints::types::HintContext;
use crate::hints::vars::Ids;

/// Supplies execution permission. Cairo enforces a boolean and rejects disabled reads.
pub(crate) fn load_use_committed_data<S: StateReader>(
    hp: &mut SnosHintProcessor<'_, S>,
    mut ctx: HintContext<'_>,
) -> OsHintResult {
    ctx.insert_value(Ids::UseCommittedData, usize::from(hp.os_hints_config.use_committed_data))?;
    Ok(())
}

/// Supplies private witness data only. The Cairo program checks membership and the response.
pub(crate) fn load_committed_data_witness<S: StateReader>(
    hp: &mut SnosHintProcessor<'_, S>,
    mut ctx: HintContext<'_>,
) -> OsHintResult {
    let root = ctx.get_integer(Ids::CommittedDataRoot)?;
    let index = ctx.get_integer(Ids::CommittedDataKey)?;
    let witness = hp.committed_data_witness(root, index).ok_or_else(|| {
        OsHintError::AssertionFailed { message: "CommittedData witness unavailable".into() }
    })?;
    let path = ctx.vm.add_memory_segment();
    let values: Vec<MaybeRelocatable> = witness
        .siblings
        .iter()
        .flat_map(|step| [starknet_types_core::felt::Felt::from(step.bit).into(), step.hash.into()])
        .collect();
    ctx.vm.load_data(path, &values)?;
    ctx.insert_value(Ids::CommittedDataSiblings, path)?;
    ctx.insert_value(Ids::CommittedDataValue, witness.value)?;
    ctx.insert_value(Ids::CommittedDataHeight, witness.siblings.len())?;
    Ok(())
}

/// Merge the requested paths for this call only. Cairo verifies the minimal union, request mapping,
/// and work counts; the hint does not authorize values or determine an unconstrained fee.
pub(crate) fn load_committed_data_batch<S: StateReader>(
    hp: &mut SnosHintProcessor<'_, S>,
    mut ctx: HintContext<'_>,
) -> OsHintResult {
    use blockifier::execution::syscalls::committed_data::{
        CommittedDataBatchProof,
        MAX_COMMITTED_DATA_READ_KEYS,
    };
    use cairo_vm::hint_processor::hint_processor_utils::felt_to_usize;
    let root = ctx.get_integer(Ids::CommittedDataRoot)?;
    let count = felt_to_usize(&ctx.get_integer(Ids::CommittedDataCount)?)?;
    if !(1..=MAX_COMMITTED_DATA_READ_KEYS).contains(&count) {
        return Err(OsHintError::AssertionFailed {
            message: "Invalid committed-data batch size".into(),
        });
    }
    let keys_ptr = ctx.get_ptr(Ids::CommittedDataKeys)?;
    let keys = (0..count)
        .map(|index| Ok(*ctx.vm.get_integer((keys_ptr + index)?)?))
        .collect::<Result<Vec<_>, OsHintError>>()?;
    let batch = CommittedDataBatchProof::new(root, &keys, |key| {
        Ok(hp.committed_data_witness(root, key).cloned())
    })
    .map_err(|error| OsHintError::AssertionFailed { message: error.to_string() })?;
    ctx.insert_value(Ids::CommittedDataBranchCount, batch.branches)?;
    ctx.insert_value(Ids::CommittedDataLeafCount, batch.unique_leaves())?;
    for (id, data) in [
        (Ids::CommittedDataProof, batch.proof),
        (Ids::CommittedDataLeaves, batch.leaves),
        (
            Ids::CommittedDataIndices,
            batch.indices.into_iter().map(starknet_types_core::felt::Felt::from).collect(),
        ),
    ] {
        let ptr = ctx.vm.add_memory_segment();
        let data: Vec<MaybeRelocatable> = data.into_iter().map(Into::into).collect();
        ctx.vm.load_data(ptr, &data)?;
        ctx.insert_value(id, ptr)?;
    }
    Ok(())
}

/// Supplies values and incremental branch claims. Both are constrained at block finalization.
pub(crate) fn load_committed_data_deferred<S: StateReader>(
    hp: &mut SnosHintProcessor<'_, S>,
    mut ctx: HintContext<'_>,
) -> OsHintResult {
    use blockifier::execution::syscalls::committed_data::CommittedDataBatchProof;
    use cairo_vm::hint_processor::hint_processor_utils::felt_to_usize;
    let root = ctx.get_integer(Ids::CommittedDataRoot)?;
    let request_count = felt_to_usize(&ctx.get_integer(Ids::CommittedDataCount)?)?;
    let request_keys = ctx.get_ptr(Ids::CommittedDataKeys)?;
    let request = (0..request_count)
        .map(|index| Ok(*ctx.vm.get_integer((request_keys + index)?)?))
        .collect::<Result<Vec<_>, OsHintError>>()?;
    hp.get_mut_current_execution_helper()?.os_logger.mark_committed_request(root, request);
    let start = ctx.get_ptr(Ids::CommittedDataCacheStart)?;
    let count = felt_to_usize(&ctx.get_integer(Ids::CommittedDataColdCount)?)?;
    let keys_ptr = ctx.get_ptr(Ids::CommittedDataColdKeys)?;
    let values_ptr = ctx.get_ptr(Ids::CommittedDataColdValues)?;
    let keys = (0..count)
        .map(|i| Ok(*ctx.vm.get_integer((keys_ptr + i)?)?))
        .collect::<Result<Vec<_>, OsHintError>>()?;
    let mut branches = 0;
    if !keys.is_empty() {
        let batch = CommittedDataBatchProof::new(root, &keys, |key| {
            Ok(hp.committed_data_witness(root, key).cloned())
        })
        .map_err(|e| OsHintError::AssertionFailed { message: e.to_string() })?;
        branches = batch
            .branch_hashes
            .iter()
            .filter(|hash| hp.committed_root_branch_cache.insert((start, **hash)))
            .count();
        for (i, key) in keys.iter().enumerate() {
            let value = hp.committed_data_witness(root, *key).unwrap().value;
            ctx.vm.insert_value((values_ptr + i)?, value)?;
        }
    }
    ctx.insert_value(Ids::CommittedDataBranchCount, branches)?;
    Ok(())
}

/// Builds one union for the exact squashed Cairo read set. Hint-side claims are never authority.
pub(crate) fn load_committed_data_root_union<S: StateReader>(
    hp: &mut SnosHintProcessor<'_, S>,
    mut ctx: HintContext<'_>,
) -> OsHintResult {
    use blockifier::execution::syscalls::committed_data::CommittedDataBatchProof;
    use cairo_vm::hint_processor::hint_processor_utils::felt_to_usize;
    use starknet_types_core::felt::Felt;
    let root = ctx.get_integer(Ids::CommittedDataRoot)?;
    let count = felt_to_usize(&ctx.get_integer(Ids::CommittedDataLeafCount)?)?;
    let leaves = ctx.get_ptr(Ids::CommittedDataLeaves)?;
    let keys = (0..count)
        .map(|i| Ok(*ctx.vm.get_integer((leaves + 3 * i)?)?))
        .collect::<Result<Vec<_>, OsHintError>>()?;
    let owners = (0..count)
        .map(|i| Ok(felt_to_usize(&*ctx.vm.get_integer((leaves + (3 * i + 2))?)?)?))
        .collect::<Result<Vec<_>, OsHintError>>()?;
    let batch = CommittedDataBatchProof::new_for_read_set(root, &keys, |key| {
        Ok(hp.committed_data_witness(root, key).cloned())
    })
    .map_err(|e| OsHintError::AssertionFailed { message: e.to_string() })?;
    fn emit(
        proof: &[Felt],
        cursor: &mut usize,
        owners: &[usize],
        counts: &mut std::collections::HashMap<usize, usize>,
        out: &mut Vec<Felt>,
    ) -> usize {
        let tag = proof[*cursor];
        let word = proof[*cursor + 1];
        *cursor += 2;
        if tag == Felt::ZERO {
            out.extend([tag, word]);
            return usize::MAX;
        }
        if tag == Felt::ONE {
            let index: usize = word.try_into().unwrap();
            out.extend([tag, word]);
            return owners[index];
        }
        assert_eq!(tag, Felt::TWO);
        let position = out.len();
        out.extend([tag, word, Felt::ZERO]);
        let left = emit(proof, cursor, owners, counts, out);
        let right = emit(proof, cursor, owners, counts, out);
        let owner = left.min(right);
        assert_ne!(owner, usize::MAX);
        let slot = counts.entry(owner).or_default();
        out[position + 2] = Felt::from(*slot);
        *slot += 1;
        owner
    }
    let mut proof = Vec::new();
    let mut cursor = 0;
    emit(&batch.proof, &mut cursor, &owners, &mut Default::default(), &mut proof);
    assert_eq!(cursor, batch.proof.len());
    let ptr = ctx.vm.add_memory_segment();
    let data: Vec<MaybeRelocatable> = proof.into_iter().map(Into::into).collect();
    ctx.vm.load_data(ptr, &data)?;
    ctx.insert_value(Ids::CommittedDataProof, ptr)?;
    ctx.insert_value(Ids::CommittedDataProofEnd, (ptr + data.len())?)?;
    Ok(())
}

/// Profiling only: neither hint supplies values consumed by Cairo constraints or charging.
pub(crate) fn start_committed_data_finalization<S: StateReader>(
    hp: &mut SnosHintProcessor<'_, S>,
    ctx: HintContext<'_>,
) -> OsHintResult {
    hp.committed_finalization_start = Some((
        ctx.vm.get_current_step(),
        ctx.get_ptr(Ids::RangeCheckPtr)?,
        ctx.get_ptr(Ids::CommittedDataBitwisePtr)?,
        ctx.get_ptr(Ids::CommittedPoseidonPtr)?,
    ));
    Ok(())
}
pub(crate) fn end_committed_data_finalization<S: StateReader>(
    hp: &mut SnosHintProcessor<'_, S>,
    ctx: HintContext<'_>,
) -> OsHintResult {
    use cairo_vm::types::builtin_name::BuiltinName;
    let (steps, rc, bitwise, poseidon) = hp.committed_finalization_start.take().unwrap();
    hp.committed_finalizations.push(cairo_vm::vm::runners::cairo_runner::ExecutionResources {
        n_steps: ctx.vm.get_current_step() - steps,
        n_memory_holes: 0,
        builtin_instance_counter: std::collections::BTreeMap::from([
            (BuiltinName::range_check, (ctx.get_ptr(Ids::RangeCheckPtr)? - rc)?),
            (BuiltinName::bitwise, (ctx.get_ptr(Ids::CommittedDataBitwisePtr)? - bitwise)? / 5),
            (BuiltinName::poseidon, (ctx.get_ptr(Ids::CommittedPoseidonPtr)? - poseidon)? / 6),
        ]),
    });
    Ok(())
}
