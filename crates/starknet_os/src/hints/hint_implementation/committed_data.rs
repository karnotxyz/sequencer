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
