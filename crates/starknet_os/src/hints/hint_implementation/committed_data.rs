use blockifier::state::state_api::StateReader;
use cairo_vm::types::relocatable::MaybeRelocatable;

use crate::hint_processor::snos_hint_processor::SnosHintProcessor;
use crate::hints::error::{OsHintError, OsHintResult};
use crate::hints::types::HintContext;
use crate::hints::vars::Ids;

/// Supplies the bounded policy; Cairo commits the complete list into the OS configuration.
pub(crate) fn insert_committed_data_readers(
    ctx: &mut HintContext<'_>,
    readers: &starknet_api::committed_data::CommittedDataReaders,
) -> OsHintResult {
    let pointer = ctx.vm.add_memory_segment();
    let values: Vec<MaybeRelocatable> =
        readers.as_slice().iter().map(|reader| (*reader.0.key()).into()).collect();
    ctx.vm.load_data(pointer, &values)?;
    ctx.insert_value(Ids::CommittedDataReaders, pointer)?;
    ctx.insert_value(
        Ids::NCommittedDataReaders,
        starknet_types_core::felt::Felt::from(values.len()),
    )?;
    Ok(())
}

/// Supplies private witness data only. The Cairo program checks membership and the response.
pub(crate) fn load_committed_data_witness<S: StateReader>(
    hp: &mut SnosHintProcessor<'_, S>,
    mut ctx: HintContext<'_>,
) -> OsHintResult {
    let root = ctx.get_integer(Ids::CommittedDataRoot)?;
    let publisher = ctx.get_integer(Ids::CommittedDataPublisher)?;
    let index = ctx.get_integer(Ids::CommittedDataIndex)?;
    let witness = hp.committed_data_witness(root, publisher, index).ok_or_else(|| {
        OsHintError::AssertionFailed { message: "CommittedData witness unavailable".into() }
    })?;
    let path = ctx.vm.add_memory_segment();
    let values: Vec<MaybeRelocatable> = witness.siblings.iter().copied().map(Into::into).collect();
    ctx.vm.load_data(path, &values)?;
    ctx.insert_value(Ids::CommittedDataSiblings, path)?;
    ctx.insert_value(Ids::CommittedDataValue, witness.value)?;
    Ok(())
}
