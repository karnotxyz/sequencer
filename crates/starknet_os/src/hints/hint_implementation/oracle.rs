use blockifier::state::state_api::StateReader;
use cairo_vm::types::relocatable::MaybeRelocatable;
use starknet_types_core::felt::Felt;

use crate::hint_processor::snos_hint_processor::SnosHintProcessor;
use crate::hints::error::{OsHintError, OsHintResult};
use crate::hints::types::HintContext;
use crate::hints::vars::Ids;

/// Supplies private witness data only. The Cairo program checks membership and the response.
pub(crate) fn load_oracle_witness<S: StateReader>(
    hp: &mut SnosHintProcessor<'_, S>,
    mut ctx: HintContext<'_>,
) -> OsHintResult {
    let root = ctx.get_integer(Ids::OracleRoot)?;
    let publisher = ctx.get_integer(Ids::OraclePublisher)?;
    let asset = ctx.get_integer(Ids::OracleAsset)?;
    let witness = hp
        .os_hints_config
        .oracle_witnesses
        .iter()
        .find(|w| w.root == root && w.publisher == publisher && Felt::from(w.asset) == asset)
        .ok_or_else(|| OsHintError::AssertionFailed {
            message: "Oracle witness unavailable".into(),
        })?;
    let path = ctx.vm.add_memory_segment();
    let values: Vec<MaybeRelocatable> = witness.siblings.iter().copied().map(Into::into).collect();
    ctx.vm.load_data(path, &values)?;
    ctx.insert_value(Ids::OracleSiblings, path)?;
    ctx.insert_value(Ids::OraclePrice, Felt::from(witness.price))?;
    Ok(())
}
