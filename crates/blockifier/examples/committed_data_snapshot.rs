//! Build a complete committed_data tree and export only the witnesses requested for replay.
//! Usage: committed_data_snapshot input.json output-prefix
//! Input: {"entries":[["0x425443","0x7b"]],"keys":["0x425443"]}.
use std::fs::File;
use std::path::Path;

use blockifier::execution::syscalls::committed_data::CommittedDataSet;
use serde::Deserialize;
use starknet_types_core::felt::Felt;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    entries: Vec<(Felt, Felt)>,
    keys: Vec<Felt>,
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err("Usage: committed_data_snapshot input.json output-prefix".into());
    }
    let input: Input = serde_json::from_reader(File::open(&args[1])?)?;
    let start = std::time::Instant::now();
    let tree = CommittedDataSet::new(input.entries)?;
    let witnesses = input
        .keys
        .iter()
        .map(|key| tree.witness(*key).ok_or("Key absent from dataset"))
        .collect::<Result<Vec<_>, _>>()?;
    for witness in &witnesses {
        if !witness.verify() {
            return Err("Witness verification failed".into());
        }
    }
    serde_json::to_writer(
        File::create(Path::new(&format!("{}.snapshot.json", args[2])))?,
        &serde_json::json!({"root":tree.root(),"entries":tree.entries()}),
    )?;
    serde_json::to_writer(
        File::create(Path::new(&format!("{}.witnesses.json", args[2])))?,
        &witnesses,
    )?;
    println!(
        "{}",
        serde_json::json!({"root":tree.root(),"entry_count":tree.entries().len(),"witnesses":witnesses.len(),"build_ms":start.elapsed().as_millis()})
    );
    Ok(())
}
