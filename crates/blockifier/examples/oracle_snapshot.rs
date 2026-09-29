//! Build a complete oracle tree and export only the witnesses requested for replay.
//! Usage: oracle_snapshot input.json output-prefix
//! Input: {"publisher":"0x...","prices":["123",...],"assets":[0,17,...]}.
use std::fs::File;
use std::path::Path;

use blockifier::execution::syscalls::oracle::OracleSnapshot;
use serde::Deserialize;
use starknet_types_core::felt::Felt;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    publisher: Felt,
    prices: Vec<String>,
    assets: Vec<u32>,
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err("Usage: oracle_snapshot input.json output-prefix".into());
    }
    let input: Input = serde_json::from_reader(File::open(&args[1])?)?;
    let prices = input.prices.iter().map(|p| p.parse::<u128>()).collect::<Result<Vec<_>, _>>()?;
    let start = std::time::Instant::now();
    let tree = OracleSnapshot::new(input.publisher, prices)?;
    let witnesses = input
        .assets
        .iter()
        .map(|asset| tree.witness(*asset).ok_or("Asset outside snapshot"))
        .collect::<Result<Vec<_>, _>>()?;
    for witness in &witnesses {
        if !witness.verify() {
            return Err("Witness verification failed".into());
        }
    }
    serde_json::to_writer(
        File::create(Path::new(&format!("{}.snapshot.json", args[2])))?,
        &serde_json::json!({"root":tree.root(),"publisher":input.publisher,"prices":input.prices}),
    )?;
    serde_json::to_writer(
        File::create(Path::new(&format!("{}.witnesses.json", args[2])))?,
        &witnesses,
    )?;
    println!(
        "{}",
        serde_json::json!({"root":tree.root(),"markets":tree.prices().len(),"witnesses":witnesses.len(),"build_ms":start.elapsed().as_millis()})
    );
    Ok(())
}
