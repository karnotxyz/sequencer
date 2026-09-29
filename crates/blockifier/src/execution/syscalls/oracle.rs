//! Experimental namespaced oracle. Witnesses are private execution input, never tx calldata.
//! The caller must read its authenticated root using ordinary storage before calling get_price.
use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use starknet_api::abi::abi_utils::selector_from_name;
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Poseidon, StarkHash};

use super::vm_syscall_utils::SyscallExecutorBaseError;

/// starknet_keccak(b"paradox_oracle_tick"): Keccak-256 truncated to 250 bits.
/// This is a protocol reservation, not an ordinary deployed contract.
pub const ORACLE_ADDRESS: Felt = Felt::from_hex_unchecked(
    "0x35b8b5f74b0dd94b43ac73391c85e8599f2af36c5c095bb734240c84b0c9995",
);
pub const ORACLE_TREE_HEIGHT: usize = 19;
pub const ORACLE_READ_GAS: u64 = 1_000_000;
const LEAF_DOMAIN: Felt = Felt::from_hex_unchecked("0x4f5241434c455f5631");

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OracleWitness {
    pub root: Felt,
    pub publisher: Felt,
    /// POC asset IDs are leaf indices, strictly below 2^19. No ambiguous duplicate leaves.
    pub asset: u32,
    pub price: u128,
    pub siblings: Vec<Felt>,
}

impl OracleWitness {
    pub fn verify(&self) -> bool {
        if self.siblings.len() != ORACLE_TREE_HEIGHT || self.asset >= 1 << ORACLE_TREE_HEIGHT {
            return false;
        }
        let mut node = Poseidon::hash_array(&[
            LEAF_DOMAIN,
            self.publisher,
            Felt::from(self.asset),
            Felt::from(self.price),
        ]);
        for (level, sibling) in self.siblings.iter().enumerate() {
            node = if (self.asset >> level) & 1 == 0 {
                Poseidon::hash(&node, sibling)
            } else {
                Poseidon::hash(sibling, &node)
            };
        }
        node == self.root
    }
}

/// Validated once on ingestion; immutable during execution. Indexed by exact root and publisher.
#[derive(Clone, Debug, Default)]
pub struct OracleWitnesses {
    witnesses: HashMap<(Felt, Felt, Felt), OracleWitness>,
    provider: Option<Arc<dyn OraclePriceProvider>>,
}

/// Providers must authenticate immutable data against the exact root before serving it.
/// Cairo independently checks the private witness during OS execution.
pub trait OraclePriceProvider: std::fmt::Debug + Send + Sync {
    fn price(&self, root: Felt, publisher: Felt, asset: u32) -> Result<Option<u128>, String>;
}

/// Complete, immutable indexed tree. Unused leaves are zero hashes, not valid zero-price quotes.
/// Store raw prices durably; rebuild and check the root before admitting a snapshot to this cache.
#[derive(Debug)]
pub struct OracleSnapshot {
    publisher: Felt,
    prices: Vec<u128>,
    levels: Vec<Vec<Felt>>,
}

impl OracleSnapshot {
    pub fn new(publisher: Felt, prices: Vec<u128>) -> Result<Self, String> {
        if prices.is_empty() || prices.len() > 1 << ORACLE_TREE_HEIGHT {
            return Err("Oracle snapshot length must be 1..=524288".into());
        }
        let mut leaves = vec![Felt::ZERO; 1 << ORACLE_TREE_HEIGHT];
        for (asset, price) in prices.iter().enumerate() {
            leaves[asset] = Poseidon::hash_array(&[
                LEAF_DOMAIN,
                publisher,
                Felt::from(asset),
                Felt::from(*price),
            ]);
        }
        let mut levels = vec![leaves];
        let mut active = prices.len();
        let mut empty = Felt::ZERO;
        for depth in 0..ORACLE_TREE_HEIGHT {
            active = active.div_ceil(2);
            empty = Poseidon::hash(&empty, &empty);
            let mut parents = vec![empty; levels[depth].len() / 2];
            for (index, pair) in levels[depth].chunks_exact(2).take(active).enumerate() {
                parents[index] = Poseidon::hash(&pair[0], &pair[1]);
            }
            levels.push(parents);
        }
        Ok(Self { publisher, prices, levels })
    }

    pub fn root(&self) -> Felt {
        self.levels[ORACLE_TREE_HEIGHT][0]
    }
    pub fn publisher(&self) -> Felt {
        self.publisher
    }
    pub fn prices(&self) -> &[u128] {
        &self.prices
    }
    pub fn price(&self, asset: u32) -> Option<u128> {
        self.prices.get(asset as usize).copied()
    }

    pub fn witness(&self, asset: u32) -> Option<OracleWitness> {
        let price = self.price(asset)?;
        let siblings = (0..ORACLE_TREE_HEIGHT)
            .map(|depth| self.levels[depth][((asset as usize) >> depth) ^ 1])
            .collect();
        Some(OracleWitness { root: self.root(), publisher: self.publisher, asset, price, siblings })
    }
}

impl OracleWitnesses {
    pub fn new(witnesses: Vec<OracleWitness>) -> Result<Self, String> {
        let mut values = HashMap::new();
        for witness in witnesses {
            if !witness.verify() {
                return Err("Invalid oracle witness".into());
            }
            let key = (witness.root, witness.publisher, Felt::from(witness.asset));
            if values.insert(key, witness).is_some() {
                return Err("Duplicate oracle witness".into());
            }
        }
        Ok(Self { witnesses: values, provider: None })
    }

    pub fn from_provider(provider: Arc<dyn OraclePriceProvider>) -> Self {
        Self { witnesses: HashMap::new(), provider: Some(provider) }
    }

    pub fn price(&self, root: Felt, publisher: Felt, asset: Felt) -> Result<Option<u128>, String> {
        if let Some(witness) = self.get(root, publisher, asset) {
            return Ok(Some(witness.price));
        }
        let asset: u32 = asset.try_into().map_err(|_| "Invalid oracle asset index")?;
        if asset >= 1 << ORACLE_TREE_HEIGHT {
            return Err("Invalid oracle asset index".into());
        }
        match &self.provider {
            Some(provider) => provider.price(root, publisher, asset),
            None => Ok(None),
        }
    }

    pub fn get(&self, root: Felt, publisher: Felt, asset: Felt) -> Option<&OracleWitness> {
        self.witnesses.get(&(root, publisher, asset))
    }
}

/// Shared VM/Native fast path. Missing data aborts execution instead of proving an arbitrary
/// revert.
pub fn read_price(
    witnesses: &OracleWitnesses,
    publisher: Felt,
    selector: Felt,
    calldata: &[Felt],
    remaining_gas: &mut u64,
) -> Result<Felt, SyscallExecutorBaseError> {
    let invalid = |info: &str| SyscallExecutorBaseError::InvalidSyscallInput {
        input: selector,
        info: info.into(),
    };
    if selector != selector_from_name("get_price").0 || calldata.len() != 2 {
        return Err(invalid("oracle expects get_price(root, asset_id)"));
    }
    let gas = remaining_gas
        .checked_sub(ORACLE_READ_GAS)
        .ok_or_else(|| invalid("insufficient oracle gas"))?;
    let price = witnesses
        .price(calldata[0], publisher, calldata[1])
        .map_err(|error| invalid(&error))?
        .ok_or_else(|| invalid("oracle witness unavailable for exact root, publisher and asset"))?;
    *remaining_gas = gas;
    Ok(Felt::from(price))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oracle_address_matches_namespace() {
        assert_eq!(ORACLE_ADDRESS, selector_from_name("paradox_oracle_tick").0);
        assert_ne!(ORACLE_ADDRESS, Felt::from(5_u32));
    }

    fn fixture() -> OracleWitness {
        OracleWitness {
            root: Felt::from_dec_str(
                "859002538335375945242249916931024040379542958783692256070336241944269298108",
            )
            .unwrap(),
            publisher: Felt::from(12345_u32),
            asset: 499999,
            price: 312345000000,
            siblings: (0..ORACLE_TREE_HEIGHT)
                .map(|i| Poseidon::hash(&Felt::from(i), &Felt::from(42_u32)))
                .collect(),
        }
    }

    #[test]
    fn oracle_cross_language_vector_and_cache_binding() {
        let w = fixture();
        assert!(w.verify());
        let cache = OracleWitnesses::new(vec![w.clone()]).unwrap();
        let mut gas = ORACLE_READ_GAS + 7;
        let price = read_price(
            &cache,
            w.publisher,
            selector_from_name("get_price").0,
            &[w.root, Felt::from(w.asset)],
            &mut gas,
        )
        .unwrap();
        assert_eq!(price, Felt::from(w.price));
        assert_eq!(gas, 7);
        assert!(cache.get(w.root + Felt::ONE, w.publisher, Felt::from(w.asset)).is_none());
        assert!(cache.get(w.root, w.publisher + Felt::ONE, Felt::from(w.asset)).is_none());
        assert!(cache.get(w.root, w.publisher, Felt::from(w.asset + 1)).is_none());
        assert!(OracleWitnesses::new(vec![w.clone(), w.clone()]).is_err());
        let mut bad = w;
        bad.price += 1;
        assert!(OracleWitnesses::new(vec![bad]).is_err());
    }
}
