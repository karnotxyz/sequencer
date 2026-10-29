//! Canonical binary Patricia trie over full felt keys. Unary paths are implicit:
//! each branch commits its critical bit, and each leaf commits its full key.
use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Poseidon, StarkHash};

use super::CommittedDataError;

/// A canonical felt has at most 252 bits. This bounds paths, not the dataset's key space.
pub const COMMITTED_DATA_TREE_HEIGHT: usize = 252;
/// Per-import allocation bound, independent of key width and total retained DB size.
pub const MAX_COMMITTED_DATA_VALUES: usize = 524_288;
const LEAF_DOMAIN: Felt = Felt::from_hex_unchecked("0x43445f4d50545f4c4541465f5631");
const BRANCH_DOMAIN: Felt = Felt::from_hex_unchecked("0x43445f4d50545f4252414e43485f5631");

/// Application-defined key and value. Neither has pricing semantics in the node.
pub type CommittedDataEntry = (Felt, Felt);

/// A bottom-up proof step. Bits must strictly increase, so skipped unary paths cost no nodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedDataSibling {
    pub bit: u8,
    pub hash: Felt,
}

/// A branch in the compact persistent representation. IDs below the entry count are leaves;
/// other IDs address branches in postorder. The last branch is the root.
#[derive(Clone, Copy, Debug)]
pub struct CommittedDataBranch {
    pub bit: u8,
    pub left: u32,
    pub right: u32,
    pub hash: Felt,
}

/// Membership evidence for a single (root, key), independent of the reading contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedDataWitness {
    pub root: Felt,
    pub key: Felt,
    pub value: Felt,
    #[serde(deserialize_with = "deserialize_siblings")]
    pub siblings: Vec<CommittedDataSibling>,
}

fn deserialize_siblings<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Vec<CommittedDataSibling>, D::Error> {
    struct Path;
    impl<'de> serde::de::Visitor<'de> for Path {
        type Value = Vec<CommittedDataSibling>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("at most 252 Patricia branches")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut path = Vec::new();
            while let Some(step) = seq.next_element()? {
                if path.len() == COMMITTED_DATA_TREE_HEIGHT {
                    return Err(serde::de::Error::custom("Patricia path too long"));
                }
                path.push(step);
            }
            Ok(path)
        }
    }
    d.deserialize_seq(Path)
}

/// Leaf commitment distinguishes stored zero from absence and binds the entire key.
pub fn leaf(key: Felt, value: Felt) -> Felt {
    Poseidon::hash_array(&[LEAF_DOMAIN, key, value])
}
/// Branch tags occupy a disjoint domain from leaves and bind the compressed path's critical bit.
pub fn branch(bit: u8, left: Felt, right: Felt) -> Felt {
    Poseidon::hash_array(&[BRANCH_DOMAIN + Felt::from(bit), left, right])
}
/// Tests a least-significant-bit-numbered position in a canonical felt.
pub fn key_bit(key: Felt, bit: u8) -> bool {
    let bytes = key.to_bytes_be();
    bytes[31 - usize::from(bit) / 8] & (1 << (bit % 8)) != 0
}

impl CommittedDataWitness {
    /// Authenticate key, value, branch order and hashes against the exact requested root.
    pub fn verify(&self) -> bool {
        let mut previous = None;
        let mut node = leaf(self.key, self.value);
        for step in &self.siblings {
            if usize::from(step.bit) >= COMMITTED_DATA_TREE_HEIGHT
                || previous.is_some_and(|bit| step.bit <= bit)
            {
                return false;
            }
            node = if key_bit(self.key, step.bit) {
                branch(step.bit, step.hash, node)
            } else {
                branch(step.bit, node, step.hash)
            };
            previous = Some(step.bit);
        }
        node == self.root
    }
}

/// Sorted immutable entries plus exactly N-1 compressed branches; no sparse empty nodes.
#[derive(Debug)]
pub struct CommittedDataSet {
    entries: Vec<CommittedDataEntry>,
    branches: Vec<CommittedDataBranch>,
    root: Felt,
}
impl CommittedDataSet {
    /// Sorts keys and rejects duplicates. Input order never changes the root.
    pub fn new(mut entries: Vec<CommittedDataEntry>) -> Result<Self, CommittedDataError> {
        if entries.is_empty() || entries.len() > MAX_COMMITTED_DATA_VALUES {
            return Err(CommittedDataError::InvalidLength);
        }
        entries.sort_unstable_by_key(|entry| entry.0);
        if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(CommittedDataError::DuplicateKey);
        }
        let mut branches = Vec::with_capacity(entries.len() - 1);
        let (_, root) = build(&entries, 0, entries.len() as u32, &mut branches)?;
        Ok(Self { entries, branches, root })
    }
    pub fn root(&self) -> Felt {
        self.root
    }
    pub fn entries(&self) -> &[CommittedDataEntry] {
        &self.entries
    }
    pub fn branches(&self) -> &[CommittedDataBranch] {
        &self.branches
    }
    /// Hot execution needs the value and charged path length, without allocating or hashing a
    /// proof.
    pub fn value_and_depth(&self, key: Felt) -> Option<(Felt, usize)> {
        let count = self.entries.len();
        let mut id = count + self.branches.len() - 1;
        let mut depth = 0;
        while id >= count {
            let node = self.branches[id - count];
            id = if key_bit(key, node.bit) { node.right } else { node.left } as usize;
            depth += 1;
        }
        let (stored_key, value) = self.entries[id];
        (stored_key == key).then_some((value, depth))
    }
    /// Fetch membership only; a missing key must never be converted into a zero value.
    pub fn witness(&self, key: Felt) -> Option<CommittedDataWitness> {
        let index = self.entries.binary_search_by_key(&key, |entry| entry.0).ok()?;
        let count = self.entries.len();
        let mut id = (count + self.branches.len() - 1) as u32;
        let mut siblings = Vec::new();
        while id as usize >= count {
            let node = self.branches[id as usize - count];
            let (child, sibling) = if key_bit(key, node.bit) {
                (node.right, node.left)
            } else {
                (node.left, node.right)
            };
            let hash = if (sibling as usize) < count {
                let entry = self.entries[sibling as usize];
                leaf(entry.0, entry.1)
            } else {
                self.branches[sibling as usize - count].hash
            };
            siblings.push(CommittedDataSibling { bit: node.bit, hash });
            id = child;
        }
        debug_assert_eq!(id as usize, index);
        siblings.reverse();
        Some(CommittedDataWitness { root: self.root, key, value: self.entries[index].1, siblings })
    }
}

fn build(
    entries: &[CommittedDataEntry],
    offset: u32,
    count: u32,
    branches: &mut Vec<CommittedDataBranch>,
) -> Result<(u32, Felt), CommittedDataError> {
    if entries.len() == 1 {
        return Ok((offset, leaf(entries[0].0, entries[0].1)));
    }
    let first = entries[0].0.to_bytes_be();
    let last = entries[entries.len() - 1].0.to_bytes_be();
    // Keys are sorted and unique, so their first differing bit is the subtree's critical bit.
    let bit = first
        .iter()
        .zip(last)
        .enumerate()
        .find_map(|(i, (&a, b))| {
            let xor = a ^ b;
            (xor != 0).then(|| ((31 - i) * 8 + 7 - xor.leading_zeros() as usize) as u8)
        })
        .ok_or(CommittedDataError::DuplicateKey)?;
    let split = entries.partition_point(|entry| !key_bit(entry.0, bit));
    let (left, left_hash) = build(&entries[..split], offset, count, branches)?;
    let (right, right_hash) = build(&entries[split..], offset + split as u32, count, branches)?;
    let hash = branch(bit, left_hash, right_hash);
    let id = count + branches.len() as u32;
    branches.push(CommittedDataBranch { bit, left, right, hash });
    Ok((id, hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sparse_keys_can_reach_the_full_felt_width() {
        let mut entries = vec![(Felt::ZERO, Felt::ZERO)];
        for bit in 0..COMMITTED_DATA_TREE_HEIGHT {
            let mut bytes = [0_u8; 32];
            bytes[31 - bit / 8] = 1 << (bit % 8);
            entries.push((Felt::from_bytes_be(&bytes), Felt::from(bit)));
        }
        let tree = CommittedDataSet::new(entries).unwrap();
        let proof = tree.witness(Felt::ZERO).unwrap();
        assert_eq!(proof.siblings.len(), COMMITTED_DATA_TREE_HEIGHT);
        assert!(proof.verify());
        assert_eq!(
            tree.value_and_depth(Felt::ZERO),
            Some((Felt::ZERO, COMMITTED_DATA_TREE_HEIGHT))
        );
        let mut reordered = proof.clone();
        reordered.siblings.swap(0, 1);
        assert!(!reordered.verify());
        let mut repeated = proof;
        repeated.siblings[1].bit = repeated.siblings[0].bit;
        assert!(!repeated.verify());
        for &(key, value) in tree.entries() {
            let proof = tree.witness(key).unwrap();
            assert!(proof.verify());
            assert_eq!(proof.value, value);
        }
    }
    #[test]
    fn full_key_membership_is_order_independent_and_tamper_evident() {
        let entries: Vec<_> = [Felt::ZERO, Felt::ONE, Felt::from(65536_u32), Felt::MAX]
            .into_iter()
            .map(|key| (key, Felt::ZERO))
            .collect();
        let tree = CommittedDataSet::new(entries.clone()).unwrap();
        assert_eq!(
            tree.root(),
            CommittedDataSet::new(entries.into_iter().rev().collect()).unwrap().root()
        );
        for entry in tree.entries() {
            let proof = tree.witness(entry.0).unwrap();
            assert!(proof.verify());
            assert_eq!(tree.value_and_depth(entry.0), Some((entry.1, proof.siblings.len())));
            let mut bad = proof.clone();
            bad.key += Felt::ONE;
            assert!(!bad.verify());
            let mut bad = proof.clone();
            bad.value += Felt::ONE;
            assert!(!bad.verify());
            let mut bad = proof.clone();
            bad.siblings[0].hash += Felt::ONE;
            assert!(!bad.verify());
            let mut bad = proof.clone();
            bad.siblings[0].bit = 255;
            assert!(!bad.verify());
        }
        assert!(tree.witness(Felt::TWO).is_none());
        assert!(CommittedDataSet::new(vec![tree.entries()[0]; 2]).is_err());
        let one = CommittedDataSet::new(vec![tree.entries()[0]]).unwrap();
        assert!(one.witness(Felt::ZERO).unwrap().verify());
    }
}
