//! A batch-local union of membership paths. The trie format and individual witnesses are unchanged.
use std::collections::{BTreeMap, HashMap};

use starknet_types_core::felt::Felt;

use super::{
    COMMITTED_DATA_TREE_HEIGHT,
    CommittedDataError,
    CommittedDataSet,
    CommittedDataWitness,
    MAX_COMMITTED_DATA_READ_KEYS,
    branch,
    key_bit,
    leaf,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Node {
    Leaf { key: Felt, value: Felt },
    Branch { bit: u8, left: Felt, right: Felt },
}

/// Private OS input for one batch. Cairo independently authenticates every returned value.
/// `proof` is preorder: [0, opaque_hash], [1, leaf_index] for a requested leaf, or [2, bit,
/// left..., right...]. Leaves are [key, value] pairs in first-request order. Indices restore
/// request order and duplicates.
#[derive(Debug, PartialEq, Eq)]
pub struct CommittedDataBatchProof {
    pub proof: Vec<Felt>,
    pub leaves: Vec<Felt>,
    pub indices: Vec<usize>,
    pub branches: usize,
}

impl CommittedDataBatchProof {
    /// Fetch each distinct key once and merge its authenticated path. No mutable cross-call cache
    /// or dataset reconstruction is needed. Missing keys remain availability failures, not zeroes.
    pub fn new(
        root: Felt,
        keys: &[Felt],
        mut witness: impl FnMut(Felt) -> Result<Option<CommittedDataWitness>, CommittedDataError>,
    ) -> Result<Self, CommittedDataError> {
        if keys.is_empty() || keys.len() > MAX_COMMITTED_DATA_READ_KEYS {
            return Err(CommittedDataError::InvalidLength);
        }
        let mut unique = BTreeMap::new();
        let mut nodes = HashMap::new();
        let mut branch_hashes = HashMap::new();
        let mut leaves = Vec::new();
        for &key in keys {
            if unique.contains_key(&key) {
                continue;
            }
            let witness = witness(key)?.ok_or(CommittedDataError::Unavailable)?;
            if witness.root != root || witness.key != key {
                return Err(CommittedDataError::InvalidWitness);
            }
            let mut hash = leaf(key, witness.value);
            insert(&mut nodes, hash, Node::Leaf { key, value: witness.value })?;
            let mut previous = None;
            for step in witness.siblings {
                if usize::from(step.bit) >= COMMITTED_DATA_TREE_HEIGHT
                    || previous.is_some_and(|bit| step.bit <= bit)
                {
                    return Err(CommittedDataError::InvalidWitness);
                }
                let (left, right) =
                    if key_bit(key, step.bit) { (step.hash, hash) } else { (hash, step.hash) };
                // Reuse native hashing as well as Cairo work on shared upper paths.
                hash = *branch_hashes
                    .entry((step.bit, left, right))
                    .or_insert_with(|| branch(step.bit, left, right));
                insert(&mut nodes, hash, Node::Branch { bit: step.bit, left, right })?;
                previous = Some(step.bit);
            }
            if hash != root {
                return Err(CommittedDataError::InvalidWitness);
            }
            unique.insert(key, leaves.len() / 2);
            leaves.extend([key, witness.value]);
        }
        let mut result = Self { proof: Vec::new(), leaves, indices: Vec::new(), branches: 0 };
        result.emit(root, COMMITTED_DATA_TREE_HEIGHT, &nodes, &unique)?;
        result.indices = keys.iter().map(|key| unique[key]).collect();
        Ok(result)
    }

    /// Build the identical union directly from an already-authenticated cached trie. Branch
    /// commitments are stored in the trie, so hot sequencer reads do not rehash membership paths.
    pub fn from_dataset(
        tree: &CommittedDataSet,
        keys: &[Felt],
    ) -> Result<Self, CommittedDataError> {
        if keys.is_empty() || keys.len() > MAX_COMMITTED_DATA_READ_KEYS {
            return Err(CommittedDataError::InvalidLength);
        }
        let mut unique = BTreeMap::new();
        let mut result = Self {
            proof: Vec::new(),
            leaves: Vec::new(),
            indices: Vec::with_capacity(keys.len()),
            branches: 0,
        };
        for key in keys {
            let index = if let Some(index) = unique.get(key) {
                *index
            } else {
                let entry = tree
                    .entries()
                    .binary_search_by_key(key, |entry| entry.0)
                    .map_err(|_| CommittedDataError::Unavailable)?;
                let index = result.unique_leaves();
                result.leaves.extend([*key, tree.entries()[entry].1]);
                unique.insert(*key, index);
                index
            };
            result.indices.push(index);
        }
        let sorted: Vec<_> = unique.into_iter().collect();
        result.emit_dataset(tree, tree.entries().len() + tree.branches().len() - 1, &sorted);
        Ok(result)
    }

    fn emit_dataset(&mut self, tree: &CommittedDataSet, id: usize, keys: &[(Felt, usize)]) {
        let count = tree.entries().len();
        if keys.is_empty() {
            let hash = if id < count {
                let (key, value) = tree.entries()[id];
                leaf(key, value)
            } else {
                tree.branches()[id - count].hash
            };
            self.proof.extend([Felt::ZERO, hash]);
        } else if id < count {
            self.proof.extend([Felt::ONE, Felt::from(keys[0].1)]);
        } else {
            let node = tree.branches()[id - count];
            let split = keys.partition_point(|(key, _)| !key_bit(*key, node.bit));
            self.branches += 1;
            self.proof.extend([Felt::TWO, Felt::from(node.bit)]);
            self.emit_dataset(tree, node.left as usize, &keys[..split]);
            self.emit_dataset(tree, node.right as usize, &keys[split..]);
        }
    }

    pub fn unique_leaves(&self) -> usize {
        self.leaves.len() / 2
    }

    /// Follow only expanded nodes; untouched subtrees are a single commitment. Strictly decreasing
    /// critical bits bound recursion even if a supplied path contains inconsistent node references.
    fn emit(
        &mut self,
        hash: Felt,
        parent_bit: usize,
        nodes: &HashMap<Felt, Node>,
        indices: &BTreeMap<Felt, usize>,
    ) -> Result<(), CommittedDataError> {
        match nodes.get(&hash) {
            None => self.proof.extend([Felt::ZERO, hash]),
            Some(Node::Leaf { key, .. }) => {
                self.proof.extend([Felt::ONE, Felt::from(indices[key])]);
            }
            Some(Node::Branch { bit, left, right }) => {
                if usize::from(*bit) >= parent_bit {
                    return Err(CommittedDataError::InvalidWitness);
                }
                self.branches += 1;
                self.proof.extend([Felt::TWO, Felt::from(*bit)]);
                self.emit(*left, usize::from(*bit), nodes, indices)?;
                self.emit(*right, usize::from(*bit), nodes, indices)?;
            }
        }
        Ok(())
    }
}

fn insert(
    nodes: &mut HashMap<Felt, Node>,
    hash: Felt,
    node: Node,
) -> Result<(), CommittedDataError> {
    if nodes.insert(hash, node).is_some_and(|existing| existing != node) {
        return Err(CommittedDataError::InvalidWitness);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::CommittedDataSet;
    use super::*;

    #[test]
    fn union_shares_branches_and_fetches_duplicates_once() {
        let tree = CommittedDataSet::new(
            (0..256_u32).map(|key| (key.into(), (key + 10).into())).collect(),
        )
        .unwrap();
        let keys = [Felt::from(3), Felt::from(2), Felt::from(3)];
        let mut fetched = 0;
        let proof = CommittedDataBatchProof::new(tree.root(), &keys, |key| {
            fetched += 1;
            Ok(tree.witness(key))
        })
        .unwrap();
        assert_eq!(proof, CommittedDataBatchProof::from_dataset(&tree, &keys).unwrap());
        assert_eq!(fetched, 2);
        assert_eq!(proof.branches, 8);
        assert_eq!(proof.unique_leaves(), 2);
        assert_eq!(proof.indices, [0, 1, 0]);
        assert_eq!(proof.leaves, [Felt::from(3), Felt::from(13), Felt::from(2), Felt::from(12)]);
    }

    #[test]
    fn cached_trie_union_matches_witness_union_for_sparse_full_width_keys() {
        let tree = CommittedDataSet::new(
            (0..300_u32)
                .map(|i| (leaf(Felt::from(i), Felt::MAX), Felt::from(i)))
                .chain([(Felt::ZERO, Felt::MAX), (Felt::MAX, Felt::ZERO)])
                .collect(),
        )
        .unwrap();
        for count in [1, 2, 100, 150, 1024] {
            let keys: Vec<_> =
                (0..count).map(|i| tree.entries()[(i * 17) % tree.entries().len()].0).collect();
            let paths =
                CommittedDataBatchProof::new(tree.root(), &keys, |key| Ok(tree.witness(key)))
                    .unwrap();
            assert_eq!(paths, CommittedDataBatchProof::from_dataset(&tree, &keys).unwrap());
        }
    }

    #[test]
    fn rejects_missing_or_mismatched_membership_before_building_union() {
        let tree = CommittedDataSet::new(vec![(Felt::ONE, Felt::ZERO)]).unwrap();
        assert!(
            CommittedDataBatchProof::new(tree.root(), &[Felt::TWO], |key| Ok(tree.witness(key)))
                .is_err()
        );
        assert!(
            CommittedDataBatchProof::new(
                tree.root(),
                &[Felt::TWO],
                |_| Ok(tree.witness(Felt::ONE))
            )
            .is_err()
        );
        assert!(
            CommittedDataBatchProof::new(Felt::ZERO, &[Felt::ONE], |key| Ok(tree.witness(key)))
                .is_err()
        );
    }
}
