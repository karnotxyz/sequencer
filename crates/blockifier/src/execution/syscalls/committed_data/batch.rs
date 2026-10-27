//! A batch-local union of membership paths. The trie format and individual witnesses are unchanged.
use std::collections::{BTreeMap, HashMap};

use starknet_types_core::felt::Felt;

use super::{
    branch,
    key_bit,
    leaf,
    CommittedDataError,
    CommittedDataSet,
    CommittedDataWitness,
    COMMITTED_DATA_TREE_HEIGHT,
    MAX_COMMITTED_DATA_READ_KEYS,
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
        result.indices = keys.iter().map(|key| unique[key]).collect();
        let mut requested: Vec<_> = unique.into_iter().collect();
        result.emit(root, COMMITTED_DATA_TREE_HEIGHT, &nodes, &mut requested)?;
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

    /// Expand only requested paths. A known hash may also occur in an unrequested sibling;
    /// expanding it there would duplicate leaves and can grow exponentially with path depth.
    fn emit(
        &mut self,
        hash: Felt,
        parent_bit: usize,
        nodes: &HashMap<Felt, Node>,
        keys: &mut [(Felt, usize)],
    ) -> Result<(), CommittedDataError> {
        if keys.is_empty() {
            self.proof.extend([Felt::ZERO, hash]);
            return Ok(());
        }
        match nodes.get(&hash) {
            None => return Err(CommittedDataError::InvalidWitness),
            Some(Node::Leaf { key, .. }) => {
                if keys.len() != 1 || keys[0].0 != *key {
                    return Err(CommittedDataError::InvalidWitness);
                }
                self.proof.extend([Felt::ONE, Felt::from(keys[0].1)]);
            }
            Some(Node::Branch { bit, left, right }) => {
                if usize::from(*bit) >= parent_bit {
                    return Err(CommittedDataError::InvalidWitness);
                }
                self.branches += 1;
                self.proof.extend([Felt::TWO, Felt::from(*bit)]);
                // Membership witnesses need not reveal the canonical shape of opaque subtrees.
                // Partition by this branch's bit rather than assuming numerical key order.
                keys.sort_unstable_by_key(|(key, _)| key_bit(*key, *bit));
                let split = keys.partition_point(|(key, _)| !key_bit(*key, *bit));
                let (left_keys, right_keys) = keys.split_at_mut(split);
                self.emit(*left, usize::from(*bit), nodes, left_keys)?;
                self.emit(*right, usize::from(*bit), nodes, right_keys)?;
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
    use super::super::{CommittedDataSet, CommittedDataSibling};
    use super::*;

    #[test]
    fn repeated_sibling_hashes_expand_only_the_requested_path() {
        let mut root = leaf(Felt::ZERO, Felt::ONE);
        let mut siblings = Vec::new();
        for bit in 0..COMMITTED_DATA_TREE_HEIGHT {
            siblings.push(CommittedDataSibling { bit: bit as u8, hash: root });
            root = branch(bit as u8, root, root);
        }
        let witness = CommittedDataWitness { root, key: Felt::ZERO, value: Felt::ONE, siblings };
        assert!(witness.verify());
        let proof =
            CommittedDataBatchProof::new(root, &[Felt::ZERO], |_| Ok(Some(witness.clone())))
                .unwrap();
        assert_eq!(proof.branches, COMMITTED_DATA_TREE_HEIGHT);
        assert_eq!(proof.proof.len(), 4 * COMMITTED_DATA_TREE_HEIGHT + 2);
        assert_eq!(proof.unique_leaves(), 1);
    }

    #[test]
    fn witness_union_routes_by_branch_bit_not_numeric_key_order() {
        // Individual witnesses authenticate routing, not the hidden subtrees' canonical shape.
        let left = leaf(Felt::TWO, Felt::from(10));
        let right = leaf(Felt::ONE, Felt::from(20));
        let root = branch(0, left, right);
        let proof = CommittedDataBatchProof::new(root, &[Felt::ONE, Felt::TWO], |key| {
            let (value, hash) = if key == Felt::ONE { (20, left) } else { (10, right) };
            let witness = CommittedDataWitness {
                root,
                key,
                value: Felt::from(value),
                siblings: vec![CommittedDataSibling { bit: 0, hash }],
            };
            assert!(witness.verify());
            Ok(Some(witness))
        })
        .unwrap();
        assert_eq!(
            proof.proof,
            [Felt::TWO, Felt::ZERO, Felt::ONE, Felt::ONE, Felt::ONE, Felt::ZERO]
        );
        assert_eq!(proof.indices, [0, 1]);
        assert_eq!(proof.branches, 1);
    }

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
