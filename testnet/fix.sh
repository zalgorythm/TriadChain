#!/bin/bash

echo "Starting TriadChain fix script (Phase 13)..."

# Ensure we are in the correct directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR" || { echo "Error: Could not change to script directory."; exit 1; }

echo "Updating src/state/merkle.rs to fix Merkle proof generation for odd leaf counts..."
# Quoted EOF to prevent shell interpretation of Rust code
cat << 'EOF_MERKLE_PROOF_REVISED' > src/state/merkle.rs
// src/state/merkle.rs

//! TriadChain Merkle Tree Module
//!
//! This module provides the implementation for a Merkle Tree, a fundamental
//! data structure used for efficient and secure verification of large data sets.
//! It includes functionalities for building a Merkle tree from a list of hashes,
//! computing the Merkle root, and generating and verifying Merkle proofs.

use blake3::Hasher;

/// The fixed size of a BLAKE3 hash output in bytes.
pub const HASH_SIZE: usize = 32;

/// Represents a Merkle Tree.
///
/// Stores the layers of hashes from leaves to the root.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// Stores all layers of the tree, where `layers[0]` are the leaves,
    /// `layers[1]` are the hashes of the leaf pairs, and so on, up to the root.
    layers: Vec<Vec<[u8; HASH_SIZE]>>,
}

impl MerkleTree {
    /// Creates a new Merkle Tree from a vector of leaf hashes.
    ///
    /// The tree is built from the bottom up, hashing pairs of nodes until a
    /// single root hash is obtained. If there's an odd number of hashes at any
    /// layer, the last hash is duplicated.
    ///
    /// # Arguments
    /// * `leaves` - A vector of 32-byte arrays, representing the initial leaf hashes.
    ///
    /// # Returns
    /// A `Result` indicating the new `MerkleTree` or an error string if construction fails.
    pub fn new(leaves: Vec<[u8; HASH_SIZE]>) -> Result<Self, String> {
        if leaves.is_empty() {
            // Handle empty tree case: a single zero-hash root
            let mut layers = Vec::new();
            layers.push(vec![[0u8; HASH_SIZE]]); // Represents an empty tree with a default root
            return Ok(MerkleTree { layers });
        }

        let mut current_layer = leaves;
        let mut layers = Vec::new();
        layers.push(current_layer.clone());

        while current_layer.len() > 1 {
            let mut next_layer = Vec::new();
            let mut i = 0;
            while i < current_layer.len() {
                let left = current_layer[i];
                let right = if i + 1 < current_layer.len() {
                    current_layer[i + 1]
                } else {
                    // Duplicate the last hash if the number of nodes is odd
                    left
                };
                let combined_hash = Self::hash_nodes(&left, &right);
                next_layer.push(combined_hash);
                i += 2;
            }
            current_layer = next_layer;
            layers.push(current_layer.clone());
        }

        Ok(MerkleTree { layers })
    }

    /// Computes the hash of two concatenated nodes.
    fn hash_nodes(left: &[u8; HASH_SIZE], right: &[u8; HASH_SIZE]) -> [u8; HASH_SIZE] {
        let mut hasher = Hasher::new();
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().as_bytes().clone()
    }

    /// Gets the Merkle root of the tree.
    ///
    /// The root is the single hash at the top-most layer of the tree.
    ///
    /// # Returns
    /// A 32-byte array representing the Merkle root.
    pub fn root(&self) -> [u8; HASH_SIZE] {
        // The root is the only element in the last layer
        *self.layers.last().expect("Merkle tree should always have at least one layer.")
            .first().expect("The last layer should always have exactly one root hash.")
    }

    /// Generates a Merkle proof for a given leaf index.
    ///
    /// A Merkle proof consists of a list of (sibling_hash, is_left_sibling) tuples
    /// needed to reconstruct the path from the leaf to the root.
    ///
    /// # Arguments
    /// * `leaf_index` - The index of the leaf node for which to generate the proof.
    ///
    /// # Returns
    /// A `Result` containing the `MerkleProof` or an error string if the index is out of bounds.
    pub fn generate_proof(&self, leaf_index: usize) -> Result<MerkleProof, String> {
        let mut proof_steps = Vec::new();
        let mut current_index = leaf_index;

        if self.layers.is_empty() || leaf_index >= self.layers[0].len() {
            return Err("Leaf index out of bounds or empty tree.".to_string());
        }

        // Iterate through layers, starting from the leaves
        for i in 0..(self.layers.len() - 1) { // Stop before the root layer
            let current_layer = &self.layers[i];

            let (sibling_hash, is_left_sibling);

            if current_index % 2 == 0 {
                // Current node is a left child, sibling is to the right
                let right_sibling_index = current_index + 1;
                if right_sibling_index < current_layer.len() {
                    sibling_hash = current_layer[right_sibling_index];
                    is_left_sibling = false; // Sibling is to the right
                } else {
                    // This case means the current node is the last node in an odd-sized layer,
                    // and it was duplicated to form a pair. Its "sibling" is itself.
                    // For proof generation, we should use the duplicated value if it contributes
                    // to the parent hash. The original logic here was correct, but the test expectations
                    // for the 'l2' case needed adjustment.
                    // However, for correct Merkle tree behavior, if current_index is even and it's the last,
                    // its sibling IS itself for hashing purposes. The proof needs this sibling.
                    sibling_hash = current_layer[current_index]; // It's duplicated, so its sibling is itself.
                    is_left_sibling = false; // Treat it as if it's on the left, and its duplicate is on the right.
                }
            } else {
                // Current node is a right child, sibling is to the left
                let left_sibling_index = current_index - 1;
                sibling_hash = current_layer[left_sibling_index];
                is_left_sibling = true; // Sibling is to the left
            }
            proof_steps.push((sibling_hash, is_left_sibling));

            // Move to the parent node in the next layer
            current_index /= 2;
        }

        Ok(MerkleProof { proof_steps })
    }
}

/// Represents a Merkle proof for a specific leaf in a Merkle tree.
///
/// Contains the hashes of the sibling nodes and their relative position
/// (left/right) required to recompute the root from a leaf hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    /// The list of (sibling_hash, is_left_sibling) tuples needed to verify
    /// the leaf against the root. `true` means the sibling is to the left of the current hash.
    pub proof_steps: Vec<([u8; HASH_SIZE], bool)>,
}

impl MerkleProof {
    /// Verifies that a given leaf hash is part of a Merkle tree with the specified root.
    ///
    /// # Arguments
    /// * `root` - The expected Merkle root of the tree.
    /// * `leaf_hash` - The hash of the leaf node to verify.
    ///
    /// # Returns
    /// `true` if the leaf hash can be verified against the root using the proof, `false` otherwise.
    pub fn verify(&self, root: [u8; HASH_SIZE], leaf_hash: [u8; HASH_SIZE]) -> bool {
        let mut current_hash = leaf_hash;

        for (proof_hash, is_left_sibling) in &self.proof_steps {
            let mut hasher = Hasher::new();
            if *is_left_sibling {
                // Sibling is to the left: combine sibling then current hash
                hasher.update(proof_hash);
                hasher.update(&current_hash);
            } else {
                // Sibling is to the right: combine current hash then sibling
                hasher.update(&current_hash);
                hasher.update(proof_hash);
            }
            current_hash = hasher.finalize().as_bytes().clone();
        }
        current_hash == root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // blake3_hash is no longer directly used in tests, h is
    // use crate::crypto::hash::blake3_hash;

    /// Helper to create a fixed hash from a string.
    fn h(s: &str) -> [u8; HASH_SIZE] {
        let mut hasher = Hasher::new();
        hasher.update(s.as_bytes());
        hasher.finalize().as_bytes().clone()
    }

    #[test]
    fn test_merkle_tree_new_empty_leaves() {
        let leaves: Vec<[u8; HASH_SIZE]> = Vec::new();
        let tree = MerkleTree::new(leaves).unwrap();
        // Root of an empty tree is a single zero hash
        assert_eq!(tree.root(), [0u8; HASH_SIZE]);
        assert_eq!(tree.layers.len(), 1);
        assert_eq!(tree.layers[0].len(), 1);
    }

    #[test]
    fn test_merkle_tree_new_even_leaves() {
        let leaves = vec![h("a"), h("b"), h("c"), h("d")];
        let tree = MerkleTree::new(leaves.clone()).unwrap();

        // Expected structure for 4 leaves:
        // Root
        // /  \
        // L1_0 L1_1
        // / \  / \
        // a  b c  d

        // Expected root calculation:
        let h_ab = MerkleTree::hash_nodes(&h("a"), &h("b"));
        let h_cd = MerkleTree::hash_nodes(&h("c"), &h("d"));
        let expected_root = MerkleTree::hash_nodes(&h_ab, &h_cd);

        assert_eq!(tree.root(), expected_root);
        assert_eq!(tree.layers.len(), 3); // 3 layers: leaves, L1, root
        assert_eq!(tree.layers[0].len(), 4);
        assert_eq!(tree.layers[1].len(), 2);
        assert_eq!(tree.layers[2].len(), 1);
    }

    #[test]
    fn test_merkle_tree_new_odd_leaves() {
        let leaves = vec![h("a"), h("b"), h("c")];
        let tree = MerkleTree::new(leaves.clone()).unwrap();

        // Expected structure for 3 leaves (c is duplicated conceptually in tree building,
        // but not explicitly in layers after the first, or in proof steps for canonical building)
        // when odd, the last is duplicated for hashing up.
        //       Root
        //      /    \
        //     L1_0  L1_1
        //    /  \  /  \
        //   a   b c   c (c is duplicated)

        // Expected root calculation:
        let h_ab = MerkleTree::hash_nodes(&h("a"), &h("b"));
        let h_cc = MerkleTree::hash_nodes(&h("c"), &h("c")); // c duplicated
        let expected_root = MerkleTree::hash_nodes(&h_ab, &h_cc);

        assert_eq!(tree.root(), expected_root);
        assert_eq!(tree.layers.len(), 3); // leaves, L1, root
        assert_eq!(tree.layers[0].len(), 3); // Original leaves
        assert_eq!(tree.layers[1].len(), 2); // (ab), (cc)
        assert_eq!(tree.layers[2].len(), 1); // root
    }

    #[test]
    fn test_merkle_proof_generation_and_verification() {
        let leaves = vec![h("leaf0"), h("leaf1"), h("leaf2"), h("leaf3")];
        let tree = MerkleTree::new(leaves.clone()).unwrap();
        let root = tree.root();

        // Test proof for leaf0 (index 0, even)
        // Path: (leaf0, h("leaf1"), false) -> (h(leaf0_leaf1), h("leaf2_leaf3"), false)
        let proof0 = tree.generate_proof(0).unwrap();
        assert!(proof0.verify(root, leaves[0]), "Proof for leaf0 should verify.");
        // Expected proof steps for leaf0: (h("leaf1"), is_left_sibling=false), then (h("leaf2_leaf3"), is_left_sibling=false)
        assert_eq!(proof0.proof_steps.len(), 2);
        assert_eq!(proof0.proof_steps[0].0, leaves[1]); // Sibling of leaf0 is leaf1 (right sibling)
        assert!(!proof0.proof_steps[0].1); // is_left_sibling = false
        let h_l2l3 = MerkleTree::hash_nodes(&leaves[2], &leaves[3]);
        assert_eq!(proof0.proof_steps[1].0, h_l2l3); // Sibling of h(leaf0_leaf1) is h(leaf2_leaf3) (right sibling)
        assert!(!proof0.proof_steps[1].1); // is_left_sibling = false


        // Test proof for leaf1 (index 1, odd)
        // Path: (leaf1, h("leaf0"), true) -> (h(leaf0_leaf1), h("leaf2_leaf3"), false)
        let proof1 = tree.generate_proof(1).unwrap();
        assert!(proof1.verify(root, leaves[1]), "Proof for leaf1 should verify.");
        assert_eq!(proof1.proof_steps.len(), 2);
        assert_eq!(proof1.proof_steps[0].0, leaves[0]); // Sibling of leaf1 is leaf0 (left sibling)
        assert!(proof1.proof_steps[0].1); // is_left_sibling = true
        let h_l2l3 = MerkleTree::hash_nodes(&leaves[2], &leaves[3]);
        assert_eq!(proof1.proof_steps[1].0, h_l2l3); // Sibling of h(leaf0_leaf1) is h(leaf2_leaf3) (right sibling)
        assert!(!proof1.proof_steps[1].1); // is_left_sibling = false

        // Test proof for leaf2 (index 2, even)
        let proof2 = tree.generate_proof(2).unwrap();
        assert!(proof2.verify(root, leaves[2]), "Proof for leaf2 should verify.");

        // Test proof for leaf3 (index 3, odd)
        let proof3 = tree.generate_proof(3).unwrap();
        assert!(proof3.verify(root, leaves[3]), "Proof for leaf3 should verify.");

        // Test invalid proof (wrong leaf hash)
        assert!(!proof0.verify(root, h("wrong_leaf")), "Proof with wrong leaf hash should not verify.");

        // Test invalid proof (wrong root)
        let wrong_root = h("wrong_root");
        assert!(!proof0.verify(wrong_root, leaves[0]), "Proof with wrong root should not verify.");

        // Test proof for odd number of leaves (leaf2 duplicated in Merkle tree build logic for L1)
        let leaves_odd = vec![h("l0"), h("l1"), h("l2")];
        let tree_odd = MerkleTree::new(leaves_odd.clone()).unwrap();
        let root_odd = tree_odd.root();

        // l0 (index 0, even) -> sibling l1 (right)
        // combined hash h(l0l1)
        // l2 (index 2, even) -> no distinct sibling, so it's duplicated h(l2l2)
        // combined h(l0l1) and h(l2l2)
        let proof_l0_odd = tree_odd.generate_proof(0).unwrap();
        assert!(proof_l0_odd.verify(root_odd, leaves_odd[0]), "Proof for l0 (odd) should verify.");
        assert_eq!(proof_l0_odd.proof_steps.len(), 2); // 2 steps: (l1, false), (h(l2l2), false)
        assert_eq!(proof_l0_odd.proof_steps[0].0, leaves_odd[1]); // Sibling of l0 is l1 (right sibling)
        assert!(!proof_l0_odd.proof_steps[0].1); // is_left_sibling = false
        let h_l2l2 = MerkleTree::hash_nodes(&leaves_odd[2], &leaves_odd[2]);
        assert_eq!(proof_l0_odd.proof_steps[1].0, h_l2l2); // Sibling of h(l0l1) is h(l2l2) (right sibling)
        assert!(!proof_l0_odd.proof_steps[1].1); // is_left_sibling = false


        let proof_l1_odd = tree_odd.generate_proof(1).unwrap();
        assert!(proof_l1_odd.verify(root_odd, leaves_odd[1]), "Proof for l1 (odd) should verify.");
        assert_eq!(proof_l1_odd.proof_steps.len(), 2); // 2 steps: (l0, true), (h(l2l2), false)
        assert_eq!(proof_l1_odd.proof_steps[0].0, leaves_odd[0]); // Sibling of l1 is l0 (left sibling)
        assert!(proof_l1_odd.proof_steps[0].1); // is_left_sibling = true
        assert_eq!(proof_l1_odd.proof_steps[1].0, h_l2l2); // Sibling of h(l0l1) is h(l2l2) (right sibling)
        assert!(!proof_l1_odd.proof_steps[1].1); // is_left_sibling = false

        // Proof for l2 (index 2, even). This node was duplicated in the tree for the next layer.
        // It should have only one step in the proof, which is the hash of (l0,l1).
        let proof_l2_odd = tree_odd.generate_proof(2).unwrap();
        assert!(proof_l2_odd.verify(root_odd, leaves_odd[2]), "Proof for l2 (odd) should verify.");
        // The proof for l2 should have one step for the sibling h(l0l1), and another step for the "duplicate" l2 itself.
        assert_eq!(proof_l2_odd.proof_steps.len(), 2); // 2 steps: (l2_duplicate, false), (h(l0l1), true)
        // First step: sibling is l2 itself (as it was duplicated for hashing in the layer)
        assert_eq!(proof_l2_odd.proof_steps[0].0, leaves_odd[2]);
        assert!(!proof_l2_odd.proof_steps[0].1); // Treat as right sibling if current is left of its duplicate
        // Second step: sibling is the hash of l0l1
        let h_l0l1 = MerkleTree::hash_nodes(&leaves_odd[0], &leaves_odd[1]);
        assert_eq!(proof_l2_odd.proof_steps[1].0, h_l0l1);
        assert!(proof_l2_odd.proof_steps[1].1); // Sibling of (l2l2) is (l0l1) (left sibling)
    }
}
EOF_MERKLE_PROOF_REVISED

echo "Updating src/state/state_tree.rs to import updated MerkleProof struct..."
# Quoted EOF to prevent shell interpretation of Rust code
cat << 'EOF_STATE_TREE' > src/state/state_tree.rs
// src/state/state_tree.rs

//! TriadChain State Tree Module
//!
//! This module implements a Merkle Patricia Trie-like structure to manage the
//! blockchain's state. Each key-value pair in the state is hashed and stored
//! in a Merkle tree, allowing for efficient state root calculation and
//! Merkle proof generation.

use blake3::Hasher;
use std::collections::HashMap;

use crate::crypto::hash::blake3_hash;
use crate::state::merkle::{MerkleProof, MerkleTree, HASH_SIZE}; // HASH_SIZE is public


/// Represents the entire state of the TriadChain, managed as a Merkle tree.
///
/// This structure provides methods to set and get key-value pairs,
/// compute the state's Merkle root, and generate Merkle proofs.
#[derive(Debug, Clone)]
pub struct StateTree {
    /// A HashMap storing the actual key-value pairs.
    data: HashMap<Vec<u8>, Vec<u8>>,
    /// The Merkle tree built from the hashes of the key-value pairs.
    merkle_tree: MerkleTree,
    /// The current root hash of the state tree.
    root_hash: [u8; HASH_SIZE],
}

impl StateTree {
    /// Creates a new, empty `StateTree`.
    ///
    /// The initial Merkle tree will contain an empty root.
    pub fn new() -> Self {
        let empty_leaves: Vec<[u8; HASH_SIZE]> = Vec::new();
        let merkle_tree = MerkleTree::new(empty_leaves)
            .expect("Failed to create empty MerkleTree. This should not happen.");
        let root_hash = merkle_tree.root();

        StateTree {
            data: HashMap::new(),
            merkle_tree,
            root_hash,
        }
    }

    /// Gets the value associated with a given key.
    ///
    /// # Arguments
    /// * `key` - The key to look up.
    ///
    /// # Returns
    /// An `Option` containing a reference to the value if found, `None` otherwise.
    pub fn get(&self, key: &[u8]) -> Option<&Vec<u8>> {
        self.data.get(key)
    }

    /// Sets a key-value pair in the state tree.
    ///
    /// This operation updates the underlying Merkle tree and recomputes the root hash.
    ///
    /// # Arguments
    /// * `key` - The key to set.
    /// * `value` - The value to associate with the key.
    ///
    /// # Returns
    /// `Ok(())` on success, or an error if the Merkle tree reconstruction fails.
    pub fn set(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), String> {
        self.data.insert(key, value);
        self.recompute_root()?;
        Ok(())
    }

    /// Gets the current root hash of the state tree.
    ///
    /// # Returns
    /// A 32-byte array representing the current Merkle root hash.
    pub fn root_hash(&self) -> [u8; HASH_SIZE] {
        self.root_hash
    }

    /// Recomputes the Merkle tree and its root hash based on the current `data`.
    ///
    /// This method is called internally after modifications to the state.
    ///
    /// # Returns
    /// `Ok(())` on success, or an error if the Merkle tree reconstruction fails.
    fn recompute_root(&mut self) -> Result<(), String> {
        let mut leaves: Vec<([u8; HASH_SIZE], [u8; HASH_SIZE])> = self.data.iter()
            .map(|(k, v)| {
                // Hash both key and value to form a single leaf hash
                let mut hasher = Hasher::new();
                hasher.update(k);
                hasher.update(v);
                (blake3_hash(k), blake3_hash(v)) // Store original key and value hashes for proof generation
            })
            .collect();

        // Sort leaves by key hash for canonical tree construction
        leaves.sort_by_key(|(k_hash, _v_hash)| *k_hash);

        let leaf_hashes: Vec<[u8; HASH_SIZE]> = leaves.iter()
            .map(|(k_hash, v_hash)| {
                let mut hasher = Hasher::new();
                hasher.update(k_hash);
                hasher.update(v_hash);
                hasher.finalize().as_bytes().clone()
            })
            .collect();

        self.merkle_tree = MerkleTree::new(leaf_hashes)
            .map_err(|e| format!("Failed to recompute MerkleTree: {}", e))?;
        self.root_hash = self.merkle_tree.root();
        Ok(())
    }

    /// Generates a Merkle proof for a given key.
    ///
    /// This proof can be used to cryptographically verify that a key-value pair
    /// is indeed part of the state tree, given its root hash.
    ///
    /// # Arguments
    /// * `key` - The key for which to generate the proof.
    ///
    /// # Returns
    /// An `Option` containing a `MerkleProof` if the key exists, `None` otherwise.
    pub fn generate_merkle_proof(&self, key: &[u8]) -> Option<MerkleProof> {
        // Find the index of the key's hash in the sorted leaves
        let target_key_hash = blake3_hash(key);

        // We need to re-derive the leaf hashes exactly as they were used to build the MerkleTree
        // in recompute_root to find the correct index.
        let mut sorted_leaf_entries: Vec<([u8; HASH_SIZE], [u8; HASH_SIZE])> = self.data.iter()
            .map(|(k, v)| (blake3_hash(k), blake3_hash(v)))
            .collect();
        sorted_leaf_entries.sort_by_key(|(k_hash, _v_hash)| *k_hash);

        // Find the index of the target_key_hash in the sorted list of key hashes
        let leaf_index = sorted_leaf_entries.iter()
            .position(|(k_hash, _v_hash)| *k_hash == target_key_hash)?;

        // The generate_proof method of MerkleTree returns a Result, so we need to handle it.
        // We convert the Result<MerkleProof, String> into an Option<MerkleProof>
        // by mapping Ok to Some and Err to None.
        self.merkle_tree.generate_proof(leaf_index).ok()
    }
}

impl Default for StateTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::blake3_hash;

    #[test]
    fn test_state_tree_new_and_root_hash() {
        let tree = StateTree::new();
        // An empty Merkle tree has a specific, consistent root hash (often all zeros for 0 leaves)
        assert_eq!(tree.root_hash(), MerkleTree::new(Vec::new()).unwrap().root());
        assert!(tree.data.is_empty());
    }

    #[test]
    fn test_state_tree_set_and_get() {
        let mut tree = StateTree::new();
        let key1 = b"key1".to_vec();
        let value1 = b"value1".to_vec();
        let key2 = b"key2".to_vec();
        let value2 = b"value2".to_vec();

        // Test set operation
        assert!(tree.set(key1.clone(), value1.clone()).is_ok());
        assert!(tree.set(key2.clone(), value2.clone()).is_ok());

        // Test get operation
        assert_eq!(tree.get(&key1), Some(&value1));
        assert_eq!(tree.get(&key2), Some(&value2));
        assert_eq!(tree.get(b"non_existent_key"), None);

        // Test update
        let updated_value1 = b"updated_value1".to_vec();
        assert!(tree.set(key1.clone(), updated_value1.clone()).is_ok());
        assert_eq!(tree.get(&key1), Some(&updated_value1));
    }

    #[test]
    fn test_state_tree_recompute_root() {
        let mut tree = StateTree::new();
        let initial_root = tree.root_hash();

        // Add an item, root should change
        let key1 = b"key1".to_vec();
        let value1 = b"value1".to_vec();
        tree.set(key1.clone(), value1.clone()).unwrap();
        let root_after_one_item = tree.root_hash();
        assert_ne!(initial_root, root_after_one_item);

        // Add another item, root should change again
        let key2 = b"key2".to_vec();
        let value2 = b"key2".to_vec();
        tree.set(key2.clone(), value2.clone()).unwrap();
        let root_after_two_items = tree.root_hash();
        assert_ne!(root_after_one_item, root_after_two_items);

        // Setting same value for existing key, root should still change if MerkleTree recomputes based on new data
        // (even if data is same, the recomputation process is explicit)
        let previous_root = tree.root_hash();
        tree.set(key1.clone(), value1.clone()).unwrap(); // Set key1 to original value1
        let root_after_resetting_same_value = tree.root_hash();
        assert_eq!(previous_root, root_after_resetting_same_value); // Root should be the same if value content is the same
    }

    #[test]
    fn test_generate_merkle_proof() {
        let mut tree = StateTree::new();

        let key1 = b"key1".to_vec();
        let value1 = b"value1".to_vec();
        let key2 = b"key2".to_vec();
        let value2 = b"value2".to_vec();
        let key3 = b"key3".to_vec();
        let value3 = b"value3".to_vec();

        tree.set(key1.clone(), value1.clone()).unwrap();
        tree.set(key2.clone(), value2.clone()).unwrap();
        tree.set(key3.clone(), value3.clone()).unwrap();

        let root = tree.root_hash();

        // Test proof for key1
        let proof1 = tree.generate_merkle_proof(&key1).expect("Proof for key1 should exist.");
        // The leaf for verification needs to be the hash of (blake3_hash(key) + blake3_hash(value))
        // exactly as constructed in recompute_root.
        let leaf1_hash_key = blake3_hash(&key1);
        let leaf1_hash_value = blake3_hash(&value1);
        let mut leaf1_hasher = Hasher::new();
        leaf1_hasher.update(&leaf1_hash_key);
        leaf1_hasher.update(&leaf1_hash_value);
        let leaf1_final_hash = leaf1_hasher.finalize().as_bytes().clone();

        assert!(proof1.verify(root, leaf1_final_hash), "Proof for key1 should verify successfully.");

        // Test proof for key2
        let proof2 = tree.generate_merkle_proof(&key2).expect("Proof for key2 should exist.");
        let leaf2_hash_key = blake3_hash(&key2);
        let leaf2_hash_value = blake3_hash(&value2);
        let mut leaf2_hasher = Hasher::new();
        leaf2_hasher.update(&leaf2_hash_key);
        leaf2_hasher.update(&leaf2_hash_value);
        let leaf2_final_hash = leaf2_hasher.finalize().as_bytes().clone();
        assert!(proof2.verify(root, leaf2_final_hash), "Proof for key2 should verify successfully.");

        // Test proof for non-existent key
        let non_existent_key = b"non_existent".to_vec();
        assert!(tree.generate_merkle_proof(&non_existent_key).is_none(), "Proof for non-existent key should be None.");

        // Test proof verification with incorrect leaf hash
        let incorrect_leaf_hash = blake3_hash(b"some_other_data");
        assert!(!proof1.verify(root, incorrect_leaf_hash), "Proof verification with incorrect leaf hash should fail.");

        // Test proof verification with incorrect root
        let incorrect_root = [0xde; HASH_SIZE];
        assert!(!proof1.verify(incorrect_root, leaf1_final_hash), "Proof verification with incorrect root should fail.");
    }
}
EOF_STATE_TREE

echo "Updating src/consensus/mod.rs to fix unused imports and test failures..."
# Quoted EOF to prevent shell interpretation of Rust code
cat << 'EOF_CONSENSUS' > src/consensus/mod.rs
// src/consensus/mod.rs

//! TriadChain Consensus Module
//!
//! This module defines the core components and logic for the TriadChain's
//! consensus mechanism, including validator structures, proposals, and voting.

use blake3::Hasher;
#[allow(unused_imports)] // Serialize and Deserialize are for future use
use serde::{Serialize, Deserialize};
use std::collections::HashMap; // Import HashMap

use crate::errors::ConsensusError; // ConsensusError is used in public API
use crate::triad::structs::TriadHeader; // TriadHeader used in public API


/// The fixed size of a BLAKE3 hash output in bytes.
pub const HASH_SIZE: usize = 32;

/// Represents a validator participant in the consensus mechanism.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validator {
    /// The public key of the validator.
    pub public_key: Vec<u8>,
    /// The stake amount held by the validator (for Proof-of-Stake).
    pub stake: u64,
    /// A flag indicating if the validator is currently active.
    pub is_active: bool,
}

impl Validator {
    /// Creates a new `Validator` instance.
    ///
    /// # Arguments
    /// * `public_key` - The validator's public key.
    /// * `stake` - The amount of stake.
    /// * `is_active` - Initial active status.
    ///
    /// # Returns
    /// A new `Validator` instance.
    pub fn new(public_key: Vec<u8>, stake: u64, is_active: bool) -> Self {
        Validator {
            public_key,
            stake,
            is_active,
        }
    }

    /// Placeholder for signature verification logic.
    /// In a real system, this would use a cryptographic library
    /// to verify `self.signature` against a message
    /// using `self.public_key`.
    ///
    /// # Arguments
    /// * `message` - The message that was signed.
    /// * `signature` - The signature to verify.
    ///
    /// # Returns
    /// `true` if the signature is valid, `false` otherwise.
    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> bool {
        // Dummy verification: always true for now.
        // In a real system, use a cryptographic library (e.g., ed25519-dalek)
        // to verify the signature with self.public_key, message, and signature.
        let _ = message; // Suppress unused variable warning
        let _ = signature; // Suppress unused variable warning
        true
    }
}

/// Represents a proposed new triad (block) in the consensus process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriadProposal {
    /// The header of the proposed triad.
    pub header: TriadHeader,
    /// The signature of the validator proposing this triad.
    pub proposer_signature: Vec<u8>,
    /// The public key of the validator who proposed this triad.
    pub proposer_public_key: Vec<u8>,
}

impl TriadProposal {
    /// Creates a new `TriadProposal`.
    ///
    /// # Arguments
    /// * `header` - The `TriadHeader` being proposed.
    /// * `proposer_signature` - The signature of the proposer.
    /// * `proposer_public_key` - The public key of the proposer.
    ///
    /// # Returns
    /// A new `TriadProposal` instance.
    pub fn new(
        header: TriadHeader,
        proposer_signature: Vec<u8>,
        proposer_public_key: Vec<u8>,
    ) -> Self {
        TriadProposal {
            header,
            proposer_signature,
            proposer_public_key,
        }
    }

    /// Verifies the signature of the proposer against the triad header's hash.
    ///
    /// # Returns
    /// `Ok(())` if the signature is valid, or a `ConsensusError` otherwise.
    pub fn verify_signature(&self) -> Result<(), ConsensusError> {
        let header_hash = self.header.calculate_hash();
        // In a real system, use a cryptographic library to verify.
        // For now, assume signature is blake3_hash(header_hash + public_key)
        let mut expected_dummy_signature_hasher = Hasher::new();
        expected_dummy_signature_hasher.update(&header_hash);
        expected_dummy_signature_hasher.update(&self.proposer_public_key);
        let expected_dummy_signature = expected_dummy_signature_hasher.finalize().as_bytes().clone().to_vec();

        if self.proposer_signature == expected_dummy_signature {
            Ok(())
        } else {
            Err(ConsensusError::InvalidBlockProposal(
                "Proposer signature verification failed.".to_string(),
            ))
        }
    }
}

/// Represents a validator's vote on a `TriadProposal`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorVote {
    /// The hash of the `TriadProposal` being voted on.
    pub proposal_hash: [u8; HASH_SIZE],
    /// The signature of the validator casting the vote.
    pub validator_signature: Vec<u8>,
    /// The public key of the validator casting the vote.
    pub validator_public_key: Vec<u8>,
    /// The timestamp of the vote.
    pub timestamp: u64,
}

impl ValidatorVote {
    /// Creates a new `ValidatorVote`.
    ///
    /// # Arguments
    /// * `proposal_hash` - The hash of the proposal.
    /// * `validator_signature` - The signature of the validator.
    /// * `validator_public_key` - The public key of the validator.
    /// * `timestamp` - The timestamp of the vote.
    ///
    /// # Returns
    /// A new `ValidatorVote` instance.
    pub fn new(
        proposal_hash: [u8; HASH_SIZE],
        validator_signature: Vec<u8>,
        validator_public_key: Vec<u8>,
        timestamp: u64,
    ) -> Self {
        ValidatorVote {
            proposal_hash,
            validator_signature,
            validator_public_key,
            timestamp,
        }
    }

    /// Verifies the signature of the validator on the vote.
    ///
    /// # Returns
    /// `Ok(())` if the signature is valid, or a `ConsensusError` otherwise.
    pub fn verify_signature(&self) -> Result<(), ConsensusError> {
        // In a real system, use a cryptographic library to verify.
        // For now, use a dummy check: blake3_hash(proposal_hash + public_key + timestamp)
        let mut expected_dummy_signature_hasher = Hasher::new();
        expected_dummy_signature_hasher.update(&self.proposal_hash);
        expected_dummy_signature_hasher.update(&self.validator_public_key);
        expected_dummy_signature_hasher.update(&self.timestamp.to_le_bytes());
        let expected_dummy_signature = expected_dummy_signature_hasher.finalize().as_bytes().clone().to_vec();

        if self.validator_signature == expected_dummy_signature {
            Ok(())
        } else {
            Err(ConsensusError::InvalidValidatorVote(
                "Validator vote signature verification failed.".to_string(),
            ))
        }
    }
}

/// A simple consensus mechanism to simulate reaching a quorum.
///
/// In a real blockchain, this would be a complex state machine involving
/// communication between validators, fraud proofs, slashing conditions, etc.
/// This placeholder function simply checks if enough votes are gathered.
///
/// # Arguments
/// * `proposal` - The `TriadProposal` to reach consensus on.
/// * `votes` - A vector of `ValidatorVote`s received for the proposal.
/// * `active_validators` - A list of currently active validators and their stakes.
/// * `required_stake_percentage` - The percentage of total active stake required for consensus (e.g., 66 for 2/3).
///
/// # Returns
/// `Ok(())` if consensus is reached, or a `ConsensusError` otherwise.
#[allow(dead_code)] // This function might not be used directly in main.rs yet
pub fn reach_consensus(
    proposal: &TriadProposal,
    // Changed votes to borrow Vec<ValidatorVote> to avoid move errors in tests
    votes: &Vec<ValidatorVote>,
    active_validators: &[Validator],
    required_stake_percentage: u8,
) -> Result<(), ConsensusError> {
    // First, verify the proposal's signature
    proposal.verify_signature()?;

    let total_active_stake: u64 = active_validators.iter().map(|v| v.stake).sum();
    if total_active_stake == 0 {
        return Err(ConsensusError::Other(
            "No active validators to reach consensus.".to_string(),
        ));
    }

    let required_stake = (total_active_stake as f64 * (required_stake_percentage as f64 / 100.0)) as u64;

    let mut current_vote_stake: u64 = 0;
    let mut unique_voters = HashMap::new(); // To prevent double-voting by the same validator

    let proposal_hash = proposal.header.calculate_hash();

    for vote in votes { // Iterate over borrowed reference
        // Ensure the vote is for the correct proposal
        if vote.proposal_hash != proposal_hash {
            continue;
        }

        // Verify vote signature
        if let Err(_e) = vote.verify_signature() {
            // Log error but don't halt consensus for one bad vote
            // println!("Warning: Invalid vote signature from {:?}: {:?}", vote.validator_public_key, _e);
            continue;
        }

        // Find the validator and check if active
        if let Some(validator) = active_validators
            .iter()
            .find(|v| v.public_key == vote.validator_public_key && v.is_active)
        {
            // Check for double-voting
            if unique_voters.insert(validator.public_key.clone(), true).is_none() {
                current_vote_stake += validator.stake;
            }
        }
    }

    if current_vote_stake >= required_stake {
        Ok(())
    } else {
        Err(ConsensusError::QuorumNotReached)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    // Explicitly import Triad and create_dummy_signed_transaction only for tests
    #[allow(unused_imports)] // Only used in dummy test helper
    use crate::triad::structs::Triad;
    #[allow(unused_imports)] // Only used in dummy test helper
    use crate::transaction::create_dummy_signed_transaction;
    use crate::crypto::hash::blake3_hash; // Used for dummy_public_key
    use chrono::Utc; // Used for timestamps in tests

    /// Helper to create a dummy validator public key (using hash for simplicity)
    fn dummy_public_key(id: &str) -> Vec<u8> {
        blake3_hash(id.as_bytes()).to_vec()
    }

    // Removed generic dummy_signature helper, as signatures are now generated directly
    // to match specific verify_signature logic.

    /// Tests `Validator` creation.
    #[test]
    fn test_validator_creation() {
        let pub_key = dummy_public_key("validator_A");
        let validator = Validator::new(pub_key.clone(), 100, true);
        assert_eq!(validator.public_key, pub_key);
        assert_eq!(validator.stake, 100);
        assert!(validator.is_active);
    }

    /// Tests `TriadProposal` creation and signature verification.
    #[test]
    fn test_triad_proposal_creation_and_signature_verification() {
        let proposer_pk = dummy_public_key("proposer");
        let prev_triad_hash = [0u8; HASH_SIZE];
        let tx_merkle_root = [1u8; HASH_SIZE];
        let state_merkle_root = [2u8; HASH_SIZE];

        // Corrected: TriadHeader::new takes 7 arguments
        let dummy_header = TriadHeader::new(
            1, // version
            prev_triad_hash,
            tx_merkle_root,
            state_merkle_root,
            Utc::now().timestamp() as u64, // timestamp
            0, // nonce
            0  // difficulty_target
        );

        let proposal_hash_msg = dummy_header.calculate_hash();
        // Generate proposer signature to explicitly match TriadProposal::verify_signature logic
        let proposer_sig = {
            let mut hasher = Hasher::new();
            hasher.update(&proposal_hash_msg);
            hasher.update(&proposer_pk);
            hasher.finalize().as_bytes().clone().to_vec()
        };

        let proposal = TriadProposal::new(dummy_header.clone(), proposer_sig, proposer_pk.clone());

        assert!(proposal.verify_signature().is_ok(), "Proposal signature should verify correctly.");

        // Test with a bad signature
        let bad_proposer_sig = blake3_hash(b"wrong_message").to_vec(); // Directly create a wrong hash
        let bad_proposal = TriadProposal::new(dummy_header, bad_proposer_sig, proposer_pk);
        assert!(bad_proposal.verify_signature().is_err(), "Proposal with bad signature should fail verification.");
    }

    /// Tests `ValidatorVote` creation and signature verification.
    #[test]
    fn test_validator_vote_creation_and_signature_verification() {
        let proposal_hash = blake3_hash(b"some_proposal_content");
        let validator_pk = dummy_public_key("voter_A");
        let timestamp = Utc::now().timestamp() as u64;

        // Generate validator signature to explicitly match ValidatorVote::verify_signature logic
        let validator_sig = {
            let mut hasher = Hasher::new();
            hasher.update(&proposal_hash);
            hasher.update(&validator_pk);
            hasher.update(&timestamp.to_le_bytes());
            hasher.finalize().as_bytes().clone().to_vec()
        };

        let vote = ValidatorVote::new(proposal_hash, validator_sig, validator_pk.clone(), timestamp);

        assert!(vote.verify_signature().is_ok(), "Validator vote signature should verify correctly.");

        // Test with a bad signature
        let bad_validator_sig = blake3_hash(b"wrong_vote_message").to_vec(); // Directly create a wrong hash
        let bad_vote = ValidatorVote::new(proposal_hash, bad_validator_sig, validator_pk, timestamp);
        assert!(bad_vote.verify_signature().is_err(), "Vote with bad signature should fail verification.");
    }

    /// Tests the `reach_consensus` function.
    #[test]
    fn test_reach_consensus() {
        let proposer_pk = dummy_public_key("proposer");
        let prev_triad_hash = [0u8; HASH_SIZE];
        let tx_merkle_root = [1u8; HASH_SIZE];
        let state_merkle_root = [2u8; HASH_SIZE];

        let dummy_header = TriadHeader::new(
            1, // version
            prev_triad_hash,
            tx_merkle_root,
            state_merkle_root,
            Utc::now().timestamp() as u64, // timestamp
            0, // nonce
            0  // difficulty_target
        );
        let proposal_hash = dummy_header.calculate_hash();
        // Generate proposer signature in the same way verify_signature does
        let proposer_sig = {
            let mut hasher = Hasher::new();
            hasher.update(&proposal_hash);
            hasher.update(&proposer_pk);
            hasher.finalize().as_bytes().clone().to_vec()
        };
        let proposal = TriadProposal::new(dummy_header, proposer_sig, proposer_pk);

        let validator_a_pk = dummy_public_key("validator_A");
        let validator_b_pk = dummy_public_key("validator_B");
        let validator_c_pk = dummy_public_key("validator_C");

        let validator_a = Validator::new(validator_a_pk.clone(), 100, true);
        let validator_b = Validator::new(validator_b_pk.clone(), 200, true);
        let validator_c = Validator::new(validator_c_pk.clone(), 300, true);

        let active_validators = vec![
            validator_a.clone(),
            validator_b.clone(),
            validator_c.clone(),
        ];

        let timestamp_a = Utc::now().timestamp() as u64;
        let timestamp_b = Utc::now().timestamp() as u64 + 1; // Slightly different timestamp
        let timestamp_c = Utc::now().timestamp() as u64 + 2;

        // Generate signatures for each vote to explicitly match ValidatorVote::verify_signature logic
        let vote_a_sig = {
            let mut hasher = Hasher::new();
            hasher.update(&proposal_hash);
            hasher.update(&validator_a_pk);
            hasher.update(&timestamp_a.to_le_bytes());
            hasher.finalize().as_bytes().clone().to_vec()
        };
        let vote_b_sig = {
            let mut hasher = Hasher::new();
            hasher.update(&proposal_hash);
            hasher.update(&validator_b_pk);
            hasher.update(&timestamp_b.to_le_bytes());
            hasher.finalize().as_bytes().clone().to_vec()
        };
        let vote_c_sig = {
            let mut hasher = Hasher::new();
            hasher.update(&proposal_hash);
            hasher.update(&validator_c_pk);
            hasher.update(&timestamp_c.to_le_bytes());
            hasher.finalize().as_bytes().clone().to_vec()
        };

        let vote_a = ValidatorVote::new(
            proposal_hash,
            vote_a_sig,
            validator_a_pk,
            timestamp_a,
        );
        let vote_b = ValidatorVote::new(
            proposal_hash,
            vote_b_sig,
            validator_b_pk,
            timestamp_b,
        );
        let vote_c = ValidatorVote::new(
            proposal_hash,
            vote_c_sig,
            validator_c_pk,
            timestamp_c,
        );

        // Scenario 1: Quorum not reached (e.g., only A votes, 100 stake out of 600 total active)
        let votes_not_enough = vec![vote_a.clone()];
        assert!(reach_consensus(&proposal, &votes_not_enough, &active_validators, 67).is_err(), "Quorum should not be reached with insufficient votes.");

        // Scenario 2: Quorum reached (e.g., A, B, and C vote, 600 stake out of 600 total active)
        let votes_enough = vec![vote_a.clone(), vote_b.clone(), vote_c.clone()];
        assert!(reach_consensus(&proposal, &votes_enough, &active_validators, 67).is_ok(), "Quorum should be reached with enough votes.");

        // Scenario 3: Double voting by a validator (should still count only once)
        let votes_double_vote = vec![vote_a.clone(), vote_a.clone(), vote_b.clone()];
        // Total active stake: 600. Required for 67%: 402.
        // A (100) + B (200) = 300. Not enough.
        assert!(reach_consensus(&proposal, &votes_double_vote, &active_validators, 67).is_err(), "Double voting should not increase stake count.");

        // Scenario 4: Invalid vote signature (should be ignored)
        let bad_sig_vote_a = ValidatorVote::new(
            proposal_hash,
            // Generate a signature based on incorrect message to simulate bad signature
            blake3_hash(b"really_wrong_message").to_vec(), // Directly create a wrong hash
            validator_a.public_key.clone(),
            timestamp_a,
        );
        let votes_with_bad_sig = vec![bad_sig_vote_a, vote_b.clone(), vote_c.clone()];
        // A's vote is invalid, so only B (200) + C (300) = 500. Enough for 67%.
        assert!(reach_consensus(&proposal, &votes_with_bad_sig, &active_validators, 67).is_ok(), "Invalid vote signatures should be ignored.");


        // Scenario 5: No active validators
        assert!(reach_consensus(&proposal, &Vec::new(), &[], 67).is_err(), "Consensus should fail with no active validators.");

        // Scenario 6: Proposal signature fails
        let bad_proposer_pk = dummy_public_key("bad_proposer");
        let bad_proposer_sig_proposal = TriadProposal::new(
            TriadHeader::new(
                1,
                [0u8; HASH_SIZE], [1u8; HASH_SIZE], [2u8; HASH_SIZE],
                Utc::now().timestamp() as u64, 0, 0
            ),
            // This signature will be incorrect for the proposal's actual header hash + bad_proposer_pk
            blake3_hash(b"wrong_message_for_proposal").to_vec(), // Directly create a wrong hash
            bad_proposer_pk,
        );
        assert!(reach_consensus(&bad_proposer_sig_proposal, &votes_enough, &active_validators, 67).is_err(), "Consensus should fail if proposal signature is invalid.");
    }
}
EOF_CONSENSUS

echo "Fix script (Phase 13) completed. Please run 'cargo test' to check for compilation and test results."
