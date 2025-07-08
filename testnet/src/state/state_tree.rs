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
