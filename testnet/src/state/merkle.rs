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
