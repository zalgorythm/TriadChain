// src/triad/structs.rs

//! TriadChain Triad Structs Module
//!
//! This module defines the core data structures for TriadChain triads (blocks),
//! including `TriadHeader` and `Triad`. It also provides methods for
//! calculating transaction Merkle roots, hashing triad headers, and validating
//! complete triads.

use blake3::Hasher;
#[allow(unused_imports)] // Serialize and Deserialize are for future use
use serde::{Serialize, Deserialize};

// Corrected import paths and removed unused ones
// TriadError is used in Triad::validate return type
use crate::errors::TriadError;
use crate::transaction::SignedTransaction;
use crate::state::merkle::MerkleTree; // Import MerkleTree for transaction root calculation

// Imports only used in tests, moved into cfg(test) block
// use crate::state::state_tree::StateTree;
// use crate::crypto::hash::blake3_hash;


/// The fixed size of a BLAKE3 hash output in bytes.
pub const HASH_SIZE: usize = 32;

/// Represents the header of a TriadChain triad (block).
///
/// Contains metadata necessary for chaining triads and validating their integrity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriadHeader {
    /// The version of the triad structure.
    pub version: u32,
    /// The hash of the previous triad's header, forming the blockchain link.
    pub previous_triad_hash: [u8; HASH_SIZE],
    /// The Merkle root of all transactions included in this triad.
    pub transactions_merkle_root: [u8; HASH_SIZE],
    /// The Merkle root of the state tree after applying transactions in this triad.
    pub state_merkle_root: [u8; HASH_SIZE],
    /// The timestamp when the triad was created (Unix epoch time).
    pub timestamp: u64,
    /// A random nonce used for Proof-of-Work (mining).
    pub nonce: u64,
    /// The target difficulty threshold for this triad (e.g., in compact form).
    pub difficulty_target: u64,
}

impl TriadHeader {
    /// Creates a new `TriadHeader`.
    ///
    /// # Arguments
    /// * `version` - The triad version.
    /// * `previous_triad_hash` - The hash of the previous triad.
    /// * `transactions_merkle_root` - The Merkle root of transactions.
    /// * `state_merkle_root` - The Merkle root of the state.
    /// * `timestamp` - The timestamp.
    /// * `nonce` - The nonce.
    /// * `difficulty_target` - The difficulty target.
    ///
    /// # Returns
    /// A new `TriadHeader` instance.
    pub fn new(
        version: u32,
        previous_triad_hash: [u8; HASH_SIZE],
        transactions_merkle_root: [u8; HASH_SIZE],
        state_merkle_root: [u8; HASH_SIZE],
        timestamp: u64,
        nonce: u64,
        difficulty_target: u64,
    ) -> Self {
        TriadHeader {
            version,
            previous_triad_hash,
            transactions_merkle_root,
            state_merkle_root,
            timestamp,
            nonce,
            difficulty_target,
        }
    }

    /// Computes the BLAKE3 hash of the `TriadHeader`.
    ///
    /// This hash uniquely identifies the triad header and is used in the Proof-of-Work.
    ///
    /// # Returns
    /// A 32-byte array representing the BLAKE3 hash of the header.
    pub fn calculate_hash(&self) -> [u8; HASH_SIZE] {
        let mut hasher = Hasher::new();
        hasher.update(&self.version.to_le_bytes()); // Use little-endian bytes
        hasher.update(&self.previous_triad_hash);
        hasher.update(&self.transactions_merkle_root);
        hasher.update(&self.state_merkle_root);
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.difficulty_target.to_le_bytes());
        hasher.finalize().as_bytes().clone()
    }

    /// Placeholder for Proof-of-Work verification.
    /// In a real implementation, this would check if `calculate_hash()` meets `difficulty_target`.
    pub fn verify_pow(&self) -> bool {
        // Dummy PoW verification: for now, just true.
        // In reality, you'd compare self.calculate_hash() against the self.difficulty_target.
        // E.g., `hash_to_u64(&self.calculate_hash()) <= self.difficulty_target`
        true
    }
}

/// Represents a complete TriadChain triad (block).
///
/// Contains the `TriadHeader` and a list of `SignedTransaction`s.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Triad {
    /// The header of the triad.
    pub header: TriadHeader,
    /// A list of signed transactions included in this triad.
    pub transactions: Vec<SignedTransaction>,
}

impl Triad {
    /// Creates a new `Triad`.
    ///
    /// # Arguments
    /// * `header` - The `TriadHeader` for this triad.
    /// * `transactions` - A `Vec` of `SignedTransaction`s included in this triad.
    ///
    /// # Returns
    /// A new `Triad` instance.
    pub fn new(header: TriadHeader, transactions: Vec<SignedTransaction>) -> Self {
        Triad {
            header,
            transactions,
        }
    }

    /// Computes the Merkle root of all transactions in the triad.
    ///
    /// Each transaction is hashed, and these hashes form the leaves of a Merkle tree.
    ///
    /// # Returns
    /// A 32-byte array representing the Merkle root of the transactions.
    /// Returns an all-zero hash if there are no transactions.
    pub fn calculate_transactions_merkle_root(&self) -> [u8; HASH_SIZE] {
        if self.transactions.is_empty() {
            return [0u8; HASH_SIZE]; // Return a fixed hash for an empty set of transactions
        }

        let transaction_hashes: Vec<[u8; HASH_SIZE]> = self.transactions
            .iter()
            .map(|tx| tx.calculate_hash()) // Call calculate_hash on SignedTransaction
            .collect();

        // Use the MerkleTree to compute the root
        let merkle_tree = MerkleTree::new(transaction_hashes)
            .expect("Failed to create MerkleTree from transaction hashes. This should not happen with non-empty list.");
        merkle_tree.root()
    }

    /// Validates the triad, including its header and transactions.
    ///
    /// This is a high-level validation function that combines several checks.
    ///
    /// # Arguments
    /// * `expected_state_merkle_root` - The expected Merkle root of the state tree *before*
    ///                                  applying transactions in this triad. This is important
    ///                                  for ensuring the previous state was correctly referenced.
    /// # Returns
    /// `Ok(())` if the triad is valid, or a `TriadError` if any validation fails.
    pub fn validate(&self, expected_state_merkle_root: [u8; HASH_SIZE]) -> Result<(), TriadError> {
        // 1. Verify Proof-of-Work (difficulty target)
        if !self.header.verify_pow() {
            return Err(TriadError::InvalidProofOfWork);
        }

        // 2. Verify `transactions_merkle_root` in header matches actual transactions.
        let actual_transactions_merkle_root = self.calculate_transactions_merkle_root();
        if self.header.transactions_merkle_root != actual_transactions_merkle_root {
            return Err(TriadError::TransactionsMerkleRootMismatch(
                self.header.transactions_merkle_root,
                actual_transactions_merkle_root,
            ));
        }

        // 3. Verify `state_merkle_root` in header matches the *expected* state root
        //    (i.e., the state root of the parent block, if we consider chaining).
        //    For actual state transition validation, a separate StateProcessor would be needed.
        if self.header.state_merkle_root != expected_state_merkle_root {
            return Err(TriadError::StateMerkleRootMismatch(
                self.header.state_merkle_root,
                expected_state_merkle_root,
            ));
        }

        // 4. Validate each transaction within the triad.
        //    This assumes `validate_signed_transaction` internally handles signature verification
        //    and other transaction-specific rules.
        for (i, tx) in self.transactions.iter().enumerate() {
            // TransactionError and ConsensusError are only used here within the loop
            // for the error formatting, so their import is local.
            #[allow(unused_imports)]
            use crate::errors::{TransactionError, ConsensusError};
            if let Err(e) = crate::transaction::validate_signed_transaction(tx) {
                return Err(TriadError::TransactionValidationFailed(format!(
                    "Transaction {} failed validation: {:?}",
                    i, e
                )));
            }
        }

        // 5. Placeholder for more complex validation (e.g., sequential nonce checks,
        //    double-spend prevention, applying transactions to a temporary state).
        //    This would typically require access to the current global state (StateTree).

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    // Explicitly import StateTree and blake3_hash only for tests
    use crate::state::state_tree::StateTree;
    use crate::crypto::hash::blake3_hash;
    use crate::transaction::create_dummy_signed_transaction; // Keep SignedTransaction for test helper

    /// Helper function to create a dummy triad header.
    fn create_dummy_triad_header(
        prev_hash: [u8; HASH_SIZE],
        tx_merkle_root: [u8; HASH_SIZE],
        state_merkle_root: [u8; HASH_SIZE],
    ) -> TriadHeader {
        TriadHeader::new(
            1, // version
            prev_hash,
            tx_merkle_root,
            state_merkle_root,
            1678886400, // timestamp (Mar 15, 2023 00:00:00 UTC)
            12345,      // nonce
            1000,       // difficulty_target
        )
    }

    /// Tests `TriadHeader` creation and hash calculation.
    #[test]
    fn test_triad_header_creation_and_hash() {
        let prev_hash = [1u8; HASH_SIZE];
        let tx_merkle_root = [2u8; HASH_SIZE];
        let state_merkle_root = [3u8; HASH_SIZE];

        let header = create_dummy_triad_header(prev_hash, tx_merkle_root, state_merkle_root);
        let header_hash = header.calculate_hash();

        // Ensure the hash is not all zeros (implies something was hashed)
        assert_ne!(header_hash, [0u8; HASH_SIZE]);

        // Change a field and ensure hash changes
        let mut modified_header = header.clone();
        modified_header.nonce = 54321;
        assert_ne!(header_hash, modified_header.calculate_hash());

        // Ensure consistency
        let header_recalc = create_dummy_triad_header(prev_hash, tx_merkle_root, state_merkle_root);
        assert_eq!(header_hash, header_recalc.calculate_hash());
    }

    /// Tests `Triad` creation.
    #[test]
    fn test_triad_creation() {
        let dummy_header = create_dummy_triad_header([0u8; HASH_SIZE], [0u8; HASH_SIZE], [0u8; HASH_SIZE]);
        let transactions = vec![
            create_dummy_signed_transaction(b"addr1", b"addr2", 10, 1, 1, b""),
            create_dummy_signed_transaction(b"addr3", b"addr4", 20, 2, 2, b""),
        ];
        let triad = Triad::new(dummy_header, transactions.clone());

        assert_eq!(triad.transactions.len(), 2);
        assert_eq!(triad.transactions[0], transactions[0]);
    }

    /// Tests `calculate_transactions_merkle_root`.
    #[test]
    fn test_calculate_transactions_merkle_root() {
        let dummy_header = create_dummy_triad_header([0u8; HASH_SIZE], [0u8; HASH_SIZE], [0u8; HASH_SIZE]);

        // Case 1: No transactions
        let triad_empty = Triad::new(dummy_header.clone(), Vec::new());
        assert_eq!(triad_empty.calculate_transactions_merkle_root(), [0u8; HASH_SIZE], "Empty transactions should yield zero hash root.");

        // Case 2: With transactions
        let tx1 = create_dummy_signed_transaction(b"A", b"B", 10, 1, 1, b"");
        let tx2 = create_dummy_signed_transaction(b"C", b"D", 20, 2, 2, b"");
        let transactions = vec![tx1.clone(), tx2.clone()];
        let triad = Triad::new(dummy_header.clone(), transactions.clone());

        let tx1_hash = tx1.calculate_hash(); // Now SignedTransaction has calculate_hash
        let tx2_hash = tx2.calculate_hash(); // Now SignedTransaction has calculate_hash

        // Manually calculate expected root
        let leaves = vec![tx1_hash, tx2_hash];
        let expected_merkle_tree = MerkleTree::new(leaves).unwrap();
        let expected_root = expected_merkle_tree.root();

        assert_eq!(triad.calculate_transactions_merkle_root(), expected_root, "Transaction Merkle root should match manual calculation.");
    }

    /// Tests `Triad::validate` method.
    #[test]
    fn test_triad_validation() {
        let mut state_tree = StateTree::new();
        // Set some dummy data in state_tree to get a non-zero root
        state_tree.set(blake3_hash(b"key1").to_vec(), b"value1".to_vec()).unwrap();
        let initial_state_root = state_tree.root_hash();

        let tx1 = create_dummy_signed_transaction(b"sender1", b"receiver1", 50, 1, 1678886000, b"data1");
        let tx2 = create_dummy_signed_transaction(b"sender2", b"receiver2", 75, 2, 1678886010, b"data2");
        let transactions = vec![tx1.clone(), tx2.clone()];

        let tx_merkle_root = Triad::new(
            create_dummy_triad_header([0u8; HASH_SIZE], [0u8; HASH_SIZE], [0u8; HASH_SIZE]),
            transactions.clone(),
        ).calculate_transactions_merkle_root();

        // Valid Triad
        let valid_header = create_dummy_triad_header(
            [0u8; HASH_SIZE],
            tx_merkle_root,
            initial_state_root, // Expected state root should match the *current* state root
        );
        let valid_triad = Triad::new(valid_header, transactions.clone());
        assert!(valid_triad.validate(initial_state_root).is_ok(), "Valid triad should pass validation.");

        // Triad with mismatched transactions Merkle root
        let bad_tx_merkle_root = [99u8; HASH_SIZE]; // Deliberately wrong
        let header_bad_tx_root = create_dummy_triad_header(
            [0u8; HASH_SIZE],
            bad_tx_merkle_root,
            initial_state_root,
        );
        let triad_bad_tx_root = Triad::new(header_bad_tx_root, transactions.clone());
        assert!(triad_bad_tx_root.validate(initial_state_root).is_err(), "Triad with bad transactions Merkle root should fail.");
        if let Err(TriadError::TransactionsMerkleRootMismatch(_, _)) = triad_bad_tx_root.validate(initial_state_root) {
            // Expected error type
        } else {
            panic!("Expected TransactionsMerkleRootMismatch error.");
        }


        // Triad with mismatched state Merkle root
        let bad_state_root = [88u8; HASH_SIZE]; // Deliberately wrong
        let header_bad_state_root = create_dummy_triad_header(
            [0u8; HASH_SIZE],
            tx_merkle_root,
            bad_state_root, // Header's state root is wrong
        );
        let triad_bad_state_root = Triad::new(header_bad_state_root, transactions.clone());
        // Validation fails because the header's state_merkle_root does not match the *passed in* expected_state_merkle_root
        assert!(triad_bad_state_root.validate(initial_state_root).is_err(), "Triad with bad state Merkle root should fail.");
        if let Err(TriadError::StateMerkleRootMismatch(_, _)) = triad_bad_state_root.validate(initial_state_root) {
            // Expected error type
        } else {
            panic!("Expected StateMerkleRootMismatch error.");
        }

        // Triad with invalid transaction (e.g., zero amount)
        let invalid_tx = create_dummy_signed_transaction(b"sender_bad", b"receiver_bad", 0, 3, 1678886020, b"bad_data");
        let mut transactions_with_invalid = transactions.clone();
        transactions_with_invalid.push(invalid_tx);

        let tx_merkle_root_with_invalid = Triad::new(
            create_dummy_triad_header([0u8; HASH_SIZE], [0u8; HASH_SIZE], [0u8; HASH_SIZE]),
            transactions_with_invalid.clone(),
        ).calculate_transactions_merkle_root();

        let header_with_invalid_tx = create_dummy_triad_header(
            [0u8; HASH_SIZE],
            tx_merkle_root_with_invalid,
            initial_state_root,
        );
        let triad_with_invalid_tx = Triad::new(header_with_invalid_tx, transactions_with_invalid);
        assert!(triad_with_invalid_tx.validate(initial_state_root).is_err(), "Triad with invalid transaction should fail.");
        if let Err(TriadError::TransactionValidationFailed(_)) = triad_with_invalid_tx.validate(initial_state_root) {
            // Expected error type
        } else {
            panic!("Expected TransactionValidationFailed error.");
        }
    }
}
