// src/triad/structs.rs

//! Defines the core data structures for TriadChain triads (blocks).

use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc}; // For timestamp
use blake3::Hasher; // For hashing
use crate::crypto::hash::blake3_hash; // Import blake3_hash
use crate::transaction::structs::SignedTransaction; // Import SignedTransaction
use crate::state::state_tree::StateTree; // Import StateTree

/// The size of a BLAKE3 hash in bytes.
const HASH_SIZE: usize = 32;

/// Represents the header of a TriadChain triad.
/// This contains metadata about the triad, including its hash, previous hash,
/// Merkle root of transactions, and timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] // Added Serialize/Deserialize
pub struct TriadHeader {
    pub hash: [u8; HASH_SIZE],          // Hash of this triad's header
    pub previous_hash: [u8; HASH_SIZE], // Hash of the previous triad's header
    pub transactions_merkle_root: [u8; HASH_SIZE], // Merkle root of all transactions in this triad
    pub state_merkle_root: [u8; HASH_SIZE], // Merkle root of the state after this triad
    pub timestamp: DateTime<Utc>,       // UTC timestamp of triad creation
    pub nonce: u64,                     // Nonce for Proof-of-Work (if applicable)
    pub difficulty: u64,                // Difficulty target for PoW
}

impl TriadHeader {
    /// Creates a new `TriadHeader`.
    #[allow(clippy::too_many_arguments)] // Allow many arguments for block header
    pub fn new(
        previous_hash: [u8; HASH_SIZE],
        transactions_merkle_root: [u8; HASH_SIZE],
        state_merkle_root: [u8; HASH_SIZE],
        timestamp: DateTime<Utc>,
        nonce: u64,
        difficulty: u64,
    ) -> Self {
        let mut header = TriadHeader {
            hash: [0u8; HASH_SIZE], // Placeholder, will be computed
            previous_hash,
            transactions_merkle_root,
            state_merkle_root,
            timestamp,
            nonce,
            difficulty,
        };
        header.hash = header.calculate_hash();
        header
    }

    /// Calculates the BLAKE3 hash of the triad header.
    /// This hash is used as the `hash` field of the header itself.
    pub fn calculate_hash(&self) -> [u8; HASH_SIZE] {
        let mut hasher = Hasher::new();
        hasher.update(&self.previous_hash);
        hasher.update(&self.transactions_merkle_root);
        hasher.update(&self.state_merkle_root);
        hasher.update(&self.timestamp.to_rfc3339().as_bytes()); // Convert DateTime to string for hashing
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.difficulty.to_le_bytes());
        hasher.finalize().as_bytes().clone()
    }
}

/// Represents a TriadChain triad (block).
/// A triad consists of a header and a list of signed transactions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] // Added Serialize/Deserialize
pub struct Triad {
    pub header: TriadHeader,
    pub transactions: Vec<SignedTransaction>,
}

impl Triad {
    /// Creates a new `Triad`.
    pub fn new(header: TriadHeader, transactions: Vec<SignedTransaction>) -> Self {
        Triad { header, transactions }
    }

    /// Calculates the Merkle root of the transactions within this triad.
    ///
    /// # Arguments
    /// * `transactions` - A slice of `SignedTransaction` to compute the Merkle root for.
    ///
    /// # Returns
    /// A 32-byte array representing the Merkle root hash.
    pub fn calculate_transactions_merkle_root(transactions: &[SignedTransaction]) -> [u8; HASH_SIZE] {
        if transactions.is_empty() {
            return [0u8; HASH_SIZE]; // Or a pre-defined empty root hash
        }
        let leaves: Vec<[u8; HASH_SIZE]> = transactions.iter()
            .map(|tx| tx.hash()) // Assuming SignedTransaction has a hash() method
            .collect();

        // This would ideally use your MerkleTree struct if it's implemented to handle Vec<[u8; HASH_SIZE]>
        // For now, a simple concatenation hash or a dummy hash if MerkleTree isn't ready.
        // For a proper MerkleTree, you'd build it from `leaves` and get its root.
        let mut hasher = Hasher::new();
        for leaf in leaves {
            hasher.update(&leaf);
        }
        hasher.finalize().as_bytes().clone()
    }

    /// Validates the entire triad.
    /// This is a placeholder for comprehensive triad validation.
    ///
    /// # Arguments
    /// * `previous_state_root` - The Merkle root of the state before this triad.
    ///
    /// # Returns
    /// `Ok(())` if the triad is valid, or an error otherwise.
    pub fn validate(&self, previous_state_root: [u8; HASH_SIZE]) -> Result<(), String> {
        // 1. Verify header hash
        if self.header.hash != self.header.calculate_hash() {
            return Err("Triad header hash mismatch".to_string());
        }

        // 2. Verify transactions Merkle root
        let calculated_tx_merkle_root = Self::calculate_transactions_merkle_root(&self.transactions);
        if self.header.transactions_merkle_root != calculated_tx_merkle_root {
            return Err("Transactions Merkle root mismatch in header".to_string());
        }

        // 3. Validate each transaction
        for tx in &self.transactions {
            if let Err(e) = tx.verify_signature() {
                return Err(format!("Invalid transaction signature: {:?}", e));
            }
            // Add more transaction-specific validation here (e.g., against state)
        }

        // 4. (Future) Validate state transition based on previous_state_root and current_state_root
        // This would involve applying transactions to a temporary state and verifying the new root.
        // if self.header.state_merkle_root != new_state.root_hash() { ... }

        // 5. (Future) Proof-of-Work or other consensus specific validation
        // if self.header.difficulty is met by self.header.hash { ... }

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::blake3_hash;
    use crate::transaction::structs::{Transaction, SignedTransaction}; // Import directly for tests
    use chrono::Utc;

    #[test]
    fn test_triad_header_creation_and_hash() {
        let prev_hash = blake3_hash(b"prev_hash").into();
        let tx_merkle_root = blake3_hash(b"tx_root").into();
        let state_merkle_root = blake3_hash(b"state_root").into();
        let timestamp = Utc::now();
        let nonce = 123;
        let difficulty = 456;

        let header = TriadHeader::new(
            prev_hash,
            tx_merkle_root,
            state_merkle_root,
            timestamp,
            nonce,
            difficulty,
        );

        assert_eq!(header.previous_hash, prev_hash);
        assert_eq!(header.transactions_merkle_root, tx_merkle_root);
        assert_eq!(header.state_merkle_root, state_merkle_root);
        assert_eq!(header.timestamp, timestamp);
        assert_eq!(header.nonce, nonce);
        assert_eq!(header.difficulty, difficulty);
        assert_eq!(header.hash, header.calculate_hash()); // Ensure hash is correctly set on creation
    }

    #[test]
    fn test_triad_creation() {
        let prev_hash = blake3_hash(b"prev_hash").into();
        let tx_merkle_root = blake3_hash(b"tx_root").into();
        let state_merkle_root = blake3_hash(b"state_root").into();
        let timestamp = Utc::now();
        let nonce = 1;
        let difficulty = 1;

        let header = TriadHeader::new(
            prev_hash,
            tx_merkle_root,
            state_merkle_root,
            timestamp,
            nonce,
            difficulty,
        );

        let tx1 = SignedTransaction::new(
            Transaction::new(blake3_hash(b"a").to_vec(), blake3_hash(b"b").to_vec(), 10, 1, Utc::now().timestamp_millis() as u64, b"".to_vec()),
            blake3_hash(b"sig1").to_vec(),
            blake3_hash(b"pub1").to_vec(),
        );
        let tx2 = SignedTransaction::new(
            Transaction::new(blake3_hash(b"c").to_vec(), blake3_hash(b"d").to_vec(), 20, 2, Utc::now().timestamp_millis() as u64, b"".to_vec()),
            blake3_hash(b"sig2").to_vec(),
            blake3_hash(b"pub2").to_vec(),
        );
        let transactions = vec![tx1.clone(), tx2.clone()];

        let triad = Triad::new(header.clone(), transactions.clone());

        assert_eq!(triad.header, header);
        assert_eq!(triad.transactions, transactions);
    }

    #[test]
    fn test_calculate_transactions_merkle_root() {
        let tx1 = SignedTransaction::new(
            Transaction::new(blake3_hash(b"a").to_vec(), blake3_hash(b"b").to_vec(), 10, 1, Utc::now().timestamp_millis() as u64, b"".to_vec()),
            blake3_hash(b"sig1").to_vec(),
            blake3_hash(b"pub1").to_vec(),
        );
        let tx2 = SignedTransaction::new(
            Transaction::new(blake3_hash(b"c").to_vec(), blake3_hash(b"d").to_vec(), 20, 2, Utc::now().timestamp_millis() as u64, b"".to_vec()),
            blake3_hash(b"sig2").to_vec(),
            blake3_hash(b"pub2").to_vec(),
        );
        let transactions = vec![tx1.clone(), tx2.clone()];

        let root = Triad::calculate_transactions_merkle_root(&transactions);
        assert_eq!(root.len(), HASH_SIZE);

        let empty_transactions: Vec<SignedTransaction> = Vec::new();
        let empty_root = Triad::calculate_transactions_merkle_root(&empty_transactions);
        assert_eq!(empty_root, [0u8; HASH_SIZE]);
    }

    #[test]
    fn test_triad_validation() {
        let prev_hash = blake3_hash(b"prev_hash").into();
        let tx_merkle_root = blake3_hash(b"tx_root").into();
        let state_merkle_root = blake3_hash(b"state_root").into();
        let timestamp = Utc::now();
        let nonce = 1;
        let difficulty = 1;

        let header = TriadHeader::new(
            prev_hash,
            tx_merkle_root,
            state_merkle_root,
            timestamp,
            nonce,
            difficulty,
        );

        let tx1 = SignedTransaction::new(
            Transaction::new(blake3_hash(b"a").to_vec(), blake3_hash(b"b").to_vec(), 10, 1, Utc::now().timestamp_millis() as u64, b"".to_vec()),
            blake3_hash(b"sig1").to_vec(),
            blake3_hash(b"pub1").to_vec(),
        );
        let transactions = vec![tx1.clone()];

        let valid_triad = Triad::new(header.clone(), transactions.clone());
        assert!(valid_triad.validate(state_merkle_root).is_ok());

        // Test with a tampered header hash
        let mut tampered_header = header.clone();
        tampered_header.hash = blake3_hash(b"tampered").into();
        let tampered_triad = Triad::new(tampered_header, transactions.clone());
        assert!(tampered_triad.validate(state_merkle_root).is_err());
        assert_eq!(tampered_triad.validate(state_merkle_root).unwrap_err(), "Triad header hash mismatch");

        // Test with tampered transactions merkle root
        let mut header_wrong_tx_root = header.clone();
        header_wrong_tx_root.transactions_merkle_root = blake3_hash(b"wrong_root").into();
        let triad_wrong_tx_root = Triad::new(header_wrong_tx_root, transactions.clone());
        assert!(triad_wrong_tx_root.validate(state_merkle_root).is_err());
        assert_eq!(triad_wrong_tx_root.validate(state_merkle_root).unwrap_err(), "Transactions Merkle root mismatch in header");
    }
}
