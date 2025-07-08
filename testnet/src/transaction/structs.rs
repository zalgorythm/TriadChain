// src/transaction/structs.rs

//! TriadChain Transaction Structs Module
//!
//! This module defines the core data structures for TriadChain transactions,
//! including `Transaction` and `SignedTransaction`. It provides methods
//! for transaction creation, hashing, and signature verification.

use crate::errors::TransactionError;
use blake3::Hasher;
#[allow(unused_imports)] // Serialize and Deserialize are for future use
use serde::{Serialize, Deserialize};

/// The fixed size of a BLAKE3 hash output in bytes.
pub const HASH_SIZE: usize = 32;

/// Represents a raw, unsigned transaction.
///
/// This structure holds all the essential details of a transaction
/// before it is signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    /// The public address of the sender.
    pub from_address: Vec<u8>,
    /// The public address of the recipient.
    pub to_address: Vec<u8>,
    /// The amount of currency being transferred.
    pub amount: u64,
    /// A nonce to prevent replay attacks and ensure transaction ordering.
    pub nonce: u64,
    /// Timestamp of the transaction.
    pub timestamp: u64,
    /// Optional data payload for smart contracts or other purposes.
    pub data: Vec<u8>,
}

impl Transaction {
    /// Creates a new `Transaction`.
    ///
    /// # Arguments
    /// * `from_address` - Sender's address.
    /// * `to_address` - Recipient's address.
    /// * `amount` - Amount to send.
    /// * `nonce` - Transaction nonce.
    /// * `timestamp` - Transaction timestamp.
    /// * `data` - Optional data payload.
    ///
    /// # Returns
    /// A new `Transaction` instance.
    pub fn new(
        from_address: Vec<u8>,
        to_address: Vec<u8>,
        amount: u64,
        nonce: u64,
        timestamp: u64,
        data: Vec<u8>,
    ) -> Self {
        Transaction {
            from_address,
            to_address,
            amount,
            nonce,
            timestamp,
            data,
        }
    }

    /// Computes the BLAKE3 hash of the `Transaction`.
    ///
    /// This hash uniquely identifies the transaction content.
    ///
    /// # Returns
    /// A 32-byte array representing the BLAKE3 hash of the transaction.
    pub fn calculate_hash(&self) -> [u8; HASH_SIZE] {
        let mut hasher = Hasher::new();
        hasher.update(&self.from_address);
        hasher.update(&self.to_address);
        hasher.update(&self.amount.to_le_bytes());
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.data);
        hasher.finalize().as_bytes().clone()
    }
}

/// Represents a signed transaction ready for inclusion in a triad (block).
///
/// Contains the raw transaction, its digital signature, and the public key
/// of the signer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTransaction {
    /// The raw transaction content.
    pub transaction: Transaction,
    /// The digital signature of the transaction.
    pub signature: Vec<u8>,
    /// The public key of the sender, used to verify the signature.
    pub public_key: Vec<u8>,
}

impl SignedTransaction {
    /// Creates a new `SignedTransaction`.
    ///
    /// # Arguments
    /// * `transaction` - The raw `Transaction`.
    /// * `signature` - The digital signature.
    /// * `public_key` - The public key of the signer.
    ///
    /// # Returns
    /// A new `SignedTransaction` instance.
    pub fn new(transaction: Transaction, signature: Vec<u8>, public_key: Vec<u8>) -> Self {
        SignedTransaction {
            transaction,
            signature,
            public_key,
        }
    }

    /// Placeholder for signature verification logic.
    /// In a real implementation, this would use a cryptographic library
    /// to verify `self.signature` against `self.transaction.calculate_hash()`
    /// using `self.public_key`.
    ///
    /// # Returns
    /// `Ok(())` if the signature is valid, or a `TransactionError` otherwise.
    pub fn verify_signature(&self) -> Result<(), TransactionError> {
        // Dummy verification: always returns Ok for now.
        // In a real system:
        // 1. Recompute the hash of `self.transaction`.
        // 2. Use a crypto library (e.g., ed25519-dalek) to verify the signature
        //    with the public key and the transaction hash.
        // let tx_hash = self.transaction.calculate_hash();
        // if !crypto_lib::verify(&self.public_key, &tx_hash, &self.signature) {
        //     return Err(TransactionError::InvalidSignature("Signature verification failed".to_string()));
        // }
        Ok(())
    }

    /// Computes the BLAKE3 hash of the `SignedTransaction`.
    /// This includes hashing the raw transaction, signature, and public key to
    /// produce a unique identifier for the signed transaction.
    ///
    /// # Returns
    /// A 32-byte array representing the BLAKE3 hash of the signed transaction.
    pub fn calculate_hash(&self) -> [u8; HASH_SIZE] {
        let mut hasher = Hasher::new();
        hasher.update(&self.transaction.calculate_hash()); // Hash the inner transaction
        hasher.update(&self.signature);
        hasher.update(&self.public_key);
        hasher.finalize().as_bytes().clone()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use blake3; // Directly import blake3 for tests in this module

    #[test]
    fn test_transaction_creation() {
        let tx = Transaction::new(
            b"sender_addr".to_vec(),
            b"receiver_addr".to_vec(),
            100,
            1,
            1234567890,
            b"some data".to_vec(),
        );

        assert_eq!(tx.from_address, b"sender_addr".to_vec());
        assert_eq!(tx.to_address, b"receiver_addr".to_vec());
        assert_eq!(tx.amount, 100);
        assert_eq!(tx.nonce, 1);
        assert_eq!(tx.timestamp, 1234567890);
        assert_eq!(tx.data, b"some data".to_vec());
    }

    #[test]
    fn test_transaction_hash() {
        let tx1 = Transaction::new(
            b"sender1".to_vec(),
            b"receiver1".to_vec(),
            100,
            1,
            1234567890,
            b"data1".to_vec(),
        );
        let tx2 = tx1.clone(); // Identical transaction
        let tx3 = Transaction::new(
            b"sender2".to_vec(), // Different sender
            b"receiver1".to_vec(),
            100,
            1,
            1234567890,
            b"data1".to_vec(),
        );

        let hash1 = tx1.calculate_hash();
        let hash2 = tx2.calculate_hash();
        let hash3 = tx3.calculate_hash();

        // Identical transactions should have identical hashes
        assert_eq!(hash1, hash2);
        // Different transactions should have different hashes
        assert_ne!(hash1, hash3);
        // Hash size should be correct
        assert_eq!(hash1.len(), HASH_SIZE);
    }

    #[test]
    fn test_signed_transaction_creation_and_placeholder_verify() {
        let tx = Transaction::new(
            b"sender_addr".to_vec(),
            b"receiver_addr".to_vec(),
            100,
            1,
            1234567890,
            b"some data".to_vec(),
        );
        let dummy_signature = blake3::hash(b"dummy_signature").as_bytes().clone().to_vec();
        let dummy_public_key = blake3::hash(b"dummy_public_key").as_bytes().clone().to_vec();

        let signed_tx = SignedTransaction::new(tx.clone(), dummy_signature.clone(), dummy_public_key.clone());

        assert_eq!(signed_tx.transaction, tx);
        assert_eq!(signed_tx.signature, dummy_signature);
        assert_eq!(signed_tx.public_key, dummy_public_key);

        // Test dummy verification (should always be Ok for now)
        assert!(signed_tx.verify_signature().is_ok());

        // Test hash calculation for signed transaction
        let signed_tx_hash = signed_tx.calculate_hash();
        assert_eq!(signed_tx_hash.len(), HASH_SIZE);
        let other_signed_tx_hash = SignedTransaction::new(
            tx.clone(),
            blake3::hash(b"another_sig").as_bytes().clone().to_vec(),
            dummy_public_key,
        ).calculate_hash();
        assert_ne!(signed_tx_hash, other_signed_tx_hash);
    }
}
