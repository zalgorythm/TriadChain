// src/crypto/hash.rs

//! TriadChain Cryptographic Hashing Module
//!
//! This module provides cryptographic hashing functionalities using the BLAKE3 algorithm.
//! It offers a simple interface for hashing arbitrary byte inputs, which is crucial
//! for various components of the TriadChain, including block headers, transactions,
//! and Merkle tree computations.

use blake3; // Import the BLAKE3 crate

/// The fixed size of a BLAKE3 hash output in bytes.
pub const HASH_SIZE: usize = 32;

/// Computes the BLAKE3 hash of the given input byte slice.
///
/// This function takes any data as a byte slice and returns its 32-byte BLAKE3 hash.
/// It's a fundamental building block for ensuring data integrity and immutability
/// within the TriadChain.
///
/// # Arguments
/// * `input` - A byte slice (`&[u8]`) to be hashed.
///
/// # Returns
/// A 32-byte array (`[u8; HASH_SIZE]`) representing the BLAKE3 hash of the input.
pub fn blake3_hash(input: &[u8]) -> [u8; HASH_SIZE] {
    // blake3::hash returns a blake3::Hash struct, which can be converted
    // to a fixed-size byte array using .as_bytes().clone().
    blake3::hash(input).as_bytes().clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests the consistency of the BLAKE3 hash function.
    ///
    /// This test ensures that:
    /// 1. Hashing the same input consistently produces the same output.
    /// 2. Hashing different inputs produces different outputs.
    /// 3. The hash output has the expected size.
    #[test]
    fn test_blake3_hash_consistency() {
        let input1 = b"Hello, TriadChain!";
        let input2 = b"Another message.";
        let input3 = b"Hello, TriadChain!"; // Same as input1

        let hash1 = blake3_hash(input1);
        let hash2 = blake3_hash(input2);
        let hash3 = blake3_hash(input3);

        // 1. Hashing the same input should produce the same output
        assert_eq!(hash1, hash3, "Hashing the same input should yield the same hash.");

        // 2. Hashing different inputs should produce different outputs (highly probable)
        assert_ne!(hash1, hash2, "Hashing different inputs should yield different hashes.");

        // 3. The hash output should have the expected size
        assert_eq!(hash1.len(), HASH_SIZE, "Hash output size should match HASH_SIZE.");
        assert_eq!(hash2.len(), HASH_SIZE, "Hash output size should match HASH_SIZE.");
    }

    /// Tests the hash of an empty input.
    #[test]
    fn test_blake3_empty_input() {
        let empty_input = b"";
        let hash = blake3_hash(empty_input);
        assert_eq!(hash.len(), HASH_SIZE, "Empty input hash should have expected size.");
        // The specific hash of an empty string is deterministic:
        let expected_empty_hash = blake3::hash(b"").as_bytes().clone();
        assert_eq!(hash, expected_empty_hash, "Hash of empty input is not consistent.");
    }
}
