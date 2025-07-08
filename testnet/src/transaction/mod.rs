// src/transaction/mod.rs

//! TriadChain Transaction Module
//!
//! This module handles transaction-related logic, including validation
//! and potentially other operations.

pub mod structs; // Declare the structs submodule

// Re-export key types from structs for easier access within the transaction module
pub use structs::{Transaction, SignedTransaction};

use crate::errors::TransactionError;

// Removed: const HASH_SIZE: usize = 32; // This constant is unused in this module's main logic

/// Validates a signed transaction.
///
/// This is a placeholder for actual transaction validation logic.
/// In a real system, this would involve:
/// - Verifying the transaction's signature.
/// - Checking for double-spending.
/// - Validating nonce, amount, and other fields against the current state.
///
/// # Arguments
/// * `signed_tx` - A reference to the `SignedTransaction` to validate.
///
/// # Returns
/// `Ok(())` if the transaction is valid, or a `TransactionError` if it's invalid.
pub fn validate_signed_transaction(signed_tx: &SignedTransaction) -> Result<(), TransactionError> {
    // Placeholder for signature verification
    signed_tx.verify_signature()?;

    // Placeholder for other validation checks
    // Example: Check if amount is non-zero
    if signed_tx.transaction.amount == 0 {
        return Err(TransactionError::InvalidAmount("Transaction amount cannot be zero".to_string()));
    }

    // Example: Check if sender and receiver addresses are not empty
    if signed_tx.transaction.from_address.is_empty() || signed_tx.transaction.to_address.is_empty() {
        return Err(TransactionError::InvalidAddress("Sender or receiver address cannot be empty".to_string()));
    }

    // You would add more complex validation logic here,
    // potentially interacting with the StateTree to check balances, nonces, etc.

    Ok(())
}

/// Creates a dummy signed transaction for testing or placeholder purposes.
///
/// # Arguments
/// * `from_addr` - Sender's address bytes.
/// * `to_addr` - Recipient's address bytes.
/// * `amount` - Amount to send.
/// * `nonce` - Transaction nonce.
/// * `timestamp` - Transaction timestamp.
/// * `data` - Optional data payload.
///
/// # Returns
/// A `SignedTransaction` instance.
#[allow(dead_code)] // Allow dead code for a utility function that might not be used everywhere
pub fn create_dummy_signed_transaction(
    from_addr: &[u8],
    to_addr: &[u8],
    amount: u64,
    nonce: u64,
    timestamp: u64,
    data: &[u8],
) -> SignedTransaction {
    let tx = Transaction::new(
        from_addr.to_vec(),
        to_addr.to_vec(),
        amount,
        nonce,
        timestamp,
        data.to_vec(),
    );

    // In a real scenario, this would involve actual private key signing.
    // For now, we'll just use a dummy signature and public key.
    let dummy_signature = blake3::hash(b"dummy_signature").as_bytes().clone(); // Directly use blake3
    let dummy_public_key = blake3::hash(b"dummy_public_key").as_bytes().clone(); // Directly use blake3

    SignedTransaction::new(tx, dummy_signature.to_vec(), dummy_public_key.to_vec())
}


#[cfg(test)]
mod tests {
    use super::*;
    use blake3; // Directly import blake3 for tests in this module
    const HASH_SIZE: usize = 32; // Moved HASH_SIZE to test scope where it's used

    #[test]
    fn test_validate_signed_transaction_valid() {
        let signed_tx = create_dummy_signed_transaction(
            b"sender_addr",
            b"receiver_addr",
            100,
            1,
            1234567890,
            b"some data",
        );
        assert!(validate_signed_transaction(&signed_tx).is_ok());
    }

    #[test]
    fn test_validate_signed_transaction_zero_amount() {
        let signed_tx = create_dummy_signed_transaction(
            b"sender_addr",
            b"receiver_addr",
            0, // Zero amount
            1,
            1234567890,
            b"some data",
        );
        assert!(validate_signed_transaction(&signed_tx).is_err());
        assert_eq!(
            validate_signed_transaction(&signed_tx).unwrap_err(),
            TransactionError::InvalidAmount("Transaction amount cannot be zero".to_string())
        );
    }

    #[test]
    fn test_validate_signed_transaction_empty_address() {
        let signed_tx_from_empty = create_dummy_signed_transaction(
            b"", // Empty sender address
            b"receiver_addr",
            100,
            1,
            1234567890,
            b"some data",
        );
        assert!(validate_signed_transaction(&signed_tx_from_empty).is_err());
        assert_eq!(
            validate_signed_transaction(&signed_tx_from_empty).unwrap_err(),
            TransactionError::InvalidAddress("Sender or receiver address cannot be empty".to_string())
        );

        let signed_tx_to_empty = create_dummy_signed_transaction(
            b"sender_addr",
            b"", // Empty receiver address
            100,
            1,
            1234567890,
            b"some data",
        );
        assert!(validate_signed_transaction(&signed_tx_to_empty).is_err());
        assert_eq!(
            validate_signed_transaction(&signed_tx_to_empty).unwrap_err(),
            TransactionError::InvalidAddress("Sender or receiver address cannot be empty".to_string())
        );
    }

    // This test specifically targets the `type annotations needed` error
    #[test]
    fn test_blake3_hash_into_conversion() {
        let input = b"test_data";
        let expected_input = b"another_test";
        let k_hash: [u8; HASH_SIZE] = blake3::hash(input).as_bytes().clone(); // Corrected: use .as_bytes().clone()

        // This is the line that caused the E0283 error if not fixed
        // and E0308 error with &expected_input if not fixed
        let expected_hash: [u8; HASH_SIZE] = blake3::hash(expected_input).as_bytes().clone(); // Corrected: use .as_bytes().clone()
        assert_eq!(expected_hash.len(), HASH_SIZE);
        assert_ne!(k_hash, expected_hash); // They should be different hashes
    }
}
