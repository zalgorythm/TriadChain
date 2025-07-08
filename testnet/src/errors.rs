// src/errors.rs

//! TriadChain Error Definitions Module
//!
//! This module centralizes all custom error types used throughout the TriadChain project.
//! Defining specific error types helps in providing more descriptive and actionable
//! feedback when operations fail, making debugging and error handling more robust.

use thiserror::Error; // Import the `Error` macro from the `thiserror` crate

/// Represents errors that can occur during transaction processing.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TransactionError {
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    #[error("Invalid amount: {0}")]
    InvalidAmount(String),
    #[error("Invalid address: {0}")]
    InvalidAddress(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    #[error("Other transaction error: {0}")]
    Other(String),
}

/// Represents errors that can occur during state management operations (e.g., StateTree).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum StateError {
    #[error("Concurrency error: {0}")]
    ConcurrencyError(String),
    #[error("Key not found: {0}")]
    NotFound(String),
    #[error("Merkle tree error: {0}")]
    MerkleTreeError(String),
    // Added for MerkleProof generation error
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Other state error: {0}")]
    Other(String),
}

/// Implement `From` trait for `MerkleError` to convert it to `StateError`.
/// This allows functions returning `Result<(), MerkleError>` to use `?` operator
/// when their caller expects `Result<(), StateError>`.
impl From<MerkleError> for StateError {
    fn from(err: MerkleError) -> Self {
        StateError::MerkleTreeError(err.to_string())
    }
}


/// Represents errors specific to Merkle tree operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MerkleError {
    #[error("Empty leaves provided to Merkle tree construction.")]
    EmptyLeaves,
    #[error("Invalid Merkle proof: {0}")]
    InvalidProof(String),
    #[error("Other Merkle error: {0}")]
    Other(String),
}

/// Represents errors that can occur during consensus operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConsensusError {
    #[error("Invalid block proposal: {0}")]
    InvalidBlockProposal(String),
    #[error("Invalid validator vote: {0}")]
    InvalidValidatorVote(String),
    #[error("Quorum not reached.")]
    QuorumNotReached,
    #[error("Timeout during consensus.")]
    Timeout,
    #[error("Other consensus error: {0}")]
    Other(String),
}

/// Represents errors specific to Triad (block) operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TriadError {
    #[error("Invalid Proof of Work.")]
    InvalidProofOfWork,
    #[error("Transactions Merkle root mismatch. Header: {0:?}, Actual: {1:?}")]
    TransactionsMerkleRootMismatch([u8; 32], [u8; 32]),
    #[error("State Merkle root mismatch. Header: {0:?}, Actual: {1:?}")]
    StateMerkleRootMismatch([u8; 32], [u8; 32]),
    #[error("Transaction validation failed: {0}")]
    TransactionValidationFailed(String),
    #[error("Other Triad error: {0}")]
    Other(String),
}

