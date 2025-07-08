// src/consensus/mod.rs

//! TriadChain Consensus Module
//!
//! This module defines the structures and logic related to the consensus mechanism
//! for TriadChain, including proposals and voting.

use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use crate::triad::structs::TriadHeader; // Import TriadHeader
use crate::errors::ConsensusError; // Assuming you have a ConsensusError defined
use crate::crypto::hash::blake3_hash; // Used for dummy signatures/public keys
use serde_bytes; // For serializing/deserializing fixed-size byte arrays

/// The size of a BLAKE3 hash in bytes.
const HASH_SIZE: usize = 32;

/// Represents a proposal for a new triad in the consensus process.
/// This would typically be created by a validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] // Added Serialize/Deserialize
pub struct TriadProposal {
    pub header: TriadHeader,
    pub proposer_id: Vec<u8>, // ID of the validator proposing the triad
    pub timestamp: DateTime<Utc>,
    #[serde(with = "serde_bytes")] // Use serde_bytes for fixed-size byte arrays
    pub signature: [u8; 64], // Signature of the proposal by the proposer
}

impl TriadProposal {
    /// Creates a new `TriadProposal`.
    pub fn new(header: TriadHeader, proposer_id: Vec<u8>, timestamp: DateTime<Utc>, signature: [u8; 64]) -> Self {
        TriadProposal {
            header,
            proposer_id,
            timestamp,
            signature,
        }
    }

    /// Verifies the signature of the proposal.
    /// This is a placeholder for actual cryptographic verification.
    pub fn verify_signature(&self) -> Result<(), ConsensusError> {
        // In a real system, this would verify self.signature against the hash of the proposal
        // content (excluding the signature itself) using self.proposer_id's public key.
        // For now, a dummy check.
        if self.signature == [0u8; 64] { // Example: don't allow all-zero signature
            return Err(ConsensusError::InvalidSignature("Proposal signature is all zeros".to_string()));
        }
        Ok(())
    }

    /// Hashes the proposal content (excluding the signature) for signing.
    pub fn hash_for_signing(&self) -> [u8; HASH_SIZE] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.header.calculate_hash());
        hasher.update(&self.proposer_id);
        hasher.update(&self.timestamp.to_rfc3339().as_bytes());
        hasher.finalize().as_bytes().clone()
    }
}

/// Represents a vote by a validator on a specific triad proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] // Added Serialize/Deserialize
pub struct ValidatorVote {
    pub proposal_hash: [u8; HASH_SIZE], // Hash of the TriadProposal being voted on
    pub voter_id: Vec<u8>,             // ID of the validator casting the vote
    pub timestamp: DateTime<Utc>,
    #[serde(with = "serde_bytes")] // Use serde_bytes for fixed-size byte arrays
    pub signature: [u8; 64],           // Signature of the vote by the voter
    pub vote_type: VoteType,           // Type of vote (e.g., Prevote, Precommit)
}

/// Defines the types of votes a validator can cast.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] // Added Serialize/Deserialize
pub enum VoteType {
    Prevote,
    Precommit,
}

impl ValidatorVote {
    /// Creates a new `ValidatorVote`.
    pub fn new(
        proposal_hash: [u8; HASH_SIZE],
        voter_id: Vec<u8>,
        timestamp: DateTime<Utc>,
        signature: [u8; 64],
        vote_type: VoteType,
    ) -> Self {
        ValidatorVote {
            proposal_hash,
            voter_id,
            timestamp,
            signature,
            vote_type,
        }
    }

    /// Verifies the signature of the vote.
    /// This is a placeholder for actual cryptographic verification.
    pub fn verify_signature(&self) -> Result<(), ConsensusError> {
        // Similar to proposal signature verification.
        if self.signature == [0u8; 64] { // Example: don't allow all-zero signature
            return Err(ConsensusError::InvalidSignature("Vote signature is all zeros".to_string()));
        }
        Ok(())
    }

    /// Hashes the vote content (excluding the signature) for signing.
    pub fn hash_for_signing(&self) -> [u8; HASH_SIZE] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.proposal_hash);
        hasher.update(&self.voter_id);
        hasher.update(&self.timestamp.to_rfc3339().as_bytes());
        hasher.update(&format!("{:?}", self.vote_type).as_bytes()); // Hash the enum variant
        hasher.finalize().as_bytes().clone()
    }
}

// Example placeholder function for consensus
/// A dummy function representing a consensus check.
///
/// In a real blockchain, this would involve complex logic like
/// Proof-of-Work, Proof-of-Stake, or other consensus algorithms.
///
/// # Returns
/// `true` if consensus is reached (placeholder), `false` otherwise.
#[allow(dead_code)] // Allow dead code for a placeholder function
pub fn reach_consensus() -> bool {
    // Simulate some work
    // let _dummy_hash = blake3_hash(b"consensus_work"); // This line was causing the unused import warning
    true // Always true for now
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::triad::structs::TriadHeader; // Import TriadHeader for tests
    use chrono::Utc;

    #[test]
    fn test_triad_proposal_creation_and_signature_verification() {
        let dummy_header = TriadHeader::new(
            [0u8; HASH_SIZE], [0u8; HASH_SIZE], [0u8; HASH_SIZE],
            Utc::now(), 0, 0
        );
        let proposer_id = blake3_hash(b"proposer1").to_vec();
        let timestamp = Utc::now();
        let signature = [1u8; 64]; // Dummy non-zero signature

        let proposal = TriadProposal::new(
            dummy_header.clone(),
            proposer_id.clone(),
            timestamp,
            signature,
        );

        assert_eq!(proposal.header, dummy_header);
        assert_eq!(proposal.proposer_id, proposer_id);
        assert_eq!(proposal.timestamp, timestamp);
        assert_eq!(proposal.signature, signature);
        assert!(proposal.verify_signature().is_ok());

        let invalid_proposal = TriadProposal::new(
            dummy_header,
            proposer_id,
            timestamp,
            [0u8; 64], // All-zero signature
        );
        assert!(invalid_proposal.verify_signature().is_err());
    }

    #[test]
    fn test_validator_vote_creation_and_signature_verification() {
        let proposal_hash = blake3_hash(b"proposal_to_vote_on").into();
        let voter_id = blake3_hash(b"voter1").to_vec();
        let timestamp = Utc::now();
        let signature = [2u8; 64]; // Dummy non-zero signature
        let vote_type = VoteType::Precommit;

        let vote = ValidatorVote::new(
            proposal_hash,
            voter_id.clone(),
            timestamp,
            signature,
            vote_type.clone(),
        );

        assert_eq!(vote.proposal_hash, proposal_hash);
        assert_eq!(vote.voter_id, voter_id);
        assert_eq!(vote.timestamp, timestamp);
        assert_eq!(vote.signature, signature);
        assert_eq!(vote.vote_type, vote_type);
        assert!(vote.verify_signature().is_ok());

        let invalid_vote = ValidatorVote::new(
            proposal_hash,
            voter_id,
            timestamp,
            [0u8; 64], // All-zero signature
            VoteType::Prevote,
        );
        assert!(invalid_vote.verify_signature().is_err());
    }

    #[test]
    fn test_reach_consensus() {
        assert!(reach_consensus());
    }
}
