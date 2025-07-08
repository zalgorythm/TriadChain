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
