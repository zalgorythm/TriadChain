// testnet/src/consensus/bft.rs

use crate::triad::TriadHeader; // For TriadProposal

// const COMMON_DERIVES: &'static str = "#[derive(Debug, Clone, PartialEq, Eq, Hash)]"; // Removed unused constant

/// Type of vote in the BFT consensus process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VoteType {
    Prepare,
    Precommit,
    Commit,
    // Potentially others like Decide or NewView
}

/// Represents a vote message sent by a validator.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VoteMessage {
    pub vote_type: VoteType,
    pub round: u64,
    /// Hash of the item being voted on (e.g., TriadHeader hash or TriadProposal hash).
    pub voted_item_hash: [u8; 32],
    // pub parent_qc_ref: Option<[u8; 32]>, // Potential future field for HotStuff-like chaining
}

/// Represents a Quorum Certificate (QC).
/// A QC is a collection of signatures from a quorum of validators for a specific vote.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct QuorumCertificate {
    pub vote_type: VoteType, // Indicates what phase this QC refers to (e.g., QC on Prepare votes)
    pub round: u64,
    /// Hash of the item that has achieved quorum.
    pub certified_item_hash: [u8; 32],
    /// List of (validator_pubkey, signature) tuples.
    /// Whitepaper implies 15/21 for finalization. This Vec would need to contain at least that many.
    pub signatures: Vec<([u8; 32], [u8; 64])>,
}

/// Represents a proposal for a new Triad or state transition.
#[derive(Debug, Clone, PartialEq, Eq)] // Removed Hash derive as TriadHeader might not be Hash directly
pub struct TriadProposal {
    pub round: u64,
    pub proposer_pubkey: [u8; 32],
    /// The actual header being proposed. This contains all necessary state information.
    pub proposed_triad_header: TriadHeader,
    /// The QuorumCertificate that justifies the parent state upon which this proposal is built.
    pub parent_qc: QuorumCertificate, // A proposal must extend a known, certified state.
    // pub transactions: Vec<Transaction> // Transactions could be part of the proposal explicitly,
                                       // or their root hash in proposed_triad_header is sufficient.
                                       // For now, assume tx_root in header is enough.
}

/// A generic wrapper for a message that has been signed by a validator.
#[derive(Debug, Clone, PartialEq, Eq)] // Removed Hash, as T might not be Hash
pub struct SignedMessage<T> {
    pub message: T,
    pub signer_pubkey: [u8; 32], // The public key of the signer (validator)
    pub signature: [u8; 64],     // The signature over the (serialized) message
}
