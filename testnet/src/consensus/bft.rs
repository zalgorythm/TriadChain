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

use std::collections::BTreeMap;

/// Holds the state for a BFT consensus instance.
#[derive(Debug, Clone)]
pub struct BftState {
    pub current_round: u64,
    pub current_leader_pubkey: [u8; 32], // For simplicity, can be fixed or passed in
    pub quorum_threshold: usize, // e.g., 15 for 15/21

    // Key: (item_hash, round) -> Vec of signed votes for that item in that round
    pub prepare_votes: BTreeMap<([u8; 32], u64), Vec<SignedMessage<VoteMessage>>>,
    pub precommit_votes: BTreeMap<([u8; 32], u64), Vec<SignedMessage<VoteMessage>>>,
    pub commit_votes: BTreeMap<([u8; 32], u64), Vec<SignedMessage<VoteMessage>>>,

    // Key: (item_hash, round) -> QC for that item, formed in that round
    // Alternatively, could be BTreeMap<[u8;32], QuorumCertificate> if only one QC per item_hash is stored,
    // but HotStuff can have QCs for different rounds for the same item (though typically for different items/blocks).
    // Let's stick to (item_hash, round) for now for flexibility.
    pub known_qcs: BTreeMap<([u8; 32], u64), QuorumCertificate>,

    // Local node's public key, useful for leader checks.
    // This might be part of a larger NodeContext struct in a full implementation.
    pub local_node_pubkey: [u8; 32],
}

impl BftState {
    pub fn new(
        initial_round: u64,
        leader_pubkey: [u8; 32],
        quorum_threshold: usize,
        local_node_pubkey: [u8; 32]
    ) -> Self {
        BftState {
            current_round: initial_round,
            current_leader_pubkey: leader_pubkey,
            quorum_threshold,
            prepare_votes: BTreeMap::new(),
            precommit_votes: BTreeMap::new(),
            commit_votes: BTreeMap::new(),
            known_qcs: BTreeMap::new(),
            local_node_pubkey,
        }
    }

    // Placeholder for methods to be implemented in subsequent steps
    // pub fn generate_proposal(...)
    // pub fn generate_vote(...)
    // pub fn process_signed_vote(...)

    /// Generates a new TriadProposal if the current node is the leader for the current round.
    ///
    /// # Arguments
    /// * `parent_qc`: The QuorumCertificate justifying the parent state this proposal extends.
    /// * `new_proposed_header`: The TriadHeader for the new Triad being proposed.
    ///   The caller is responsible for ensuring this header is valid and correctly
    ///   links to the parent state certified by `parent_qc` (i.e.,
    ///   `new_proposed_header.parent_hash == parent_qc.certified_item_hash`).
    ///
    /// # Returns
    /// `Some(TriadProposal)` if the current node is the leader, `None` otherwise.
    pub fn generate_proposal(
        &self,
        parent_qc: QuorumCertificate, // The QC for the parent this proposal extends
        new_proposed_header: TriadHeader, // The header for the new triad/block
    ) -> Option<TriadProposal> {
        if self.local_node_pubkey != self.current_leader_pubkey {
            return None; // Not the leader for the current round
        }

        // Basic sanity check: the new header should correctly point to the parent certified by the QC.
        // This check might be more involved in a full system (e.g. checking QC's round vs proposal round).
        if new_proposed_header.parent_hash != parent_qc.certified_item_hash {
            // This indicates a misbehaving proposer or incorrect input from the application layer.
            // In a real system, this might log an error or panic depending on trust assumptions.
            // For now, let's prevent creating an invalid proposal.
            // Or, this responsibility could be solely on the caller.
            // For robustness of BftState, a check is good.
            // Consider returning Result<TriadProposal, Error> if more error states are needed.
            // For now, returning None if inputs are inconsistent.
            // TODO: Log this inconsistency if a logging mechanism is added.
            return None;
        }

        // TODO: Further validation of parent_qc itself (e.g., signatures, round progression)
        // For now, we assume parent_qc is validly formed.

        Some(TriadProposal {
            round: self.current_round,
            proposer_pubkey: self.local_node_pubkey,
            proposed_triad_header: new_proposed_header,
            parent_qc,
        })
    }

    /// Validates a given proposal and generates a vote if validation passes.
    ///
    /// # Arguments
    /// * `proposal`: The `TriadProposal` to validate and vote on.
    /// * `vote_type`: The type of vote to generate (e.g., Prepare, Precommit).
    ///
    /// # Returns
    /// `Some(VoteMessage)` if the proposal is valid and a vote is generated,
    /// `None` otherwise.
    pub fn generate_vote(
        &self,
        proposal: &TriadProposal,
        vote_type: VoteType,
    ) -> Option<VoteMessage> {
        // 1. Basic Round Check: Proposal should be for the current round.
        //    (HotStuff has more complex round synchronization, this is simplified).
        if proposal.round != self.current_round {
            // TODO: Log "Proposal for wrong round"
            return None;
        }

        // 2. Parent QC Validation (Simplified):
        //    - Check if the parent QC's round is less than the proposal's round.
        //    - Check if the parent QC's certified item hash matches the proposal's parent hash.
        //    A full implementation would verify signatures in parent_qc and check against known state.
        if proposal.parent_qc.round >= proposal.round {
            // TODO: Log "Parent QC round not less than proposal round"
            return None;
        }
        if proposal.proposed_triad_header.parent_hash != proposal.parent_qc.certified_item_hash {
            // This should also be caught by generate_proposal, but good to double check as a voter.
            // TODO: Log "Proposal parent hash mismatch with parent QC"
            return None;
        }
        // TODO: Check if proposal.parent_qc is actually known/valid (e.g., in self.known_qcs).
        //       For now, we assume it's structurally okay if passed basic checks.

        // 3. Proposal Content Validation (Placeholder for future checks):
        //    - Is proposed_triad_header internally consistent?
        //    - Are transactions valid (if they were part of the proposal explicitly)?
        //    - Does the proposal extend the state correctly from parent_qc? (Requires state access)
        //    For now, these are skipped.

        // If all checks pass (for this simplified phase):
        let voted_item_hash = proposal.proposed_triad_header.hash();

        Some(VoteMessage {
            vote_type,
            round: proposal.round, // Or self.current_round, should be the same here
            voted_item_hash,
        })
    }

    /// Processes a signed vote message. Stores the vote, checks for quorum,
    /// and forms a QuorumCertificate (QC) if quorum is met.
    ///
    /// # Arguments
    /// * `signed_vote`: The `SignedMessage<VoteMessage>` received from a validator.
    ///
    /// # Returns
    /// `Some(QuorumCertificate)` if a new QC is formed, `None` otherwise.
    ///
    /// TODO:
    ///  - Implement actual signature verification.
    ///  - Add protection against duplicate votes from the same validator for the same item/round/type.
    ///  - More robust validation of the vote's content against current BFT state.
    pub fn process_signed_vote(
        &mut self,
        signed_vote: SignedMessage<VoteMessage>,
    ) -> Option<QuorumCertificate> {
        let vote_msg = &signed_vote.message;

        // 1. Basic Vote Validation (Simplified)
        if vote_msg.round != self.current_round {
            // TODO: Log "Vote for wrong round" or handle out-of-round votes (e.g., for catch-up)
            return None;
        }
        // TODO: Validate that signed_vote.signer_pubkey is a known validator.
        // TODO: Verify signature signed_vote.signature over serialized vote_msg.message.

        let votes_map_key = (vote_msg.voted_item_hash, vote_msg.round);

        // Get the appropriate vote list based on vote_type
        let current_vote_list = match vote_msg.vote_type {
            VoteType::Prepare => self.prepare_votes.entry(votes_map_key).or_insert_with(Vec::new),
            VoteType::Precommit => self.precommit_votes.entry(votes_map_key).or_insert_with(Vec::new),
            VoteType::Commit => self.commit_votes.entry(votes_map_key).or_insert_with(Vec::new),
        };

        // Check for duplicate vote from the same signer for this specific item, round, and type
        if current_vote_list.iter().any(|sv| sv.signer_pubkey == signed_vote.signer_pubkey) {
            // TODO: Log "Duplicate vote received"
            return None; // Already have a vote from this signer for this item/round/type
        }

        current_vote_list.push(signed_vote.clone()); // Store the clone of the signed vote

        // 3. Check for Quorum
        if current_vote_list.len() >= self.quorum_threshold {
            // Quorum met, form a QC
            let signatures_for_qc: Vec<([u8; 32], [u8; 64])> = current_vote_list
                .iter()
                // Take up to quorum_threshold signatures, though in practice it might be exactly that many
                // if we stop processing once QC is formed, or more if votes arrive concurrently.
                // For simplicity, let's just take all we have if it's >= threshold.
                // A real implementation might be more specific about which ones form the "first" QC.
                .map(|sv| (sv.signer_pubkey, sv.signature))
                .collect();

            let new_qc = QuorumCertificate {
                vote_type: vote_msg.vote_type, // The type of votes this QC is for
                round: vote_msg.round,
                certified_item_hash: vote_msg.voted_item_hash,
                signatures: signatures_for_qc,
            };

            // Store and return the new QC
            // Note: This might overwrite an existing QC if one was somehow formed earlier for the exact same item/round.
            // This simple implementation assumes one QC per (item, round, vote_type leading to QC).
            // HotStuff typically has one QC per (view/round) for a specific proposal that gained traction.
            // The key for known_qcs might need refinement based on how QCs are used (e.g. just item_hash if round is implicit in state machine).
            // For now (item_hash, round) is used as key for known_qcs.
            self.known_qcs.insert(votes_map_key, new_qc.clone());

            // TODO: Potentially clean up the vote list now that a QC has been formed,
            // or leave them for audit/later inspection. For now, leave them.

            return Some(new_qc);
        }

        None // No new QC formed yet
    }
}
