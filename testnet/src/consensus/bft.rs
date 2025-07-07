// testnet/src/consensus/bft.rs

use crate::triad::TriadHeader; // For TriadProposal
use crate::crypto::signing; // Correct module import for signing utilities

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
}

impl VoteMessage {
    /// Provides a canonical byte representation of the VoteMessage for signing.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let vote_type_u8: u8 = match self.vote_type {
            VoteType::Prepare => 0,
            VoteType::Precommit => 1,
            VoteType::Commit => 2,
        };
        bytes.push(vote_type_u8);
        bytes.extend_from_slice(&self.round.to_be_bytes());
        bytes.extend_from_slice(&self.voted_item_hash);
        bytes
    }
}

/// Represents a Quorum Certificate (QC).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct QuorumCertificate {
    pub vote_type: VoteType,
    pub round: u64,
    pub certified_item_hash: [u8; 32],
    pub signatures: Vec<([u8; 32], [u8; 64])>,
}

/// Represents a proposal for a new Triad or state transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriadProposal {
    pub round: u64,
    pub proposer_pubkey: [u8; 32],
    pub proposed_triad_header: TriadHeader,
    pub parent_qc: QuorumCertificate,
}

/// A generic wrapper for a message that has been signed by a validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedMessage<T> {
    pub message: T,
    pub signer_pubkey: [u8; 32],
    pub signature: [u8; 64],
}

 use std::collections::BTreeMap;

/// Holds the state for a BFT consensus instance.
#[derive(Debug, Clone)]
pub struct BftState {
    pub validator_set: Vec<[u8; 32]>,
    pub current_round: u64,
    pub current_leader_pubkey: [u8; 32],
    pub quorum_threshold: usize,
    pub prepare_votes: BTreeMap<([u8; 32], u64), Vec<SignedMessage<VoteMessage>>>,
    pub precommit_votes: BTreeMap<([u8; 32], u64), Vec<SignedMessage<VoteMessage>>>,
    pub commit_votes: BTreeMap<([u8; 32], u64), Vec<SignedMessage<VoteMessage>>>,
    pub known_qcs: BTreeMap<([u8; 32], u64), QuorumCertificate>,
    pub local_node_pubkey: [u8; 32],
    pub highest_prepare_qc_by_round: BTreeMap<u64, QuorumCertificate>,
    pub highest_precommit_qc_by_round: BTreeMap<u64, QuorumCertificate>,
    pub committed_item_hashes: std::collections::HashSet<[u8; 32]>,
}

impl BftState {
    pub fn new(
        initial_round: u64,
        validator_set: Vec<[u8; 32]>,
        quorum_threshold: usize,
        local_node_pubkey: [u8; 32]
    ) -> Self {
        if validator_set.is_empty() {
            panic!("BftState: validator_set cannot be empty.");
        }
        let current_leader_pubkey = validator_set[initial_round as usize % validator_set.len()].clone();
        BftState {
            validator_set,
            current_round: initial_round,
            current_leader_pubkey,
            quorum_threshold,
            prepare_votes: BTreeMap::new(),
            precommit_votes: BTreeMap::new(),
            commit_votes: BTreeMap::new(),
            known_qcs: BTreeMap::new(),
            local_node_pubkey,
            highest_prepare_qc_by_round: BTreeMap::new(),
            highest_precommit_qc_by_round: BTreeMap::new(),
            committed_item_hashes: std::collections::HashSet::new(),
        }
    }

    pub fn generate_proposal(
        &self,
        parent_qc: QuorumCertificate,
        new_proposed_header: TriadHeader,
    ) -> Option<TriadProposal> {
        if self.local_node_pubkey != self.current_leader_pubkey {
            return None;
        }
        if new_proposed_header.parent_hash != parent_qc.certified_item_hash {
            return None;
        }
        Some(TriadProposal {
            round: self.current_round,
            proposer_pubkey: self.local_node_pubkey,
            proposed_triad_header: new_proposed_header,
            parent_qc,
        })
    }

    pub fn generate_vote(
        &self,
        proposal: &TriadProposal,
        vote_type: VoteType,
    ) -> Option<VoteMessage> {
        if proposal.round != self.current_round {
            return None;
        }
        if proposal.parent_qc.round >= proposal.round {
            return None;
        }
        if proposal.proposed_triad_header.parent_hash != proposal.parent_qc.certified_item_hash {
            return None;
        }
        let proposed_header_hash = proposal.proposed_triad_header.hash();
        match vote_type {
            VoteType::Prepare => {}
            VoteType::Precommit => {
                match self.highest_prepare_qc_by_round.get(&proposal.round) {
                    Some(prepare_qc) => {
                        if prepare_qc.certified_item_hash != proposed_header_hash || prepare_qc.vote_type != VoteType::Prepare {
                            return None;
                        }
                    }
                    None => return None,
                }
            }
            VoteType::Commit => {
                match self.highest_precommit_qc_by_round.get(&proposal.round) {
                    Some(precommit_qc) => {
                        if precommit_qc.certified_item_hash != proposed_header_hash || precommit_qc.vote_type != VoteType::Precommit {
                            return None;
                        }
                    }
                    None => return None,
                }
            }
        }
        Some(VoteMessage {
            vote_type,
            round: proposal.round,
            voted_item_hash: proposed_header_hash,
        })
    }

    pub fn process_signed_vote(
        &mut self,
        signed_vote: SignedMessage<VoteMessage>,
    ) -> Option<QuorumCertificate> {
        let vote_msg = &signed_vote.message;
        let message_bytes = vote_msg.to_bytes();

        let public_key = match signing::PublicKey::from_bytes(&signed_vote.signer_pubkey) {
            Ok(pk) => pk,
            Err(_) => return None,
        };
        let signature = match signing::Signature::from_bytes(&signed_vote.signature) {
            Ok(sig) => sig,
            Err(_) => return None,
        };

        if !signing::verify(&message_bytes, &signature, &public_key) {
            return None;
        }

        if vote_msg.round != self.current_round {
            return None;
        }

        let votes_map_key = (vote_msg.voted_item_hash, vote_msg.round);
        let current_vote_list = match vote_msg.vote_type {
            VoteType::Prepare => self.prepare_votes.entry(votes_map_key).or_insert_with(Vec::new),
            VoteType::Precommit => self.precommit_votes.entry(votes_map_key).or_insert_with(Vec::new),
            VoteType::Commit => self.commit_votes.entry(votes_map_key).or_insert_with(Vec::new),
        };

        if current_vote_list.iter().any(|sv| sv.signer_pubkey == signed_vote.signer_pubkey) {
            return None;
        }
        current_vote_list.push(signed_vote.clone());

        if current_vote_list.len() >= self.quorum_threshold {
            let signatures_for_qc: Vec<([u8; 32], [u8; 64])> = current_vote_list
                .iter()
                .map(|sv| (sv.signer_pubkey, sv.signature))
                .collect();
            let new_qc = QuorumCertificate {
                vote_type: vote_msg.vote_type,
                round: vote_msg.round,
                certified_item_hash: vote_msg.voted_item_hash,
                signatures: signatures_for_qc,
            };
            self.known_qcs.insert(votes_map_key, new_qc.clone());
            match new_qc.vote_type {
                VoteType::Prepare => {
                    self.highest_prepare_qc_by_round.insert(new_qc.round, new_qc.clone());
                }
                VoteType::Precommit => {
                    self.highest_precommit_qc_by_round.insert(new_qc.round, new_qc.clone());
                }
                VoteType::Commit => {
                    self.committed_item_hashes.insert(new_qc.certified_item_hash);
                }
            }
            return Some(new_qc);
        }
        None
    }

    pub fn advance_round(&mut self) {
        self.current_round += 1;
        if self.validator_set.is_empty() {
            panic!("BftState::advance_round: validator_set is empty, cannot determine leader.");
        }
        self.current_leader_pubkey = self.validator_set[self.current_round as usize % self.validator_set.len()].clone();
    }
}
