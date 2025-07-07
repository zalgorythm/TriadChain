#[cfg(test)]
mod tests {
    use crate::consensus::bft::{VoteType, VoteMessage, QuorumCertificate, TriadProposal, SignedMessage};
    use crate::triad::TriadHeader; // For TriadProposal test
    use crate::crypto::hash::blake3_hash; // For dummy hashes

    // Helper to create a dummy TriadHeader for proposal testing
    fn dummy_triad_header() -> TriadHeader {
        TriadHeader {
            level: 1,
            position: "pos_1".to_string(),
            position_hash: blake3_hash(b"pos_1"),
            parent_hash: [0u8; 32],
            tx_root: [1u8; 32],
            state_root: [2u8; 32],
            tx_count: 0,
            max_capacity: 1004,
            split_nonce: 0,
            timestamp: 1234567890,
            validator_sigs: [None; 15],
        }
    }

    // Helper for dummy pubkey
    fn dummy_pubkey(id: u8) -> [u8; 32] {
        let mut pk = [0u8; 32];
        pk[0] = id;
        pk
    }

    // Helper for dummy signature
    fn dummy_signature(id: u8) -> [u8; 64] {
        let mut sig = [0u8; 64];
        sig[0] = id;
        sig
    }

    // Helper for dummy item hash
    fn dummy_item_hash(id: u8) -> [u8; 32] {
        let mut hash = [0u8; 32];
        hash[0] = id;
        hash
    }

    #[test]
    fn test_vote_type_instantiation() {
        let vt_prepare = VoteType::Prepare;
        // let vt_precommit = VoteType::Precommit; // Removed unused variable
        let vt_commit = VoteType::Commit;
        assert_eq!(vt_prepare, VoteType::Prepare);
        assert_ne!(vt_prepare, vt_commit); // vt_prepare is compared with vt_commit
    }

    #[test]
    fn test_vote_message_instantiation() {
        let vote_msg = VoteMessage {
            vote_type: VoteType::Prepare,
            round: 1,
            voted_item_hash: dummy_item_hash(1),
        };
        assert_eq!(vote_msg.round, 1);
        assert_eq!(vote_msg.vote_type, VoteType::Prepare);
    }

    #[test]
    fn test_quorum_certificate_instantiation() {
        let qc = QuorumCertificate {
            vote_type: VoteType::Precommit, // QC on Precommit votes
            round: 2,
            certified_item_hash: dummy_item_hash(2),
            signatures: vec![
                (dummy_pubkey(1), dummy_signature(1)),
                (dummy_pubkey(2), dummy_signature(2)),
            ],
        };
        assert_eq!(qc.signatures.len(), 2);
        assert_eq!(qc.round, 2);
    }

    #[test]
    fn test_triad_proposal_instantiation() {
        // Need a dummy QC for the parent_qc field
        let dummy_parent_qc = QuorumCertificate {
            vote_type: VoteType::Commit, // Parent QC is usually on Commit
            round: 0,
            certified_item_hash: dummy_item_hash(0), // Parent's hash
            signatures: vec![(dummy_pubkey(5), dummy_signature(5))],
        };

        let proposal = TriadProposal {
            round: 1,
            proposer_pubkey: dummy_pubkey(3),
            proposed_triad_header: dummy_triad_header(),
            parent_qc: dummy_parent_qc,
        };
        assert_eq!(proposal.round, 1);
        assert_eq!(proposal.proposed_triad_header.level, 1);
    }

    #[test]
    fn test_signed_message_instantiation() {
        let vote_msg_content = VoteMessage {
            vote_type: VoteType::Commit,
            round: 3,
            voted_item_hash: dummy_item_hash(3),
        };

        let signed_vote_msg: SignedMessage<VoteMessage> = SignedMessage {
            message: vote_msg_content,
            signer_pubkey: dummy_pubkey(4),
            signature: dummy_signature(4),
        };
        assert_eq!(signed_vote_msg.message.round, 3);
        assert_eq!(signed_vote_msg.signer_pubkey[0], 4);
    }
}
