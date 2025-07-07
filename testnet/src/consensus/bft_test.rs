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

    // --- Tests for BftState methods ---

    // Helper to create a default BftState for testing
    fn default_bft_state(local_pk: [u8; 32], leader_pk: [u8; 32], quorum: usize) -> crate::consensus::bft::BftState {
        crate::consensus::bft::BftState::new(1, leader_pk, quorum, local_pk)
    }

    // Helper to create a TriadHeader with a specific parent hash
    fn header_for_parent(parent_hash: [u8; 32], level: u64, position: &str) -> TriadHeader {
        TriadHeader {
            level,
            position: position.to_string(),
            position_hash: blake3_hash(position.as_bytes()),
            parent_hash, // Set explicitly
            tx_root: dummy_item_hash(level as u8), // Some dummy hash
            state_root: dummy_item_hash(level as u8 + 100), // Some dummy hash
            tx_count: 0,
            max_capacity: (1000.0 * (1.0 + 0.004 * level as f64)) as u16,
            split_nonce: 0,
            timestamp: 1234567890 + level as i64,
            validator_sigs: [None; 15],
        }
    }


    #[test]
    fn test_bft_state_generate_proposal() {
        let leader_pk = dummy_pubkey(1);
        let non_leader_pk = dummy_pubkey(2);
        let quorum = 2; // For simple 2 out of 3 tests later perhaps

        let mut state_leader = default_bft_state(leader_pk, leader_pk, quorum);
        state_leader.current_round = 5;

        let mut state_non_leader = default_bft_state(non_leader_pk, leader_pk, quorum);
        state_non_leader.current_round = 5;

        let parent_certified_hash = dummy_item_hash(10);
        let parent_qc = QuorumCertificate {
            vote_type: VoteType::Commit, // QC from previous round's commit
            round: 4,
            certified_item_hash: parent_certified_hash,
            signatures: vec![(dummy_pubkey(100), dummy_signature(100))], // Dummy signature
        };

        let valid_new_header = header_for_parent(parent_certified_hash, 1, "pos_A");
        let invalid_new_header = header_for_parent(dummy_item_hash(11), 1, "pos_B"); // Wrong parent hash

        // Leader generates proposal successfully
        let proposal_opt = state_leader.generate_proposal(parent_qc.clone(), valid_new_header.clone());
        assert!(proposal_opt.is_some());
        let proposal = proposal_opt.unwrap();
        assert_eq!(proposal.round, 5);
        assert_eq!(proposal.proposer_pubkey, leader_pk);
        assert_eq!(proposal.proposed_triad_header.level, valid_new_header.level); // Check header content
        assert_eq!(proposal.parent_qc.round, parent_qc.round);

        // Non-leader attempts to generate proposal
        let non_leader_proposal_opt = state_non_leader.generate_proposal(parent_qc.clone(), valid_new_header.clone());
        assert!(non_leader_proposal_opt.is_none(), "Non-leader should not generate proposal");

        // Leader attempts to generate proposal with inconsistent header (parent_hash mismatch)
        let inconsistent_proposal_opt = state_leader.generate_proposal(parent_qc.clone(), invalid_new_header.clone());
        assert!(inconsistent_proposal_opt.is_none(), "Proposal with inconsistent parent hash should fail");
    }

    #[test]
    fn test_bft_state_generate_vote() {
        let validator_pk = dummy_pubkey(1);
        let leader_pk = dummy_pubkey(2); // Different from validator for this test
        let quorum = 2;
        let mut state = default_bft_state(validator_pk, leader_pk, quorum);
        state.current_round = 1;

        let parent_hash_val = dummy_item_hash(20);
        let parent_qc = QuorumCertificate {
            vote_type: VoteType::Commit,
            round: 0, // Parent QC from previous round
            certified_item_hash: parent_hash_val,
            signatures: vec![], // Dummy
        };

        let proposed_header = header_for_parent(parent_hash_val, 1, "prop_pos_1");
        let valid_proposal = TriadProposal {
            round: 1, // Matches current round
            proposer_pubkey: leader_pk,
            proposed_triad_header: proposed_header.clone(),
            parent_qc: parent_qc.clone(),
        };

        // Valid proposal -> should generate vote
        let vote_opt = state.generate_vote(&valid_proposal, VoteType::Prepare);
        assert!(vote_opt.is_some());
        let vote = vote_opt.unwrap();
        assert_eq!(vote.vote_type, VoteType::Prepare);
        assert_eq!(vote.round, 1);
        assert_eq!(vote.voted_item_hash, proposed_header.hash());

        // Invalid: Proposal for wrong round
        let wrong_round_proposal = TriadProposal { round: 2, ..valid_proposal.clone() };
        assert!(state.generate_vote(&wrong_round_proposal, VoteType::Prepare).is_none());

        // Invalid: Parent QC round not less than proposal round
        let bad_parent_qc_round = QuorumCertificate { round: 1, ..parent_qc.clone() };
        let bad_parent_qc_proposal = TriadProposal { parent_qc: bad_parent_qc_round, ..valid_proposal.clone() };
        assert!(state.generate_vote(&bad_parent_qc_proposal, VoteType::Prepare).is_none());

        // Invalid: Proposal parent hash mismatch with parent QC
        let mismatched_header = header_for_parent(dummy_item_hash(21), 1, "mismatch_pos"); // Different parent hash
        let bad_proposal_parent_hash = TriadProposal { proposed_triad_header: mismatched_header, ..valid_proposal.clone() };
        assert!(state.generate_vote(&bad_proposal_parent_hash, VoteType::Prepare).is_none());
    }

    #[test]
    fn test_bft_state_process_signed_vote_and_qc_formation() {
        let leader_pk = dummy_pubkey(1);
        let validator1_pk = dummy_pubkey(10);
        let validator2_pk = dummy_pubkey(11);
        // let validator3_pk = dummy_pubkey(12); // Unused, quorum is 2
        let quorum = 2; // Quorum of 2 votes needed

        let mut state = default_bft_state(leader_pk, leader_pk, quorum); // local_node is leader
        state.current_round = 1;

        let item_hash_to_vote_on = dummy_item_hash(30);

        // Create and process first vote (Prepare)
        let vote1_msg = VoteMessage { vote_type: VoteType::Prepare, round: 1, voted_item_hash: item_hash_to_vote_on };
        let signed_vote1 = SignedMessage { message: vote1_msg, signer_pubkey: validator1_pk, signature: dummy_signature(10) };
        let qc_opt1 = state.process_signed_vote(signed_vote1.clone());
        assert!(qc_opt1.is_none(), "QC should not form with only 1 vote");
        assert_eq!(state.prepare_votes.get(&(item_hash_to_vote_on, 1)).unwrap().len(), 1);

        // Process duplicate vote from validator1 - should be ignored
        let qc_opt_dup = state.process_signed_vote(signed_vote1.clone()); // Same signed vote
        assert!(qc_opt_dup.is_none(), "QC should not form from duplicate vote");
        assert_eq!(state.prepare_votes.get(&(item_hash_to_vote_on, 1)).unwrap().len(), 1, "Duplicate vote should not be added");

        // Create and process second vote from a different validator (Prepare)
        let vote2_msg = VoteMessage { vote_type: VoteType::Prepare, round: 1, voted_item_hash: item_hash_to_vote_on };
        let signed_vote2 = SignedMessage { message: vote2_msg, signer_pubkey: validator2_pk, signature: dummy_signature(11) };
        let qc_opt2 = state.process_signed_vote(signed_vote2.clone());

        assert!(qc_opt2.is_some(), "QC should form when quorum (2) is met for Prepare votes");
        let qc = qc_opt2.unwrap();
        assert_eq!(qc.vote_type, VoteType::Prepare);
        assert_eq!(qc.round, 1);
        assert_eq!(qc.certified_item_hash, item_hash_to_vote_on);
        assert_eq!(qc.signatures.len(), 2); // Contains sigs from validator1 and validator2
        assert!(qc.signatures.contains(&(validator1_pk, dummy_signature(10))));
        assert!(qc.signatures.contains(&(validator2_pk, dummy_signature(11))));

        // Check if QC is stored in known_qcs
        assert!(state.known_qcs.contains_key(&(item_hash_to_vote_on, 1)));

        // Process a third vote (should not form a new QC for the same item/round/type if one already formed,
        // but current impl might just add to list and re-form if list grows.
        // Let's assume it just adds to the list for now, the QC is formed once threshold is met).
        // The test above already confirmed QC formation.
        // A more robust check would be that process_signed_vote doesn't return Some(QC) again for the same (item,round,type)
        // if a QC was already formed and returned. Our current BftState.known_qcs keying might need adjustment for this.
        // For now, let's test that a vote for a different round or item doesn't interfere.

        let item_hash_other = dummy_item_hash(31);
        let vote_other_item_msg = VoteMessage { vote_type: VoteType::Prepare, round: 1, voted_item_hash: item_hash_other };
        let signed_vote_other_item = SignedMessage { message: vote_other_item_msg, signer_pubkey: validator1_pk, signature: dummy_signature(10) };
        let qc_opt_other = state.process_signed_vote(signed_vote_other_item);
        assert!(qc_opt_other.is_none(), "QC should not form for a different item with only 1 vote");
        assert_eq!(state.prepare_votes.get(&(item_hash_other, 1)).unwrap().len(), 1);
    }

    #[test]
    fn test_bft_state_advance_round() {
        let mut state = default_bft_state(dummy_pubkey(1), dummy_pubkey(1), 2);
        let initial_round = state.current_round;
        state.advance_round();
        assert_eq!(state.current_round, initial_round + 1, "Round should advance by 1");
    }

    #[test]
    fn test_generate_vote_phase_dependencies() {
        let validator_pk = dummy_pubkey(1);
        let leader_pk = dummy_pubkey(2);
        let quorum = 2;
        let mut state = default_bft_state(validator_pk, leader_pk, quorum);
        state.current_round = 1;

        let parent_hash_val = dummy_item_hash(50);
        let parent_qc_committed = QuorumCertificate {
            vote_type: VoteType::Commit, round: 0, certified_item_hash: parent_hash_val, signatures: vec![],
        };
        let proposed_header = header_for_parent(parent_hash_val, 1, "phase_test_pos");
        let proposal = TriadProposal {
            round: 1, proposer_pubkey: leader_pk,
            proposed_triad_header: proposed_header.clone(),
            parent_qc: parent_qc_committed.clone(),
        };
        let proposed_header_hash = proposed_header.hash();

        // Attempt to generate Precommit without PrepareQC -> should fail
        assert!(state.generate_vote(&proposal, VoteType::Precommit).is_none(), "Precommit vote should not be generated without PrepareQC");

        // Add a PrepareQC for the proposal
        let prepare_qc = QuorumCertificate {
            vote_type: VoteType::Prepare, round: 1, certified_item_hash: proposed_header_hash, signatures: vec![],
        };
        state.highest_prepare_qc_by_round.insert(1, prepare_qc.clone());

        // Now, Precommit vote should be possible
        let precommit_vote_opt = state.generate_vote(&proposal, VoteType::Precommit);
        assert!(precommit_vote_opt.is_some(), "Precommit vote should be generated with PrepareQC");
        assert_eq!(precommit_vote_opt.unwrap().vote_type, VoteType::Precommit);

        // Attempt to generate Commit without PrecommitQC -> should fail
        assert!(state.generate_vote(&proposal, VoteType::Commit).is_none(), "Commit vote should not be generated without PrecommitQC");

        // Add a PrecommitQC for the proposal
        let precommit_qc = QuorumCertificate {
            vote_type: VoteType::Precommit, round: 1, certified_item_hash: proposed_header_hash, signatures: vec![],
        };
        state.highest_precommit_qc_by_round.insert(1, precommit_qc.clone());

        // Now, Commit vote should be possible
        let commit_vote_opt = state.generate_vote(&proposal, VoteType::Commit);
        assert!(commit_vote_opt.is_some(), "Commit vote should be generated with PrecommitQC");
        assert_eq!(commit_vote_opt.unwrap().vote_type, VoteType::Commit);
    }

    #[test]
    fn test_full_three_phase_commit_flow() {
        let leader_pk = dummy_pubkey(1);
        let validator_pks: Vec<_> = (10..13).map(dummy_pubkey).collect(); // 3 validators
        let quorum = 2; // 2 out of 3 needed

        let mut leader_bft_state = default_bft_state(leader_pk, leader_pk, quorum);
        leader_bft_state.current_round = 1;

        let mut validator_states: Vec<_> = validator_pks.iter()
            .map(|pk| default_bft_state(*pk, leader_pk, quorum))
            .collect();
        validator_states.iter_mut().for_each(|s| s.current_round = 1);


        // 0. Setup: Parent QC
        let parent_item_hash = dummy_item_hash(100);
        let parent_qc = QuorumCertificate {
            vote_type: VoteType::Commit, round: 0, certified_item_hash: parent_item_hash, signatures: vec![],
        };

        // 1. Leader generates a proposal
        let proposed_header = header_for_parent(parent_item_hash, 1, "round_1_proposal");
        let proposal_opt = leader_bft_state.generate_proposal(parent_qc.clone(), proposed_header.clone());
        assert!(proposal_opt.is_some());
        let proposal = proposal_opt.unwrap();
        let proposed_header_hash = proposed_header.hash();

        // 2. Validators receive proposal and generate Prepare votes
        let mut prepare_votes_signed: Vec<SignedMessage<VoteMessage>> = Vec::new();
        for (i, pk) in validator_pks.iter().enumerate() {
            if let Some(vote_msg) = validator_states[i].generate_vote(&proposal, VoteType::Prepare) {
                prepare_votes_signed.push(SignedMessage { message: vote_msg, signer_pubkey: *pk, signature: dummy_signature(i as u8) });
            }
        }
        assert_eq!(prepare_votes_signed.len(), validator_pks.len(), "All validators should generate Prepare votes");

        // 3. Leader (or any node) processes Prepare votes to form PrepareQC
        let mut prepare_qc_opt: Option<QuorumCertificate> = None;
        for signed_vote in prepare_votes_signed.iter().take(quorum) { // Send enough for quorum
            prepare_qc_opt = leader_bft_state.process_signed_vote(signed_vote.clone());
            if prepare_qc_opt.is_some() { break; }
        }
        assert!(prepare_qc_opt.is_some(), "PrepareQC should be formed");
        let prepare_qc = prepare_qc_opt.unwrap();
        assert_eq!(prepare_qc.vote_type, VoteType::Prepare);
        assert_eq!(prepare_qc.certified_item_hash, proposed_header_hash);
        assert!(leader_bft_state.highest_prepare_qc_by_round.contains_key(&1));

        // (Distribute PrepareQC to validators - simulated by updating their state)
        for state in validator_states.iter_mut() {
            state.highest_prepare_qc_by_round.insert(1, prepare_qc.clone());
        }

        // 4. Validators generate Precommit votes (they've "seen" PrepareQC)
        let mut precommit_votes_signed: Vec<SignedMessage<VoteMessage>> = Vec::new();
        for (i, pk) in validator_pks.iter().enumerate() {
            if let Some(vote_msg) = validator_states[i].generate_vote(&proposal, VoteType::Precommit) {
                precommit_votes_signed.push(SignedMessage { message: vote_msg, signer_pubkey: *pk, signature: dummy_signature((i + 10) as u8) });
            }
        }
        assert_eq!(precommit_votes_signed.len(), validator_pks.len(), "All validators should generate Precommit votes");

        // 5. Leader processes Precommit votes to form PrecommitQC
        let mut precommit_qc_opt: Option<QuorumCertificate> = None;
        for signed_vote in precommit_votes_signed.iter().take(quorum) {
            precommit_qc_opt = leader_bft_state.process_signed_vote(signed_vote.clone());
            if precommit_qc_opt.is_some() { break; }
        }
        assert!(precommit_qc_opt.is_some(), "PrecommitQC should be formed");
        let precommit_qc = precommit_qc_opt.unwrap();
        assert_eq!(precommit_qc.vote_type, VoteType::Precommit);
        assert_eq!(precommit_qc.certified_item_hash, proposed_header_hash);
        assert!(leader_bft_state.highest_precommit_qc_by_round.contains_key(&1));

        // (Distribute PrecommitQC to validators)
        for state in validator_states.iter_mut() {
            state.highest_precommit_qc_by_round.insert(1, precommit_qc.clone());
        }

        // 6. Validators generate Commit votes
        let mut commit_votes_signed: Vec<SignedMessage<VoteMessage>> = Vec::new();
        for (i, pk) in validator_pks.iter().enumerate() {
            if let Some(vote_msg) = validator_states[i].generate_vote(&proposal, VoteType::Commit) {
                commit_votes_signed.push(SignedMessage { message: vote_msg, signer_pubkey: *pk, signature: dummy_signature((i + 20) as u8) });
            }
        }
        assert_eq!(commit_votes_signed.len(), validator_pks.len(), "All validators should generate Commit votes");

        // 7. Leader processes Commit votes to form CommitQC and commit item
        let mut commit_qc_opt: Option<QuorumCertificate> = None;
        for signed_vote in commit_votes_signed.iter().take(quorum) {
            commit_qc_opt = leader_bft_state.process_signed_vote(signed_vote.clone());
            if commit_qc_opt.is_some() { break; }
        }
        assert!(commit_qc_opt.is_some(), "CommitQC should be formed");
        let commit_qc = commit_qc_opt.unwrap();
        assert_eq!(commit_qc.vote_type, VoteType::Commit);
        assert_eq!(commit_qc.certified_item_hash, proposed_header_hash);

        assert!(leader_bft_state.committed_item_hashes.contains(&proposed_header_hash), "Item should be committed");

        // 8. Leader advances round (example trigger)
        leader_bft_state.advance_round();
        assert_eq!(leader_bft_state.current_round, 2);
    }
}
