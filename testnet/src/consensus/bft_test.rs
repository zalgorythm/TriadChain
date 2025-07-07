#[cfg(test)]
mod tests {
    use crate::consensus::bft::{VoteType, VoteMessage, QuorumCertificate, TriadProposal, SignedMessage, BftState};
    use crate::triad::TriadHeader;
    use crate::crypto::hash::blake3_hash;
    use crate::crypto::signing::{self, Keypair}; // Corrected import

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

    fn dummy_pubkey(id: u8) -> [u8; 32] {
        let mut pk = [0u8; 32];
        pk[0] = id;
        pk
    }

    fn dummy_item_hash(id: u8) -> [u8; 32] {
        let mut hash = [0u8; 32];
        hash[0] = id;
        hash
    }

    #[test]
    fn test_vote_type_instantiation() {
        let vt_prepare = VoteType::Prepare;
        let vt_commit = VoteType::Commit;
        assert_eq!(vt_prepare, VoteType::Prepare);
        assert_ne!(vt_prepare, vt_commit);
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
        let keypair1 = Keypair::generate();
        let keypair2 = Keypair::generate();
        let sig1 = signing::sign(b"message", &keypair1.secret);
        let sig2 = signing::sign(b"message", &keypair2.secret);

        let qc = QuorumCertificate {
            vote_type: VoteType::Precommit,
            round: 2,
            certified_item_hash: dummy_item_hash(2),
            signatures: vec![
                (keypair1.public.to_bytes(), sig1.to_bytes()),
                (keypair2.public.to_bytes(), sig2.to_bytes()),
            ],
        };
        assert_eq!(qc.signatures.len(), 2);
        assert_eq!(qc.round, 2);
    }

    #[test]
    fn test_triad_proposal_instantiation() {
        let keypair_proposer = Keypair::generate();
        let keypair_parent_qc_signer = Keypair::generate();
        let parent_qc_sig = signing::sign(b"parent_data", &keypair_parent_qc_signer.secret);

        let dummy_parent_qc = QuorumCertificate {
            vote_type: VoteType::Commit,
            round: 0,
            certified_item_hash: dummy_item_hash(0),
            signatures: vec![(keypair_parent_qc_signer.public.to_bytes(), parent_qc_sig.to_bytes())],
        };

        let proposal = TriadProposal {
            round: 1,
            proposer_pubkey: keypair_proposer.public.to_bytes(),
            proposed_triad_header: dummy_triad_header(),
            parent_qc: dummy_parent_qc,
        };
        assert_eq!(proposal.round, 1);
        assert_eq!(proposal.proposed_triad_header.level, 1);
    }

    #[test]
    fn test_signed_message_instantiation() {
        let keypair_signer = Keypair::generate();
        let vote_msg_content = VoteMessage {
            vote_type: VoteType::Commit,
            round: 3,
            voted_item_hash: dummy_item_hash(3),
        };
        let message_bytes = vote_msg_content.to_bytes();
        let signature = signing::sign(&message_bytes, &keypair_signer.secret);

        let signed_vote_msg: SignedMessage<VoteMessage> = SignedMessage {
            message: vote_msg_content,
            signer_pubkey: keypair_signer.public.to_bytes(),
            signature: signature.to_bytes(),
        };
        assert_eq!(signed_vote_msg.message.round, 3);
        assert_eq!(signed_vote_msg.signer_pubkey, keypair_signer.public.to_bytes());
    }

    fn default_bft_state(
        local_pk: [u8; 32],
        initial_round: u64,
        validator_set: Vec<[u8; 32]>,
        quorum: usize
    ) -> BftState {
        BftState::new(initial_round, validator_set, quorum, local_pk)
    }

    fn header_for_parent(parent_hash: [u8; 32], level: u64, position: &str) -> TriadHeader {
        TriadHeader {
            level,
            position: position.to_string(),
            position_hash: blake3_hash(position.as_bytes()),
            parent_hash,
            tx_root: dummy_item_hash(level as u8),
            state_root: dummy_item_hash(level as u8 + 100),
            tx_count: 0,
            max_capacity: (1000.0 * (1.0 + 0.004 * level as f64)) as u16,
            split_nonce: 0,
            timestamp: 1234567890 + level as i64,
            validator_sigs: [None; 15],
        }
    }

    #[test]
    fn test_bft_state_new_initial_leader() {
        let validator_pks_set = vec![dummy_pubkey(1), dummy_pubkey(2), dummy_pubkey(3)];

        let state_r0 = BftState::new(0, validator_pks_set.clone(), 2, validator_pks_set[0]);
        assert_eq!(state_r0.current_leader_pubkey, validator_pks_set[0]);
        assert_eq!(state_r0.current_round, 0);

        let state_r1 = BftState::new(1, validator_pks_set.clone(), 2, validator_pks_set[0]);
        assert_eq!(state_r1.current_leader_pubkey, validator_pks_set[1]);

        let state_r3 = BftState::new(3, validator_pks_set.clone(), 2, validator_pks_set[0]);
        assert_eq!(state_r3.current_leader_pubkey, validator_pks_set[0]);
    }

    #[test]
    #[should_panic(expected = "BftState: validator_set cannot be empty.")]
    fn test_bft_state_new_empty_validator_set_panics() {
        BftState::new(0, vec![], 1, dummy_pubkey(0));
    }

    #[test]
    fn test_bft_state_generate_proposal() {
        let validator_pks_set = vec![dummy_pubkey(1), dummy_pubkey(2), dummy_pubkey(3)];
        let initial_round: u64 = 5; // Explicitly u64
        let leader_for_round5 = validator_pks_set[initial_round as usize % validator_pks_set.len()];
        let non_leader_for_round5 = validator_pks_set[(initial_round as usize + 1) % validator_pks_set.len()];
        let quorum = 2;

        let state_leader = default_bft_state(leader_for_round5, initial_round, validator_pks_set.clone(), quorum);
        assert_eq!(state_leader.current_leader_pubkey, leader_for_round5);

        let state_non_leader = default_bft_state(non_leader_for_round5, initial_round, validator_pks_set.clone(), quorum);
        assert_eq!(state_non_leader.current_leader_pubkey, leader_for_round5); // Correct: current_leader is global for the round
        assert_ne!(state_non_leader.local_node_pubkey, state_non_leader.current_leader_pubkey);

        let parent_certified_hash = dummy_item_hash(10);
        let parent_qc = QuorumCertificate {
            vote_type: VoteType::Commit,
            round: 4,
            certified_item_hash: parent_certified_hash,
            signatures: vec![(dummy_pubkey(100), [0u8;64])],
        };

        let valid_new_header = header_for_parent(parent_certified_hash, 1, "pos_A");
        let invalid_new_header = header_for_parent(dummy_item_hash(11), 1, "pos_B");

        let proposal_opt = state_leader.generate_proposal(parent_qc.clone(), valid_new_header.clone());
        assert!(proposal_opt.is_some());
        let proposal = proposal_opt.unwrap();
        assert_eq!(proposal.round, initial_round);
        assert_eq!(proposal.proposer_pubkey, leader_for_round5); // Check against the actual leader

        let non_leader_proposal_opt = state_non_leader.generate_proposal(parent_qc.clone(), valid_new_header.clone());
        assert!(non_leader_proposal_opt.is_none());

        let inconsistent_proposal_opt = state_leader.generate_proposal(parent_qc.clone(), invalid_new_header.clone());
        assert!(inconsistent_proposal_opt.is_none());
    }

    #[test]
    fn test_bft_state_generate_vote() {
        let validator_node_pk = dummy_pubkey(1);
        let leader_for_round1_pk = dummy_pubkey(2);
        let other_validator_pk = dummy_pubkey(3);
        // Order for leader election: leader_for_round1_pk (idx 0), validator_node_pk (idx 1), other_validator_pk (idx 2)
        let validator_pks_set = vec![leader_for_round1_pk, validator_node_pk, other_validator_pk];

        let quorum = 2;
        let initial_round: u64 = 1; // Explicitly u64

        // BftState for validator_node_pk. For round 1, leader is validator_pks_set[1] (which is validator_node_pk).
        let state_validator_node = default_bft_state(validator_node_pk, initial_round, validator_pks_set.clone(), quorum);
        assert_eq!(state_validator_node.current_leader_pubkey, validator_node_pk);
        assert_eq!(state_validator_node.current_round, 1);

        let parent_hash_val = dummy_item_hash(20);
        let parent_qc = QuorumCertificate {
            vote_type: VoteType::Commit,
            round: 0,
            certified_item_hash: parent_hash_val,
            signatures: vec![],
        };

        let proposed_header = header_for_parent(parent_hash_val, 1, "prop_pos_1");
        // Proposal must be from the actual leader of round 1 (validator_node_pk in this setup)
        let valid_proposal = TriadProposal {
            round: 1,
            proposer_pubkey: validator_node_pk, // Corrected: proposal from actual leader
            proposed_triad_header: proposed_header.clone(),
            parent_qc: parent_qc.clone(),
        };

        let vote_opt = state_validator_node.generate_vote(&valid_proposal, VoteType::Prepare);
        assert!(vote_opt.is_some());
        let vote = vote_opt.unwrap();
        assert_eq!(vote.vote_type, VoteType::Prepare);
        assert_eq!(vote.round, 1);
        assert_eq!(vote.voted_item_hash, proposed_header.hash());

        let wrong_round_proposal = TriadProposal { round: 2, ..valid_proposal.clone() };
        assert!(state_validator_node.generate_vote(&wrong_round_proposal, VoteType::Prepare).is_none());

        let bad_parent_qc_round = QuorumCertificate { round: 1, ..parent_qc.clone() };
        let bad_parent_qc_proposal = TriadProposal { parent_qc: bad_parent_qc_round, ..valid_proposal.clone() };
        assert!(state_validator_node.generate_vote(&bad_parent_qc_proposal, VoteType::Prepare).is_none());

        let mismatched_header = header_for_parent(dummy_item_hash(21), 1, "mismatch_pos");
        let bad_proposal_parent_hash = TriadProposal { proposed_triad_header: mismatched_header, ..valid_proposal.clone() };
        assert!(state_validator_node.generate_vote(&bad_proposal_parent_hash, VoteType::Prepare).is_none());
    }

    #[test]
    fn test_bft_state_process_signed_vote_and_qc_formation() {
        let keypair_coord = Keypair::generate();
        let keypair_v1 = Keypair::generate();
        let keypair_v2 = Keypair::generate();

        let pk_coord = keypair_coord.public.to_bytes();
        let pk_v1 = keypair_v1.public.to_bytes();
        let pk_v2 = keypair_v2.public.to_bytes();

        let validator_pks_set = vec![pk_coord, pk_v1, pk_v2];
        let quorum = 2;
        let initial_round: u64 = 1; // Explicitly u64

        let mut state = default_bft_state(pk_coord, initial_round, validator_pks_set.clone(), quorum);
        // For round 1, leader is validator_pks_set[1] (pk_v1)
        assert_eq!(state.current_leader_pubkey, pk_v1);
        assert_eq!(state.current_round, 1);

        let item_hash_to_vote_on = dummy_item_hash(30);

        let vote1_msg = VoteMessage { vote_type: VoteType::Prepare, round: 1, voted_item_hash: item_hash_to_vote_on };
        let vote1_bytes = vote1_msg.to_bytes();
        let signature1 = signing::sign(&vote1_bytes, &keypair_v1.secret);
        let signed_vote1 = SignedMessage { message: vote1_msg.clone(), signer_pubkey: pk_v1, signature: signature1.to_bytes() };

        let qc_opt1 = state.process_signed_vote(signed_vote1.clone());
        assert!(qc_opt1.is_none());
        assert_eq!(state.prepare_votes.get(&(item_hash_to_vote_on, 1)).unwrap().len(), 1);

        let qc_opt_dup = state.process_signed_vote(signed_vote1.clone());
        assert!(qc_opt_dup.is_none());
        assert_eq!(state.prepare_votes.get(&(item_hash_to_vote_on, 1)).unwrap().len(), 1);

        let vote2_msg = VoteMessage { vote_type: VoteType::Prepare, round: 1, voted_item_hash: item_hash_to_vote_on };
        let vote2_bytes = vote2_msg.to_bytes();
        let signature2 = signing::sign(&vote2_bytes, &keypair_v2.secret);
        let signed_vote2 = SignedMessage { message: vote2_msg.clone(), signer_pubkey: pk_v2, signature: signature2.to_bytes() };

        let qc_opt2 = state.process_signed_vote(signed_vote2.clone());
        assert!(qc_opt2.is_some());
        let qc = qc_opt2.unwrap();
        assert_eq!(qc.vote_type, VoteType::Prepare);
        assert_eq!(qc.signatures.len(), 2);
        assert!(qc.signatures.contains(&(pk_v1, signature1.to_bytes())));
        assert!(qc.signatures.contains(&(pk_v2, signature2.to_bytes())));
        assert!(state.known_qcs.contains_key(&(item_hash_to_vote_on, 1)));

        let vote3_msg = VoteMessage { vote_type: VoteType::Precommit, round: 1, voted_item_hash: item_hash_to_vote_on };
        let vote3_bytes = vote3_msg.to_bytes();
        let signature3_by_v1 = signing::sign(&vote3_bytes, &keypair_v1.secret);
        let signed_vote3_wrong_signer = SignedMessage {
            message: vote3_msg.clone(),
            signer_pubkey: pk_v2,
            signature: signature3_by_v1.to_bytes()
        };
        let qc_opt3_invalid_sig = state.process_signed_vote(signed_vote3_wrong_signer);
        assert!(qc_opt3_invalid_sig.is_none());

        let random_signature_bytes = [7u8; 64];
        let signed_vote4_random_sig = SignedMessage {
            message: vote3_msg.clone(),
            signer_pubkey: pk_v1,
            signature: random_signature_bytes
        };
        let qc_opt4_random_sig = state.process_signed_vote(signed_vote4_random_sig);
        assert!(qc_opt4_random_sig.is_none());

        let item_hash_other = dummy_item_hash(31);
        let vote_other_item_msg = VoteMessage { vote_type: VoteType::Prepare, round: 1, voted_item_hash: item_hash_other };
        let vote_other_bytes = vote_other_item_msg.to_bytes();
        let sig_other = signing::sign(&vote_other_bytes, &keypair_v1.secret);
        let signed_vote_other_item = SignedMessage { message: vote_other_item_msg, signer_pubkey: pk_v1, signature: sig_other.to_bytes() };

        let qc_opt_other = state.process_signed_vote(signed_vote_other_item);
        assert!(qc_opt_other.is_none());
        assert_eq!(state.prepare_votes.get(&(item_hash_other, 1)).unwrap().len(), 1);
    }

    #[test]
    fn test_bft_state_advance_round_and_leader_rotation() {
        let validator_pks_set = vec![dummy_pubkey(10), dummy_pubkey(11), dummy_pubkey(12)];
        let local_node_pk = validator_pks_set[0];
        let quorum = 2;
        let initial_round: u64 = 0; // Explicitly u64

        let mut state = default_bft_state(local_node_pk, initial_round, validator_pks_set.clone(), quorum);

        assert_eq!(state.current_round, 0);
        assert_eq!(state.current_leader_pubkey, validator_pks_set[0]);

        state.advance_round();
        assert_eq!(state.current_round, 1);
        assert_eq!(state.current_leader_pubkey, validator_pks_set[1]);

        state.advance_round();
        assert_eq!(state.current_round, 2);
        assert_eq!(state.current_leader_pubkey, validator_pks_set[2]);

        state.advance_round();
        assert_eq!(state.current_round, 3);
        assert_eq!(state.current_leader_pubkey, validator_pks_set[0]);

        state.advance_round();
        assert_eq!(state.current_round, 4);
        assert_eq!(state.current_leader_pubkey, validator_pks_set[1]);
    }

    #[test]
    fn test_generate_vote_phase_dependencies() {
        let validator_node_pk = dummy_pubkey(1);
        let leader_for_round1_pk = dummy_pubkey(2);
        let other_validator_pk = dummy_pubkey(3);
        let validator_pks_set = vec![leader_for_round1_pk, validator_node_pk, other_validator_pk];
        let quorum = 2;
        let initial_round: u64 = 1; // Explicitly u64

        let mut state = default_bft_state(validator_node_pk, initial_round, validator_pks_set.clone(), quorum);
        assert_eq!(state.current_leader_pubkey, validator_node_pk);

        let parent_hash_val = dummy_item_hash(50);
        let parent_qc_committed = QuorumCertificate {
            vote_type: VoteType::Commit, round: 0, certified_item_hash: parent_hash_val, signatures: vec![],
        };
        let proposed_header = header_for_parent(parent_hash_val, 1, "phase_test_pos");
        let proposal = TriadProposal {
            round: 1, proposer_pubkey: state.current_leader_pubkey,
            proposed_triad_header: proposed_header.clone(),
            parent_qc: parent_qc_committed.clone(),
        };
        let proposed_header_hash = proposed_header.hash();

        assert!(state.generate_vote(&proposal, VoteType::Precommit).is_none());

        let prepare_qc = QuorumCertificate {
            vote_type: VoteType::Prepare, round: 1, certified_item_hash: proposed_header_hash, signatures: vec![],
        };
        state.highest_prepare_qc_by_round.insert(1, prepare_qc.clone());

        let precommit_vote_opt = state.generate_vote(&proposal, VoteType::Precommit);
        assert!(precommit_vote_opt.is_some());
        assert_eq!(precommit_vote_opt.unwrap().vote_type, VoteType::Precommit);

        assert!(state.generate_vote(&proposal, VoteType::Commit).is_none());

        let precommit_qc = QuorumCertificate {
            vote_type: VoteType::Precommit, round: 1, certified_item_hash: proposed_header_hash, signatures: vec![],
        };
        state.highest_precommit_qc_by_round.insert(1, precommit_qc.clone());

        let commit_vote_opt = state.generate_vote(&proposal, VoteType::Commit);
        assert!(commit_vote_opt.is_some());
        assert_eq!(commit_vote_opt.unwrap().vote_type, VoteType::Commit);
    }

    #[test]
    fn test_full_three_phase_commit_flow() {
        let keypair_v0 = Keypair::generate();
        let keypair_v1 = Keypair::generate();
        let keypair_v2 = Keypair::generate();

        let pk_v0_bytes = keypair_v0.public.to_bytes();
        let pk_v1_bytes = keypair_v1.public.to_bytes();
        let pk_v2_bytes = keypair_v2.public.to_bytes();

        let validator_pks_set = vec![pk_v0_bytes, pk_v1_bytes, pk_v2_bytes];
        let validator_keypairs = vec![keypair_v0, keypair_v1, keypair_v2];

        let quorum = 2;
        let initial_round_test: u64 = 1; // Explicitly u64

        let actual_leader_for_round_1 = validator_pks_set[initial_round_test as usize % validator_pks_set.len()];
        assert_eq!(actual_leader_for_round_1, pk_v1_bytes);
        let mut coordinator_bft_state = default_bft_state(actual_leader_for_round_1, initial_round_test, validator_pks_set.clone(), quorum);

        let mut validator_bft_states: Vec<_> = validator_pks_set.iter()
            .map(|pk| default_bft_state(*pk, initial_round_test, validator_pks_set.clone(), quorum))
            .collect();

        let parent_item_hash = dummy_item_hash(100);
        let parent_qc = QuorumCertificate {
            vote_type: VoteType::Commit, round: 0, certified_item_hash: parent_item_hash, signatures: vec![],
        };

        let proposed_header = header_for_parent(parent_item_hash, 1, "round_1_proposal");
        let proposal_opt = coordinator_bft_state.generate_proposal(parent_qc.clone(), proposed_header.clone());
        assert!(proposal_opt.is_some());
        let proposal = proposal_opt.unwrap();
        assert_eq!(proposal.proposer_pubkey, actual_leader_for_round_1);
        let proposed_header_hash = proposed_header.hash();

        let mut prepare_votes_signed: Vec<SignedMessage<VoteMessage>> = Vec::new();
        for (i, _pk_bytes) in validator_pks_set.iter().enumerate() {
            if let Some(vote_msg) = validator_bft_states[i].generate_vote(&proposal, VoteType::Prepare) {
                let vote_bytes = vote_msg.to_bytes();
                let signature = signing::sign(&vote_bytes, &validator_keypairs[i].secret);
                prepare_votes_signed.push(SignedMessage {
                    message: vote_msg,
                    signer_pubkey: validator_keypairs[i].public.to_bytes(),
                    signature: signature.to_bytes()
                });
            }
        }
        assert_eq!(prepare_votes_signed.len(), validator_pks_set.len());

        let mut prepare_qc_opt: Option<QuorumCertificate> = None;
        for signed_vote in prepare_votes_signed.iter().take(quorum) {
            prepare_qc_opt = coordinator_bft_state.process_signed_vote(signed_vote.clone());
            if prepare_qc_opt.is_some() { break; }
        }
        assert!(prepare_qc_opt.is_some());
        let prepare_qc = prepare_qc_opt.unwrap();
        assert_eq!(prepare_qc.vote_type, VoteType::Prepare);
        assert_eq!(prepare_qc.certified_item_hash, proposed_header_hash);
        assert!(coordinator_bft_state.highest_prepare_qc_by_round.contains_key(&initial_round_test));

        for state in validator_bft_states.iter_mut() {
            state.highest_prepare_qc_by_round.insert(initial_round_test, prepare_qc.clone());
        }

        let mut precommit_votes_signed: Vec<SignedMessage<VoteMessage>> = Vec::new();
        for (i, _pk_bytes) in validator_pks_set.iter().enumerate() {
            if let Some(vote_msg) = validator_bft_states[i].generate_vote(&proposal, VoteType::Precommit) {
                let vote_bytes = vote_msg.to_bytes();
                let signature = signing::sign(&vote_bytes, &validator_keypairs[i].secret);
                precommit_votes_signed.push(SignedMessage {
                    message: vote_msg,
                    signer_pubkey: validator_keypairs[i].public.to_bytes(),
                    signature: signature.to_bytes()
                });
            }
        }
        assert_eq!(precommit_votes_signed.len(), validator_pks_set.len());

        let mut precommit_qc_opt: Option<QuorumCertificate> = None;
        for signed_vote in precommit_votes_signed.iter().take(quorum) {
            precommit_qc_opt = coordinator_bft_state.process_signed_vote(signed_vote.clone());
            if precommit_qc_opt.is_some() { break; }
        }
        assert!(precommit_qc_opt.is_some());
        let precommit_qc = precommit_qc_opt.unwrap();
        assert_eq!(precommit_qc.vote_type, VoteType::Precommit);
        assert_eq!(precommit_qc.certified_item_hash, proposed_header_hash);
        assert!(coordinator_bft_state.highest_precommit_qc_by_round.contains_key(&initial_round_test));

        for state in validator_bft_states.iter_mut() {
            state.highest_precommit_qc_by_round.insert(initial_round_test, precommit_qc.clone());
        }

        let mut commit_votes_signed: Vec<SignedMessage<VoteMessage>> = Vec::new();
        for (i, _pk_bytes) in validator_pks_set.iter().enumerate() {
            if let Some(vote_msg) = validator_bft_states[i].generate_vote(&proposal, VoteType::Commit) {
                let vote_bytes = vote_msg.to_bytes();
                let signature = signing::sign(&vote_bytes, &validator_keypairs[i].secret);
                commit_votes_signed.push(SignedMessage {
                    message: vote_msg,
                    signer_pubkey: validator_keypairs[i].public.to_bytes(),
                    signature: signature.to_bytes()
                });
            }
        }
        assert_eq!(commit_votes_signed.len(), validator_pks_set.len());

        let mut commit_qc_opt: Option<QuorumCertificate> = None;
        for signed_vote in commit_votes_signed.iter().take(quorum) {
            commit_qc_opt = coordinator_bft_state.process_signed_vote(signed_vote.clone());
            if commit_qc_opt.is_some() { break; }
        }
        assert!(commit_qc_opt.is_some());
        let commit_qc = commit_qc_opt.unwrap();
        assert_eq!(commit_qc.vote_type, VoteType::Commit);
        assert_eq!(commit_qc.certified_item_hash, proposed_header_hash);

        assert!(coordinator_bft_state.committed_item_hashes.contains(&proposed_header_hash));

        coordinator_bft_state.advance_round();
        assert_eq!(coordinator_bft_state.current_round, initial_round_test + 1);
    }
}
