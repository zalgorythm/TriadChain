#[cfg(test)]
mod tests {
    use crate::triad::{Triad, Transaction}; // Use re-exported versions
    use crate::triad::routing::{calculate_transaction_path, find_target_triad};
    use crate::crypto::hash::blake3_hash;
    use std::sync::Arc;
    use parking_lot::RwLock;

    // Helper to create a default transaction
    fn sample_transaction(nonce: u64) -> Transaction {
        Transaction {
            version: 1,
            nonce,
            sender: [1u8; 32],
            recipient: [2u8; 32],
            amount: 100,
            gas_limit: 20000,
            signature: [3u8; 64],
            data: vec![4, 5, 6],
        }
    }

    #[test]
    fn test_transaction_creation() {
        let tx = sample_transaction(1);
        assert_eq!(tx.nonce, 1);
        assert_eq!(tx.sender, [1u8; 32]);
    }

    #[test]
    fn test_calculate_transaction_path_basic() {
        let sender = [0xAAu8; 32];
        let nonce = 0x123456789ABCDEF0u64;

        let mut input_data = Vec::with_capacity(32 + 8);
        input_data.extend_from_slice(&sender);
        input_data.extend_from_slice(&nonce.to_be_bytes());
        let expected_hash = blake3_hash(&input_data);

        // Expected path choices from the first byte of the hash
        // (byte >> 6) & 0b11, (byte >> 4) & 0b11, etc.
        let expected_path_byte0_q1 = (expected_hash[0] >> 6) & 0b11;
        let expected_path_byte0_q2 = (expected_hash[0] >> 4) & 0b11;
        let expected_path_byte0_q3 = (expected_hash[0] >> 2) & 0b11;
        let expected_path_byte0_q4 = expected_hash[0] & 0b11;

        let path = calculate_transaction_path(&sender, nonce);

        assert_eq!(path.len(), 32 * 4, "Path length should be 128.");
        assert_eq!(path[0], expected_path_byte0_q1, "First path choice mismatch.");
        assert_eq!(path[1], expected_path_byte0_q2, "Second path choice mismatch.");
        assert_eq!(path[2], expected_path_byte0_q3, "Third path choice mismatch.");
        assert_eq!(path[3], expected_path_byte0_q4, "Fourth path choice mismatch.");

        // Test with different sender/nonce to ensure path changes
        let sender2 = [0xBB; 32];
        let nonce2 = 0xFEDCBA9876543210u64;
        let path2 = calculate_transaction_path(&sender2, nonce2);
        assert_ne!(path, path2, "Paths for different inputs should not be identical.");
    }

    // Helper to create a simple triad for testing
    fn create_test_triad(level: u64, position: &str, parent: Option<Arc<RwLock<Triad>>>) -> Arc<RwLock<Triad>> {
        Triad::new(level, position.to_string(), parent.map(|p| Arc::downgrade(&p)))
    }

    #[test]
    fn test_find_target_triad() {
        // Build a small triad tree:
        // Root ("R")
        //  +- Child0 ("R0") -> Grandchild00 ("R00")
        //  +- Child1 ("R1")
        //  +- Child2 ("R2") (empty)
        //  +- Child3 ("R3")
        let root = create_test_triad(0, "R", None);
        let child0 = create_test_triad(1, "R0", Some(Arc::clone(&root)));
        let child1 = create_test_triad(1, "R1", Some(Arc::clone(&root)));
        let grandchild00 = create_test_triad(2, "R00", Some(Arc::clone(&child0)));
        // Child3 is also created for a different path test later
        let child3 = create_test_triad(1, "R3", Some(Arc::clone(&root)));


        {
            let root_w = root.write(); // Removed mut
            root_w.add_child(Arc::clone(&child0), 0).unwrap();
            root_w.add_child(Arc::clone(&child1), 1).unwrap();
            // Child at index 2 is deliberately left None (empty)
            root_w.add_child(Arc::clone(&child3), 3).unwrap();


            let child0_w = child0.write(); // Removed mut
            child0_w.add_child(Arc::clone(&grandchild00), 0).unwrap();
        }

        // Test cases:
        // 1. Path leads to deepest existing triad (grandchild00)
        let path1 = vec![0, 0]; // R -> Child0 -> Grandchild00
        let target1 = find_target_triad(Arc::clone(&root), &path1);
        assert!(Arc::ptr_eq(&target1, &grandchild00), "Path1 should lead to grandchild00");
        assert_eq!(target1.read().header.position, "R00");

        // 2. Path leads to a shallower triad (child1) because next step doesn't exist
        let path2 = vec![1, 0]; // R -> Child1 -> (No child at 0 for Child1)
        let target2 = find_target_triad(Arc::clone(&root), &path2);
        assert!(Arc::ptr_eq(&target2, &child1), "Path2 should lead to child1");
        assert_eq!(target2.read().header.position, "R1");

        // 3. Path leads to root because first step doesn't exist (e.g. path to non-existent child2 from root)
        let path3 = vec![2, 0]; // R -> (No Child2)
        let target3 = find_target_triad(Arc::clone(&root), &path3);
        assert!(Arc::ptr_eq(&target3, &root), "Path3 should lead to root because child at index 2 is None");
        assert_eq!(target3.read().header.position, "R");

        // 4. Empty path returns the starting triad
        let path4 = vec![];
        let target4 = find_target_triad(Arc::clone(&root), &path4);
        assert!(Arc::ptr_eq(&target4, &root), "Empty path should return start triad");

        // 5. Path is longer than existing structure
        let path5 = vec![0, 0, 0, 0]; // R -> Child0 -> Grandchild00 -> (deeper non-existent)
        let target5 = find_target_triad(Arc::clone(&root), &path5);
        assert!(Arc::ptr_eq(&target5, &grandchild00), "Path5 should lead to deepest existing: grandchild00");

        // 6. Path with an invalid choice (e.g., 4) - should stop at triad before invalid choice
        //    Assuming current_triad_arc is root, child3 is at root.children[3]
        let path6 = vec![3, 4, 0]; // R -> Child3 -> (invalid choice 4)
                                   // find_target_triad stops at Child3 because choice 4 is > 3
        let target6 = find_target_triad(Arc::clone(&root), &path6);
        assert!(Arc::ptr_eq(&target6, &child3), "Path6 should lead to child3 before invalid choice");
        assert_eq!(target6.read().header.position, "R3");
    }

    #[test]
    fn test_triad_add_transaction() {
        let triad_arc = create_test_triad(0, "test_triad", None);

        // Default capacity for level 0 is 1000
        let max_cap = triad_arc.read().header.max_capacity;
        assert_eq!(max_cap, 1000, "Default capacity for level 0 should be 1000");

        let tx1 = sample_transaction(1);
        let tx2 = sample_transaction(2);

        // Add first transaction
        {
            let mut triad_w = triad_arc.write();
            let result = triad_w.add_transaction(tx1.clone());
            assert!(result.is_ok());
            assert_eq!(triad_w.header.tx_count, 1);
            assert_eq!(triad_w.transactions.len(), 1);

            let mut expected_tx_root_data = Vec::new();
            expected_tx_root_data.extend_from_slice(&tx1.sender);
            expected_tx_root_data.extend_from_slice(&tx1.nonce.to_be_bytes());
            assert_eq!(triad_w.header.tx_root, blake3_hash(&expected_tx_root_data));
        }

        // Add second transaction
         {
            let mut triad_w = triad_arc.write();
            let result = triad_w.add_transaction(tx2.clone());
            assert!(result.is_ok());
            assert_eq!(triad_w.header.tx_count, 2);
            assert_eq!(triad_w.transactions.len(), 2);

            let mut expected_tx_root_data = Vec::new();
            expected_tx_root_data.extend_from_slice(&tx1.sender);
            expected_tx_root_data.extend_from_slice(&tx1.nonce.to_be_bytes());
            expected_tx_root_data.extend_from_slice(&tx2.sender);
            expected_tx_root_data.extend_from_slice(&tx2.nonce.to_be_bytes());
            assert_eq!(triad_w.header.tx_root, blake3_hash(&expected_tx_root_data));
        }
    }

    #[test]
    fn test_triad_add_transaction_capacity_limit() {
        let triad_arc = create_test_triad(0, "cap_triad", None);
        // Manually set a small capacity for testing
        let test_capacity = 2u16;
        triad_arc.write().header.max_capacity = test_capacity;
        triad_arc.write().header.tx_count = 0; // Ensure count is reset if header was cloned weirdly

        assert_eq!(triad_arc.read().header.max_capacity, test_capacity);


        let tx1 = sample_transaction(10);
        let tx2 = sample_transaction(11);
        let tx3 = sample_transaction(12);

        assert!(triad_arc.write().add_transaction(tx1.clone()).is_ok());
        assert_eq!(triad_arc.read().header.tx_count, 1);

        assert!(triad_arc.write().add_transaction(tx2.clone()).is_ok());
        assert_eq!(triad_arc.read().header.tx_count, 2);

        // Now at capacity
        let result = triad_arc.write().add_transaction(tx3.clone());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), format!("Triad at maximum capacity ({} transactions). Cannot add more.", test_capacity));
        assert_eq!(triad_arc.read().header.tx_count, test_capacity); // Count should not have changed
        assert_eq!(triad_arc.read().transactions.len(), test_capacity as usize); // Vec length
    }
}
