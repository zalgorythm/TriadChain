#[cfg(test)]
mod tests {
    // Reverted to more explicit imports as `use super::*;` was not resolving Triad/TriadHeader
    use crate::triad::{Triad, TriadHeader, TriadState};
    use crate::crypto::hash::blake3_hash;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    // use std::collections::BTreeMap; // Removed unused import

    /// Creates a sample `TriadHeader` instance with preset values for use in tests.
    ///
    /// The returned header uses fixed values for all fields, suitable for deterministic testing of encoding and hashing logic.
    ///
    /// # Examples
    ///
    /// ```
    /// let header = default_header();
    /// assert_eq!(header.level, 1);
    /// assert_eq!(header.position, "01");
    /// ```
    fn default_header() -> TriadHeader {
        TriadHeader {
            level: 1,
            position: "01".to_string(),
            position_hash: blake3_hash(b"01"),
            parent_hash: [0; 32], // Not relevant for this specific test of canonical_encoding itself
            tx_root: [1; 32],
            state_root: [2; 32],
            tx_count: 10,
            max_capacity: 1004, // 1000 * (1 + 0.004 * 1)
            split_nonce: 12345, // This is not part of canonical_encoding
            timestamp: 1678886400, // Example timestamp
            validator_sigs: [None; 15], // Not part of canonical_encoding
        }
    }

    #[test]
    fn test_triad_header_canonical_encoding() {
        let header = default_header();

        let mut expected_bytes = Vec::new();
        expected_bytes.extend(header.level.to_be_bytes());
        expected_bytes.extend(header.position.as_bytes());
        expected_bytes.extend(header.position_hash);
        expected_bytes.extend(header.tx_root);
        expected_bytes.extend(header.state_root);
        expected_bytes.extend(header.tx_count.to_be_bytes());
        expected_bytes.extend(header.max_capacity.to_be_bytes());
        expected_bytes.extend(header.timestamp.to_be_bytes());

        let encoded_bytes = header.canonical_encoding();
        assert_eq!(encoded_bytes, expected_bytes, "Canonical encoding did not match expected bytes.");
    }

    /// Tests that a genesis `Triad` (level 0, no parent) has a zeroed parent hash, correct level, max capacity, and a timestamp within the creation window.
    fn test_parent_hash_calculation_genesis() {
        let time_before = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        // Genesis triad (no parent)
        let genesis_arc = Triad::new(0, "0".to_string(), None);
        let time_after = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;

        let genesis_triad = genesis_arc.read();
        assert_eq!(genesis_triad.header.parent_hash, [0u8; 32], "Genesis parent_hash should be all zeros.");
        assert!(genesis_triad.is_root());
        assert_eq!(genesis_triad.header.level, 0, "Genesis level should be 0.");
        assert_eq!(genesis_triad.header.max_capacity, 1000, "Genesis max_capacity should be 1000.");
        assert!(genesis_triad.header.timestamp >= time_before && genesis_triad.header.timestamp <= time_after,
                "Genesis timestamp {} should be between {} and {}", genesis_triad.header.timestamp, time_before, time_after);
    }

    /// Tests that a child triad correctly computes its `parent_hash` as the hash of the parent's canonical encoding,
    /// and verifies that header fields such as level, max capacity, and timestamp are set as expected for both parent and child triads.
    fn test_parent_hash_calculation_with_parent() {
        // Create a parent triad
        let parent_level = 0u64;
        let parent_position = "0".to_string();

        let parent_time_before = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let parent_arc = Triad::new(parent_level, parent_position.clone(), None);
        let parent_time_after = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;

        // Check parent's auto-set fields
        {
            let parent_triad_read = parent_arc.read();
            assert_eq!(parent_triad_read.header.max_capacity, 1000, "Parent (level 0) max_capacity should be 1000.");
            assert!(parent_triad_read.header.timestamp >= parent_time_before && parent_triad_read.header.timestamp <= parent_time_after,
                    "Parent timestamp {} should be between {} and {}", parent_triad_read.header.timestamp, parent_time_before, parent_time_after);
        }

        // Manually set some fields for the parent's header that are part of canonical_encoding for parent_hash test
        // Note: We are testing parent_hash calc, so parent's timestamp for that encoding can be fixed.
        // The actual live timestamp of the parent object is tested above.
        let fixed_parent_timestamp_for_encoding: i64 = 1234567890;
        {
            let mut parent_triad_mut = parent_arc.write();
            parent_triad_mut.header.tx_root = blake3_hash(b"parent_tx_root");
            parent_triad_mut.header.state_root = blake3_hash(b"parent_state_root");
            parent_triad_mut.header.tx_count = 5;
            parent_triad_mut.header.timestamp = fixed_parent_timestamp_for_encoding; // Override for predictable encoding
        }

        let parent_header_for_encoding = parent_arc.read().header.clone(); // Clone to avoid holding lock

        // Calculate expected parent_hash using the parent header with the fixed timestamp
        assert_eq!(parent_header_for_encoding.timestamp, fixed_parent_timestamp_for_encoding, "Timestamp for encoding should be the fixed one.");
        let expected_parent_hash = blake3_hash(&parent_header_for_encoding.canonical_encoding());

        // Create a child triad
        let child_level = 1u64;
        let child_position = "00".to_string();

        let child_time_before = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let child_arc = Triad::new(child_level, child_position, Some(Arc::downgrade(&parent_arc)));
        let child_time_after = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;

        let child_triad = child_arc.read();

        assert_eq!(child_triad.header.parent_hash, expected_parent_hash, "Child's parent_hash does not match the hash of parent's canonical_encoding.");
        assert_eq!(child_triad.header.level, child_level);
        assert_eq!(child_triad.header.max_capacity, 1004, "Child (level 1) max_capacity should be 1004.");
        assert!(child_triad.header.timestamp >= child_time_before && child_triad.header.timestamp <= child_time_after,
                "Child timestamp {} should be between {} and {}", child_triad.header.timestamp, child_time_before, child_time_after);
    }
    
    /// Tests that a genesis `Triad` is correctly initialized as a root with the expected max capacity and a timestamp within the creation window.
    fn test_genesis_creation() { // This is somewhat redundant with test_parent_hash_calculation_genesis now
        let time_before = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let genesis_arc = Triad::new(0, "0".to_string(), None);
        let time_after = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;

        let triad = genesis_arc.read();
        assert!(triad.is_root());
        assert_eq!(triad.header.max_capacity, 1000);
        assert!(triad.header.timestamp >= time_before && triad.header.timestamp <= time_after);
    }

    /// Tests that the `max_capacity` field of a `Triad` is correctly calculated for various levels.
    ///
    /// This test iterates over several triad levels and their expected maximum capacities,
    /// creates a `Triad` at each level, and asserts that the computed `max_capacity` matches
    /// the expected value based on the scaling formula.
    fn test_triad_max_capacity_various_levels() {
        let levels_and_expected_capacities = [
            (0u64, 1000u16),
            (1u64, 1004u16),
            (5u64, 1020u16),
            (10u64, 1040u16),
            (250u64, 2000u16), // 1000 * (1 + 0.004 * 250) = 1000 * (1 + 1) = 2000
        ];

        for (level, expected_capacity) in levels_and_expected_capacities.iter() {
            let triad_arc = Triad::new(*level, format!("pos-{}", level), None);
            let triad = triad_arc.read();
            assert_eq!(triad.header.max_capacity, *expected_capacity,
                       "Max capacity for level {} was expected to be {} but got {}",
                       level, expected_capacity, triad.header.max_capacity);
        }
    }

    // --- Tests for TriadState::recompute_root ---

    fn key_val(k: u8, v_str: &str) -> ([u8; 32], Vec<u8>) {
        let mut key = [0u8; 32];
        key[0] = k;
        (key, v_str.as_bytes().to_vec())
    }

    // Helper to compute leaf hash as per TriadState logic
    fn compute_leaf_hash(key: &[u8; 32], value: &Vec<u8>) -> [u8; 32] {
        let mut leaf_data = Vec::new();
        leaf_data.extend_from_slice(key);
        leaf_data.extend_from_slice(&blake3_hash(value));
        blake3_hash(&leaf_data)
    }

    // Helper to compute internal Merkle node hash
    fn compute_internal_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut data = Vec::new();
        data.extend_from_slice(left);
        data.extend_from_slice(right);
        blake3_hash(&data)
    }

    #[test]
    fn test_triad_state_recompute_root_empty() {
        let mut state = TriadState::new(); // New already computes root once.
        assert_eq!(state.root, blake3_hash(b"empty_state_root"), "Default empty root mismatch");

        state.recompute_root(); // Recompute on an already empty state
        assert_eq!(state.root, blake3_hash(b"empty_state_root"), "Recomputed empty root mismatch");
        assert_eq!(state.version, 1, "Version should be 1 after one recompute");
    }

    #[test]
    fn test_triad_state_recompute_root_single_leaf() {
        let mut state = TriadState::new();
        let (k1, v1) = key_val(1, "value1");
        state.storage.insert(k1.clone(), v1.clone());
        state.recompute_root();

        let expected_root = compute_leaf_hash(&k1, &v1);
        assert_eq!(state.root, expected_root, "Root for single leaf mismatch");
    }

    #[test]
    fn test_triad_state_recompute_root_two_leaves() {
        let mut state = TriadState::new();
        let (k1, v1) = key_val(1, "value1");
        let (k2, v2) = key_val(2, "value2"); // BTreeMap sorts by key

        state.storage.insert(k1.clone(), v1.clone());
        state.storage.insert(k2.clone(), v2.clone());
        state.recompute_root();

        let leaf1_hash = compute_leaf_hash(&k1, &v1);
        let leaf2_hash = compute_leaf_hash(&k2, &v2);
        let expected_root = compute_internal_node_hash(&leaf1_hash, &leaf2_hash);

        assert_eq!(state.root, expected_root, "Root for two leaves mismatch");
    }

    #[test]
    fn test_triad_state_recompute_root_three_leaves() {
        let mut state = TriadState::new();
        let (k1, v1) = key_val(1, "value1");
        let (k2, v2) = key_val(2, "value2");
        let (k3, v3) = key_val(3, "value3");

        state.storage.insert(k1.clone(), v1.clone());
        state.storage.insert(k2.clone(), v2.clone());
        state.storage.insert(k3.clone(), v3.clone());
        state.recompute_root();

        let leaf1_hash = compute_leaf_hash(&k1, &v1);
        let leaf2_hash = compute_leaf_hash(&k2, &v2);
        let leaf3_hash = compute_leaf_hash(&k3, &v3);

        // Level 1 hashes: H(L1,L2), H(L3,L3) because L3 is duplicated
        let node12_hash = compute_internal_node_hash(&leaf1_hash, &leaf2_hash);
        let node33_hash = compute_internal_node_hash(&leaf3_hash, &leaf3_hash); // L3 duplicated

        // Level 2 hash (root): H(H(L1,L2), H(L3,L3))
        let expected_root = compute_internal_node_hash(&node12_hash, &node33_hash);

        assert_eq!(state.root, expected_root, "Root for three leaves mismatch");
    }

    #[test]
    fn test_triad_state_root_changes_on_modification() {
        let mut state = TriadState::new();
        let (k1, v1_initial) = key_val(1, "initial_value");
        state.storage.insert(k1.clone(), v1_initial);
        state.recompute_root();
        let root1 = state.root;

        // Modify value
        let v1_modified = "modified_value".as_bytes().to_vec();
        state.storage.insert(k1.clone(), v1_modified);
        state.recompute_root();
        let root2 = state.root;
        assert_ne!(root1, root2, "Root should change when a value is modified");

        // Add new key
        let (k2, v2) = key_val(2, "another_value");
        state.storage.insert(k2, v2);
        state.recompute_root();
        let root3 = state.root;
        assert_ne!(root2, root3, "Root should change when a new key is added");

        // Remove a key
        state.storage.remove(&k1);
        state.recompute_root();
        let root4 = state.root;
        assert_ne!(root3, root4, "Root should change when a key is removed");

        // Remove last key, should go to empty root
        state.storage.remove(&k2);
        state.recompute_root();
        assert_eq!(state.root, blake3_hash(b"empty_state_root"), "Root should be empty_state_root after removing all keys");
    }
}

    #[test]
    fn test_triad_header_canonical_encoding_edge_cases() {
        // Test with empty position
        let mut header = default_header();
        header.position = "".to_string();
        header.position_hash = blake3_hash(b"");
        
        let encoded = header.canonical_encoding();
        assert!(!encoded.is_empty(), "Canonical encoding should not be empty even with empty position");
        
        // Test with very long position
        header.position = "a".repeat(1000);
        header.position_hash = blake3_hash(header.position.as_bytes());
        let encoded_long = header.canonical_encoding();
        assert!(encoded_long.len() > encoded.len(), "Encoding with long position should be longer");
    }

    #[test]
    fn test_triad_header_canonical_encoding_deterministic() {
        let header1 = default_header();
        let header2 = default_header();
        
        assert_eq!(header1.canonical_encoding(), header2.canonical_encoding(), 
                   "Identical headers should produce identical canonical encodings");
    }

    #[test]
    fn test_triad_header_canonical_encoding_field_order() {
        let mut header = default_header();
        let original_encoding = header.canonical_encoding();
        
        // Modify different fields and ensure encoding changes
        header.level = 999;
        let level_modified = header.canonical_encoding();
        assert_ne!(original_encoding, level_modified, "Level change should affect encoding");
        
        header = default_header();
        header.tx_count = 999;
        let tx_count_modified = header.canonical_encoding();
        assert_ne!(original_encoding, tx_count_modified, "TX count change should affect encoding");
        
        header = default_header();
        header.max_capacity = 9999;
        let capacity_modified = header.canonical_encoding();
        assert_ne!(original_encoding, capacity_modified, "Max capacity change should affect encoding");
    }

    #[test]
    fn test_triad_creation_with_invalid_weak_parent() {
        // Test creating a triad with a weak reference that might be dropped
        let parent_arc = Triad::new(0, "parent".to_string(), None);
        let weak_parent = Arc::downgrade(&parent_arc);
        
        // Drop the strong reference
        drop(parent_arc);
        
        // This should handle the case where parent is dropped
        let child_arc = Triad::new(1, "child".to_string(), Some(weak_parent));
        let child = child_arc.read();
        
        // The child should still be created but with zero parent hash
        assert_eq!(child.header.parent_hash, [0u8; 32], "Child with dropped parent should have zero parent hash");
    }

    #[test]
    fn test_triad_position_hash_calculation() {
        let positions = vec!["0", "00", "01", "10", "11", "000", "001", "010", "011", "100", "101", "110", "111"];
        
        for position in positions {
            let triad_arc = Triad::new(1, position.to_string(), None);
            let triad = triad_arc.read();
            
            let expected_hash = blake3_hash(position.as_bytes());
            assert_eq!(triad.header.position_hash, expected_hash,
                       "Position hash for '{}' should match blake3 hash of position bytes", position);
        }
    }

    #[test]
    fn test_triad_max_capacity_boundary_values() {
        let boundary_cases = [
            (0u64, 1000u16),
            (1u64, 1004u16),
            (249u64, 1996u16),
            (250u64, 2000u16), // Exactly double
            (251u64, 2004u16),
            (500u64, 3000u16),
            (1000u64, 5000u16),
        ];
        
        for (level, expected_capacity) in boundary_cases.iter() {
            let triad_arc = Triad::new(*level, format!("level-{}", level), None);
            let triad = triad_arc.read();
            assert_eq!(triad.header.max_capacity, *expected_capacity,
                       "Max capacity for level {} should be {} but got {}",
                       level, expected_capacity, triad.header.max_capacity);
        }
    }

    #[test]
    fn test_triad_max_capacity_formula() {
        // Test the formula: 1000 * (1 + 0.004 * level)
        for level in 0..=100 {
            let expected = (1000.0 * (1.0 + 0.004 * level as f64)) as u16;
            let triad_arc = Triad::new(level, format!("test-{}", level), None);
            let triad = triad_arc.read();
            assert_eq!(triad.header.max_capacity, expected,
                       "Max capacity formula failed for level {}", level);
        }
    }

    #[test]
    fn test_triad_timestamp_bounds() {
        let time_before = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let triad_arc = Triad::new(0, "timestamp_test".to_string(), None);
        let time_after = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        
        let triad = triad_arc.read();
        assert!(triad.header.timestamp >= time_before,
                "Timestamp {} should be >= {}", triad.header.timestamp, time_before);
        assert!(triad.header.timestamp <= time_after,
                "Timestamp {} should be <= {}", triad.header.timestamp, time_after);
        assert!(triad.header.timestamp > 0, "Timestamp should be positive");
    }

    #[test]
    fn test_triad_deep_hierarchy() {
        let mut current_parent = Triad::new(0, "root".to_string(), None);
        let mut expected_capacity = 1000u16;
        
        for level in 1..=10 {
            expected_capacity = (1000.0 * (1.0 + 0.004 * level as f64)) as u16;
            let child = Triad::new(level, format!("child-{}", level), Some(Arc::downgrade(&current_parent)));
            
            let child_read = child.read();
            assert_eq!(child_read.header.level, level, "Level should match");
            assert_eq!(child_read.header.max_capacity, expected_capacity, "Capacity should match for level {}", level);
            assert_ne!(child_read.header.parent_hash, [0u8; 32], "Non-genesis should have non-zero parent hash");
            
            current_parent = child;
        }
    }

    #[test]
    fn test_triad_concurrent_access() {
        use std::thread;
        use std::sync::Arc;
        
        let triad_arc = Triad::new(0, "concurrent_test".to_string(), None);
        let triad_arc_clone = Arc::clone(&triad_arc);
        
        let handles: Vec<_> = (0..10).map(|i| {
            let triad_clone = Arc::clone(&triad_arc_clone);
            thread::spawn(move || {
                let triad = triad_clone.read();
                assert_eq!(triad.header.level, 0);
                assert_eq!(triad.header.position, "concurrent_test");
                assert_eq!(triad.header.max_capacity, 1000);
                i // Return something to satisfy the closure
            })
        }).collect();
        
        for handle in handles {
            handle.join().expect("Thread should complete successfully");
        }
    }

    #[test]
    fn test_triad_validator_signatures_initialization() {
        let triad_arc = Triad::new(0, "validator_test".to_string(), None);
        let triad = triad_arc.read();
        
        // Check that all validator signatures are initialized to None
        for (i, sig) in triad.header.validator_sigs.iter().enumerate() {
            assert!(sig.is_none(), "Validator signature at index {} should be None", i);
        }
        assert_eq!(triad.header.validator_sigs.len(), 15, "Should have exactly 15 validator signature slots");
    }

    #[test]
    fn test_triad_split_nonce_initialization() {
        let triad_arc = Triad::new(0, "nonce_test".to_string(), None);
        let triad = triad_arc.read();
        
        // Split nonce should be initialized to some value
        assert!(triad.header.split_nonce > 0, "Split nonce should be initialized to a positive value");
    }

    #[test]
    fn test_triad_position_variations() {
        let positions = vec![
            "0", "1", "00", "01", "10", "11",
            "000", "001", "010", "011", "100", "101", "110", "111",
            "0000", "1111", "0101", "1010"
        ];
        
        for position in positions {
            let triad_arc = Triad::new(1, position.to_string(), None);
            let triad = triad_arc.read();
            
            assert_eq!(triad.header.position, position, "Position should match input");
            assert_eq!(triad.header.position_hash, blake3_hash(position.as_bytes()),
                       "Position hash should match blake3 of position");
        }
    }

    #[test]
    fn test_triad_level_zero_characteristics() {
        let triad_arc = Triad::new(0, "genesis".to_string(), None);
        let triad = triad_arc.read();
        
        assert_eq!(triad.header.level, 0, "Level should be 0");
        assert_eq!(triad.header.max_capacity, 1000, "Genesis capacity should be 1000");
        assert_eq!(triad.header.parent_hash, [0u8; 32], "Genesis parent hash should be zero");
        assert!(triad.is_root(), "Genesis should be root");
    }

    #[test]
    fn test_triad_header_fields_initialization() {
        let triad_arc = Triad::new(5, "test_position".to_string(), None);
        let triad = triad_arc.read();
        
        // Test all fields are properly initialized
        assert_eq!(triad.header.level, 5);
        assert_eq!(triad.header.position, "test_position");
        assert_eq!(triad.header.position_hash, blake3_hash(b"test_position"));
        assert_eq!(triad.header.parent_hash, [0u8; 32]); // No parent
        assert_eq!(triad.header.tx_root, [0u8; 32]); // Default initialization
        assert_eq!(triad.header.state_root, [0u8; 32]); // Default initialization
        assert_eq!(triad.header.tx_count, 0); // Default initialization
        assert_eq!(triad.header.max_capacity, 1020); // 1000 * (1 + 0.004 * 5)
        assert!(triad.header.split_nonce > 0);
        assert!(triad.header.timestamp > 0);
        assert_eq!(triad.header.validator_sigs.len(), 15);
    }

    #[test]
    fn test_parent_hash_with_modified_parent_fields() {
        let parent_arc = Triad::new(0, "parent".to_string(), None);
        
        // Modify parent fields that affect canonical encoding
        {
            let mut parent = parent_arc.write();
            parent.header.tx_root = [99u8; 32];
            parent.header.state_root = [88u8; 32];
            parent.header.tx_count = 42;
            parent.header.timestamp = 1234567890;
        }
        
        let parent_header = parent_arc.read().header.clone();
        let expected_parent_hash = blake3_hash(&parent_header.canonical_encoding());
        
        let child_arc = Triad::new(1, "child".to_string(), Some(Arc::downgrade(&parent_arc)));
        let child = child_arc.read();
        
        assert_eq!(child.header.parent_hash, expected_parent_hash,
                   "Child parent hash should match hash of parent's canonical encoding");
    }

    #[test]
    fn test_canonical_encoding_byte_order() {
        let header = default_header();
        let encoded = header.canonical_encoding();
        
        // Verify the encoding starts with the level (first 8 bytes in big-endian)
        let level_bytes = &encoded[0..8];
        assert_eq!(level_bytes, &header.level.to_be_bytes(),
                   "First 8 bytes should be level in big-endian format");
        
        // Verify position comes next
        let position_start = 8;
        let position_end = position_start + header.position.len();
        let position_bytes = &encoded[position_start..position_end];
        assert_eq!(position_bytes, header.position.as_bytes(),
                   "Position bytes should follow level");
    }

    #[test]
    fn test_multiple_triads_unique_hashes() {
        let triad1 = Triad::new(1, "01".to_string(), None);
        let triad2 = Triad::new(1, "10".to_string(), None);
        let triad3 = Triad::new(2, "01".to_string(), None);
        
        let hash1 = triad1.read().header.position_hash;
        let hash2 = triad2.read().header.position_hash;
        let hash3 = triad3.read().header.position_hash;
        
        assert_ne!(hash1, hash2, "Different positions should have different hashes");
        assert_eq!(hash1, hash3, "Same position should have same hash regardless of level");
    }

    #[test]
    fn test_is_root_method() {
        let root_triad = Triad::new(0, "root".to_string(), None);
        let non_root_triad = Triad::new(1, "non_root".to_string(), None);
        
        assert!(root_triad.read().is_root(), "Level 0 triad should be root");
        assert!(!non_root_triad.read().is_root(), "Level 1 triad should not be root");
    }

    #[test]
    fn test_triad_memory_layout() {
        let triad_arc = Triad::new(0, "memory_test".to_string(), None);
        
        // Test that we can create multiple references without issues
        let weak_ref = Arc::downgrade(&triad_arc);
        let strong_ref = Arc::clone(&triad_arc);
        
        assert!(weak_ref.upgrade().is_some(), "Weak reference should be upgradeable");
        
        drop(strong_ref);
        assert!(weak_ref.upgrade().is_some(), "Weak reference should still be upgradeable");
        
        drop(triad_arc);
        assert!(weak_ref.upgrade().is_none(), "Weak reference should not be upgradeable after dropping all strong refs");
    }
