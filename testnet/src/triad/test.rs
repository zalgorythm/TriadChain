#[cfg(test)]
mod tests {
    // Reverted to more explicit imports as `use super::*;` was not resolving Triad/TriadHeader
    use crate::triad::{Triad, TriadHeader};
    use crate::crypto::hash::blake3_hash;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH}; // Removed unused Duration

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
}
