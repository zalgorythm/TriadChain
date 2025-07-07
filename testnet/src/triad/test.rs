#[cfg(test)]
mod tests {
    // Reverted to more explicit imports as `use super::*;` was not resolving Triad/TriadHeader
    use crate::triad::{Triad, TriadHeader};
    use crate::crypto::hash::blake3_hash;
    use std::sync::Arc;

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

    #[test]
    fn test_parent_hash_calculation_genesis() {
        // Genesis triad (no parent)
        let genesis_arc = Triad::new(0, "0".to_string(), None);
        let genesis_triad = genesis_arc.read();
        assert_eq!(genesis_triad.header.parent_hash, [0u8; 32], "Genesis parent_hash should be all zeros.");
        assert!(genesis_triad.is_root());
    }

    #[test]
    fn test_parent_hash_calculation_with_parent() {
        // Create a parent triad
        let parent_level = 0u64;
        let parent_position = "0".to_string();
        // Manually set some fields for the parent's header that are part of canonical_encoding
        let parent_arc = Triad::new(parent_level, parent_position.clone(), None);
        {
            let mut parent_triad_mut = parent_arc.write();
            parent_triad_mut.header.tx_root = blake3_hash(b"parent_tx_root");
            parent_triad_mut.header.state_root = blake3_hash(b"parent_state_root");
            parent_triad_mut.header.tx_count = 5;
            // max_capacity for level 0 is 1000 * (1 + 0.004 * 0) = 1000
            // timestamp for parent
            parent_triad_mut.header.timestamp = 1234567890;
            // position_hash is already set by Triad::new
            // level is set by Triad::new
            // position is set by Triad::new
        }

        let parent_header_for_encoding = parent_arc.read().header.clone(); // Clone to avoid holding lock

        // Calculate expected parent_hash
        let expected_parent_hash = blake3_hash(&parent_header_for_encoding.canonical_encoding());

        // Create a child triad
        let child_level = 1u64;
        let child_position = "00".to_string();
        let child_arc = Triad::new(child_level, child_position, Some(Arc::downgrade(&parent_arc)));
        let child_triad = child_arc.read();

        assert_eq!(
            child_triad.header.parent_hash,
            expected_parent_hash,
            "Child's parent_hash does not match the hash of parent's canonical_encoding."
        );
    }
    
    #[test]
    fn test_genesis_creation() {
        let genesis = Triad::new(0, "0".to_string(), None);
        let triad = genesis.read();
        assert!(triad.is_root());
    }
}
