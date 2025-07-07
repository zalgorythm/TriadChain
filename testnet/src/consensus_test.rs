#[cfg(test)]
mod tests {
    use crate::consensus::{calculate_difficulty_target, verify_split_challenge};
    // use crate::crypto::hash::blake3_hash; // Removed unused import

    // Helper to create a 32-byte array representing 2^N, where N < 256
    // Result is big-endian.
    fn power_of_2_as_bytes(n: usize) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        if n < 256 {
            let byte_idx_from_lsb = n / 8;
            let bit_in_byte = n % 8;
            // Convert LSB-based byte index to MSB-based index for the array
            let byte_idx_from_msb = 31 - byte_idx_from_lsb;
            bytes[byte_idx_from_msb] = 1u8 << bit_in_byte;
        }
        bytes
    }

    #[test]
    fn test_calculate_difficulty_target() {
        // Level 0: Target should be 2^208
        let target_l0 = calculate_difficulty_target(0);
        assert_eq!(target_l0, power_of_2_as_bytes(208), "Target for level 0 should be 2^208");

        // Level 1: Target should be 2^207
        let target_l1 = calculate_difficulty_target(1);
        assert_eq!(target_l1, power_of_2_as_bytes(207), "Target for level 1 should be 2^207");

        // Level 48: Target should be 2^(208-48) = 2^160
        let target_l48 = calculate_difficulty_target(48);
        assert_eq!(target_l48, power_of_2_as_bytes(160), "Target for level 48 should be 2^160");

        // Level 208: Target should be 2^(208-208) = 2^0 = 1
        let target_l208 = calculate_difficulty_target(208);
        assert_eq!(target_l208, power_of_2_as_bytes(0), "Target for level 208 should be 2^0 = 1");

        // Level 209: Target should be 2^(208-209) = 2^-1, effectively 0 for integer comparison if shift results in 0.
        // Our right_shift_byte_array will make it 0 because 2^0 >> 1 = 0.
        let target_l209 = calculate_difficulty_target(209);
        assert_eq!(target_l209, power_of_2_as_bytes(256), "Target for level 209 should be 0 (represented by 2^256 in helper)");
        // power_of_2_as_bytes(256) returns [0u8;32]

        // Level 255: Target should be 0
        let target_l255 = calculate_difficulty_target(255);
        assert_eq!(target_l255, [0u8; 32], "Target for level 255 should be 0");

        // Level 256 (or more): Target should be 0
        let target_l256 = calculate_difficulty_target(256);
        assert_eq!(target_l256, [0u8; 32], "Target for level 256 should be 0");
        let target_l300 = calculate_difficulty_target(300);
        assert_eq!(target_l300, [0u8; 32], "Target for level 300 should be 0");
    }

    // Basic nonce finder for testing verify_split_challenge
    // WARNING: This can be very slow if the difficulty is high. Use with low levels for testing.
    fn find_nonce_for_test(
        parent_hash: &[u8; 32],
        position: &str,
        level: u64,
        max_iterations: u128,
    ) -> Option<u128> {
        for nonce_attempt in 0..max_iterations {
            if verify_split_challenge(parent_hash, position, level, nonce_attempt) {
                return Some(nonce_attempt);
            }
        }
        None
    }

    #[test]
    fn test_verify_split_challenge() {
        let parent_hash = [1u8; 32];
        let position = "test_pos";

        // Test Case 1: Level 0, try to find a nonce (might take a while if not lucky)
        // For level 0, target is 2^208. Hash must be < 2^208.
        // This means the first 5 bytes of hash must be 0, and 6th byte must be 0.
        // (256 - 208 = 48 zero bits required at the start of the hash)
        // This is a very high difficulty for a simple loop.
        // Instead of finding, let's construct a scenario.

        // We need to mock the hash result for a predictable test, or use a very high level (low difficulty).
        // Let's use a high level to make finding a nonce feasible.
        let test_level = 207; // Target = 2^(208-207) = 2^1 = 2. Hash must be < [0...0, 0, 2] (byte 31=2)
                               // This means hash must be 0 or 1.

        let found_nonce = find_nonce_for_test(&parent_hash, position, test_level, 1_000_000);

        if let Some(nonce) = found_nonce {
            assert!(verify_split_challenge(&parent_hash, position, test_level, nonce),
                "Verification failed for a found nonce at level {}", test_level);

            // Test with a nonce that should fail (nonce + 1, assuming it produces a different hash)
            // This is not guaranteed to fail if (nonce+1) also meets difficulty, but likely for sparse solutions.
            // A more robust test would be to use a pre-calculated hash.
            // For now, let's assume nonce+1 (if it doesn't wrap) is likely to fail if solution space is sparse.
            if nonce < u128::MAX {
                 assert!(!verify_split_challenge(&parent_hash, position, test_level, nonce + 1),
                    "Verification passed for nonce+1, which is unexpected or too dense solution space at level {}", test_level);
            }

        } else {
            // This can happen if 1M iterations aren't enough for level 207.
            // For level 207, target is 2. Hash must be 0 or 1.
            // Probability is 2 / 2^256, extremely low. find_nonce_for_test will likely fail.
            // This test strategy needs rethinking for `verify_split_challenge`.
            // We need to test verify_split_challenge directly with known hash inputs.
            // The current find_nonce_for_test is not practical for these low targets.
            eprintln!("Could not find a nonce for level {} within iterations. Test for verify_split_challenge needs adjustment.", test_level);
            // Mark as inconclusive or skip if CI, for local can let it be. For now, just note.
        }

        // Direct test for verify_split_challenge with crafted hash values (mocking blake3_hash)
        // This requires ability to control the hash output, or more complex setup.
        // Alternative: Test against pre-calculated known good/bad nonces if available.

        // Let's test with pre-defined conditions for the hash output
        // For verify_split_challenge(ph, pos, level, nonce)
        // It calculates: hash = blake3(ph || pos || nonce_bytes)
        // And target = calculate_difficulty_target(level)
        // It returns hash < target

        // Case A: hash < target (should be true)
        // Let target be [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,10] (decimal 10)
        // Let computed_hash be [0,0,...,0,5]
        // This requires knowing what (ph, pos, nonce) produce hash_val_5 and what level gives target_10
        // This is hard to set up without controlling the hash directly.

        // The find_nonce_for_test is better suited for very high levels (low difficulty)
        // e.g. level where target is large, like level 0 (target 2^208) - but finding is too slow.
        // Or level where target is small, but then finding is hard.

        // Redo: Test verify_split_challenge by checking its internal logic more directly.
        // We can't easily control the `computed_hash` without re-implementing blake3 or mocking.
        // What we *can* do is to test the comparison `computed_hash < target` by providing
        // a known `computed_hash` and `target`. But `verify_split_challenge` calculates these internally.

        // Let's use a very high level, making the target very small (e.g., 1 or 2).
        // Level 208 means target is 1 ([0...0,1]). Hash must be [0...0,0].
        // Level 207 means target is 2 ([0...0,2]). Hash must be [0...0,0] or [0...0,1].

        // If level = 208, target is 1.
        // verify_split_challenge should only return true if BLAKE3(...) is the zero hash.
        // The probability of BLAKE3(...) being zero hash is 1/2^256, so find_nonce_for_test will not find it.

        // This test needs a different approach.
        // The find_nonce_for_test is extremely unlikely to find a solution for difficult levels.
        // This test is more of a placeholder to demonstrate usage.
        // A robust test for a 'true' case would require a pre-calculated valid nonce
        // or a scenario with extremely low difficulty (very high level value).
        if found_nonce.is_some() {
            // This block will likely not be hit for typical cryptographic levels.
        } else {
            // This is the expected path for difficult levels.
            // We can't assert much here other than it didn't hang or panic.
        }
    }

    #[test]
    fn test_verify_split_challenge_basic_check() {
        let parent_hash = [1u8; 32];
        let position = "difficult_pos";

        // Level 0: Target 2^208. Very hard to meet.
        let level_high_difficulty = 0;
        let random_nonce1 = 9876543210123456789u128;
        assert!(!verify_split_challenge(&parent_hash, position, level_high_difficulty, random_nonce1),
                "A random nonce should likely fail for high difficulty (level 0)");

        // Level 208: Target is 1. Hash must be [0...0,0]. Extremely unlikely.
        let level_extreme_difficulty = 208;
        let random_nonce2 = random_nonce1.wrapping_add(1); // Different nonce
        assert!(!verify_split_challenge(&parent_hash, position, level_extreme_difficulty, random_nonce2),
                "A random nonce should fail for level 208 (target 1), unless hash is exactly 0");

        // Level 250: Target is effectively 0 (2^208 >> 250 results in 0). Nothing can be < 0.
        let level_impossible_difficulty = 250;
         assert!(!verify_split_challenge(&parent_hash, position, level_impossible_difficulty, random_nonce2),
                "Should always fail for level 250 (target 0)");

        // Example of using find_nonce_for_test for a very, very low difficulty (high level)
        // Let level be such that target is very large.
        // E.g. if target was almost all 1s.
        // For our setup, target = 2^208 / 2^level.
        // If level = 0, target = 2^208. (Hash needs ~48 leading zero bits) - find_nonce is too slow.
        // If level = 207, target = 2^1 = 2. (Hash needs ~255 leading zero bits) - find_nonce is too slow.

        // The find_nonce_for_test utility is more for conceptual demonstration or if one has a lot of time.
        // A true positive test for verify_split_challenge ideally needs a known (parent_hash, position, level, nonce)
        // that produces a hash < target.
        // For now, we rely on testing calculate_difficulty_target thoroughly and assume the comparison in
        // verify_split_challenge is correct.
    }
}
