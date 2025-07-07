// consensus/mod.rs

pub mod bft; // Declare the bft submodule
#[cfg(test)]
mod bft_test; // Added test module for bft structs

/// Represents a validator in the system.
#[derive(Debug, Clone, PartialEq, Eq, Hash)] // Added common derives
pub struct Validator {
    pub pubkey: [u8; 32],
    // Could add other fields later, like stake, ID, etc.
}

/// Helper function to perform a bit-wise right shift on a 32-byte array.
/// Shifts are performed in place.
fn right_shift_byte_array(arr: &mut [u8; 32], mut shift_amount: u64) {
    if shift_amount == 0 {
        return;
    }

    // If shift amount is >= 256, all bits are shifted out, array becomes all zeros.
    if shift_amount >= 256 {
        arr.fill(0);
        return;
    }

    let num_bytes = arr.len();

    // Handle byte-level shifts first (shifting by multiples of 8 bits)
    let byte_shifts = (shift_amount / 8) as usize;
    if byte_shifts > 0 {
        for i in (0..num_bytes).rev() {
            if i >= byte_shifts {
                arr[i] = arr[i - byte_shifts];
            } else {
                arr[i] = 0;
            }
        }
        shift_amount %= 8; // Remaining bit shifts
    }

    if shift_amount == 0 {
        return;
    }

    // Handle remaining bit-level shifts (0 to 7 bits)
    let mut carry_over: u8 = 0;
    for i in 0..num_bytes {
        let next_carry_over = arr[i] << (8 - shift_amount as u8); // Bits that will be shifted into the previous byte
        arr[i] = (arr[i] >> shift_amount as u8) | carry_over;
        carry_over = next_carry_over;
    }
}

/// Calculates the difficulty target for Proof-of-Split.
/// Target T = 2^208 / 2^level.
/// Represented as a 32-byte array (big-endian).
pub fn calculate_difficulty_target(level: u64) -> [u8; 32] {
    let mut target_bytes = [0u8; 32];

    if 208 < 256 {
        let byte_index_from_lsb = 208 / 8;
        let bit_in_byte = 208 % 8;
        let byte_index_from_msb = 31 - byte_index_from_lsb;
        if byte_index_from_msb < 32 {
             target_bytes[byte_index_from_msb] = 1u8 << bit_in_byte;
        }
    }

    right_shift_byte_array(&mut target_bytes, level);

    target_bytes
}

use crate::crypto::hash::blake3_hash;

/// Verifies if a given `split_nonce` satisfies the Proof-of-Split challenge.
///
/// The challenge is `BLAKE3(parent_hash || position || split_nonce) < difficulty_target`.
/// The `difficulty_target` is calculated as `2^208 / 2^level`.
///
/// # Arguments
/// * `parent_hash`: The hash of the parent triad's header.
/// * `position`: The canonical Sierpinski coordinate string of the new triad being proposed.
/// * `level`: The fractal depth of the new triad.
/// * `split_nonce`: The nonce being verified.
///
/// # Returns
/// `true` if the hash of the inputs is less than the difficulty target, `false` otherwise.
pub fn verify_split_challenge(
    parent_hash: &[u8; 32],
    position: &str,
    level: u64,
    split_nonce: u128,
) -> bool {
    let mut input_data = Vec::new();
    input_data.extend_from_slice(parent_hash);
    input_data.extend_from_slice(position.as_bytes());
    input_data.extend_from_slice(&split_nonce.to_be_bytes());

    let computed_hash = blake3_hash(&input_data);
    let target = calculate_difficulty_target(level);

    // Perform lexicographical comparison of byte arrays.
    // H < T is true if computed_hash is lexicographically smaller than target.
    computed_hash < target
}

/// Assigns a validator to a quadrant (0-3) for a given Triad position.
///
/// The assignment is determined by:
/// `BLAKE3(validator_pubkey || BLAKE3(triad_position_string))[0] % 4`
///
/// # Arguments
/// * `pubkey`: The public key of the validator.
/// * `position`: The canonical Sierpinski coordinate string of the Triad.
///
/// # Returns
/// A `u8` value (0, 1, 2, or 3) representing the assigned quadrant.
pub fn assign_to_quadrant(pubkey: &[u8; 32], position: &str) -> u8 {
    let pos_bytes = position.as_bytes();
    let pos_hash = blake3_hash(pos_bytes); // pos_hash is [u8; 32]

    let mut input_for_final_hash = Vec::with_capacity(32 + 32);
    input_for_final_hash.extend_from_slice(pubkey);
    input_for_final_hash.extend_from_slice(&pos_hash); // Pass as slice

    let final_hash = blake3_hash(&input_for_final_hash);

    final_hash[0] % 4
}
