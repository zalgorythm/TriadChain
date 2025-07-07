use crate::crypto::hash::blake3_hash;
// use crate::triad::structs::Transaction; // Removed unused import for now

/// Calculates the routing path for a transaction based on its sender and nonce.
///
/// The path is determined by `h = BLAKE3(tx.sender || tx.nonce)`.
/// Bit-pairs are extracted from `h` to decide the branch at each fractal level.
/// (Bits 7,6) -> first choice, (Bits 5,4) -> second choice, etc. from each byte of the hash.
/// Each choice is a u8 value from 0 to 3.
///
/// Returns a Vec<u8> representing the sequence of quadrant choices.
pub fn calculate_transaction_path(sender: &[u8; 32], nonce: u64) -> Vec<u8> {
    let mut input_data = Vec::with_capacity(32 + 8);
    input_data.extend_from_slice(sender);
    input_data.extend_from_slice(&nonce.to_be_bytes());

    let hash_output = blake3_hash(&input_data); // blake3_hash returns [u8; 32]

    // Each byte of the hash provides 4 path choices (2 bits per choice).
    // Total path length will be 32 bytes * 4 choices/byte = 128 choices.
    let mut path_choices = Vec::with_capacity(hash_output.len() * 4);

    for &byte_val in hash_output.iter() {
        // Extract 4 pairs of 2 bits from each byte, from most significant to least significant.
        path_choices.push((byte_val >> 6) & 0b11); // Top 2 bits
        path_choices.push((byte_val >> 4) & 0b11); // Next 2 bits
        path_choices.push((byte_val >> 2) & 0b11); // Next 2 bits
        path_choices.push(byte_val & 0b11);        // Bottom 2 bits
    }
    path_choices
}

use crate::triad::structs::Triad;
use std::sync::Arc;
use parking_lot::RwLock;

/// Finds the deepest existing Triad along a given path, starting from a given Triad.
///
/// Traverses the Triad tree according to the sequence of quadrant choices in `path`.
/// If a child Triad does not exist at any point along the path, the current Triad
/// is returned as it's the deepest one found that matches the path prefix.
///
/// # Arguments
/// * `start_triad_arc`: An `Arc<RwLock<Triad>>` to start traversal from.
/// * `path`: A slice of `u8` values, where each value (0-3) is a quadrant choice.
///
/// # Returns
/// An `Arc<RwLock<Triad>>` to the deepest Triad found along the path.
pub fn find_target_triad(
    mut current_triad_arc: Arc<RwLock<Triad>>, // mut is needed here
    path: &[u8]
) -> Arc<RwLock<Triad>> {
    for &quadrant_choice in path {
        if quadrant_choice > 3 {
            // Invalid path component.
            break;
        }

        let maybe_child_arc: Option<Arc<RwLock<Triad>>> = {
            // Inner scope to ensure locks are dropped before current_triad_arc is potentially reassigned.
            let current_triad_locked = current_triad_arc.read();
            let children_locked = current_triad_locked.children.read(); // This also borrows from current_triad_arc indirectly

            children_locked[quadrant_choice as usize].as_ref().map(Arc::clone)
        }; // current_triad_locked and children_locked are dropped here.

        if let Some(child_arc_cloned) = maybe_child_arc {
            current_triad_arc = child_arc_cloned; // Now it's safe to reassign
        } else {
            // No child exists at this path segment, or invalid choice. The current triad is the deepest.
            break;
        }
    }
    current_triad_arc
}
