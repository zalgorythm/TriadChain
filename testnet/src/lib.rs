// src/lib.rs

//! TriadChain Library
//!
//! This crate provides the core components for the TriadChain blockchain,
//! including cryptographic primitives, transaction management, state
//! representation (Merkleized state tree), and consensus mechanisms.

// Publicly expose modules
pub mod crypto;
pub mod errors;
pub mod state;
pub mod transaction;
pub mod triad;
pub mod consensus;


// Re-export key types for easier access
pub use crate::triad::structs::{Triad, TriadHeader};
pub use crate::transaction::structs::{Transaction, SignedTransaction};
pub use crate::state::state_tree::StateTree;
pub use crate::crypto::hash::blake3_hash; // Re-export for convenience


// Example of a simple function (can be removed or expanded as needed)
/// Adds two unsigned 32-bit integers.
///
/// # Arguments
/// * `left` - The first integer.
/// * `right` - The second integer.
///
/// # Returns
/// The sum of the two integers.
pub fn add(left: u32, right: u32) -> u32 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
