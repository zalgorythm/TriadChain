// This file makes the 'triad' directory a module.
// It declares submodules within 'triad' and can re-export items.

pub mod structs;
pub mod test; // Contains #[cfg(test)] mod tests for structs.rs related things
pub mod routing;
#[cfg(test)]
mod routing_test; // Added new test module for routing

// Re-export important items for easier access from outside the triad module,
// e.g., `use crate::triad::Triad;`
pub use structs::{Triad, TriadHeader, TriadState, Transaction}; // Added Transaction
