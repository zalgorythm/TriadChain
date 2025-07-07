use parking_lot::RwLock;
use std::sync::{Arc, Weak};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH}; // Added for timestamp
// Removed direct blake3 import as it's now encapsulated in crypto::hash
use crate::crypto::hash::blake3_hash; // Import the centralized blake3_hash

#[derive(Debug, Clone, PartialEq, Eq)] // Added PartialEq, Eq
pub struct TriadHeader {
    pub level: u64,
    pub position: String,
    pub position_hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub tx_root: [u8; 32],
    pub state_root: [u8; 32],
    pub tx_count: u16,
    pub max_capacity: u16,
    pub split_nonce: u128,
    pub timestamp: i64,
    pub validator_sigs: [Option<[u8; 64]>; 15],
}

impl TriadHeader {
    pub fn canonical_encoding(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.level.to_be_bytes());
        bytes.extend(self.position.as_bytes());
        bytes.extend(self.position_hash);
        bytes.extend(self.tx_root);
        bytes.extend(self.state_root);
        bytes.extend(self.tx_count.to_be_bytes());
        bytes.extend(self.max_capacity.to_be_bytes());
        bytes.extend(self.timestamp.to_be_bytes());
        bytes
    }

    /// Computes the hash of the TriadHeader using its canonical encoding.
    pub fn hash(&self) -> [u8; 32] {
        blake3_hash(&self.canonical_encoding())
    }
}

#[derive(Debug, Clone)]
pub struct Transaction {
    pub version: u8,
    pub nonce: u64,
    pub sender: [u8; 32],    // Public key hash
    pub recipient: [u8; 32], // Public key hash
    pub amount: u64,
    pub gas_limit: u64,
    pub signature: [u8; 64], // Ed25519 signature
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct TriadState {
    pub storage: BTreeMap<[u8; 32], Vec<u8>>,
    pub root: [u8; 32],
    pub version: u64,
}

impl TriadState {
    pub fn new() -> Self {
        Self {
            storage: BTreeMap::new(),
            root: blake3_hash(b"empty_state_root"),
            version: 0,
        }
    }

    pub fn recompute_root(&mut self) {
        if self.storage.is_empty() {
            self.root = blake3_hash(b"empty_state_root");
        } else {
            let leaf_hashes: Vec<[u8; 32]> = self.storage.iter() // Removed mut
                .map(|(key, value)| {
                    let mut leaf_data = Vec::new();
                    leaf_data.extend_from_slice(key); // key is already [u8; 32]
                    leaf_data.extend_from_slice(&blake3_hash(value)); // value is Vec<u8>
                    blake3_hash(&leaf_data)
                })
                .collect();

            self.root = Self::build_merkle_tree_recursive(leaf_hashes);
        }
        self.version += 1;
    }

    // Helper function to recursively build the Merkle tree
    fn build_merkle_tree_recursive(mut hashes: Vec<[u8; 32]>) -> [u8; 32] {
        if hashes.is_empty() {
            // This case should be handled by the caller (recompute_root)
            // or return a predefined hash for empty list if called directly.
            // For safety, returning the "empty_state_root" hash.
            return blake3_hash(b"empty_state_root_internal_unexpected");
        }
        if hashes.len() == 1 {
            return hashes[0];
        }

        // If odd number of hashes, duplicate the last one
        if hashes.len() % 2 != 0 {
            hashes.push(hashes.last().unwrap().clone());
        }

        let mut next_level_hashes = Vec::new();
        for chunk in hashes.chunks_exact(2) {
            let mut combined_hash_data = Vec::new();
            combined_hash_data.extend_from_slice(&chunk[0]);
            combined_hash_data.extend_from_slice(&chunk[1]);
            next_level_hashes.push(blake3_hash(&combined_hash_data));
        }
        Self::build_merkle_tree_recursive(next_level_hashes)
    }
}

#[derive(Debug)]
pub struct Triad {
    pub header: TriadHeader,
    pub transactions: Vec<Transaction>, // Added field to store transactions
    pub state: RwLock<TriadState>,
    pub children: RwLock<[Option<Arc<RwLock<Triad>>>; 4]>,
    pub parent: Option<Weak<RwLock<Triad>>>,
}

impl Triad {
    pub fn new(
        level: u64,
        position: String,
        parent: Option<Weak<RwLock<Triad>>>,
    ) -> Arc<RwLock<Self>> {
        let position_hash = blake3_hash(position.as_bytes());

        let current_unix_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("SystemTime before UNIX EPOCH or clock error")
            .as_secs();
        
        // Calculate parent hash without locking parent
        let parent_hash = parent.as_ref().and_then(|weak| {
            weak.upgrade().map(|arc| {
                let parent = arc.read();
                blake3_hash(&parent.header.canonical_encoding())
            })
        }).unwrap_or([0; 32]);

        Arc::new(RwLock::new(Self {
            header: TriadHeader {
                level,
                position,
                position_hash,
                parent_hash,
                tx_root: [0; 32],
                state_root: TriadState::new().root,
                tx_count: 0,
                max_capacity: (1000.0 * (1.0 + 0.004 * level as f64)) as u16,
                split_nonce: 0,
                timestamp: current_unix_time as i64,
                validator_sigs: [None; 15],
            },
            transactions: Vec::new(), // Initialize transactions vector
            state: RwLock::new(TriadState::new()),
            children: RwLock::new([None, None, None, None]), // Corrected initialization for non-Copy type
            parent,
        }))
    }

    pub fn is_root(&self) -> bool {
        self.header.level == 0
    }

    pub fn update_child_root(&self, child_pos: &str, new_root: [u8; 32]) {
        let key = blake3_hash(child_pos.as_bytes()); // Use BLAKE3(child_pos) as key

        let mut state = self.state.write();
        state.storage.insert(key, new_root.to_vec());
        state.recompute_root();
    }

    pub fn add_child(&self, child: Arc<RwLock<Triad>>, index: usize) -> Result<(), &'static str> {
        if index >= 4 {
            return Err("Child index out of bounds (0-3)");
        }
        let mut children = self.children.write();
        if children[index].is_some() {
            return Err("Child already exists at this index");
        }
        children[index] = Some(child);
        Ok(())
    }

    pub fn propagate_state(&self) {
        if self.is_root() {
            return;
        }

        // Capture current state before locking parent
        let child_pos = self.header.position.clone();
        let child_root = self.state.read().root;

        let parent_weak = match &self.parent {
            Some(weak) => weak.clone(),
            None => return,
        };

        let parent_arc = match parent_weak.upgrade() {
            Some(arc) => arc,
            None => return,
        };

        // Update parent's state
        {
            let parent = parent_arc.write();
            parent.update_child_root(&child_pos, child_root);
        }

        // Propagate further upward
        let parent = parent_arc.read();
        parent.propagate_state();
    }

    /// Adds a transaction to this Triad if capacity allows.
    /// Updates transaction count and re-calculates tx_root.
    pub fn add_transaction(&mut self, transaction: Transaction) -> Result<(), String> {
        if self.header.tx_count >= self.header.max_capacity {
            return Err(format!(
                "Triad at maximum capacity ({} transactions). Cannot add more.",
                self.header.max_capacity
            ));
        }

        self.transactions.push(transaction);
        self.header.tx_count += 1;

        // Update tx_root. This is a simplified version.
        // A proper Merkle root should be calculated.
        // For now, hash all transaction senders + nonces as a placeholder.
        let mut tx_data_for_root = Vec::new();
        for tx in &self.transactions {
            tx_data_for_root.extend_from_slice(&tx.sender);
            tx_data_for_root.extend_from_slice(&tx.nonce.to_be_bytes());
        }
        if tx_data_for_root.is_empty() {
            self.header.tx_root = [0; 32]; // Or some defined empty root
        } else {
            self.header.tx_root = blake3_hash(&tx_data_for_root);
        }

        Ok(())
    }
}
