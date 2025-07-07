use parking_lot::RwLock;
use std::sync::{Arc, Weak};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH}; // Added for timestamp
// Removed direct blake3 import as it's now encapsulated in crypto::hash
use crate::crypto::hash::blake3_hash; // Import the centralized blake3_hash

#[derive(Debug, Clone)]
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
        // Simplified for example - real implementation would use Merkle tree
        let mut combined = Vec::new();
        for (key, value) in &self.storage {
            combined.extend(key);
            combined.extend(value);
        }
        self.root = blake3_hash(&combined);
        self.version += 1;
    }
}

#[derive(Debug)]
pub struct Triad {
    pub header: TriadHeader, // Removed RwLock - header should be immutable after creation
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
          }
