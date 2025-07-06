
triadchain-testnet/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── config/
│   │   ├── mod.rs
│   │   └── default.rs
│   ├── crypto/
│   │   ├── mod.rs
│   │   ├── hashes.rs
│   │   └── signatures.rs
│   │   └── zksnarks.rs
│   ├── core/
│   │   ├── mod.rs
│   │   ├── transaction.rs
│   │   ├── triad.rs
│   │   └── state.rs
│   │   └── genesis.rs
│   ├── network/
│   │   ├── mod.rs
│   │   ├── p2p.rs
│   │   ├── message.rs
│   │   └── discovery.rs
│   ├── consensus/
│   │   ├── mod.rs
│   │   ├── proof_of_split.rs
│   │   └── hotstuff.rs
│   ├── node/
│   │   ├── mod.rs
│   │   ├── node_runner.rs
│   │   ├── role_manager.rs
│   │   └── validator.rs
│   │   └── relayer.rs
│   │   └── observer.rs
│   │   └── archiver.rs
│   ├── utils/
│   │   ├── mod.rs
│   │   ├── trie.rs
│   │   ├── fractal_math.rs
│   │   └── types.rs
│   └── database/
│       ├── mod.rs
│       └── kv_store.rs
└── tests/
    ├── integration_tests.rs
    └── unit_tests/
        ├── crypto_tests.rs
        ├── core_tests.rs
        └── consensus_tests.rs
└── scripts/
    ├── start_node.sh
    ├── generate_keys.sh
    └── deploy_testnet.sh
└── README.md
└── .env.example

Consolidated and Corrected File Structure Description:
triadchain-testnet/ (Root Directory)
 * Cargo.toml:
   * Description: The manifest file for your Rust project. It declares project metadata, dependencies (crates), and build configurations. This is where you'll list all the external Rust libraries (crates) your project uses, like blake3, ed25519-dalek, tokio (for async networking), serde (for serialization), and any ZK-SNARK libraries.
   * Key Dependencies (examples to include):
     * blake3 = "1.x"
     * ed25519-dalek = "1.x"
     * rand_core = { version = "0.x", features = ["std"] }
     * tokio = { version = "1.x", features = ["full"] }
     * futures = "0.3"
     * serde = { version = "1.x", features = ["derive"] }
     * bincode = "1.x"
     * log = "0.4" & env_logger = "0.10"
     * async-trait = "0.1"
     * parking_lot = "0.12"
     * lmdb-rs or rocksdb
     * halo2 or bellperson
 * src/:
   * Description: Contains all the Rust source code for your TriadChain node. To ensure a clear and acyclic dependency graph, the project will organize modules in a layered fashion. Core components (crypto, utils) will form foundational layers, on which higher-level components (core, network, consensus) will depend. The node module will orchestrate interactions between these components. Any cross-cutting concerns or shared data structures that could lead to apparent cycles will be defined in utils/types.rs or a new common/ module, which will be the lowest-level dependency.
   * main.rs:
     * Description: The entry point of your application. It will parse command-line arguments (e.g., node type, configuration file path), initialize the logger, load the configuration, and start the TriadChain node runner.
     * Purpose: Orchestrates the startup and lifecycle of a TriadChain node.
   * lib.rs:
     * Description: The root of your TriadChain library. This file exports modules from subdirectories, making them available throughout your project and to potential external crates.
     * Purpose: Defines the library structure and public API for your blockchain components.
   * config/:
     * mod.rs: Declares modules within the config directory.
     * default.rs:
       * Description: Defines structures for network configuration (bootstrap nodes, port, validator stakes, difficulty targets, etc.), node-specific settings, and initial parameters for the testnet.
       * Purpose: Centralizes all configurable parameters for easy modification and deployment.
   * crypto/:
     * mod.rs: Declares modules within the crypto directory.
     * hashes.rs:
       * Description: Implements the BLAKE3 hashing functions used for various purposes: triad hashes, transaction roots, state roots, PoS puzzles, and position_hash. The position_hash is derived by applying BLAKE3 to the canonical string representation of a triad's fractal path.
       * Purpose: Provides cryptographic hashing primitives.
     * signatures.rs:
       * Description: Implements Ed25519 digital signature generation and verification. Includes functions for keypair generation, signing transaction payloads, and verifying validator signatures.
       * Purpose: Ensures transaction authenticity and validator identity.
     * zksnarks.rs:
       * Description: Placeholder for integrating a ZK-SNARK library (e.g., halo2 or bellperson). This module will expose an API for generating and verifying PositionalValidationProof (used in Proof-of-Split to prove valid subdivision) and CrossTriadTransactionProof (used by Relayer nodes for atomic cross-shard operations). These proofs will be compact, cryptographically verifiable objects that are included within TriadHeader (for PoS) or Transaction (for cross-triad ops) and verified during consensus/transaction processing. The core constraints will include:
         struct PositionCircuit {
    parent_position: [u8; 32],   // Private
    child_position: [u8; 32],    // Public
    nonce: u128,                 // Private
}
// Constraints:
// 1. child_position = BLAKE3(parent_position || suffix)
//    where suffix ∈ {0,1,2,3}
// 2. BLAKE3(parent_position || child_position || nonce) < target
// 3. Valid Sierpiński subdivision (ensuring child coordinates fall within the expected region relative to the parent's, as defined by the fixed 0, 1, 2, 3 child patterns).

       * Purpose: Enables zero-knowledge proofs for security and efficiency.
   * core/:
     * mod.rs: Declares modules within the core directory. Error handling within this module will primarily use Rust's Result<T, E> type, leveraging custom error enums from utils/types.rs.
     * transaction.rs:
       * Description: Defines the Transaction struct, including version, nonce, sender, recipient, amount, gas_limit, signature, data, and target_position: String (optional triad position like "0.1.2"). Transactions are deterministically routed: h = BLAKE3(tx.sender || tx.nonce) extracts bit pairs to form a path, continuing until an existing triad is found. If the exact path doesn't exist, the nearest existing ancestor triad (found by traversing upwards from the implied depth) is used.
       * Purpose: Represents the fundamental unit of value transfer and smart contract interaction.
     * triad.rs:
       * Description: Defines the TriadHeader and Triad struct.
         struct TriadHeader {
    level: u64,                 // Fractal depth (0 = genesis)
    position: String,            // Sierpiński coordinates (e.g., "0.2.1")
    position_hash: [u8; 32],     // BLAKE3(canonical_form)
    parent_hash: [u8; 32],       // BLAKE3(serialized parent)
    tx_root: [u8; 32],           // Transactions Merkle root
    state_root: [u8; 32],        // Local state root
    split_nonce: u128,           // Proof-of-Split solution
    timestamp: i64,              // Unix timestamp
    validator_sigs: Vec<[u8; 64]>, // BFT signatures
    tx_count: u16,               // Current transactions (0-1000)
    capacity: u16,               // Max transactions (calculated)
}

         Implements methods for triad creation, subdivision, and Merkle tree generation for transactions. The capacity decreases with depth: capacity = BASE_CAPACITY / log2(level + 2). This accounts for smaller transaction batches in deeper triads, while the aggregate network throughput (Σ(capacity × 4^level)) still grows exponentially due to the increasing number of triads. Child pointers are an array of four [u8; 32] child hashes, representing the BLAKE3 hash of each of its four sub-triads upon splitting.
       * Purpose: Represents the core fractal data structure.
     * state.rs:
       * Description: Manages the local state for each triad, typically as a Merkle Patricia Trie. Each Triad implicitly represents a logical shard. Includes functions for applying transactions, updating account balances, computing the local_state_root (the root of the specific triad's state), and computing the subtree_state_root (a recursive Merkle root aggregating the local_state_roots of all child triads within that branch, forming a verifiable snapshot of a fractal sub-tree's state). The network's Global Root is specifically the subtree_state_root of the genesis triad (Level 0, position '0').
       * Purpose: Maintains the current ledger state for each triad and propagates changes hierarchically.
     * genesis.rs:
       * Description: Logic for generating the initial "genesis triad" at level 0. Its position is "0", state_root is BLAKE3("TRIADCHAIN_GENESIS_STATE"), contains a single coinbase transaction creating 2.1B TRI, and has a predefined validator set of 21 foundation nodes. It is immutable and cannot split until network launch.
       * Purpose: Provides the starting point for the entire ledger.
   * network/:
     * mod.rs: Declares modules within the network directory. Error handling within this module will primarily use Rust's Result<T, E> type, leveraging custom error enums from utils/types.rs.
     * p2p.rs:
       * Description: Implements the peer-to-peer communication layer using an asynchronous runtime (like Tokio). Handles node connections, message serialization/deserialization, and basic message routing.
       * Purpose: Enables nodes to discover and communicate with each other.
     * message.rs:
       * Description: Defines the various message types exchanged between nodes (e.g., TriadProposal, PreVote, PreCommit, Commit, NewTransaction, DiscoveryRequest, DiscoveryResponse).
       * Purpose: Standardizes inter-node communication.
     * discovery.rs:
       * Description: Implements peer discovery mechanisms (e.g., connecting to hardcoded bootstrap nodes, mDNS for local network discovery, gossip protocols to find new peers).
       * Purpose: Allows new nodes to join the network and find active participants.
   * consensus/:
     * mod.rs: Declares modules within the consensus directory. Error handling within this module will primarily use Rust's Result<T, E> type, leveraging custom error enums from utils/types.rs.
     * proof_of_split.rs:
       * Description: Implements the Proof-of-Split puzzle (BLAKE3(parent_hash || position || nonce) < effective_target). Defines the Split Proposer as the node that detects a triad at capacity, solves the PoS puzzle, constructs child triads, and initiates BFT consensus. Proposer selection is via the first validator to broadcast a valid proof.
       * Purpose: Provides the work-based mechanism for triad creation.
     * hotstuff.rs:
       * Description: Implements the HotStuff-BFT three-phase commit protocol. Validator sets consist of 21 nodes per shard level. A "Position Group" refers to validators responsible for a quadrant (e.g., Level 1: 4 groups (0,1,2,3); Level 2: 16 groups (0.0, 0.1, ..., 3.3)). Validator assignment to a group is group_index = BLAKE3(validator_pk || position) % GROUP_SIZE, where GROUP_SIZE is the number of validators in that specific group. Signatures from 15/21 (2/3+1) validators are required.
       * Purpose: Ensures rapid and deterministic finality for triad splits.
   * node/:
     * mod.rs: Declares modules within the node directory. Error handling within this module will primarily use Rust's Result<T, E> type, leveraging custom error enums from utils/types.rs.
     * node_runner.rs:
       * Description: The core logic for running a TriadChain node. It orchestrates the interaction between the network, consensus, core, database components, and the role_manager.
       * Purpose: Drives the main loop and functionality of a running node.
     * role_manager.rs:
       * Description: This module manages the instantiation and lifecycle of different node roles. It provides a shared context or message bus for inter-role communication (e.g., a validator notifying the archiver of a new finalized triad, or a relayer querying the local state from the core component), allowing a single node binary to run multiple services concurrently.
       * Purpose: Coordinates multiple node functionalities within a single process.
     * validator.rs:
       * Description: Specific logic for Validator nodes: participating in HotStuff-BFT, solving PoS, proposing splits, and verifying incoming triads.
       * Purpose: Implements the validator role.
     * relayer.rs:
       * Description: Specific logic for Relay nodes: routing cross-triad transactions, managing two-phase commit with ZK-proofs, and potentially maintaining cross-triad routing tables.
       * Purpose: Implements the relayer role.
     * observer.rs:
       * Description: Specific logic for Observer nodes: synchronizing triad headers and state roots, verifying proofs (SPV, recursive ZK-proofs), but not participating in consensus.
       * Purpose: Implements the light client/observer role.
     * archiver.rs:
       * Description: Specific logic for Archiver nodes: storing full historical data (transactions, old states) and potentially serving it via IPFS or other means.
       * Purpose: Implements the historical data storage role.
   * utils/:
     * mod.rs: Declares modules within the utils directory. Error handling within this module will primarily use Rust's Result<T, E> type, leveraging custom error enums from utils/types.rs.
     * trie.rs:
       * Description: Generic Merkle Patricia Trie implementation for efficient state management within each triad.
       * Purpose: Provides data structure for state.
     * fractal_math.rs:
       * Description: Helper functions for Sierpiński triangle geometry, positional addressing (e.g., converting path strings to internal representations), normalization (canonical form: no trailing ".0" segments, single "0" for genesis), and child derivation. Hashing uses BLAKE3(canonical_form).
       * Purpose: Encapsulates the unique fractal logic.
     * types.rs:
       * Description: Common type definitions, error enums, and utility traits used across the project.
       * Purpose: Ensures type consistency and error handling.
   * database/:
     * mod.rs: Declares modules within the database directory. Error handling within this module will primarily use Rust's Result<T, E> type, leveraging custom error enums from utils/types.rs.
     * kv_store.rs:
       * Description: An abstraction layer for a persistent key-value store (e.g., using rocksdb or lmdb-rs). The store will primarily persist Triad headers (keyed by their BLAKE3 hash), raw Transaction data (keyed by transaction hash), and the individual key-value pairs that compose a triad's local state. Indices (e.g., transaction by sender, triad by position) will also be stored here.
       * Purpose: Provides persistent storage for the ledger.
 * tests/:
   * integration_tests.rs:
     * Description: End-to-end tests for larger components interacting, e.g., simulating a small network of nodes, observing triad splits, and cross-triad transactions.
     * Purpose: Verifies the correct functioning of integrated modules.
   * unit_tests/:
     * crypto_tests.rs: Tests for hashing, signing, and ZK-SNARK circuit validity.
     * core_tests.rs: Tests for transaction processing, triad structure, and state transitions.
     * consensus_tests.rs: Tests for Proof-of-Split puzzle logic and HotStuff-BFT state transitions.
     * Purpose: Ensures individual components work as expected.
 * scripts/:
   * start_node.sh:
     * Description: A shell script to compile and run a single TriadChain node with specified configuration (e.g., cargo run --release --bin triadchain-node -- --type validator --config config/validator_node.toml).
     * Purpose: Simplifies node startup for testing.
   * generate_keys.sh:
     * Description: A script to generate test validator key pairs for your testnet.
     * Purpose: Facilitates setting up multiple participants.
   * deploy_testnet.sh:
     * Description: A more complex script to spin up multiple nodes across different processes or machines, simulating a small testnet. This might involve Docker Compose later.
     * Purpose: Automates the setup of a multi-node test environment.
 * README.md:
   * Description: Project overview, setup instructions, how to run tests, and how to deploy a local testnet. Includes a note on throughput scaling: Effective TPS = 1000 × 4^n × (1 / (1 + 0.1n²)), where the 0.1n² overhead models cross-triad proof verification and state synchronization latency, based on benchmarks from similar fractal architectures and sharding simulations. Essential for anyone joining your private testing.
   * Purpose: Documentation for developers and testers.
 * .env.example:
   * Description: Example environment variables for node configuration (e.g., LOG_LEVEL=info, TRIADCHAIN_NODE_ID=1).
   * Purpose: Manages sensitive or deployment-specific configuration outside of source code.
   
