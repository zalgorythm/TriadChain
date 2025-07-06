# TriadChain – Architecture Overview

TriadChain is organized for clarity, modularity, and extensibility.  
Below is a high-level overview of the main directories and their responsibilities.

## Directory Structure

```
triadchain-testnet/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── config/
│   ├── crypto/
│   ├── core/
│   ├── network/
│   ├── consensus/
│   ├── node/
│   ├── utils/
│   └── database/
├── tests/
├── scripts/
├── README.md
├── .env.example
```

## Key Components

### Cargo.toml
- Rust project manifest and dependencies.

### src/

- **main.rs:** Application entry point.
- **lib.rs:** Public API, module exports.

#### config/
- Network and node configuration structures.

#### crypto/
- Hashes, digital signatures, and ZK-SNARKs (ZKP integration planned).

#### core/
- Transaction struct, triad (fractal shard) logic, state management.

#### network/
- P2P node discovery, message definitions, networking.

#### consensus/
- Proof-of-Split (PoS) puzzle, HotStuff-BFT protocol for finality.

#### node/
- Node runtime, role management (validator, relayer, observer, archiver).

#### utils/
- Trie implementation, fractal math, common types, errors.

#### database/
- Persistent storage layer abstraction (RocksDB, LMDB).

### tests/
- Integration and unit tests.

### scripts/
- Node start-up, key generation, local testnet deployment.

### .env.example
- Example environment variables.

---

_For detailed module-by-module explanations, see `docs/MODULES.md` (planned)._
