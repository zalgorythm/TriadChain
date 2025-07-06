# TriadChain

**A Fractal-Based Distributed Ledger System**

---

TriadChain is an experimental distributed ledger platform that leverages recursive Sierpiński triangle subdivision to achieve exponential scalability and geometric security. By reimagining consensus and state propagation through fractal geometry, TriadChain aims to overcome the scalability and throughput limitations of traditional blockchains.

---

## 🚧 Project Status

**This repository contains a work-in-progress implementation of the TriadChain protocol.**  
- The system is not yet mainnet-ready.
- It is not recommended for production or commercial use.
- We welcome community contributions, testing, and feedback as we progress toward a robust, secure, and scalable mainnet launch.

---

## ✨ Key Features

- **Fractal Architecture:** Recursive triad (triangle) data structures replace linear chains for state and consensus, enabling exponential throughput scaling.
- **Geometric Consensus:** Novel "Proof-of-Split" mining and HotStuff-BFT validator rotation, secured by cryptographic proofs and vector constraints.
- **Recursive State Propagation:** Efficient Merkle root updates and conflict resolution across fractal subdivisions.
- **Position-Based Routing:** Deterministic transaction routing via BLAKE3-hashed Sierpiński coordinates.
- **Zero-Knowledge Proofs:** ZK-SNARK circuits enforce geometric and consensus constraints.

---

## 📖 Documentation

- [WHITEPAPER.md](./WHITEPAPER.md): Full protocol specification, architecture, and rationale.
- [testnet/README.md](./testnet/README.md): Details for running and contributing to the current testnet.

---

## 🤝 Contributing

If you have discovered this repository and are interested in contributing:
- Review the [whitepaper](./WHITEPAPER.md) to understand the protocol and goals.
- Experiment with the codebase and testnet.
- Open issues or pull requests for bugs, improvements, or research discussions.
- All contributions are welcome—TriadChain thrives on open innovation.

---

## ⚠️ Disclaimer

**TriadChain is under active development.  
There are no guarantees of stability, security, or data persistence at this stage.  
Test tokens and deployments have no real-world value.  
Do not use this codebase for commercial or high-value purposes until an official mainnet release.**

---

## 🗺️ Roadmap

| Milestone                      | Target Date      |
| ------------------------------ | --------------- |
| Cryptographic Primitives       | 2024-08         |
| Fractal Data Structure         | 2024-09         |
| Consensus Implementation       | 2024-11         |
| Genesis Testnet Launch         | 2024-10-01      |
| Level 5 Scaling Test           | 2024-11         |
| Cross-Triad TX Validation      | 2024-12         |
| Security Audit                 | 2025-03         |
| Public Mainnet Launch          | 2025-05         |

See [WHITEPAPER.md](./WHITEPAPER.md) for further details.

---

## 📚 References

- Mandelbrot, B. — *The Fractal Geometry of Nature*
- Yin, M. et al. — *HotStuff: BFT Consensus in the Lens of Blockchain*
- Boneh, D. et al. — *Geometric Cryptography in Lattices*
- Aumasson, J. — *BLAKE3: One Function, Fast Everywhere*

*And more, see [WHITEPAPER.md](./WHITEPAPER.md).*

---

## 🏗️ License

This project is released under the MIT License.

---

> “In the triangle, we find the strongest shape—the only polygon that cannot collapse without bending its sides.  
> In TriadChain, we find the strongest ledger—one that grows without collapsing under its own weight.”  
> — TriadChain Genesis Inscription

---
