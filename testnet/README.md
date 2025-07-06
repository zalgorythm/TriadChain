# TriadChain Testnet

Welcome to the TriadChain testnet environment.  
This network is designed as a staging ground for developing, validating, and refining a mainnet-ready implementation of TriadChain.

---

## Purpose

The current testnet is an active development and research environment. Our primary goal is to reach a robust, scalable, and secure mainnet implementation before any official deployment. While the network is not yet production-ready, **community contributions and feedback are welcome**.

---

## Status

**This testnet is not yet recommended for commercial, production, or high-value use.**  
Stability, performance, and security are still being actively improved.

---

## About TriadChain

TriadChain is a fractal-based distributed ledger system utilizing recursive Sierpiński triangle subdivision to achieve scalable throughput and geometric security.  
See [WHITEPAPER.md](../WHITEPAPER.md) for detailed protocol specifications.

---

## How to Participate

If you have found this repository and are interested in contributing to the project’s development, you are encouraged to:

- Review the [whitepaper](../WHITEPAPER.md) and protocol documentation
- Experiment with the testnet code and submit issues or pull requests
- Join discussions to help shape the security, consensus, and scalability mechanisms

All contributors are expected to follow responsible disclosure and act in good faith.

---

## Getting Started

1. **Clone the repository:**
    ```bash
    git clone https://github.com/zalgorythm/TriadChain.git
    cd TriadChain/testnet
    ```

2. **Install prerequisites:**
    - Rust (nightly)
    - Required cryptography libraries (see [WHITEPAPER.md](../WHITEPAPER.md))

3. **Configure and run a testnet node:**
    - Use the sample configuration or request guidance via a GitHub issue or discussion.
    - Example:
        ```bash
        cargo build --release
        ./target/release/triadchain-testnet --config ./testnet.toml
        ```

---

## Guidelines

- **No Guarantees:**  
  The testnet is experimental. Data and tokens have no real-world value and may be reset without notice.
- **Not for Production:**  
  Do not use this code or network for commercial applications at this stage.
- **Feedback Welcome:**  
  Bug reports, feature requests, and protocol discussions are appreciated.

---

## Roadmap Highlights

- Genesis testnet launch (2024-10-01)
- Fractal scaling experiments (Level 5+)
- Cross-triad transaction validation
- Mainnet release: TBD

---

## Resources

- [Whitepaper](../WHITEPAPER.md)
- [Documentation](../docs/)
- [Issues](https://github.com/zalgorythm/TriadChain/issues)
- [Discussions](https://github.com/zalgorythm/TriadChain/discussions)

---

**TriadChain testnet is where protocol innovation happens. Help us shape the future of scalable distributed ledgers—your contributions are welcome!**

---
