// testnet/src/crypto/signing.rs

// Use types from ed25519-dalek v2.x
pub use ed25519_dalek::{
    Signature, VerifyingKey as PublicKey, // VerifyingKey is the PublicKey type in v2
    SIGNATURE_LENGTH, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH // SECRET_KEY_LENGTH is for the seed part
};
// For signing, we need SigningKey. For key generation, we often work with the keypair.
use ed25519_dalek::SigningKey;
use ed25519_dalek::Signer; // Trait for sign method
use ed25519_dalek::Verifier; // Trait for verify method

use rand::rngs::OsRng;

/// A keypair containing an Ed25519 public (VerifyingKey) and secret (SigningKey).
#[derive(Debug)] // SigningKey is not Clone.
pub struct Keypair {
    pub public: PublicKey, // This is VerifyingKey
    pub secret: SigningKey,
}

impl Keypair {
    /// Generates a new Ed25519 keypair using OsRng.
    pub fn generate() -> Self {
        let mut csprng = OsRng{};
        let signing_key = SigningKey::generate(&mut csprng); // Generates a full signing key
        let verifying_key = signing_key.verifying_key();
        Keypair {
            public: verifying_key,
            secret: signing_key,
        }
    }

    /// Creates a Keypair from secret key bytes (seed).
    /// The input `bytes` should be `SECRET_KEY_LENGTH` (32 bytes) for the seed.
    pub fn from_seed_bytes(seed_bytes: &[u8; SECRET_KEY_LENGTH]) -> Self {
        let signing_key = SigningKey::from_bytes(seed_bytes);
        let verifying_key = signing_key.verifying_key();
        Keypair {
            public: verifying_key,
            secret: signing_key,
        }
    }
}

/// Signs a message using the provided Ed25519 signing key.
pub fn sign(message_bytes: &[u8], signing_key: &SigningKey) -> Signature {
    signing_key.sign(message_bytes)
}

/// Verifies an Ed25519 signature for a given message and public/verifying key.
pub fn verify(message_bytes: &[u8], signature: &Signature, verifying_key: &PublicKey) -> bool {
    verifying_key.verify(message_bytes, signature).is_ok()
}
