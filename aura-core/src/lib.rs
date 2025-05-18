pub mod address;
pub mod crypto;
pub mod error;
pub mod genesis;
pub mod keys;
pub mod note;
pub mod transaction;
pub mod zkp; // This will define traits/structs for ZKP interaction

// Re-export key types for easier access
pub use address::AuraAddress;
pub use error::CoreError;
pub use keys::{PrivateKey, PublicKey, SeedPhrase, Signature}; // Example key types
pub use note::{Note, NoteCommitment, Nullifier};
pub use transaction::{Fee, Memo, Transaction, ZkProofData};

// Define a global curve type for consistency (e.g., BLS12-381)
pub type AuraCurve = ark_bls12_381::Bls12_381;
pub type CurveFr = ark_bls12_381::Fr; // Field element for scalars, values
pub type CurveG1 = ark_bls12_381::G1Projective; // Group element for commitments, keys

// --- Constants ---
pub const AURA_ADDR_HRP: &str = "aura"; // Human-readable part for Aura addresses
pub const NATIVE_DENOM: &str = "uaura"; // Smallest unit of Aura
