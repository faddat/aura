use crate::AuraAddress; // Assuming AuraAddress is defined
use crate::note::{NoteCommitment, Nullifier};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

// --- Fee ---
#[derive(
    Clone, Copy, Debug, Serialize, Deserialize, Default, CanonicalSerialize, CanonicalDeserialize,
)]
pub struct Fee(pub u64); // Amount of uaura

// --- Memo ---
#[derive(Clone, Debug, Serialize, Deserialize, CanonicalSerialize, CanonicalDeserialize)]
pub struct Memo(pub Vec<u8>); // Max 512 bytes, typically encrypted for recipient

impl Default for Memo {
    fn default() -> Self {
        Memo(Vec::new())
    }
}

// --- ZkProofData ---
// This is what the ZKP actually produces. Its structure depends on the proving system (e.g., Groth16).
// For Groth16, it's usually three group elements (A, B, C).
#[derive(
    Clone, Debug, Serialize, Deserialize, CanonicalSerialize, CanonicalDeserialize, Default,
)]
pub struct ZkProofData {
    // Example for Groth16 (actual types from ark-groth16::Proof)
    // pub a: CurveG1,
    // pub b: CurveG2, // Or G1 if symmetric pairing
    // pub c: CurveG1,
    pub proof_bytes: Vec<u8>, // Store serialized proof bytes for now
}

// --- Transaction ---
// This is the structure that gets put on the blockchain (or at least its hash).
// It contains public information and the ZK proof.
#[derive(Clone, Debug, Serialize, Deserialize, CanonicalSerialize, CanonicalDeserialize)]
pub struct Transaction {
    pub spent_nullifiers: Vec<Nullifier>,
    pub new_note_commitments: Vec<NoteCommitment>,
    // pub encrypted_output_notes: Vec<Vec<u8>>, // Encrypted notes for recipients
    pub zk_proof_data: ZkProofData,
    pub fee: Fee,
    pub anchor: [u8; 32], // Merkle root of the note commitment tree at the time of tx creation
    // Other public data like an ephemeral public key for note encryption, if needed by protocol
    // pub ephemeral_public_key: Option<PublicKeyBytes>,
    pub memo: Memo, // Could be a single public memo or related to how notes are encrypted
}

impl Transaction {
    // Method to calculate transaction ID (hash of the transaction)
    pub fn id(&self) -> Result<[u8; 32], crate::CoreError> {
        let mut bytes = Vec::new();
        self.serialize_compressed(&mut bytes)
            .map_err(|e| crate::CoreError::Serialization(e.to_string()))?;

        let mut hasher = sha2::Sha256::new();
        hasher.update(&bytes);
        Ok(hasher.finalize().into())
    }
}
