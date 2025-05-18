use crate::note::{NoteCommitment, Nullifier};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use sha2::Digest; // For Sha256::new()

#[derive(
    Clone, Copy, Debug, Serialize, Deserialize, Default, CanonicalSerialize, CanonicalDeserialize,
)]
pub struct Fee(pub u64);

#[derive(
    Clone, Debug, Serialize, Deserialize, CanonicalSerialize, CanonicalDeserialize, Default,
)]
pub struct Memo(pub Vec<u8>);

#[derive(
    Clone, Debug, Serialize, Deserialize, CanonicalSerialize, CanonicalDeserialize, Default,
)]
pub struct ZkProofData {
    pub proof_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, CanonicalSerialize, CanonicalDeserialize)]
pub struct Transaction {
    pub spent_nullifiers: Vec<Nullifier>,
    pub new_note_commitments: Vec<NoteCommitment>,
    pub zk_proof_data: ZkProofData,
    pub fee: Fee,
    pub anchor: [u8; 32],
    pub memo: Memo,
}

impl Transaction {
    pub fn id(&self) -> Result<[u8; 32], crate::CoreError> {
        let mut bytes = Vec::new();
        // Transaction struct itself needs to implement CanonicalSerialize for this to work via derive
        self.serialize_compressed(&mut bytes)
            .map_err(|e| crate::CoreError::Serialization(e.to_string()))?;

        let mut hasher = sha2::Sha256::new();
        hasher.update(&bytes);
        Ok(hasher.finalize().into())
    }
}
