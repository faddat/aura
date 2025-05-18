use crate::{AuraAddress, CoreError, CurveFr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize}; // Trait needed
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Note {
    pub value: u64,
    pub owner_pk_info: Vec<u8>, // This should ideally be a CurveFr (hash of pk) for circuit efficiency
    pub randomness: CurveFr,
}

impl Note {
    pub fn new(value: u64, owner_address: &AuraAddress, randomness: CurveFr) -> Self {
        // For circuit, owner_pk_info should ideally be a hash.
        // If owner_address.payload() IS the compressed public key,
        // then the ZKP circuit would need to hash it to get owner_pk_hash.
        // Or, wallet prepares owner_pk_hash from owner_address.
        Note {
            value,
            // For now, keep as bytes. Wallet/prover will need to convert to CurveFr for circuit.
            owner_pk_info: owner_address.payload().to_vec(),
            randomness,
        }
    }

    // This non-circuit commitment function should match the ZKP circuit's commitment
    pub fn commitment_outside_circuit(&self) -> Result<NoteCommitment, CoreError> {
        // Placeholder - MUST MATCH ZKP CIRCUIT (e.g., Poseidon)
        // For now, using SHA256 for illustration
        let mut hasher = Sha256::new();
        hasher.update(self.value.to_le_bytes());

        // Hash owner_pk_info if it's not already a hash suitable for Poseidon input
        // For simplicity, directly using bytes, but circuit will use Fr elements.
        // let owner_pk_hash_fr = CurveFr::from_le_bytes_mod_order(&crypto::hash_data(&self.owner_pk_info));
        hasher.update(&self.owner_pk_info);

        let mut randomness_bytes = Vec::new();
        self.randomness
            .serialize_compressed(&mut randomness_bytes)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        hasher.update(&randomness_bytes);

        let hash_result = hasher.finalize();
        Ok(NoteCommitment(hash_result.into()))
    }
}

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct NoteCommitment(pub [u8; 32]); // This should ideally be CurveFr if Poseidon output is Fr

impl NoteCommitment {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
    // Add from_fr if commitment is CurveFr
    // pub fn from_fr(fr: CurveFr) -> Result<Self, CoreError> { ... }
}

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct Nullifier(pub [u8; 32]); // This should ideally be CurveFr

impl Nullifier {
    // This non-circuit nullifier function should match the ZKP circuit's nullifier
    pub fn new_outside_circuit(
        note_randomness: &CurveFr,
        spending_key_scalar: &CurveFr,
    ) -> Result<Self, CoreError> {
        // Placeholder - MUST MATCH ZKP CIRCUIT (e.g., Poseidon)
        let mut hasher = Sha256::new();

        let mut randomness_bytes = Vec::new();
        note_randomness
            .serialize_compressed(&mut randomness_bytes)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        hasher.update(&randomness_bytes);

        let mut sk_bytes = Vec::new();
        spending_key_scalar
            .serialize_compressed(&mut sk_bytes)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        hasher.update(&sk_bytes);

        let hash_result = hasher.finalize();
        Ok(Nullifier(hash_result.into()))
    }
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
    // Add from_fr if nullifier is CurveFr
    // pub fn from_fr(fr: CurveFr) -> Result<Self, CoreError> { ... }
}
