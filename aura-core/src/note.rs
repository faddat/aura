use crate::{AuraAddress, CoreError, CurveFr};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// TODO: IMPLEMENTATION WARNING
// This codebase uses the sha2 hash function for commitments instead of the Poseidon hash
// which would be more ZKP-friendly. To use Poseidon properly, you need to:
// 1. Initialize matrices properly for PoseidonConfig
// 2. Implement hashing in zkp.rs using PoseidonSponge
// 3. Add proper implementations of PoseidonSpongeVar for circuit constraints
//
// The current implementation is a placeholder for development. In a production
// environment, you should implement proper ZK-friendly primitives.

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Note {
    pub value: u64,
    pub owner_pk_info: Vec<u8>,
    pub randomness: CurveFr,
}

impl Note {
    pub fn new(value: u64, owner_address: &AuraAddress, randomness: CurveFr) -> Self {
        Note {
            value,
            owner_pk_info: owner_address.payload().to_vec(),
            randomness,
        }
    }

    pub fn commitment_outside_circuit(&self) -> Result<NoteCommitment, CoreError> {
        let mut hasher = Sha256::new();
        hasher.update(self.value.to_le_bytes());
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
pub struct NoteCommitment(pub [u8; 32]);

impl NoteCommitment {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
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
pub struct Nullifier(pub [u8; 32]);

impl Nullifier {
    pub fn new_outside_circuit(
        note_randomness: &CurveFr,
        spending_key_scalar: &CurveFr,
    ) -> Result<Self, CoreError> {
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
}
