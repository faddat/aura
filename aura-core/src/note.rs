use crate::{AuraAddress, CoreError, CurveFr, CurveG1}; // Assuming AuraAddress
use ark_ff::PrimeField; // For from_le_bytes_mod_order
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sha2::{Digest, Sha256}; // Or a ZKP-friendly hash like Poseidon

// --- Note ---
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Note {
    pub value: u64,             // Amount of uaura
    pub owner_pk_info: Vec<u8>, // Public key bytes of the owner, or diversified address components
    pub randomness: CurveFr,    // rho, for unique commitment
                                // pub memo: Option<[u8; 512]>, // Optional encrypted memo
}

impl Note {
    pub fn new(value: u64, owner_address: &AuraAddress, randomness: CurveFr) -> Self {
        Note {
            value,
            owner_pk_info: owner_address.payload().to_vec(), // Simplified: using raw address payload
            randomness,
        }
    }

    pub fn commitment(&self) -> Result<NoteCommitment, CoreError> {
        // This needs to be a ZKP-friendly hash (e.g., Poseidon) or a Pedersen hash.
        // For "crazy simple" placeholder, we use SHA256, but this MUST be replaced.
        // The actual commitment scheme depends heavily on the ZKP circuit.
        // E.g., Commit(value, owner_pk_info_hash, randomness)

        let mut hasher = Sha256::new(); // Placeholder - REPLACE WITH ZKP-FRIENDLY HASH
        hasher.update(self.value.to_le_bytes());

        let mut owner_bytes = Vec::new();
        // self.owner_pk_info.serialize_compressed(&mut owner_bytes).map_err(|e| CoreError::Serialization(e.to_string()))?;
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

// --- Note Commitment ---
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct NoteCommitment(pub [u8; 32]); // Output of the commitment function

impl NoteCommitment {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

// --- Nullifier ---
// nf = Hash(note_commitment, sk, position_in_merkle_tree_or_rho)
// For privacy, usually nf = Hash(rho, sk) or nf = Hash(note_secret, sk) where note_secret is derived from rho.
// Or, more commonly in Zcash-like systems, nf = CRH(rho, sk_spend, cm_pos), where cm_pos is the position.
// For simplicity here, let's do Hash(rho, sk_bytes). The ZKP must enforce this.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct Nullifier(pub [u8; 32]);

impl Nullifier {
    pub fn new(
        note_randomness: &CurveFr,
        spending_key_scalar: &CurveFr,
    ) -> Result<Self, CoreError> {
        // This needs to be a ZKP-friendly hash (e.g., Poseidon) or a Pedersen hash.
        // For "crazy simple" placeholder, we use SHA256, but this MUST be replaced.
        let mut hasher = Sha256::new(); // Placeholder - REPLACE WITH ZKP-FRIENDLY HASH

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
