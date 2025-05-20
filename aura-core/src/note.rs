use crate::{AuraAddress, CoreError, CurveFr};
use ark_crypto_primitives::sponge::{
    CryptographicSponge, FieldBasedCryptographicSponge,
    poseidon::{PoseidonConfig, PoseidonSponge},
};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::convert::TryInto;

// TODO: Poseidon is wired up for commitments but circuit integration is still
// a mock. When a real circuit is implemented, ensure `poseidon_config()` is used
// consistently both inside and outside the circuit.

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Note {
    pub value: u64,
    pub owner_pk_info: Vec<u8>,
    pub randomness: CurveFr,
}

/// Return Poseidon parameters used for note commitments.
pub fn poseidon_config() -> PoseidonConfig<CurveFr> {
    use ark_crypto_primitives::sponge::poseidon::traits::find_poseidon_ark_and_mds;

    const FULL_ROUNDS: usize = 8;
    const PARTIAL_ROUNDS: usize = 31;
    const ALPHA: u64 = 17;
    const RATE: usize = 3;
    const CAPACITY: usize = 1;

    let (ark, mds) = find_poseidon_ark_and_mds::<CurveFr>(
        CurveFr::MODULUS_BIT_SIZE as u64,
        RATE,
        FULL_ROUNDS as u64,
        PARTIAL_ROUNDS as u64,
        0,
    );

    PoseidonConfig::new(FULL_ROUNDS, PARTIAL_ROUNDS, ALPHA, mds, ark, RATE, CAPACITY)
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
        let mut sponge = PoseidonSponge::<CurveFr>::new(&poseidon_config());

        let owner_fr = CurveFr::from_le_bytes_mod_order(&self.owner_pk_info);
        sponge.absorb(&CurveFr::from(self.value));
        sponge.absorb(&owner_fr);
        sponge.absorb(&self.randomness);

        let hash_result = sponge.squeeze_native_field_elements(1)[0];
        let mut bytes = Vec::new();
        hash_result
            .serialize_compressed(&mut bytes)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::Serialization("Invalid length".to_string()))?;
        Ok(NoteCommitment(arr))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AURA_ADDR_HRP;

    #[test]
    fn commitment_is_stable() {
        let addr = AuraAddress::new(AURA_ADDR_HRP, vec![1u8; 48]).unwrap();
        let randomness = CurveFr::from(42u64);
        let note = Note::new(100, &addr, randomness);

        let c1 = note.commitment_outside_circuit().unwrap();
        let c2 = note.commitment_outside_circuit().unwrap();
        assert_eq!(c1, c2);

        let mut sponge = PoseidonSponge::<CurveFr>::new(&poseidon_config());
        sponge.absorb(&CurveFr::from(100u64));
        sponge.absorb(&CurveFr::from_le_bytes_mod_order(addr.payload()));
        sponge.absorb(&randomness);
        let expected = sponge.squeeze_native_field_elements(1)[0];
        let mut bytes = Vec::new();
        expected.serialize_compressed(&mut bytes).unwrap();
        let arr: [u8; 32] = bytes.as_slice().try_into().unwrap();
        assert_eq!(c1.to_bytes(), arr);
    }
}
