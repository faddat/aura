//! Aura Wallet Library
//!
//! This library provides wallet functionality for the Aura blockchain.

use ark_crypto_primitives::sponge::{
    CryptographicSponge, FieldBasedCryptographicSponge, poseidon::PoseidonSponge,
};
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{SeedableRng, rngs::StdRng};
use aura_core::keys::{generate_keypair_from_seed_phrase_str, generate_new_keypair_and_seed};
use aura_core::{
    CurveFr, Fee, Memo, Note, Nullifier, PrivateKey, PublicKey, SeedPhrase, Transaction,
    ZkpHandler, ZkpParameters, poseidon_config,
};

/// Represents an in-memory wallet keypair with optional seed phrase.
#[derive(Clone)]
pub struct Wallet {
    pub seed_phrase: Option<SeedPhrase>,
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
    pub address: aura_core::AuraAddress,
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use aura_core::{CoreError, ZkpParameters};

    #[test]
    fn new_random_and_from_seed_phrase_produce_same_keys() {
        let wallet1 = Wallet::new_random().expect("new_random failed");
        let phrase = wallet1.seed_phrase.as_ref().unwrap().as_str();
        let wallet2 = Wallet::from_seed_phrase(&phrase).expect("from_seed_phrase failed");
        assert_eq!(wallet1.private_key, wallet2.private_key);
        assert_eq!(wallet1.public_key, wallet2.public_key);
        assert_eq!(wallet1.address, wallet2.address);
    }

    #[test]
    fn new_note_sets_value_and_owner() {
        let wallet = Wallet::new_random().expect("new_random failed");
        let value = 100u64;
        let note = wallet.new_note(value);
        assert_eq!(note.value, value);
        assert_eq!(note.owner_pk_info, wallet.address.payload().to_vec());
    }

    #[test]
    fn build_transfer_success_and_failure() {
        let wallet = Wallet::new_random().expect("new_random failed");
        let recipient = wallet.address.clone();
        let value = 50u64;
        let randomness = CurveFr::from(7u64);
        let input_note = Note::new(value, &wallet.address, randomness);
        let fee = 5u64;
        let amount = 40u64;
        // success case: generate dummy ZKP parameters
        let params = ZkpParameters::generate_dummy_for_circuit()
            .expect("ZKP parameter generation failed");
        let (tx, change_note) = wallet
            .build_transfer(input_note.clone(), &recipient, amount, fee, &params)
            .expect("build_transfer should succeed");
        assert_eq!(tx.fee.0, fee);
        assert_eq!(tx.spent_nullifiers.len(), 1);
        let expected_nullifier = Nullifier::new_outside_circuit(&randomness, &wallet.private_key.0)
            .expect("nullifier creation failed");
        assert_eq!(tx.spent_nullifiers[0], expected_nullifier);
        assert_eq!(tx.new_note_commitments.len(), 2);
        let expected_change_commit = change_note
            .commitment_outside_circuit()
            .expect("change_commitment failed");
        assert_eq!(tx.new_note_commitments[1], expected_change_commit);
        assert_eq!(change_note.value, value - amount - fee);

        // failure case: insufficient funds
        let err = wallet
            .build_transfer(input_note, &recipient, value - fee + 1, fee, &params)
            .unwrap_err();
        assert!(matches!(err, CoreError::InsufficientFunds));
    }
}

impl Wallet {
    /// Generate a new random wallet with a fresh seed phrase.
    pub fn new_random() -> Result<Self, aura_core::CoreError> {
        let (seed, sk, pk, addr) = generate_new_keypair_and_seed()?;
        Ok(Self {
            seed_phrase: Some(seed),
            private_key: sk,
            public_key: pk,
            address: addr,
        })
    }

    /// Create a wallet from an existing BIP39 seed phrase.
    pub fn from_seed_phrase(phrase: &str) -> Result<Self, aura_core::CoreError> {
        let (sk, pk, addr) = generate_keypair_from_seed_phrase_str(phrase)?;
        Ok(Self {
            seed_phrase: Some(SeedPhrase::parse_phrase(phrase)?),
            private_key: sk,
            public_key: pk,
            address: addr,
        })
    }

    /// Create a new note owned by this wallet with random blinding.
    pub fn new_note(&self, value: u64) -> Note {
        let mut seed = <StdRng as SeedableRng>::Seed::default();
        getrandom::fill(&mut seed).expect("Failed to generate RNG seed");
        let mut rng = StdRng::from_seed(seed);
        let randomness = CurveFr::rand(&mut rng);
        Note::new(value, &self.address, randomness)
    }

    /// Build a simple transfer transaction consuming `input_note` and sending
    /// `amount` to `recipient`. Any remaining value after fee is returned to a
    /// change note for this wallet. The function returns the transaction and the
    /// newly created change note.
    pub fn build_transfer(
        &self,
        input_note: Note,
        recipient: &aura_core::AuraAddress,
        amount: u64,
        fee: u64,
        params: &ZkpParameters,
    ) -> Result<(Transaction, Note), aura_core::CoreError> {
        if amount + fee > input_note.value {
            return Err(aura_core::CoreError::InsufficientFunds);
        }

        let change_value = input_note.value - amount - fee;

        let mut seed = <StdRng as SeedableRng>::Seed::default();
        getrandom::fill(&mut seed).expect("Failed to generate RNG seed");
        let mut rng = StdRng::from_seed(seed);
        let out_randomness = CurveFr::rand(&mut rng);
        let change_randomness = CurveFr::rand(&mut rng);
        let anchor = CurveFr::rand(&mut rng);

        let output_note = Note::new(amount, recipient, out_randomness);
        let change_note = Note::new(change_value, &self.address, change_randomness);

        let output_commit = output_note.commitment_outside_circuit()?;
        let change_commit = change_note.commitment_outside_circuit()?;

        let nullifier =
            Nullifier::new_outside_circuit(&input_note.randomness, &self.private_key.0)?;

        // Helper hashes for circuit
        let mut sponge = PoseidonSponge::new(&poseidon_config());
        sponge.absorb(&input_note.randomness);
        sponge.absorb(&self.private_key.0);
        let expected_nullifier = sponge.squeeze_native_field_elements(1)[0];

        let mut sponge1 = PoseidonSponge::new(&poseidon_config());
        sponge1.absorb(&CurveFr::from(amount));
        sponge1.absorb(&CurveFr::from_le_bytes_mod_order(recipient.payload()));
        sponge1.absorb(&out_randomness);
        let expected_out_commit = sponge1.squeeze_native_field_elements(1)[0];

        let mut sponge2 = PoseidonSponge::new(&poseidon_config());
        sponge2.absorb(&CurveFr::from(change_value));
        sponge2.absorb(&CurveFr::from_le_bytes_mod_order(self.address.payload()));
        sponge2.absorb(&change_randomness);
        let expected_change_commit = sponge2.squeeze_native_field_elements(1)[0];

        let circuit = aura_core::TransferCircuit {
            input_note_value: Some(input_note.value),
            input_note_owner_pk_hash: Some(CurveFr::from_le_bytes_mod_order(
                &input_note.owner_pk_info,
            )),
            input_note_randomness: Some(input_note.randomness),
            input_spending_key_scalar: Some(self.private_key.0),
            output1_note_value: Some(amount),
            output1_note_owner_pk_hash: Some(CurveFr::from_le_bytes_mod_order(recipient.payload())),
            output1_note_randomness: Some(out_randomness),
            output2_note_value: Some(change_value),
            output2_note_owner_pk_hash: Some(CurveFr::from_le_bytes_mod_order(
                self.address.payload(),
            )),
            output2_note_randomness: Some(change_randomness),
            anchor: Some(anchor),
            fee: Some(fee),
            expected_nullifier: Some(expected_nullifier),
            expected_output1_commitment: Some(expected_out_commit),
            expected_output2_commitment: Some(expected_change_commit),
        };

        let proof = ZkpHandler::generate_proof(&params.proving_key, circuit)?;
        let public_inputs = ZkpHandler::prepare_public_inputs_for_verification(
            anchor,
            fee,
            expected_nullifier,
            expected_out_commit,
            expected_change_commit,
        );
        if !ZkpHandler::verify_proof(&params.prepared_verifying_key, &public_inputs, &proof)? {
            return Err(aura_core::CoreError::ProofVerification(
                "self-verification failed".to_string(),
            ));
        }

        let mut anchor_bytes = Vec::new();
        anchor
            .serialize_compressed(&mut anchor_bytes)
            .map_err(|e| aura_core::CoreError::Serialization(e.to_string()))?;
        let anchor_arr: [u8; 32] = anchor_bytes
            .as_slice()
            .try_into()
            .map_err(|_| aura_core::CoreError::Serialization("Invalid length".to_string()))?;

        let tx = Transaction {
            spent_nullifiers: vec![nullifier],
            new_note_commitments: vec![output_commit, change_commit],
            zk_proof_data: proof,
            fee: Fee(fee),
            anchor: anchor_arr,
            memo: Memo(Vec::new()),
        };

        Ok((tx, change_note))
    }
}
