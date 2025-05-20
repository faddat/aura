//! Aura Wallet Library
//!
//! This library provides wallet functionality for the Aura blockchain.

use ark_ff::UniformRand;
use ark_std::rand::{SeedableRng, rngs::StdRng};
use aura_core::keys::{generate_keypair_from_seed_phrase_str, generate_new_keypair_and_seed};
use aura_core::{
    CurveFr, Fee, Memo, Note, Nullifier, PrivateKey, PublicKey, SeedPhrase, Transaction,
    ZkProofData,
};

/// Represents an in-memory wallet keypair with optional seed phrase.
#[derive(Clone)]
pub struct Wallet {
    pub seed_phrase: Option<SeedPhrase>,
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
    pub address: aura_core::AuraAddress,
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
        let mut rng = StdRng::from_entropy();
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
    ) -> Result<(Transaction, Note), aura_core::CoreError> {
        if amount + fee > input_note.value {
            return Err(aura_core::CoreError::InsufficientFunds);
        }

        let change_value = input_note.value - amount - fee;

        let mut rng = StdRng::from_entropy();
        let out_randomness = CurveFr::rand(&mut rng);
        let change_randomness = CurveFr::rand(&mut rng);

        let output_note = Note::new(amount, recipient, out_randomness);
        let change_note = Note::new(change_value, &self.address, change_randomness);

        let output_commit = output_note.commitment_outside_circuit()?;
        let change_commit = change_note.commitment_outside_circuit()?;

        let nullifier =
            Nullifier::new_outside_circuit(&input_note.randomness, &self.private_key.0)?;

        let tx = Transaction {
            spent_nullifiers: vec![nullifier],
            new_note_commitments: vec![output_commit, change_commit],
            zk_proof_data: ZkProofData {
                proof_bytes: Vec::new(),
            },
            fee: Fee(fee),
            anchor: [0u8; 32],
            memo: Memo(Vec::new()),
        };

        Ok((tx, change_note))
    }
}
