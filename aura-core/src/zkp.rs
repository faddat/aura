use crate::note::poseidon_config;
use crate::transaction::ZkProofData;
use crate::{AuraCurve, CoreError, CurveFr};
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::{
    CryptographicSponge, FieldBasedCryptographicSponge,
    poseidon::{PoseidonSponge, constraints::PoseidonSpongeVar},
};
use ark_ff::PrimeField;
use ark_ff::Zero;
use ark_groth16::{
    Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey, prepare_verifying_key,
};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::io::BufReader;
use ark_std::rand::{RngCore, SeedableRng, rngs::StdRng};
use ark_std::vec::Vec;
use std::fs::File;
use std::path::Path;

// ========================================================================
// TODO: IMPLEMENTATION WARNING
// ========================================================================
// This implementation is a MOCK implementation of the ZKP system that
// is intended for development and testing purposes only.
//
// To implement a proper ZKP system:
// 1. Create proper Poseidon hashing for commitments
// 2. Implement proper constraints in TransferCircuit
// 3. Fix PoseidonSpongeVar usage in the constraint generation
// 4. Implement proper parameter generation, proving, and verification
//
// The mock implementation doesn't actually create any proofs, it just
// provides stubs that allow the code to compile and simulate functionality.
// ========================================================================

#[cfg(feature = "tracing")]
use tracing;

#[derive(Clone, Default)]
pub struct TransferCircuit {
    pub input_note_value: Option<u64>,
    pub input_note_owner_pk_hash: Option<CurveFr>,
    pub input_note_randomness: Option<CurveFr>,
    pub input_spending_key_scalar: Option<CurveFr>,
    pub output1_note_value: Option<u64>,
    pub output1_note_owner_pk_hash: Option<CurveFr>,
    pub output1_note_randomness: Option<CurveFr>,
    pub output2_note_value: Option<u64>,
    pub output2_note_owner_pk_hash: Option<CurveFr>,
    pub output2_note_randomness: Option<CurveFr>,
    pub anchor: Option<CurveFr>,
    pub fee: Option<u64>,
    pub expected_nullifier: Option<CurveFr>,
    pub expected_output1_commitment: Option<CurveFr>,
    pub expected_output2_commitment: Option<CurveFr>,
}

impl ConstraintSynthesizer<CurveFr> for TransferCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<CurveFr>) -> Result<(), SynthesisError> {
        let poseidon_cfg = poseidon_config();

        // Witnesses for the input note
        let input_value = FpVar::<CurveFr>::new_witness(cs.clone(), || {
            self.input_note_value
                .map(CurveFr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let input_owner = FpVar::<CurveFr>::new_witness(cs.clone(), || {
            self.input_note_owner_pk_hash
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let input_randomness = FpVar::<CurveFr>::new_witness(cs.clone(), || {
            self.input_note_randomness
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let spending_key = FpVar::<CurveFr>::new_witness(cs.clone(), || {
            self.input_spending_key_scalar
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Witnesses for the output notes
        let out1_value = FpVar::<CurveFr>::new_witness(cs.clone(), || {
            self.output1_note_value
                .map(CurveFr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let out1_owner = FpVar::<CurveFr>::new_witness(cs.clone(), || {
            self.output1_note_owner_pk_hash
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let out1_randomness = FpVar::<CurveFr>::new_witness(cs.clone(), || {
            self.output1_note_randomness
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let out2_value = FpVar::<CurveFr>::new_witness(cs.clone(), || {
            self.output2_note_value
                .map(CurveFr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let out2_owner = FpVar::<CurveFr>::new_witness(cs.clone(), || {
            self.output2_note_owner_pk_hash
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let out2_randomness = FpVar::<CurveFr>::new_witness(cs.clone(), || {
            self.output2_note_randomness
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Public inputs
        let anchor = FpVar::<CurveFr>::new_input(cs.clone(), || {
            self.anchor.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let fee = FpVar::<CurveFr>::new_input(cs.clone(), || {
            self.fee
                .map(CurveFr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let expected_nullifier = FpVar::<CurveFr>::new_input(cs.clone(), || {
            self.expected_nullifier
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let expected_out1_commit = FpVar::<CurveFr>::new_input(cs.clone(), || {
            self.expected_output1_commitment
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let expected_out2_commit = FpVar::<CurveFr>::new_input(cs.clone(), || {
            self.expected_output2_commitment
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Nullifier = Poseidon(randomness, spending_key)
        let mut sponge = PoseidonSpongeVar::new(cs.clone(), &poseidon_cfg);
        sponge.absorb(&input_randomness)?;
        sponge.absorb(&spending_key)?;
        let nullifier = sponge.squeeze_field_elements(1)?[0].clone();
        nullifier.enforce_equal(&expected_nullifier)?;

        // Output commitment 1
        let mut sponge1 = PoseidonSpongeVar::new(cs.clone(), &poseidon_cfg);
        sponge1.absorb(&out1_value)?;
        sponge1.absorb(&out1_owner)?;
        sponge1.absorb(&out1_randomness)?;
        let out1_commit = sponge1.squeeze_field_elements(1)?[0].clone();
        out1_commit.enforce_equal(&expected_out1_commit)?;

        // Output commitment 2
        let mut sponge2 = PoseidonSpongeVar::new(cs.clone(), &poseidon_cfg);
        sponge2.absorb(&out2_value)?;
        sponge2.absorb(&out2_owner)?;
        sponge2.absorb(&out2_randomness)?;
        let out2_commit = sponge2.squeeze_field_elements(1)?[0].clone();
        out2_commit.enforce_equal(&expected_out2_commit)?;

        // Value conservation: input = out1 + out2 + fee
        let sum = out1_value + out2_value + fee;
        input_value.enforce_equal(&sum)?;

        // Anchor is not used but ensures it is included as public input
        let _ = anchor;

        Ok(())
    }
}

pub struct ZkpParameters {
    pub proving_key: ProvingKey<AuraCurve>,
    pub verifying_key: VerifyingKey<AuraCurve>,
    pub prepared_verifying_key: PreparedVerifyingKey<AuraCurve>,
}

impl ZkpParameters {
    pub fn generate_dummy_for_circuit() -> Result<Self, CoreError> {
        let mut seed = <StdRng as SeedableRng>::Seed::default();
        getrandom::fill(&mut seed).unwrap();
        let mut rng = StdRng::from_seed(seed);
        let dummy_circuit = TransferCircuit {
            input_note_value: Some(0),
            input_note_owner_pk_hash: Some(CurveFr::zero()),
            input_note_randomness: Some(CurveFr::zero()),
            input_spending_key_scalar: Some(CurveFr::zero()),
            output1_note_value: Some(0),
            output1_note_owner_pk_hash: Some(CurveFr::zero()),
            output1_note_randomness: Some(CurveFr::zero()),
            output2_note_value: Some(0),
            output2_note_owner_pk_hash: Some(CurveFr::zero()),
            output2_note_randomness: Some(CurveFr::zero()),
            anchor: Some(CurveFr::zero()),
            fee: Some(0),
            expected_nullifier: Some(CurveFr::zero()),
            expected_output1_commitment: Some(CurveFr::zero()),
            expected_output2_commitment: Some(CurveFr::zero()),
        };

        let (pk, vk) = Groth16::<AuraCurve>::circuit_specific_setup(dummy_circuit, &mut rng)
            .map_err(|e| CoreError::ZkpSetup(e.to_string()))?;
        let pvk = prepare_verifying_key(&vk);

        Ok(Self {
            proving_key: pk,
            verifying_key: vk,
            prepared_verifying_key: pvk,
        })
    }

    pub fn load_from_files(_pk_path: &Path, _vk_path: &Path) -> Result<Self, CoreError> {
        let mut pk_file = BufReader::new(File::open(_pk_path)?);
        let mut vk_file = BufReader::new(File::open(_vk_path)?);
        let pk = ProvingKey::<AuraCurve>::deserialize_compressed(&mut pk_file)
            .map_err(|e| CoreError::Deserialization(e.to_string()))?;
        let vk = VerifyingKey::<AuraCurve>::deserialize_compressed(&mut vk_file)
            .map_err(|e| CoreError::Deserialization(e.to_string()))?;
        let pvk = prepare_verifying_key(&vk);
        Ok(Self {
            proving_key: pk,
            verifying_key: vk,
            prepared_verifying_key: pvk,
        })
    }

    pub fn load_from_bytes(_pk_bytes: &[u8], _vk_bytes: &[u8]) -> Result<Self, CoreError> {
        let pk = ProvingKey::<AuraCurve>::deserialize_compressed(&mut &_pk_bytes[..])
            .map_err(|e| CoreError::Deserialization(e.to_string()))?;
        let vk = VerifyingKey::<AuraCurve>::deserialize_compressed(&mut &_vk_bytes[..])
            .map_err(|e| CoreError::Deserialization(e.to_string()))?;
        let pvk = prepare_verifying_key(&vk);
        Ok(Self {
            proving_key: pk,
            verifying_key: vk,
            prepared_verifying_key: pvk,
        })
    }

    pub fn save_to_files(&self, _pk_path: &Path, _vk_path: &Path) -> Result<(), CoreError> {
        let mut pk_file = File::create(_pk_path)?;
        self.proving_key
            .serialize_compressed(&mut pk_file)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let mut vk_file = File::create(_vk_path)?;
        self.verifying_key
            .serialize_compressed(&mut vk_file)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        Ok(())
    }
}

pub struct ZkpHandler;

impl ZkpHandler {
    pub fn generate_proof(
        proving_key: &ProvingKey<AuraCurve>,
        circuit: TransferCircuit,
    ) -> Result<ZkProofData, CoreError> {
        let mut seed = <StdRng as SeedableRng>::Seed::default();
        getrandom::fill(&mut seed).unwrap();
        let mut rng = StdRng::from_seed(seed);
        let proof = Groth16::<AuraCurve>::prove(proving_key, circuit, &mut rng)
            .map_err(|e| CoreError::ProofGeneration(e.to_string()))?;
        let mut bytes = Vec::new();
        proof
            .serialize_compressed(&mut bytes)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        Ok(ZkProofData { proof_bytes: bytes })
    }

    pub fn prepare_public_inputs_for_verification(
        anchor: CurveFr,
        fee: u64,
        expected_nullifier: CurveFr,
        expected_output1_commitment: CurveFr,
        expected_output2_commitment: CurveFr,
    ) -> Vec<CurveFr> {
        vec![
            anchor,
            CurveFr::from(fee),
            expected_nullifier,
            expected_output1_commitment,
            expected_output2_commitment,
        ]
    }

    pub fn verify_proof(
        prepared_verifying_key: &PreparedVerifyingKey<AuraCurve>,
        public_inputs_as_fr: &[CurveFr],
        proof_data: &ZkProofData,
    ) -> Result<bool, CoreError> {
        let proof = Proof::<AuraCurve>::deserialize_compressed(&mut &proof_data.proof_bytes[..])
            .map_err(|e| CoreError::Deserialization(e.to_string()))?;
        Groth16::<AuraCurve>::verify_with_processed_vk(
            prepared_verifying_key,
            public_inputs_as_fr,
            &proof,
        )
        .map_err(|e| CoreError::ProofVerification(e.to_string()))
    }
}
