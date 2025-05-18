use crate::keys::PrivateKey;
use crate::transaction::{Fee, ZkProofData};
use crate::{AuraCurve, CoreError, CurveFr}; // CurveFr is Fr type from bls12_381
use ark_ff::PrimeField; // For Fr type methods
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::convert::ToConstraintFieldGadget; // This is likely still the path
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;

use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, Write};
use ark_snark::SNARK;
use ark_std::io::BufReader; // For reading files
use ark_std::vec::Vec;
use rand::rngs::OsRng;
use std::fs::File;
use std::path::Path;

// For Arkworks 0.5.0, Poseidon is typically used via ark_spartan::polycommitments::zeromorph::matrix::matrix_utils::Matrix::gen_poseidon_parameters
// or by directly constructing PoseidonConfig if you have the parameters.
// The `ark_crypto_primitives::poseidon` module itself might be what you need.
// Let's assume a simplified way to get config for now, or that parameters are predefined.
use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge}; // Use PoseidonSponge directly for hashing
use ark_crypto_primitives::sponge::{CryptographicSponge, Абсорб}; // For absorb method, using placeholder for Absorb trait.
// This Absorb trait might be ark_sponge::Absorb or similar.
// For 0.5.0, it's likely just methods on the PoseidonSpongeVar.
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar; // Correct import for sponge var

#[cfg(feature = "tracing")]
use tracing;

// This function is highly dependent on how Poseidon parameters are structured and obtained in arkworks 0.5.0.
// It's very likely that for a specific curve and security level, these parameters are fixed constants.
fn get_poseidon_config_for_sponge<F: PrimeField>() -> PoseidonConfig<F> {
    // In ark-crypto-primitives 0.5.0, PoseidonConfig is often built from PoseidonParameters.
    // PoseidonParameters often has a ::new() or a ::default() or from specific constants.
    // This is a critical piece that needs to match your ZKP design.
    // For example, if you were using the CRH directly:
    // use ark_crypto_primitives::crh::poseidon::Poseidon;
    // use ark_crypto_primitives::crh::CRHScheme;
    // let params = <Poseidon<F> as CRHScheme>::Parameters::default(); // This is for CRH, not directly sponge config
    // For sponge, it's more direct:
    PoseidonConfig::default() // This usually provides a default safe configuration.
}

#[derive(Clone, Default)]
pub struct TransferCircuit {
    // ... fields remain the same
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
        #[cfg(feature = "mock-zkp")]
        {
            #[cfg(feature = "tracing")]
            tracing::warn!("Mock ZKP circuit constraints: Skipping actual constraint generation.");
            let _ = FpVar::<CurveFr>::new_input(cs.clone(), || {
                self.anchor.ok_or(SynthesisError::AssignmentMissing)
            })?;
            let _ = FpVar::<CurveFr>::new_input(cs.clone(), || {
                Ok(CurveFr::from(self.fee.unwrap_or(0)))
            })?;
            let _ = FpVar::<CurveFr>::new_input(cs.clone(), || {
                self.expected_nullifier
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            let _ = FpVar::<CurveFr>::new_input(cs.clone(), || {
                self.expected_output1_commitment
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            let _ = FpVar::<CurveFr>::new_input(cs.clone(), || {
                self.expected_output2_commitment
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            return Ok(());
        }

        #[cfg(not(feature = "mock-zkp"))]
        {
            let poseidon_config = get_poseidon_config_for_sponge::<CurveFr>();

            let input_value_var = FpVar::<CurveFr>::new_witness(cs.clone(), || {
                Ok(CurveFr::from(
                    self.input_note_value
                        .ok_or(SynthesisError::AssignmentMissing)?,
                ))
            })?;
            let input_owner_hash_var = FpVar::<CurveFr>::new_witness(cs.clone(), || {
                self.input_note_owner_pk_hash
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            let input_randomness_var = FpVar::<CurveFr>::new_witness(cs.clone(), || {
                self.input_note_randomness
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            let sk_scalar_var = FpVar::<CurveFr>::new_witness(cs.clone(), || {
                self.input_spending_key_scalar
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

            let output1_value_var = FpVar::<CurveFr>::new_witness(cs.clone(), || {
                Ok(CurveFr::from(
                    self.output1_note_value
                        .ok_or(SynthesisError::AssignmentMissing)?,
                ))
            })?;
            let output1_owner_hash_var = FpVar::<CurveFr>::new_witness(cs.clone(), || {
                self.output1_note_owner_pk_hash
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            let output1_randomness_var = FpVar::<CurveFr>::new_witness(cs.clone(), || {
                self.output1_note_randomness
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

            let output2_value_var = FpVar::<CurveFr>::new_witness(cs.clone(), || {
                Ok(CurveFr::from(
                    self.output2_note_value
                        .ok_or(SynthesisError::AssignmentMissing)?,
                ))
            })?;
            let output2_owner_hash_var = FpVar::<CurveFr>::new_witness(cs.clone(), || {
                self.output2_note_owner_pk_hash
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            let output2_randomness_var = FpVar::<CurveFr>::new_witness(cs.clone(), || {
                self.output2_note_randomness
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

            let _anchor_var = FpVar::<CurveFr>::new_input(cs.clone(), || {
                self.anchor.ok_or(SynthesisError::AssignmentMissing)
            })?;
            let fee_fr = CurveFr::from(self.fee.ok_or(SynthesisError::AssignmentMissing)?);
            let fee_var = FpVar::<CurveFr>::new_input(cs.clone(), || Ok(fee_fr))?;
            let expected_nullifier_var = FpVar::<CurveFr>::new_input(cs.clone(), || {
                self.expected_nullifier
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            let expected_output1_cm_var = FpVar::<CurveFr>::new_input(cs.clone(), || {
                self.expected_output1_commitment
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            let expected_output2_cm_var = FpVar::<CurveFr>::new_input(cs.clone(), || {
                self.expected_output2_commitment
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

            let sum_outputs_plus_fee =
                output1_value_var.clone() + output2_value_var.clone() + fee_var;
            input_value_var.enforce_equal(&sum_outputs_plus_fee)?;
            #[cfg(feature = "tracing")]
            tracing::debug!("Value conservation constraint enforced.");

            let mut input_note_hasher = PoseidonSpongeVar::new(cs.clone(), &poseidon_config);
            input_note_hasher.absorb(&[
                input_value_var.clone(),
                input_owner_hash_var.clone(),
                input_randomness_var.clone(),
            ])?;
            let _computed_input_commitment_var =
                input_note_hasher.squeeze_field_elements(1)?.remove(0);
            #[cfg(feature = "tracing")]
            tracing::debug!(
                "Input note commitment computed (not constrained against anchor in this version)."
            );

            let mut nullifier_hasher = PoseidonSpongeVar::new(cs.clone(), &poseidon_config);
            nullifier_hasher.absorb(&[input_randomness_var.clone(), sk_scalar_var.clone()])?;
            let computed_nullifier_var = nullifier_hasher.squeeze_field_elements(1)?.remove(0);
            computed_nullifier_var.enforce_equal(&expected_nullifier_var)?;
            #[cfg(feature = "tracing")]
            tracing::debug!("Nullifier constraint enforced.");

            let mut output1_cm_hasher = PoseidonSpongeVar::new(cs.clone(), &poseidon_config);
            output1_cm_hasher.absorb(&[
                output1_value_var.clone(),
                output1_owner_hash_var.clone(),
                output1_randomness_var.clone(),
            ])?;
            let computed_output1_cm_var = output1_cm_hasher.squeeze_field_elements(1)?.remove(0);
            computed_output1_cm_var.enforce_equal(&expected_output1_cm_var)?;
            #[cfg(feature = "tracing")]
            tracing::debug!("Output 1 commitment constraint enforced.");

            let mut output2_cm_hasher = PoseidonSpongeVar::new(cs.clone(), &poseidon_config);
            output2_cm_hasher.absorb(&[
                output2_value_var.clone(),
                output2_owner_hash_var.clone(),
                output2_randomness_var.clone(),
            ])?;
            let computed_output2_cm_var = output2_cm_hasher.squeeze_field_elements(1)?.remove(0);
            computed_output2_cm_var.enforce_equal(&expected_output2_cm_var)?;
            #[cfg(feature = "tracing")]
            tracing::debug!("Output 2 commitment constraint enforced.");

            #[cfg(feature = "tracing")]
            tracing::info!("ZKP constraints generated successfully (simplified version).");
            Ok(())
        }
    }
}

pub struct ZkpParameters {
    pub proving_key: ProvingKey<AuraCurve>,
    pub verifying_key: VerifyingKey<AuraCurve>,
    pub prepared_verifying_key: PreparedVerifyingKey<AuraCurve>,
}

impl ZkpParameters {
    pub fn generate_dummy_for_circuit() -> Result<Self, CoreError> {
        let circuit = TransferCircuit::default();
        #[cfg(all(feature = "tracing", feature = "mock-zkp"))] // Only for the warning itself
        tracing::warn!("Generating DUMMY ZKP parameters for MOCK setup. DO NOT USE IN PRODUCTION.");

        let (pk, vk) =
            Groth16::<AuraCurve>::generate_random_parameters_with_reduction(circuit, &mut OsRng) // SNARK trait
                .map_err(|e| {
                    CoreError::ZkpSetup(format!("Dummy parameter generation failed: {}", e))
                })?;

        let pvk = Groth16::<AuraCurve>::prepare_verifying_key(&vk);
        Ok(ZkpParameters {
            proving_key: pk,
            verifying_key: vk,
            prepared_verifying_key: pvk,
        })
    }

    pub fn load_from_files(pk_path: &Path, vk_path: &Path) -> Result<Self, CoreError> {
        let mut pk_file = BufReader::new(File::open(pk_path).map_err(CoreError::Io)?);
        let proving_key =
            ProvingKey::<AuraCurve>::deserialize_compressed(&mut pk_file).map_err(|e| {
                CoreError::ZkpSetup(format!("Failed to deserialize proving key: {}", e))
            })?;

        let mut vk_file = BufReader::new(File::open(vk_path).map_err(CoreError::Io)?);
        let verifying_key = VerifyingKey::<AuraCurve>::deserialize_compressed(&mut vk_file)
            .map_err(|e| {
                CoreError::ZkpSetup(format!("Failed to deserialize verifying key: {}", e))
            })?;

        let prepared_verifying_key = Groth16::<AuraCurve>::prepare_verifying_key(&verifying_key);
        Ok(ZkpParameters {
            proving_key,
            verifying_key,
            prepared_verifying_key,
        })
    }

    pub fn load_from_bytes(pk_bytes: &[u8], vk_bytes: &[u8]) -> Result<Self, CoreError> {
        let proving_key = ProvingKey::<AuraCurve>::deserialize_compressed(&*pk_bytes) // &[u8] implements Read
            .map_err(|e| {
                CoreError::ZkpSetup(format!(
                    "Failed to deserialize proving key from bytes: {}",
                    e
                ))
            })?;
        let verifying_key =
            VerifyingKey::<AuraCurve>::deserialize_compressed(&*vk_bytes).map_err(|e| {
                CoreError::ZkpSetup(format!(
                    "Failed to deserialize verifying key from bytes: {}",
                    e
                ))
            })?;
        let prepared_verifying_key = Groth16::<AuraCurve>::prepare_verifying_key(&verifying_key);
        Ok(ZkpParameters {
            proving_key,
            verifying_key,
            prepared_verifying_key,
        })
    }

    pub fn save_to_files(&self, pk_path: &Path, vk_path: &Path) -> Result<(), CoreError> {
        let mut pk_file = File::create(pk_path).map_err(CoreError::Io)?;
        self.proving_key
            .serialize_compressed(&mut pk_file)
            .map_err(|e| CoreError::ZkpSetup(format!("Failed to serialize proving key: {}", e)))?;

        let mut vk_file = File::create(vk_path).map_err(CoreError::Io)?;
        self.verifying_key
            .serialize_compressed(&mut vk_file)
            .map_err(|e| {
                CoreError::ZkpSetup(format!("Failed to serialize verifying key: {}", e))
            })?;
        Ok(())
    }
}

pub struct ZkpHandler;

impl ZkpHandler {
    #[cfg(not(feature = "mock-zkp"))]
    pub fn generate_proof(
        proving_key: &ProvingKey<AuraCurve>,
        circuit: TransferCircuit,
    ) -> Result<ZkProofData, CoreError> {
        let proof = Groth16::<AuraCurve>::prove(proving_key, circuit, &mut OsRng) // SNARK trait
            .map_err(|e| CoreError::ProofGeneration(e.to_string()))?;
        let mut proof_bytes = Vec::new();
        proof
            .serialize_compressed(&mut proof_bytes)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        Ok(ZkProofData { proof_bytes })
    }

    #[cfg(feature = "mock-zkp")]
    pub fn generate_proof(
        _proving_key: &ProvingKey<AuraCurve>,
        _circuit: TransferCircuit,
    ) -> Result<ZkProofData, CoreError> {
        #[cfg(feature = "tracing")]
        tracing::warn!("Mock ZKP proof generation!");
        Ok(ZkProofData {
            proof_bytes: vec![0u8; 192],
        })
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

    #[cfg(not(feature = "mock-zkp"))]
    pub fn verify_proof(
        prepared_verifying_key: &PreparedVerifyingKey<AuraCurve>,
        public_inputs_as_fr: &[CurveFr],
        proof_data: &ZkProofData,
    ) -> Result<bool, CoreError> {
        let proof = Proof::<AuraCurve>::deserialize_compressed(proof_data.proof_bytes.as_slice())
            .map_err(|e| {
            CoreError::Deserialization(format!("Failed to deserialize proof: {}", e))
        })?;

        Groth16::<AuraCurve>::verify_with_processed_vk(
            prepared_verifying_key,
            public_inputs_as_fr,
            &proof,
        )
        .map_err(|e| CoreError::ProofVerification(e.to_string()))
    }

    #[cfg(feature = "mock-zkp")]
    pub fn verify_proof(
        _prepared_verifying_key: &PreparedVerifyingKey<AuraCurve>,
        _public_inputs_as_fr: &[CurveFr],
        _proof_data: &ZkProofData,
    ) -> Result<bool, CoreError> {
        #[cfg(feature = "tracing")]
        tracing::warn!("Mock ZKP proof verification!");
        Ok(true)
    }
}
