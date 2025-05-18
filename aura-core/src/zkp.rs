use crate::keys::PrivateKey;
// Note, NoteCommitment, Nullifier structs are not directly part of circuit's field arithmetic,
// but their Fr representations are.
use crate::transaction::{Fee, ZkProofData};
use crate::{AuraCurve, CoreError, CurveFr};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::convert::ToConstraintFieldGadget;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar; // Corrected import path

use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, Write};
use ark_snark::SNARK;
use ark_std::vec::Vec;
use rand::rngs::OsRng;
use std::fs::File;
use std::path::Path;

use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::{
    PoseidonConfig, PoseidonParameters, PoseidonSpongeVar,
};
// Removed: BasicOptimizedAddRemoveAlchemyInformation, PoseidonCRHVar, CRHSchemeGadget as using sponge directly

#[cfg(feature = "tracing")]
use tracing;

fn get_poseidon_config<F: PrimeField>() -> PoseidonConfig<F> {
    // For arkworks 0.5.0, PoseidonParameters::default() may not exist or be what we need.
    // We need to construct it, or use a predefined set.
    // A common way is to get parameters for a specific CRH width.
    // For sponge, it's more about the internal state.
    // Let's use parameters suitable for a sponge. These would be domain parameters for the chain.
    // For Poseidon, refer to `ark-crypto-primitives/src/sponge/poseidon.rs`
    // and how it generates `DEFAULT_POSEIDON_CONFIG_PARAMS_OPTIMIZED_FOR_CONSTRAINTS`.
    // This is complex to reproduce here. A real app would have these as constants.

    // Placeholder: Create a basic config. This is NOT secure for production.
    // The actual matrix and round constants need to be properly generated or taken from a secure spec.
    let full_rounds = 8;
    let partial_rounds = 31; // Example for BLS12-381 Fr, adjust based on security bits
    let alpha = 5; // Common choice for BLS12-381
    let rate = 2;
    let capacity = 1;
    // The MDS matrix and round constants are the hard part to get right here without existing constants.
    // For now, let's assume some dummy/example ones, or rely on a default if one exists for sponges.
    // `ark_crypto_primitives::sponge::poseidon::get_poseidon_parameters_for_test_only` might be an option for tests.
    // For now, if `PoseidonParameters::default()` is not suitable for a sponge, this is a critical gap.
    // A simplified approach for now:
    let params = ark_crypto_primitives::poseidon::get_default_parameters::<F>(
        rate + capacity,
        alpha as u64,
        full_rounds as u64,
        partial_rounds as u64,
        0,
    )
    .unwrap();

    PoseidonConfig {
        full_rounds: params.full_rounds as usize,
        partial_rounds: params.partial_rounds as usize,
        alpha: params.alpha,
        mds_matrix: params.mds_matrix,
        round_constants: params.round_constants,
        rate: params.rate as usize,
        capacity: params.capacity as usize,
    }
}

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
            let poseidon_config = get_poseidon_config::<CurveFr>();

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
        #[cfg(all(feature = "tracing", feature = "mock-zkp"))]
        tracing::warn!("Generating DUMMY ZKP parameters for MOCK setup. DO NOT USE IN PRODUCTION.");

        // In Arkworks 0.5.0, generate_random_parameters_with_reduction returns Result<(PK, VK), _>
        let (pk, vk) =
            Groth16::<AuraCurve>::generate_random_parameters_with_reduction(circuit, &mut OsRng)
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
        let pk_file = File::open(pk_path).map_err(|e| {
            CoreError::ZkpSetup(format!(
                "Failed to open proving key file {:?}: {}",
                pk_path, e
            ))
        })?;
        let proving_key = ProvingKey::<AuraCurve>::deserialize_compressed(&mut &*pk_file) // Pass as Read trait object
            .map_err(|e| {
                CoreError::ZkpSetup(format!("Failed to deserialize proving key: {}", e))
            })?;
        let vk_file = File::open(vk_path).map_err(|e| {
            CoreError::ZkpSetup(format!(
                "Failed to open verifying key file {:?}: {}",
                vk_path, e
            ))
        })?;
        let verifying_key = VerifyingKey::<AuraCurve>::deserialize_compressed(&mut &*vk_file) // Pass as Read trait object
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
        let proving_key = ProvingKey::<AuraCurve>::deserialize_compressed(&*pk_bytes) // Pass as Read trait object
            .map_err(|e| {
                CoreError::ZkpSetup(format!(
                    "Failed to deserialize proving key from bytes: {}",
                    e
                ))
            })?;
        let verifying_key = VerifyingKey::<AuraCurve>::deserialize_compressed(&*vk_bytes) // Pass as Read trait object
            .map_err(|e| {
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
        let mut pk_file = File::create(pk_path).map_err(|e| {
            CoreError::ZkpSetup(format!(
                "Failed to create proving key file {:?}: {}",
                pk_path, e
            ))
        })?;
        self.proving_key
            .serialize_compressed(&mut pk_file)
            .map_err(|e| CoreError::ZkpSetup(format!("Failed to serialize proving key: {}", e)))?;
        let mut vk_file = File::create(vk_path).map_err(|e| {
            CoreError::ZkpSetup(format!(
                "Failed to create verifying key file {:?}: {}",
                vk_path, e
            ))
        })?;
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
        let proof = Groth16::<AuraCurve>::prove(proving_key, circuit, &mut OsRng)
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
        }) // Groth16 on BLS12-381: A(G1), B(G2), C(G1) -> 48 + 96 + 48 = 192 bytes compressed
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
        // verify_with_processed_vk is the correct function for Groth16
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
