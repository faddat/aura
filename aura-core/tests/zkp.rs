use ark_crypto_primitives::sponge::{
    CryptographicSponge, FieldBasedCryptographicSponge, poseidon::PoseidonSponge,
};
use ark_ff::UniformRand;
use ark_std::test_rng;
use aura_core::{CurveFr, TransferCircuit, ZkpHandler, ZkpParameters, poseidon_config};

fn poseidon_hash_two(a: CurveFr, b: CurveFr) -> CurveFr {
    let cfg = poseidon_config();
    let mut s = PoseidonSponge::new(&cfg);
    s.absorb(&a);
    s.absorb(&b);
    s.squeeze_native_field_elements(1)[0]
}

fn poseidon_hash_three(a: CurveFr, b: CurveFr, c: CurveFr) -> CurveFr {
    let cfg = poseidon_config();
    let mut s = PoseidonSponge::new(&cfg);
    s.absorb(&a);
    s.absorb(&b);
    s.absorb(&c);
    s.squeeze_native_field_elements(1)[0]
}

#[test]
fn proof_roundtrip() {
    let mut rng = test_rng();
    let params = ZkpParameters::generate_dummy_for_circuit().unwrap();

    let input_value = 10u64;
    let input_owner = CurveFr::rand(&mut rng);
    let input_rand = CurveFr::rand(&mut rng);
    let sk = CurveFr::rand(&mut rng);

    let out1_value = 4u64;
    let out1_owner = CurveFr::rand(&mut rng);
    let out1_rand = CurveFr::rand(&mut rng);

    let out2_value = 5u64;
    let out2_owner = CurveFr::rand(&mut rng);
    let out2_rand = CurveFr::rand(&mut rng);

    let fee = 1u64;
    let anchor = CurveFr::rand(&mut rng);

    let expected_nullifier = poseidon_hash_two(input_rand, sk);
    let expected_out1_commit =
        poseidon_hash_three(CurveFr::from(out1_value), out1_owner, out1_rand);
    let expected_out2_commit =
        poseidon_hash_three(CurveFr::from(out2_value), out2_owner, out2_rand);

    let circuit = TransferCircuit {
        input_note_value: Some(input_value),
        input_note_owner_pk_hash: Some(input_owner),
        input_note_randomness: Some(input_rand),
        input_spending_key_scalar: Some(sk),
        output1_note_value: Some(out1_value),
        output1_note_owner_pk_hash: Some(out1_owner),
        output1_note_randomness: Some(out1_rand),
        output2_note_value: Some(out2_value),
        output2_note_owner_pk_hash: Some(out2_owner),
        output2_note_randomness: Some(out2_rand),
        anchor: Some(anchor),
        fee: Some(fee),
        expected_nullifier: Some(expected_nullifier),
        expected_output1_commitment: Some(expected_out1_commit),
        expected_output2_commitment: Some(expected_out2_commit),
    };

    let proof = ZkpHandler::generate_proof(&params.proving_key, circuit).unwrap();

    let public_inputs = ZkpHandler::prepare_public_inputs_for_verification(
        anchor,
        fee,
        expected_nullifier,
        expected_out1_commit,
        expected_out2_commit,
    );

    assert!(
        ZkpHandler::verify_proof(&params.prepared_verifying_key, &public_inputs, &proof).unwrap()
    );
}

#[test]
fn proof_verification_fails() {
    let mut rng = test_rng();
    let params = ZkpParameters::generate_dummy_for_circuit().unwrap();

    let input_value = 3u64;
    let input_owner = CurveFr::rand(&mut rng);
    let input_rand = CurveFr::rand(&mut rng);
    let sk = CurveFr::rand(&mut rng);
    let out1_value = 1u64;
    let out1_owner = CurveFr::rand(&mut rng);
    let out1_rand = CurveFr::rand(&mut rng);
    let out2_value = 1u64;
    let out2_owner = CurveFr::rand(&mut rng);
    let out2_rand = CurveFr::rand(&mut rng);
    let fee = 1u64;
    let anchor = CurveFr::rand(&mut rng);
    let expected_nullifier = poseidon_hash_two(input_rand, sk);
    let expected_out1_commit =
        poseidon_hash_three(CurveFr::from(out1_value), out1_owner, out1_rand);
    let expected_out2_commit =
        poseidon_hash_three(CurveFr::from(out2_value), out2_owner, out2_rand);

    let circuit = TransferCircuit {
        input_note_value: Some(input_value),
        input_note_owner_pk_hash: Some(input_owner),
        input_note_randomness: Some(input_rand),
        input_spending_key_scalar: Some(sk),
        output1_note_value: Some(out1_value),
        output1_note_owner_pk_hash: Some(out1_owner),
        output1_note_randomness: Some(out1_rand),
        output2_note_value: Some(out2_value),
        output2_note_owner_pk_hash: Some(out2_owner),
        output2_note_randomness: Some(out2_rand),
        anchor: Some(anchor),
        fee: Some(fee),
        expected_nullifier: Some(expected_nullifier),
        expected_output1_commitment: Some(expected_out1_commit),
        expected_output2_commitment: Some(expected_out2_commit),
    };

    let proof = ZkpHandler::generate_proof(&params.proving_key, circuit).unwrap();

    let mut public_inputs = ZkpHandler::prepare_public_inputs_for_verification(
        anchor,
        fee,
        expected_nullifier,
        expected_out1_commit,
        expected_out2_commit,
    );

    // tamper with one input
    public_inputs[2] += CurveFr::from(1u64);
    assert!(
        !ZkpHandler::verify_proof(&params.prepared_verifying_key, &public_inputs, &proof).unwrap()
    );
}
