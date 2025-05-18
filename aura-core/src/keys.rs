use crate::error::CoreError;
use crate::{AURA_ADDR_HRP, AuraAddress, CurveFr, CurveG1};
use ark_ec::{AffineRepr, CurveGroup}; // Added CurveGroup for G1::mul
use ark_ff::{BigInteger as ArkBigInteger, PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bip39::{Mnemonic, Seed as ActualBip39Seed}; // Language is part of Mnemonic methods
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize}; // For Signature struct
use zeroize::Zeroize;

// --- Seed (raw bytes derived from Mnemonic) ---
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Seed(ActualBip39Seed);

impl Seed {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

// --- Seed Phrase ---
#[derive(Clone)]
pub struct SeedPhrase(Mnemonic);

impl SeedPhrase {
    pub fn new_random() -> Result<Self, CoreError> {
        let mnemonic = Mnemonic::generate(12).map_err(CoreError::from)?; // Default is English
        Ok(SeedPhrase(mnemonic))
    }

    pub fn from_str(phrase: &str) -> Result<Self, CoreError> {
        // Mnemonic::parse_normalized is generally safer for user input
        let mnemonic = Mnemonic::parse_normalized(phrase).map_err(CoreError::from)?;
        Ok(SeedPhrase(mnemonic))
    }

    pub fn as_str(&self) -> String {
        self.0.to_phrase() // Corrected method name
    }

    pub fn to_seed(&self) -> Seed {
        Seed(ActualBip39Seed::new(&self.0, ""))
    }
}

#[derive(Clone, Zeroize, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq, Debug)]
#[zeroize(drop)]
pub struct PrivateKey(pub CurveFr);

impl PrivateKey {
    pub fn new_random() -> Self {
        let mut rng = OsRng;
        PrivateKey(CurveFr::rand(&mut rng))
    }

    pub fn from_seed(seed: &Seed) -> Result<Self, CoreError> {
        let seed_bytes = seed.as_bytes();
        if seed_bytes.len() < 32 {
            return Err(CoreError::KeyDerivation(
                "BIP39 seed is too short (< 32 bytes)".to_string(),
            ));
        }
        let sk_scalar = CurveFr::from_be_bytes_mod_order(&seed_bytes[..32]);
        Ok(PrivateKey(sk_scalar))
    }

    pub fn from_seed_phrase_str(phrase: &str) -> Result<Self, CoreError> {
        let seed_phrase_obj = SeedPhrase::from_str(phrase)?;
        let bip39_seed = seed_phrase_obj.to_seed();
        Self::from_seed(&bip39_seed)
    }

    pub fn to_bytes_be(&self) -> Vec<u8> {
        self.0.into_bigint().to_bytes_be()
    }

    pub fn from_bytes_be(bytes: &[u8]) -> Result<Self, CoreError> {
        Ok(PrivateKey(CurveFr::from_be_bytes_mod_order(bytes)))
    }
}

#[derive(Clone, Copy, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq, Debug)]
pub struct PublicKey(pub CurveG1);

impl PublicKey {
    pub fn from_private(sk: &PrivateKey) -> Self {
        // For ark-ec 0.5.0, prime_subgroup_generator() is typically on the Affine form.
        let generator_affine = <CurveG1 as CurveGroup>::Affine::prime_subgroup_generator();
        let generator_projective: CurveG1 = generator_affine.into();
        PublicKey(generator_projective * sk.0) // Scalar multiplication
    }

    pub fn to_address(&self) -> Result<AuraAddress, CoreError> {
        let mut pk_bytes = Vec::new();
        self.0
            .serialize_compressed(&mut pk_bytes)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        AuraAddress::from_pubkey_bytes(&pk_bytes, AURA_ADDR_HRP)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub placeholder_data: Vec<u8>,
}

pub fn generate_keypair_from_seed_phrase_str(
    phrase: &str,
) -> Result<(PrivateKey, PublicKey, AuraAddress), CoreError> {
    let seed_phrase_obj = SeedPhrase::from_str(phrase)?;
    let bip39_seed = seed_phrase_obj.to_seed();
    let sk = PrivateKey::from_seed(&bip39_seed)?;
    let pk = PublicKey::from_private(&sk);
    let addr = pk.to_address()?;
    Ok((sk, pk, addr))
}

pub fn generate_new_keypair_and_seed()
-> Result<(SeedPhrase, PrivateKey, PublicKey, AuraAddress), CoreError> {
    let seed_phrase_obj = SeedPhrase::new_random()?;
    let bip39_seed = seed_phrase_obj.to_seed();
    let sk = PrivateKey::from_seed(&bip39_seed)?;
    let pk = PublicKey::from_private(&sk);
    let addr = pk.to_address()?;
    Ok((seed_phrase_obj, sk, pk, addr))
}
