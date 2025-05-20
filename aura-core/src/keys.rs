use crate::error::CoreError;
use crate::{AURA_ADDR_HRP, AuraAddress, CurveFr, CurveG1};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger as ArkBigInteger, PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{RngCore, SeedableRng, rngs::StdRng};
use bip39::{Language, Mnemonic};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Seed(pub [u8; 64]);

impl Seed {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone)]
pub struct SeedPhrase(Mnemonic);

impl SeedPhrase {
    pub fn new_random() -> Result<Self, CoreError> {
        let mut entropy = [0u8; 16];
        getrandom::fill(&mut entropy).map_err(|e| CoreError::KeyDerivation(e.to_string()))?;

        let mnemonic = Mnemonic::from_entropy(&entropy)
            .map_err(|e| CoreError::KeyDerivation(e.to_string()))?;
        Ok(SeedPhrase(mnemonic))
    }

    pub fn parse_phrase(phrase: &str) -> Result<Self, CoreError> {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase)
            .map_err(|e| CoreError::KeyDerivation(e.to_string()))?;
        Ok(SeedPhrase(mnemonic))
    }

    pub fn as_str(&self) -> String {
        self.0.to_string()
    }

    pub fn to_seed(&self) -> Seed {
        let seed_bytes = self.0.to_seed("");
        let mut array = [0u8; 64];
        array.copy_from_slice(&seed_bytes[0..64]);
        Seed(array)
    }
}

#[derive(Clone, Zeroize, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq, Debug)]
#[zeroize(drop)]
pub struct PrivateKey(pub CurveFr);

impl PrivateKey {
    pub fn new_random() -> Self {
        let mut seed = <StdRng as SeedableRng>::Seed::default();
        getrandom::fill(&mut seed).unwrap();
        let mut rng = StdRng::from_seed(seed);
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
        let seed_phrase_obj = SeedPhrase::parse_phrase(phrase)?;
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
        let generator_affine = <CurveG1 as CurveGroup>::Affine::generator();
        let generator_projective: CurveG1 = generator_affine.into();
        PublicKey(generator_projective * sk.0)
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
    let seed_phrase_obj = SeedPhrase::parse_phrase(phrase)?;
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
