use crate::error::CoreError;
use crate::{AURA_ADDR_HRP, AuraAddress, CurveFr, CurveG1}; // Assuming AuraAddress is defined elsewhere
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bip39::{Language, Mnemonic};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

// --- Seed Phrase ---
#[derive(Clone, Zeroize)]
#[zeroize(drop)] // Ensure the mnemonic is cleared on drop
pub struct SeedPhrase(Mnemonic);

impl SeedPhrase {
    pub fn new_random() -> Result<Self, CoreError> {
        let mnemonic = Mnemonic::generate_in(Language::English, 12) // 12 or 24 words
            .map_err(|e| CoreError::Bip39(format!("{:?}", e)))?;
        Ok(SeedPhrase(mnemonic))
    }

    pub fn from_str(phrase: &str) -> Result<Self, CoreError> {
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English)
            .map_err(|e| CoreError::Bip39(format!("{:?}", e)))?;
        Ok(SeedPhrase(mnemonic))
    }

    pub fn as_str(&self) -> &str {
        self.0.phrase()
    }

    /// Derive a master seed (e.g., 512 bits) from the mnemonic.
    /// For simplicity, we'll just hash the phrase. Proper BIP39 uses PBKDF2.
    /// For "crazy simple" this is okay, but for production, use BIP39 seed derivation.
    fn to_master_seed(&self) -> [u8; 64] {
        // 512 bits
        // WARNING: This is a simplified seed derivation for "crazy simple".
        // Production systems should use BIP39's specified seed generation (Mnemonic::to_seed).
        let mut hasher = Sha256::new();
        hasher.update(self.0.phrase().as_bytes());
        let result_first_32 = hasher.finalize_reset();
        hasher.update(result_first_32); // Simple stretch
        let result_second_32 = hasher.finalize();

        let mut seed = [0u8; 64];
        seed[..32].copy_from_slice(&result_first_32);
        seed[32..].copy_from_slice(&result_second_32);
        seed
    }
}

// --- Private Key (Spending Key) ---
// This will be a scalar in the field CurveFr
#[derive(Clone, Zeroize, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq, Debug)]
#[zeroize(drop)]
pub struct PrivateKey(pub CurveFr); // Make pub(crate) if direct access isn't needed outside

impl PrivateKey {
    pub fn new_random() -> Self {
        PrivateKey(CurveFr::rand(&mut OsRng))
    }

    pub fn from_seed(seed_phrase: &SeedPhrase) -> Result<Self, CoreError> {
        let master_seed = seed_phrase.to_master_seed();
        // Derive private key from master seed.
        // For "crazy simple", we can hash the seed to get a field element.
        // More robust systems use HKDF or SLIP-0010 for derivation paths.
        let sk_scalar = CurveFr::from_be_bytes_mod_order(&master_seed[..32]); // Use first 32 bytes
        Ok(PrivateKey(sk_scalar))
    }

    pub fn to_bytes_be(&self) -> Vec<u8> {
        self.0.into_bigint().to_bytes_be()
    }

    pub fn from_bytes_be(bytes: &[u8]) -> Result<Self, CoreError> {
        Ok(PrivateKey(CurveFr::from_be_bytes_mod_order(bytes)))
    }
}

// --- Public Key ---
// This will be a point on the curve CurveG1
#[derive(Clone, Copy, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq, Debug)]
pub struct PublicKey(pub CurveG1);

impl PublicKey {
    pub fn from_private(sk: &PrivateKey) -> Self {
        let generator = CurveG1::prime_subgroup_generator();
        PublicKey(generator * sk.0)
    }

    /// Derive the AuraAddress from this public key
    pub fn to_address(&self) -> Result<AuraAddress, CoreError> {
        let mut pk_bytes = Vec::new();
        self.0
            .serialize_compressed(&mut pk_bytes)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        AuraAddress::from_pubkey_bytes(&pk_bytes, AURA_ADDR_HRP)
    }
}

// --- Signature (Placeholder - ZKPs replace traditional signatures for transfers) ---
// We might still need signatures for other things (e.g., validator messages in Malachite if not ZKP based).
// For now, let's assume ZKPs cover the main financial transaction authorization.
// If general signatures are needed, you'd implement something like Schnorr or ECDSA over CurveG1/CurveFr.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    // r: CurveFr,
    // s: CurveFr,
    pub placeholder_data: Vec<u8>, // Remove later
}

// Example functions that would be here if general sigs were used:
// impl PrivateKey {
// pub fn sign(&self, message_hash: &[u8]) -> Result<Signature, CoreError> { unimplemented!() }
// }
// impl PublicKey {
// pub fn verify(&self, message_hash: &[u8], signature: &Signature) -> Result<bool, CoreError> { unimplemented!() }
// }

// --- Key Management Helper ---
pub fn generate_keypair_from_seed_phrase_str(
    phrase: &str,
) -> Result<(PrivateKey, PublicKey, AuraAddress), CoreError> {
    let seed = SeedPhrase::from_str(phrase)?;
    let sk = PrivateKey::from_seed(&seed)?;
    let pk = PublicKey::from_private(&sk);
    let addr = pk.to_address()?;
    Ok((sk, pk, addr))
}

pub fn generate_new_keypair_and_seed()
-> Result<(SeedPhrase, PrivateKey, PublicKey, AuraAddress), CoreError> {
    let seed = SeedPhrase::new_random()?;
    let sk = PrivateKey::from_seed(&seed)?;
    let pk = PublicKey::from_private(&sk);
    let addr = pk.to_address()?;
    Ok((seed, sk, pk, addr))
}
