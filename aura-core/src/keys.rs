use crate::error::CoreError;
use crate::{AURA_ADDR_HRP, AuraAddress, CurveFr, CurveG1};
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bip39::{Language, Mnemonic, Seed as Bip39Seed}; // Renamed to avoid conflict
use rand::rngs::OsRng;
// use sha2::{Digest, Sha256}; // No longer needed for simplified seed derivation if using bip39::Seed
use zeroize::Zeroize;

// --- Seed (raw bytes derived from Mnemonic) ---
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Seed(Bip39Seed); // Wrap bip39::Seed

impl Seed {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

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

    /// Derive a master seed from the mnemonic using BIP39 standard.
    /// The empty passphrase "" is standard for non-password-protected seeds.
    pub fn to_seed(&self) -> Seed {
        Seed(Bip39Seed::new(&self.0, ""))
    }
}

// --- Private Key (Spending Key) ---
// This will be a scalar in the field CurveFr
#[derive(Clone, Zeroize, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq, Debug)]
#[zeroize(drop)]
pub struct PrivateKey(pub CurveFr);

impl PrivateKey {
    pub fn new_random() -> Self {
        PrivateKey(CurveFr::rand(&mut OsRng))
    }

    /// Derives a private key from the first 32 bytes of the BIP39 seed.
    /// For "crazy simple," this is a basic way to get a deterministic key.
    /// More advanced systems use HD Wallet derivation paths (e.g., SLIP-0010)
    /// from the BIP39 seed to derive multiple keys.
    pub fn from_seed(seed: &Seed) -> Result<Self, CoreError> {
        let seed_bytes = seed.as_bytes();
        if seed_bytes.len() < 32 {
            return Err(CoreError::KeyDerivation(
                "BIP39 seed is too short (< 32 bytes)".to_string(),
            ));
        }
        // Use the first 32 bytes of the 64-byte BIP39 seed for the private key scalar.
        // This is a common simple approach.
        let sk_scalar = CurveFr::from_be_bytes_mod_order(&seed_bytes[..32]);
        Ok(PrivateKey(sk_scalar))
    }

    // Helper to directly get PK from a seed phrase string
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
        // Ensure pk_bytes is exactly ADDRESS_PAYLOAD_LENGTH if that's a strict requirement
        // For BLS12-381 G1 compressed, it's 48 bytes. G2 is 96 bytes.
        // ADDRESS_PAYLOAD_LENGTH in address.rs is 33, which is more like secp256k1.
        // This needs to be consistent. Let's assume ADDRESS_PAYLOAD_LENGTH in address.rs
        // will be updated to match the actual curve's compressed pubkey size.
        // If AuraAddress expects a different format (e.g. hash), that needs to be done here.
        AuraAddress::from_pubkey_bytes(&pk_bytes, AURA_ADDR_HRP)
    }
}

// --- Signature (Placeholder) ---
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub placeholder_data: Vec<u8>,
}

// --- Key Management Helper ---
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
