use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Deserialization error: {0}")]
    Deserialization(String),
    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    #[error("Invalid address: {0}")]
    InvalidAddress(String),
    #[error("Invalid seed phrase: {0}")]
    InvalidSeedPhrase(String),
    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),
    #[error("Cryptography error: {0}")]
    CryptoError(String),
    #[error("ZKP proof generation failed: {0}")]
    ProofGeneration(String),
    #[error("ZKP proof verification failed: {0}")]
    ProofVerification(String),
    #[error("ZKP setup error: {0}")]
    ZkpSetup(String),
    #[error("Invalid note: {0}")]
    InvalidNote(String),
    #[error("Invalid nullifier: {0}")]
    InvalidNullifier(String),
    #[error("Insufficient funds")]
    InsufficientFunds,
    #[error("Genesis parsing error: {0}")]
    GenesisParsing(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Hex decoding error: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("Bech32 error: {0}")]
    Bech32(String),
    #[error("BIP39 error: {0}")]
    Bip39(#[from] bip39::Error), // bip39 v2.x Error implements std::error::Error
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Other error: {0}")]
    Other(String),
}

// Specific bech32 error conversions for v0.11
impl From<bech32::Error> for CoreError {
    // General bech32::Error
    fn from(e: bech32::Error) -> Self {
        CoreError::Bech32(format!("Bech32 generic error: {}", e))
    }
}
// The previous From impls for sub-module errors might still be useful if you match on them,
// but bech32::Error itself should cover decode/encode/hrp errors.
impl From<bech32::primitives::hrp::Error> for CoreError {
    fn from(e: bech32::primitives::hrp::Error) -> Self {
        CoreError::Bech32(format!("Bech32 HRP error: {}", e))
    }
}
impl From<bech32::primitives::gf32::Error> for CoreError {
    fn from(e: bech32::primitives::gf32::Error) -> Self {
        CoreError::Bech32(format!("Bech32 GF32/Fe32 error: {}", e))
    }
}
impl From<bech32::primitives::convert_bits::Error> for CoreError {
    fn from(e: bech32::primitives::convert_bits::Error) -> Self {
        CoreError::Bech32(format!("Bech32 bit conversion error: {:?}", e))
    }
}
