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
    #[error("Bech32 encoding/decoding error: {0}")]
    Bech32(#[from] bech32::Error),
    #[error("BIP39 error: {0}")]
    Bip39(String), // Can't directly use bip39::Error as it's not exported nicely for thiserror
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Other error: {0}")]
    Other(String),
}

// Helper for Bip39 errors
impl From<bip39::ErrorKind> for CoreError {
    fn from(e: bip39::ErrorKind) -> Self {
        CoreError::Bip39(format!("{:?}", e))
    }
}
