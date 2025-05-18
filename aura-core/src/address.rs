use crate::AURA_ADDR_HRP;
use crate::error::CoreError;
use bech32::{self, FromBase32, ToBase32, Variant};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

const ADDRESS_PAYLOAD_LENGTH: usize = 33; // Example: 32 bytes for compressed pubkey + 1 type byte

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AuraAddress {
    hrp: String,
    payload: Vec<u8>, // Typically the raw public key bytes (e.g., compressed secp256k1 or BLS12-381)
}

impl AuraAddress {
    pub fn new(hrp: &str, payload: Vec<u8>) -> Result<Self, CoreError> {
        // Basic validation, e.g. payload length
        if payload.len() != ADDRESS_PAYLOAD_LENGTH { // Adjust as needed
            // return Err(CoreError::InvalidAddress(format!("Invalid payload length: {}", payload.len())));
            // For now, let's be flexible for early dev. Production should be strict.
        }
        Ok(AuraAddress {
            hrp: hrp.to_string(),
            payload,
        })
    }

    pub fn from_pubkey_bytes(pubkey_bytes: &[u8], hrp: &str) -> Result<Self, CoreError> {
        // Here, pubkey_bytes would be the compressed form of an elliptic curve point.
        // We might add a version/type byte if needed in the future.
        // For now, let's assume pubkey_bytes is directly the payload.
        // This needs to match how PublicKey::to_address serializes it.
        // If PublicKey::to_address creates a 33-byte array (e.g. from ark-serialize compressed), then this is fine.
        Self::new(hrp, pubkey_bytes.to_vec())
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn hrp(&self) -> &str {
        &self.hrp
    }
}

impl fmt::Display for AuraAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded = bech32::encode(&self.hrp, self.payload.to_base32(), Variant::Bech32m)
            .map_err(|_| fmt::Error)?; // Convert bech32 error to fmt::Error
        write!(f, "{}", encoded)
    }
}

impl fmt::Debug for AuraAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AuraAddress({})", self.to_string())
    }
}

impl FromStr for AuraAddress {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (hrp, data, variant) = bech32::decode(s)?;
        if variant != Variant::Bech32m {
            // Or Bech32 if that's chosen
            return Err(CoreError::InvalidAddress(
                "Invalid bech32 variant".to_string(),
            ));
        }
        if hrp != AURA_ADDR_HRP {
            // return Err(CoreError::InvalidAddress(format!("Invalid HRP: expected {}, got {}", AURA_ADDR_HRP, hrp)));
            // Be flexible for now if other HRPs are part of genesis for non-native assets.
        }
        let payload = Vec::<u8>::from_base32(&data)?;
        Ok(AuraAddress { hrp, payload })
    }
}

// Implement Serialize and Deserialize to use the String representation
impl Serialize for AuraAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for AuraAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        AuraAddress::from_str(&s).map_err(serde::de::Error::custom)
    }
}
