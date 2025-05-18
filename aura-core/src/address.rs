use crate::AURA_ADDR_HRP;
use crate::error::CoreError;
use bech32::{self, FromBase32, ToBase32, Variant};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

// For BLS12-381, a compressed G1 point is 48 bytes.
// If you add a version/type byte, it could be 49.
// Let's assume for now the payload is just the compressed G1 point.
pub const AURA_ADDRESS_PAYLOAD_LENGTH: usize = 48;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AuraAddress {
    hrp: String,
    payload: Vec<u8>, // Raw public key bytes (compressed BLS12-381 G1 point)
}

impl AuraAddress {
    pub fn new(hrp: &str, payload: Vec<u8>) -> Result<Self, CoreError> {
        if payload.len() != AURA_ADDRESS_PAYLOAD_LENGTH {
            return Err(CoreError::InvalidAddress(format!(
                "Invalid payload length: expected {}, got {}",
                AURA_ADDRESS_PAYLOAD_LENGTH,
                payload.len()
            )));
        }
        Ok(AuraAddress {
            hrp: hrp.to_string(),
            payload,
        })
    }

    /// Creates an AuraAddress from compressed public key bytes.
    pub fn from_pubkey_bytes(pubkey_bytes: &[u8], hrp: &str) -> Result<Self, CoreError> {
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
        // Bech32m is generally preferred for new protocols over original Bech32
        let encoded = bech32::encode(&self.hrp, self.payload.to_base32(), Variant::Bech32m)
            .map_err(|_| fmt::Error)?;
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
            // Enforce Bech32m
            return Err(CoreError::InvalidAddress(
                "Invalid bech32 variant, expected Bech32m".to_string(),
            ));
        }
        // Allow flexibility in HRP for genesis if it contains non-native asset addresses,
        // but for native Aura addresses, it should match.
        // If strictly only Aura addresses, uncomment the check:
        // if hrp != AURA_ADDR_HRP {
        //     return Err(CoreError::InvalidAddress(format!("Invalid HRP: expected {}, got {}", AURA_ADDR_HRP, hrp)));
        // }
        let payload = Vec::<u8>::from_base32(&data)?;
        // Re-validate length after decoding
        if payload.len() != AURA_ADDRESS_PAYLOAD_LENGTH {
            return Err(CoreError::InvalidAddress(format!(
                "Invalid payload length after decoding: expected {}, got {}",
                AURA_ADDRESS_PAYLOAD_LENGTH,
                payload.len()
            )));
        }
        Ok(AuraAddress { hrp, payload })
    }
}

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
