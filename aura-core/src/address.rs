use crate::AURA_ADDR_HRP;
use crate::error::CoreError;
use bech32::{Bech32m, DecodeError, Fe32, Hrp, encode}; // Fe32 for 5-bit elements
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

pub const AURA_ADDRESS_PAYLOAD_LENGTH: usize = 48;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AuraAddress {
    hrp_str: String,
    payload: Vec<u8>, // 8-bit data
}

impl AuraAddress {
    pub fn new(hrp_str: &str, payload: Vec<u8>) -> Result<Self, CoreError> {
        if payload.len() != AURA_ADDRESS_PAYLOAD_LENGTH {
            return Err(CoreError::InvalidAddress(format!(
                "Invalid payload length: expected {}, got {}",
                AURA_ADDRESS_PAYLOAD_LENGTH,
                payload.len()
            )));
        }
        // Validate HRP string if needed
        if Hrp::parse_unchecked(hrp_str).as_str() != hrp_str {
            // Basic check
            return Err(CoreError::InvalidAddress(format!(
                "Invalid HRP characters in: {}",
                hrp_str
            )));
        }
        Ok(AuraAddress {
            hrp_str: hrp_str.to_string(),
            payload,
        })
    }

    pub fn from_pubkey_bytes(pubkey_bytes: &[u8], hrp_str: &str) -> Result<Self, CoreError> {
        Self::new(hrp_str, pubkey_bytes.to_vec())
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn hrp_str(&self) -> &str {
        &self.hrp_str
    }
}

fn u8_to_fe32_vec(data: &[u8]) -> Result<Vec<Fe32>, bech32::primitives::convert_bits::Error> {
    let mut five_bit_payload = Vec::new();
    bech32::primitives::convert_bits::convert_bits(data, 8, 5, true, &mut five_bit_payload)?;
    five_bit_payload
        .into_iter()
        .map(Fe32::try_from)
        .collect::<Result<Vec<Fe32>, _>>()
        .map_err(|_| bech32::primitives::convert_bits::Error::InvalidPadding) // Or a more specific error
}

fn fe32_to_u8_vec(data_fe: &[Fe32]) -> Result<Vec<u8>, bech32::primitives::convert_bits::Error> {
    let five_bit_data: Vec<u8> = data_fe.iter().map(|fe| fe.to_u8()).collect();
    let mut eight_bit_payload = Vec::new();
    bech32::primitives::convert_bits::convert_bits(
        &five_bit_data,
        5,
        8,
        false,
        &mut eight_bit_payload,
    )?;
    Ok(eight_bit_payload)
}

impl fmt::Display for AuraAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hrp = Hrp::parse_unchecked(&self.hrp_str);
        match u8_to_fe32_vec(&self.payload) {
            Ok(fe_payload) => {
                let encoded = Bech32m::encode_str(&hrp, &fe_payload).map_err(|_| fmt::Error)?; // Convert encode::Error to fmt::Error
                write!(f, "{}", encoded)
            }
            Err(_) => Err(fmt::Error), // Failed 8-to-5 bit conversion
        }
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
        // bech32 v0.11 decode returns a Result<Hrpstring, DecodeError>
        // Hrpstring has methods hrp(), data()
        let (hrp_decoded, data_fe32, _variant) = bech32::decode(s).map_err(|e: DecodeError| {
            CoreError::Bech32(format!("Bech32m decoding error: {}", e))
        })?;

        // Recheck variant if necessary, though decode with specific checksum (Bech32m) should ensure it.
        // if variant != Bech32m::VARIANT { ... }

        let payload = fe32_to_u8_vec(&data_fe32)
            .map_err(|e| CoreError::Bech32(format!("Bech32 bit conversion error: {:?}", e)))?;

        let hrp_str = hrp_decoded.as_str().to_string();

        if hrp_str != AURA_ADDR_HRP {
            // Optionally allow other HRPs if genesis might contain them
            // For strict Aura addresses, this should be an error.
            // tracing::warn!("Decoded address HRP '{}' does not match expected HRP '{}'", hrp_str, AURA_ADDR_HRP);
        }

        if payload.len() != AURA_ADDRESS_PAYLOAD_LENGTH {
            return Err(CoreError::InvalidAddress(format!(
                "Invalid payload length after decoding: expected {}, got {}",
                AURA_ADDRESS_PAYLOAD_LENGTH,
                payload.len()
            )));
        }
        Ok(AuraAddress { hrp_str, payload })
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
