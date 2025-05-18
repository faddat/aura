use crate::AURA_ADDR_HRP;
use crate::error::CoreError;
use bech32::{self, Bech32m, Fe32, Hrp};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

pub const AURA_ADDRESS_PAYLOAD_LENGTH: usize = 48; // For BLS12-381 G1 compressed

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
        Hrp::parse_unchecked(hrp_str); // Will panic on invalid HRP chars for parse_unchecked. Use Hrp::parse for Result.
        // Hrp::parse(hrp_str).map_err(CoreError::from)?;
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

fn u8_to_fe32_vec(data: &[u8]) -> Result<Vec<Fe32>, ConvertBitsError> {
    let mut five_bit_payload: Vec<u8> = Vec::new(); // Must be Vec<u8> for convert_bits
    bech32::convert_bits(data, 8, 5, true, &mut five_bit_payload)?;
    five_bit_payload
        .into_iter()
        .map(Fe32::try_from)
        .collect::<Result<Vec<Fe32>, _>>()
        .map_err(|_: Gf32Error| ConvertBitsError::InvalidData) // Map Gf32Error
}

fn fe32_to_u8_vec(data_fe: &[Fe32]) -> Result<Vec<u8>, ConvertBitsError> {
    let five_bit_data: Vec<u8> = data_fe.iter().map(|fe| fe.to_u8()).collect();
    let mut eight_bit_payload = Vec::new();
    bech32::convert_bits(&five_bit_data, 5, 8, false, &mut eight_bit_payload)?;
    Ok(eight_bit_payload)
}

impl fmt::Display for AuraAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hrp = Hrp::parse_unchecked(&self.hrp_str); // Assumes valid by construction in Self::new
        match u8_to_fe32_vec(&self.payload) {
            Ok(fe_payload) => {
                // bech32::encode takes Hrp and &[Fe32] and the variant is part of the type (Bech32m)
                let b = Bech32m; // Checksum type
                let encoded_str = b
                    .encode_str(&hrp, &fe_payload)
                    .map_err(|_: EncodeError| fmt::Error)?;
                write!(f, "{}", encoded_str)
            }
            Err(_) => Err(fmt::Error),
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
        // bech32::decode takes a &str and returns Result<(Hrp, Vec<Fe32>, Variant), DecodeError>
        let (hrp_decoded, data_u5) = bech32::decode(s).map_err(CoreError::from)?;
        let data_fe32 = data_u5
            .iter()
            .copied()
            .map(|b| Fe32::from(b))
            .collect::<Vec<Fe32>>();
        if hrp_decoded != AURA_ADDR_HRP {
            return Err(CoreError::InvalidAddress(
                "Decoded variant is not Bech32m".to_string(),
            ));
        }

        let payload = fe32_to_u8_vec(&data_fe32).map_err(CoreError::from)?;

        let hrp_str = hrp_decoded.as_str().to_string();

        if hrp_str != AURA_ADDR_HRP {
            // Optionally handle other HRPs
            // For strict Aura addresses, this could be an error.
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
