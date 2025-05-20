use crate::AURA_ADDR_HRP;
use crate::error::CoreError;
use bech32::{self, Bech32m, Hrp};
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
        // Validate HRP string; Hrp::parse returns an error on invalid characters
        Hrp::parse(hrp_str).map_err(CoreError::from)?;
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

impl fmt::Display for AuraAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Parse HRP; if invalid, error in formatting
        let hrp = Hrp::parse(&self.hrp_str).map_err(|_| fmt::Error)?;
        bech32::encode::<Bech32m>(hrp, &self.payload)
            .map_err(|_| fmt::Error)
            .and_then(|encoded| write!(f, "{}", encoded))
    }
}

impl fmt::Debug for AuraAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AuraAddress({})", self)
    }
}

impl FromStr for AuraAddress {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (hrp_decoded, data_bytes) =
            bech32::decode(s).map_err(|e| CoreError::Bech32(format!("Decode error: {}", e)))?;

        let hrp_str = hrp_decoded.as_str().to_string();

        if hrp_str != AURA_ADDR_HRP {
            return Err(CoreError::InvalidAddress("Invalid HRP".to_string()));
        }

        let payload = data_bytes;

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
