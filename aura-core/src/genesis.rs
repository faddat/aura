use crate::NATIVE_DENOM;
use crate::address::AuraAddress;
use crate::error::CoreError;
use serde::Deserialize;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

#[derive(Deserialize, Debug, Clone)]
pub struct GenesisCoin {
    pub amount: String, // Keep as string to handle large numbers, then parse to u64
    pub denom: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct GenesisAccount {
    pub address: AuraAddress, // Uses custom Deserialize for AuraAddress
    pub coins: Vec<GenesisCoin>,
    #[serde(default)] // For backward compatibility if not present
    pub is_validator: bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct GenesisState {
    pub app_state: Vec<GenesisAccount>, // Assuming top-level array in genesis.json
    pub chain_id: Option<String>,       // Optional chain_id
    pub genesis_time: Option<String>,   // Optional genesis_time
}

impl GenesisState {
    pub fn from_file(path: &Path) -> Result<Self, CoreError> {
        let file = File::open(path).map_err(CoreError::Io)?;
        let reader = BufReader::new(file);

        // The example genesis file is an array, not an object with "app_state"
        // So we deserialize directly into Vec<GenesisAccount>
        // And wrap it into GenesisState manually.
        let accounts: Vec<GenesisAccount> = serde_json::from_reader(reader)
            .map_err(|e| CoreError::GenesisParsing(e.to_string()))?;

        Ok(GenesisState {
            app_state: accounts,
            chain_id: None, // Or parse from a different structure if present
            genesis_time: None,
        })
    }

    pub fn total_native_supply(&self) -> Result<u64, CoreError> {
        let mut total: u64 = 0;
        for account in &self.app_state {
            for coin in &account.coins {
                if coin.denom == NATIVE_DENOM {
                    let amount = coin.amount.parse::<u64>().map_err(|e| {
                        CoreError::GenesisParsing(format!(
                            "Invalid amount '{}' for address {}: {}",
                            coin.amount, account.address, e
                        ))
                    })?;
                    total = total.checked_add(amount).ok_or_else(|| {
                        CoreError::GenesisParsing(format!(
                            "Total supply overflow when adding {} for address {}",
                            amount, account.address
                        ))
                    })?;
                }
            }
        }
        Ok(total)
    }
}
