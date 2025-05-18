use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NodeConfig {
    pub p2p_listen_address: String,
    pub rpc_listen_address: String,
    pub bootstrap_peers: Vec<String>,
    pub genesis_file_path: String,
    pub node_data_dir: String, // Directory for node's redb database, Malachite state, etc.
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            p2p_listen_address: "/ip4/0.0.0.0/tcp/26656".to_string(),
            rpc_listen_address: "127.0.0.1:26657".to_string(),
            bootstrap_peers: Vec::new(),
            genesis_file_path: "~/.aura/genesis.json".to_string(),
            node_data_dir: "~/.aura/node_data".to_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WalletConfig {
    pub default_node_rpc_url: String,
    pub wallets_dir: String, // Directory for wallet redb databases
}

impl Default for WalletConfig {
    fn default() -> Self {
        WalletConfig {
            default_node_rpc_url: "http://127.0.0.1:26657".to_string(),
            wallets_dir: "~/.aura/wallets".to_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct AuraAppConfig {
    pub node: NodeConfig,
    pub wallet: WalletConfig,
    // Add other global settings if needed
}

impl AuraAppConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let builder = config::Config::builder()
            .add_source(config::File::from(path).required(true))
            .add_source(config::Environment::with_prefix("AURA").separator("__")); // e.g., AURA_NODE__RPC_LISTEN_ADDRESS

        let settings = builder.build()?;
        settings
            .try_deserialize()
            .context("Failed to deserialize configuration")
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let toml_string =
            toml::to_string_pretty(self).context("Failed to serialize configuration to TOML")?;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory: {:?}", parent))?;
        }
        fs::write(path, toml_string)
            .with_context(|| format!("Failed to write configuration to: {:?}", path))
    }

    pub fn load_or_init(path: &Path) -> Result<Self> {
        if path.exists() {
            Self::load(path)
        } else {
            tracing::info!(
                "Configuration file not found at {:?}, creating default.",
                path
            );
            let default_config = Self::default();
            default_config.save(path)?;
            tracing::info!("Default configuration saved. Please review and edit it if necessary.");
            Ok(default_config)
        }
    }
}

pub fn init_config_file(path: &Path) -> Result<()> {
    if path.exists() {
        tracing::warn!(
            "Configuration file already exists at {:?}. \
            If you want to regenerate it, please delete the existing file first.",
            path
        );
        return Ok(());
    }
    let default_config = AuraAppConfig::default();
    default_config.save(path)?;
    tracing::info!(
        "Default configuration file created at {:?}. \
        Please review and edit it, especially the genesis_file_path and any validator-specific settings.",
        path
    );
    Ok(())
}
