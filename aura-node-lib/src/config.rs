use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Configuration for the Aura node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuraNodeConfig {
    /// Node identity
    pub node_id: String,

    /// Path to the state database
    pub db_path: PathBuf,

    /// Configuration for the P2P networking
    pub p2p: P2PConfig,

    /// Configuration for the consensus engine
    pub consensus: ConsensusConfig,

    /// RPC server configuration
    pub rpc: Option<RpcConfig>,
}

/// P2P network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2PConfig {
    /// Listen address for P2P connections
    pub listen_addr: String,

    /// External address for other nodes to connect to
    pub external_addr: Option<String>,

    /// Seed nodes to connect to
    pub seeds: Vec<String>,

    /// Maximum number of peers to connect to
    pub max_peers: usize,
}

/// Consensus configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    /// Initial validators in the network
    pub validators: Vec<ValidatorInfo>,

    /// Consensus timeout settings
    pub timeouts: TimeoutConfig,
}

/// Validator information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Validator ID
    pub id: String,

    /// Validator's public key
    pub public_key: String,

    /// Validator's voting power
    pub power: u64,
}

/// Timeout configuration for consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    /// Timeout for propose step (in milliseconds)
    pub propose: u64,

    /// Timeout for prevote step (in milliseconds)
    pub prevote: u64,

    /// Timeout for precommit step (in milliseconds)
    pub precommit: u64,

    /// Timeout for commit step (in milliseconds)
    pub commit: u64,
}

/// RPC server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcConfig {
    /// Listen address for RPC server
    pub listen_addr: String,

    /// Enabled RPC methods
    pub methods: Vec<String>,
}

impl AuraNodeConfig {
    /// Load configuration from a file
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let config_str = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("Failed to read config file: {}", e)))?;

        serde_json::from_str(&config_str)
            .map_err(|e| Error::Config(format!("Failed to parse config: {}", e)))
    }

    /// Save configuration to a file
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let config_str = serde_json::to_string_pretty(self)
            .map_err(|e| Error::Config(format!("Failed to serialize config: {}", e)))?;

        std::fs::write(path, config_str)
            .map_err(|e| Error::Config(format!("Failed to write config file: {}", e)))
    }

    /// Create a default configuration
    pub fn default_config(node_id: &str, db_path: impl AsRef<Path>) -> Self {
        Self {
            node_id: node_id.to_string(),
            db_path: db_path.as_ref().to_path_buf(),
            p2p: P2PConfig {
                listen_addr: "0.0.0.0:26656".to_string(),
                external_addr: None,
                seeds: vec![],
                max_peers: 50,
            },
            consensus: ConsensusConfig {
                validators: vec![],
                timeouts: TimeoutConfig {
                    propose: 3000,
                    prevote: 1000,
                    precommit: 1000,
                    commit: 1000,
                },
            },
            rpc: Some(RpcConfig {
                listen_addr: "127.0.0.1:26657".to_string(),
                methods: vec!["status".to_string(), "broadcast_tx".to_string()],
            }),
        }
    }
}
