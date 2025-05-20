use crate::config::AuraAppConfig;
use anyhow::{Context, Result, anyhow};
use aura_node_lib::malachitebft_app::node::Node as MalachiteAppNodeTrait;
use clap::Subcommand;
use futures::TryStreamExt;
use ipfs_api::{IpfsApi, IpfsClient};
use std::path::Path;
use std::sync::Arc; // Required for Arc::new

use bech32::{self, Bech32m, primitives::hrp::Hrp};
use serde::{Deserialize, Serialize};

#[derive(Subcommand, Debug)]
pub enum NodeCommands {
    /// Start the Aura node
    Start {
        /// Seed phrase for the node's identity (especially if it's a validator)
        #[clap(long, env = "AURA_NODE_SEED_PHRASE")]
        seed_phrase: Option<String>,
    },
    /// Show node status (to be implemented)
    Status,
}

#[derive(Serialize, Deserialize)]
struct SnapshotCoin {
    amount: String,
    denom: String,
}

#[derive(Serialize, Deserialize)]
struct SnapshotAccount {
    address: String,
    coins: Vec<SnapshotCoin>,
    #[serde(default)]
    is_validator: bool,
}

fn convert_address(addr: &str) -> Result<String> {
    let (hrp, data) =
        bech32::decode(addr).map_err(|e| anyhow!(format!("bech32 decode error: {}", e)))?;
    if hrp.as_str() != "unicorn" {
        return Err(anyhow!(format!("unexpected hrp: {}", hrp.as_str())));
    }
    let new_hrp = Hrp::parse_unchecked("whiteaura");
    let encoded = bech32::encode::<Bech32m>(new_hrp, &data)
        .map_err(|e| anyhow!(format!("bech32 encode error: {}", e)))?;
    Ok(encoded)
}

async fn ensure_genesis_from_snapshot(path: &Path) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    tracing::info!("Genesis file {:?} not found. Downloading snapshot...", path);
    // Fetch genesis JSON from IPFS
    const CID: &str = "QmNLocWsww2QgXGawfMPj8tn9ggzEt4dbiywAKiFjgGQhr";
    tracing::info!("Fetching genesis from IPFS CID {}", CID);
    // Fetch genesis JSON from IPFS in a blocking context to keep this future Send
    let json = tokio::task::spawn_blocking(move || -> Result<String> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| anyhow!("Failed to build runtime: {}", e))?;
        rt.block_on(async move {
            let client = IpfsClient::default();
            let mut body: Vec<u8> = Vec::new();
            let mut stream = client.cat(CID);
            while let Some(chunk) = stream
                .try_next()
                .await
                .map_err(|e| anyhow!("IPFS fetch error: {}", e))?
            {
                body.extend_from_slice(&chunk);
            }
            String::from_utf8(body).map_err(|e| anyhow!("Invalid UTF-8 from IPFS: {}", e))
        })
    })
    .await
    .map_err(|e| anyhow!("Blocking IPFS fetch failed: {}", e))??;
    let mut accounts: Vec<SnapshotAccount> = serde_json::from_str(&json)?;
    for acc in &mut accounts {
        acc.address = convert_address(&acc.address)?;
        for coin in &mut acc.coins {
            if coin.denom == "uwunicorn" {
                coin.denom = "uaura".to_string();
            }
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(&accounts)?)?;
    Ok(())
}

pub async fn handle_node_command(
    commands: NodeCommands,
    app_config: &AuraAppConfig,
    _config_path: &Path, // In case we need to reload or save specific parts
) -> Result<()> {
    match commands {
        NodeCommands::Start { seed_phrase } => {
            tracing::info!("Starting Aura node...");
            tracing::debug!(
                "Node configuration from app_config.node: {:?}",
                app_config.node
            );

            let genesis_path = {
                let path = shellexpand::tilde(&app_config.node.genesis_file_path).into_owned();
                std::path::PathBuf::from(path)
            };
            ensure_genesis_from_snapshot(&genesis_path).await?;

            // Construct aura_node_lib::config::AuraNodeConfig from aura::config::NodeConfig
            let node_lib_config = aura_node_lib::AuraNodeConfig {
                node_id: "simulation-node-0".to_string(), // Example node ID for simulation
                db_path: {
                    let data_dir = shellexpand::tilde(&app_config.node.node_data_dir).into_owned();
                    let dir_path = std::path::PathBuf::from(data_dir);
                    if !dir_path.exists() {
                        std::fs::create_dir_all(&dir_path).with_context(|| {
                            format!("Failed to create node data directory: {:?}", dir_path)
                        })?;
                    }
                    dir_path.join("aura_node_sim.db")
                },
                p2p: aura_node_lib::config::P2PConfig {
                    listen_addr: app_config.node.p2p_listen_address.clone(),
                    external_addr: None,
                    seeds: app_config.node.bootstrap_peers.clone(),
                    max_peers: 10, // Reduced for single node simulation
                },
                consensus: aura_node_lib::config::ConsensusConfig {
                    validators: vec![], // Not used in single node PoA-less simulation
                    timeouts: aura_node_lib::config::TimeoutConfig {
                        propose: 3000,
                        prevote: 1000,
                        precommit: 1000,
                        commit: 1000,
                    },
                },
                rpc: Some(aura_node_lib::config::RpcConfig {
                    listen_addr: app_config.node.rpc_listen_address.clone(),
                    methods: vec!["status".to_string(), "broadcast_tx".to_string()],
                }),
            };
            tracing::info!("Constructed AuraNodeLibConfig: {:?}", node_lib_config);

            // Node identity (PrivateKey)
            let node_sk = match seed_phrase {
                Some(sp) => {
                    tracing::info!("Using provided seed phrase for node identity.");
                    aura_core::keys::PrivateKey::from_seed_phrase_str(&sp).map_err(|e| {
                        anyhow::anyhow!("Failed to derive private key from seed: {}", e)
                    })?
                }
                None => {
                    tracing::warn!(
                        "No seed phrase provided. Generating a new random private key for simulation. THIS IS EPHEMERAL."
                    );
                    // For a persistent simulated node, you might want to load/save this key or use a fixed dev seed.
                    // Example fixed dev seed: "test test test test test test test test test test test junk"
                    // let dev_seed = "test test test test test test test test test test test junk";
                    // aura_core::keys::PrivateKey::from_seed_phrase_str(dev_seed)?
                    aura_core::keys::PrivateKey::new_random()
                }
            };

            // Build the AuraNode struct directly (new() was removed)
            let home_dir = shellexpand::tilde(&app_config.node.node_data_dir).into_owned();
            let home_dir = std::path::PathBuf::from(home_dir);

            let malachite_cfg_path = home_dir.join("malachite.toml");

            let aura_node = aura_node_lib::node::AuraNode::new(
                home_dir.clone(),
                node_lib_config,
                malachite_cfg_path,
                Arc::new(node_sk),
            );

            MalachiteAppNodeTrait::run(aura_node)
                .await
                .map_err(|e| anyhow::anyhow!("AuraNode run exited: {}", e))?;

            tracing::info!("Aura node simulation loop finished.");
            Ok(())
        }
        NodeCommands::Status => {
            tracing::info!("Fetching Aura node status...");
            println!("Node status command executed (implementation pending).");
            Ok(())
        }
    }
}
