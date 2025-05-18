use crate::config::AuraAppConfig;
use anyhow::{Context, Result};
use clap::Subcommand;
use std::path::Path;
use std::sync::Arc; // Required for Arc::new

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

            // Construct aura_node_lib::config::AuraNodeConfig from aura::config::NodeConfig
            let node_lib_config = aura_node_lib::AuraNodeConfig {
                node_id: "simulation-node-0".to_string(), // Example node ID for simulation
                db_path: {
                    let expanded_node_data_dir =
                        shellexpand::tilde(&app_config.node.node_data_dir).into_owned();
                    let data_dir_path = std::path::PathBuf::from(expanded_node_data_dir);
                    if !data_dir_path.exists() {
                        std::fs::create_dir_all(&data_dir_path).with_context(|| {
                            format!("Failed to create node data directory: {:?}", data_dir_path)
                        })?;
                    }
                    data_dir_path.join("aura_node_sim.db") // Specific DB name for simulation
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

            let node = aura_node_lib::node::AuraNode::new(node_lib_config, node_sk)
                .map_err(|e| anyhow::anyhow!("Failed to initialize AuraNode: {}", e))?;

            // start_simulation_loop runs indefinitely or until an unrecoverable error.
            Arc::new(node)
                .start_simulation_loop()
                .await
                .map_err(|e| anyhow::anyhow!("Simulation loop exited: {}", e))?;

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
