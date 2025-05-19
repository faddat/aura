use anyhow::Result;
use clap::Parser;
use serde::Serialize;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

mod config;
mod node_cmd;
mod utils_cmd;
mod wallet_cmd;

use config::AuraAppConfig; // Assuming a top-level config struct

#[derive(Parser)]
#[clap(author, version, about = "Aura: A Fully Private Cryptocurrency Client", long_about = None)]
#[clap(propagate_version = true)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,

    /// Path to the Aura configuration file
    #[clap(short, long, global = true, default_value = "~/.aura/config.toml")]
    config_path: String,

    /// Increase message verbosity (can be used multiple times)
    #[clap(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Manage and run an Aura node
    #[clap(subcommand)]
    Node(node_cmd::NodeCommands),
    /// Manage Aura wallets and transactions
    #[clap(subcommand)]
    Wallet(wallet_cmd::WalletCommands),
    /// Utility functions
    #[clap(subcommand)]
    Utils(utils_cmd::UtilsCommands),
    /// Initialize Aura configuration
    InitConfig,
    /// Generate a new node private key and save it under <home>/node_key.json
    Keygen {
        /// Home directory where the key file will be written
        #[clap(long)]
        home: std::path::PathBuf,
    },
    /// Create and run a self-contained single-node devnet in ./.testnet
    SingleNodeTestnet,
    /// Create and run a multi-node (local) testnet in ./.testnet-multi
    MultiNodeTestnet {
        /// Number of nodes to start (default 4)
        #[clap(short, long, default_value_t = 4)]
        nodes: u16,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let base_filter = match cli.verbose {
        0 => "aura=info",
        1 => "aura=debug",
        _ => "aura=trace",
    };

    // Reduce log noise for multi-node testnet unless user explicitly increased verbosity.
    let (filter_str, max_level) = match (&cli.command, cli.verbose) {
        (Commands::MultiNodeTestnet { .. }, 0) => (base_filter, tracing::Level::INFO),
        _ => (base_filter, tracing::Level::TRACE),
    };

    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::new(filter_str))
        .with_max_level(max_level)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("Setting default tracing subscriber failed");

    tracing::info!("Aura client starting up...");

    // Expand tilde in config path
    let expanded_config_path = shellexpand::tilde(&cli.config_path).into_owned();
    let config_path = std::path::PathBuf::from(expanded_config_path);

    if let Commands::InitConfig = cli.command {
        return config::init_config_file(&config_path);
    }

    // Load or initialize configuration
    let app_config = AuraAppConfig::load_or_init(&config_path)?;
    tracing::debug!("Loaded application config: {:?}", app_config);

    match cli.command {
        Commands::Keygen { home } => {
            use aura_core::keys::PrivateKey;
            use serde::Serialize;

            #[derive(Serialize)]
            struct KeyFile {
                private_key_hex: String,
            }

            std::fs::create_dir_all(&home)?;
            let sk = PrivateKey::new_random();
            let key_hex = hex::encode(sk.to_bytes_be());
            let key_path = home.join("node_key.json");
            std::fs::write(
                &key_path,
                serde_json::to_vec_pretty(&KeyFile {
                    private_key_hex: key_hex,
                })?,
            )?;
            println!("Node key written to {}", key_path.display());
        }
        Commands::SingleNodeTestnet => {
            use aura_core::keys::SeedPhrase;
            use std::fs;
            use std::path::PathBuf;

            let home_dir = std::fs::canonicalize(PathBuf::from(".testnet").as_path())
                .unwrap_or_else(|_| PathBuf::from(".testnet"));
            fs::create_dir_all(&home_dir)?;

            // --------- seed phrase (persist) ---------
            let seed_path = home_dir.join("seed_phrase.txt");
            let seed_phrase_str: String = if seed_path.exists() {
                fs::read_to_string(&seed_path)?
            } else {
                let sp = SeedPhrase::new_random()?;
                let s = sp.as_str();
                fs::write(&seed_path, &s)?;
                s
            };

            // --------- node key (persist) ------------
            let key_path = home_dir.join("node_key.json");
            {
                use aura_node_lib::malachitebft_test::PrivateKey as MalPriv;
                // Always (re)write the key in malachite-compatible JSON format to avoid legacy
                // hex key formats that this devnet no longer supports.
                let priv_key = MalPriv::generate(rand::thread_rng());
                fs::write(&key_path, serde_json::to_vec_pretty(&priv_key)?)?;
            }

            // --------- genesis ------------------------
            use aura_node_lib::malachitebft_test as mal_test;
            use mal_test::{Genesis as MalGenesis, PrivateKey as MalPriv, Validator, ValidatorSet};

            let genesis_path = home_dir.join("genesis.json");

            // Load the node's private key so we can derive its public key & address
            let priv_key_json = fs::read_to_string(&key_path)?;
            let priv_key: MalPriv = serde_json::from_str(&priv_key_json)?;
            let pub_key = priv_key.public_key();

            // Build a single-validator set with voting power 1
            let validator = Validator::new(pub_key, 1);
            let validator_set = ValidatorSet::new(vec![validator]);

            let genesis = MalGenesis { validator_set };
            let genesis_json = serde_json::to_string_pretty(&genesis)?;
            fs::write(&genesis_path, genesis_json)?;

            // --------- malachite config ---------------
            let mal_cfg_path = home_dir.join("malachite.toml");
            {
                let tpl = format!(
                    r#"moniker = "devnet-node"
home = "{home}"
genesis_file = "genesis.json"
priv_validator_key_file = "node_key.json"
node_key_file = "node_key.json"

[p2p]
listen_addr = "/ip4/0.0.0.0/tcp/26656"
persistent_peers = []
protocol = {{ type = "broadcast" }}
rpc_max_size = "10MiB"
pubsub_max_size = "4MiB"

[consensus]
timeout_propose   = "3s"
timeout_prevote   = "1s"
timeout_precommit = "1s"
timeout_commit    = "1s"
timeout_propose_delta = "0s"
timeout_prevote_delta = "0s"
timeout_precommit_delta = "0s"
timeout_rebroadcast = "5s"
value_payload = "parts-only"

[consensus.p2p]
listen_addr = "/ip4/0.0.0.0/tcp/26656"
persistent_peers = []
protocol = {{ type = "broadcast" }}
rpc_max_size = "10MiB"
pubsub_max_size = "4MiB"
"#,
                    home = home_dir.display()
                );
                fs::write(&mal_cfg_path, tpl)?;
            }

            // --------- build temp app config ----------
            let node_conf = config::NodeConfig {
                p2p_listen_address: "/ip4/0.0.0.0/tcp/26656".to_string(),
                rpc_listen_address: "127.0.0.1:26657".to_string(),
                bootstrap_peers: vec![],
                genesis_file_path: genesis_path.to_string_lossy().into(),
                node_data_dir: home_dir.to_string_lossy().into(),
            };
            let tmp_cfg = AuraAppConfig {
                node: node_conf,
                wallet: app_config.wallet.clone(),
            };

            node_cmd::handle_node_command(
                node_cmd::NodeCommands::Start {
                    seed_phrase: Some(seed_phrase_str),
                },
                &tmp_cfg,
                &home_dir,
            )
            .await?;
        }
        Commands::MultiNodeTestnet { nodes } => {
            use aura_core::keys::SeedPhrase;
            use futures::future::join_all;
            use std::fs;
            use std::path::PathBuf;

            let base_home: PathBuf = std::fs::canonicalize(PathBuf::from(".testnet-multi"))
                .unwrap_or_else(|_| PathBuf::from(".testnet-multi"));
            fs::create_dir_all(&base_home)?;

            // --------- generate keys and seed phrases ---------
            use aura_node_lib::malachitebft_test as mal_test;
            use mal_test::{Genesis as MalGenesis, PrivateKey as MalPriv, Validator, ValidatorSet};

            let mut validators: Vec<(mal_test::PublicKey, PathBuf)> = Vec::new();

            // For each node create directory, key, seed phrase, store priv key
            for idx in 0..nodes {
                let node_dir = base_home.join(format!("node{}", idx));
                fs::create_dir_all(&node_dir)?;

                // seed phrase
                let seed_path = node_dir.join("seed_phrase.txt");
                let _seed_phrase_str: String = if seed_path.exists() {
                    fs::read_to_string(&seed_path)?
                } else {
                    let sp = SeedPhrase::new_random()?;
                    let s = sp.as_str();
                    fs::write(&seed_path, &s)?;
                    s
                };

                // private key for malachite / consensus
                let key_path = node_dir.join("node_key.json");
                let priv_key: MalPriv = if key_path.exists() {
                    serde_json::from_str(&fs::read_to_string(&key_path)?)?
                } else {
                    let pk = MalPriv::generate(rand::thread_rng());
                    fs::write(&key_path, serde_json::to_vec_pretty(&pk)?)?;
                    pk
                };

                let pub_key = priv_key.public_key();
                validators.push((pub_key, node_dir));
            }

            // Build validator set genesis
            let validator_set = ValidatorSet::new(
                validators
                    .iter()
                    .map(|(pk, _)| Validator::new(*pk, 1))
                    .collect::<Vec<_>>(),
            );
            let genesis = MalGenesis { validator_set };
            let genesis_json = serde_json::to_string_pretty(&genesis)?;

            // Write genesis.json to each node dir
            for (_, node_dir) in validators.iter() {
                fs::write(node_dir.join("genesis.json"), &genesis_json)?;
            }

            // Build and run each node
            let mut handles = Vec::new();

            for (idx, (_, node_dir)) in validators.iter().enumerate() {
                // malachite config
                let listen_port = 26656 + idx as u16;
                let rpc_port = 26660 + idx as u16;

                let listen_addr = format!("/ip4/0.0.0.0/tcp/{}", listen_port);

                // peers list (multiaddress with id placeholder). For local network we can omit or include others' listen_addr.
                let mut persistent = Vec::new();
                for (p_idx, _) in validators.iter().enumerate() {
                    if p_idx != idx {
                        let peer_addr = format!("/ip4/127.0.0.1/tcp/{}", 26656 + p_idx as u16);
                        persistent.push(peer_addr);
                    }
                }

                let mal_cfg_path = node_dir.join("malachite.toml");

                #[derive(Serialize)]
                struct ProtocolConfig {
                    #[serde(rename = "type")]
                    protocol_type: String,
                }

                #[derive(Serialize)]
                struct P2PConfig {
                    listen_addr: String,
                    persistent_peers: Vec<String>,
                    protocol: ProtocolConfig,
                    rpc_max_size: String,
                    pubsub_max_size: String,
                }

                #[derive(Serialize)]
                struct ConsensusP2PConfig {
                    listen_addr: String,
                    persistent_peers: Vec<String>,
                    protocol: ProtocolConfig,
                    rpc_max_size: String,
                    pubsub_max_size: String,
                }

                #[derive(Serialize)]
                struct ConsensusConfigSection {
                    timeout_propose: String,
                    timeout_prevote: String,
                    timeout_precommit: String,
                    timeout_commit: String,
                    timeout_propose_delta: String,
                    timeout_prevote_delta: String,
                    timeout_precommit_delta: String,
                    timeout_rebroadcast: String,
                    value_payload: String,
                    #[serde(rename = "p2p")]
                    p2p: ConsensusP2PConfig,
                }

                #[derive(Serialize)]
                struct MalachiteConfig {
                    moniker: String,
                    home: String,
                    genesis_file: String,
                    priv_validator_key_file: String,
                    node_key_file: String,
                    p2p: P2PConfig,
                    consensus: ConsensusConfigSection,
                }

                let config = MalachiteConfig {
                    moniker: format!("node-{idx}"),
                    home: node_dir.to_string_lossy().to_string(),
                    genesis_file: "genesis.json".to_string(),
                    priv_validator_key_file: "node_key.json".to_string(),
                    node_key_file: "node_key.json".to_string(),
                    p2p: P2PConfig {
                        listen_addr: listen_addr.clone(),
                        persistent_peers: persistent.clone(),
                        protocol: ProtocolConfig {
                            protocol_type: "broadcast".to_string(),
                        },
                        rpc_max_size: "10MiB".to_string(),
                        pubsub_max_size: "4MiB".to_string(),
                    },
                    consensus: ConsensusConfigSection {
                        timeout_propose: "3s".to_string(),
                        timeout_prevote: "1s".to_string(),
                        timeout_precommit: "1s".to_string(),
                        timeout_commit: "1s".to_string(),
                        timeout_propose_delta: "0s".to_string(),
                        timeout_prevote_delta: "0s".to_string(),
                        timeout_precommit_delta: "0s".to_string(),
                        timeout_rebroadcast: "5s".to_string(),
                        value_payload: "parts-only".to_string(),
                        p2p: ConsensusP2PConfig {
                            listen_addr: listen_addr.clone(),
                            persistent_peers: persistent.clone(),
                            protocol: ProtocolConfig {
                                protocol_type: "broadcast".to_string(),
                            },
                            rpc_max_size: "10MiB".to_string(),
                            pubsub_max_size: "4MiB".to_string(),
                        },
                    },
                };

                let toml_cfg = toml::to_string(&config)?;
                fs::write(&mal_cfg_path, toml_cfg)?;

                // Build temporary app config
                let node_conf = config::NodeConfig {
                    p2p_listen_address: listen_addr.clone(),
                    rpc_listen_address: format!("127.0.0.1:{}", rpc_port),
                    bootstrap_peers: persistent.clone(),
                    genesis_file_path: node_dir.join("genesis.json").to_string_lossy().into(),
                    node_data_dir: node_dir.to_string_lossy().into(),
                };

                let seed_phrase_str = fs::read_to_string(node_dir.join("seed_phrase.txt"))?;

                let tmp_cfg = AuraAppConfig {
                    node: node_conf,
                    wallet: app_config.wallet.clone(),
                };

                let cfg_clone = tmp_cfg.clone();
                let dir_clone = node_dir.clone();

                handles.push(tokio::spawn(async move {
                    if let Err(e) = node_cmd::handle_node_command(
                        node_cmd::NodeCommands::Start {
                            seed_phrase: Some(seed_phrase_str),
                        },
                        &cfg_clone,
                        &dir_clone,
                    )
                    .await
                    {
                        eprintln!("Node {idx} exited with error: {e}");
                    }
                }));
            }

            // Wait on all nodes indefinitely (or until one exits)
            let _ = join_all(handles).await;
        }
        Commands::Node(node_commands) => {
            node_cmd::handle_node_command(node_commands, &app_config, &config_path).await?
        }
        Commands::Wallet(wallet_commands) => {
            wallet_cmd::handle_wallet_command(wallet_commands, &app_config, &config_path).await?
        }
        Commands::Utils(utils_commands) => {
            utils_cmd::handle_utils_command(utils_commands, &app_config, &config_path).await?
        }
        Commands::InitConfig => unreachable!(), // Handled above
    }

    tracing::info!("Aura command finished successfully.");
    Ok(())
}
