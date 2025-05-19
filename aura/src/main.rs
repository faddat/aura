use anyhow::Result;
use clap::Parser;
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = match cli.verbose {
        0 => "aura=info", // Default
        1 => "aura=debug",
        _ => "aura=trace",
    };
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::new(log_level))
        .with_max_level(tracing::Level::TRACE) // Ensure all levels can be captured
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
            use aura_core::keys::{PrivateKey, SeedPhrase};
            use serde::Serialize;
            use std::fs;
            use std::path::PathBuf;

            let home_dir = PathBuf::from(".testnet");
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
            if !key_path.exists() {
                #[derive(Serialize)]
                struct KeyFile {
                    private_key_hex: String,
                }
                let sk = PrivateKey::new_random();
                let kf = KeyFile {
                    private_key_hex: hex::encode(sk.to_bytes_be()),
                };
                fs::write(&key_path, serde_json::to_vec_pretty(&kf)?)?;
            }

            // --------- genesis ------------------------
            let genesis_path = home_dir.join("genesis.json");
            if !genesis_path.exists() {
                fs::write(
                    &genesis_path,
                    r#"{
  "height": 0,
  "time": "2025-01-01T00:00:00Z",
  "app_hash": "",
  "validator_set": [],
  "consensus_params": {}
}
+"#,
                )?;
            }

            // --------- malachite config ---------------
            let mal_cfg_path = home_dir.join("malachite.toml");
            if !mal_cfg_path.exists() {
                fs::write(
                    &mal_cfg_path,
                    format!(
                        "moniker = \"devnet-node\"\nhome = \"{}\"\ngenesis_file = \"genesis.json\"\npriv_validator_key_file = \"node_key.json\"\nnode_key_file = \"node_key.json\"\n\n[p2p]\nlisten_addr = \"/ip4/0.0.0.0/tcp/26656\"\nexternal_addr = \"\"\nseeds = []\n\n[consensus]\ntimeout_propose_ms   = 3000\ntimeout_prevote_ms   = 1000\ntimeout_precommit_ms = 1000\ntimeout_commit_ms    = 1000\n",
                        home_dir.display()
                    ),
                )?;
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
