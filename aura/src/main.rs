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
