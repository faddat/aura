use clap::Parser;

// Define your subcommands using clap
#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Manage and run an Aura node
    Node(aura_cli::node_cmd::NodeArgs),
    /// Manage Aura wallets and transactions
    Wallet(aura_cli::wallet_cmd::WalletArgs),
    /// Utility functions
    Utils(aura_cli::utils_cmd::UtilsArgs),
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Setup logging, config loading etc.

    match cli.command {
        Commands::Node(args) => aura_cli::node_cmd::run(args)?,
        Commands::Wallet(args) => aura_cli::wallet_cmd::run(args)?,
        Commands::Utils(args) => aura_cli::utils_cmd::run(args)?,
    }
    Ok(())
}
