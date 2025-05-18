use std::sync::{Arc, Mutex};

use aura_core::{CoreError, Transaction};

use informalsystems_malachitebft_app as malachitebft_app;
use informalsystems_malachitebft_config as malachitebft_config;
use informalsystems_malachitebft_core_types as malachitebft_core_types;
use informalsystems_malachitebft_engine as malachitebft_engine;

mod application;
mod config;
mod node;
mod state;

pub use application::AuraApplication;
pub use config::AuraNodeConfig;
pub use node::AuraNode;
pub use state::AuraState;

/// Represents the state of the Aura node
#[derive(Debug)]
pub struct AuraNodeState {
    /// The current application state
    app_state: Arc<Mutex<AuraState>>,
    /// Node configuration
    config: AuraNodeConfig,
}

/// Result type used throughout the library
pub type Result<T> = std::result::Result<T, Error>;

/// Error type for Aura node operations
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Consensus error: {0}")]
    Consensus(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("State error: {0}")]
    State(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Core error: {0}")]
    Core(#[from] CoreError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Other error: {0}")]
    Other(String),
}

/// Re-export important Malachite types for convenience
pub mod types {
    pub use informalsystems_malachitebft_app::NodeId;
    pub use informalsystems_malachitebft_core_types::{
        block::Block,
        consensus::{BlockHeader, Height, Round, Vote},
        crypto::Signature,
    };
}

fn main() {
    println!("Hello, world!");
}
