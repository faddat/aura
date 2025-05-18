use std::sync::{Arc, Mutex};

use aura_core::CoreError;

// Re-export Malachite types for use in our crate
pub use malachitebft_app;
pub use malachitebft_config;
pub use malachitebft_core_consensus;
pub use malachitebft_core_types;
pub use malachitebft_engine;
pub use malachitebft_peer;

// Create a types module for convenient re-exports
pub mod types {
    pub use malachitebft_core_types::{
        Height, Round, Signature, Value as Block, ValueId as BlockId,
    };
    pub use malachitebft_peer::PeerId as NodeId;
}

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
