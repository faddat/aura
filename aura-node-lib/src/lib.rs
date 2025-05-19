use std::sync::{Arc, Mutex}; // Mutex is used in AuraApplication

use aura_core::CoreError;
pub use redb::{CommitError, DatabaseError, StorageError, TableError, TransactionError};

// Re-export Malachite types for use in our crate
pub use malachitebft_app;
pub use malachitebft_config;
pub use malachitebft_core_consensus;
pub use malachitebft_core_types;
pub use malachitebft_engine;
pub use malachitebft_peer;

pub mod config; // Make config module public
pub mod node; // Make node module public to access AuraNode
mod state;

// application module temporarily disabled until ABCI shim updated
// mod application;
// pub use application::AuraApplication;

pub use config::AuraNodeConfig;
pub use node::AuraNode; // Export AuraNode
pub use state::{AuraState, Block, ValidatorUpdate}; // Export ValidatorUpdate as well

/// Represents the state of the Aura node (potentially for higher-level management, currently unused)
#[derive(Debug)]
#[allow(dead_code)] // This struct seems unused for now
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

    #[error("Database error: {0}")]
    Database(String),

    #[error("Other error: {0}")]
    Other(String),
}

// Add From implementations for database errors
impl From<DatabaseError> for Error {
    fn from(err: DatabaseError) -> Self {
        Self::Database(err.to_string())
    }
}

impl From<TransactionError> for Error {
    fn from(err: TransactionError) -> Self {
        Self::Database(err.to_string())
    }
}

impl From<TableError> for Error {
    fn from(err: TableError) -> Self {
        Self::Database(err.to_string())
    }
}

impl From<StorageError> for Error {
    fn from(err: StorageError) -> Self {
        Self::Database(err.to_string())
    }
}

impl From<CommitError> for Error {
    fn from(err: CommitError) -> Self {
        Self::Database(err.to_string())
    }
}
