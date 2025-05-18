use std::str::FromStr;
use std::sync::{Arc, Mutex};

use tokio::runtime::Runtime;
use tracing::{error, info};

use crate::{
    Error, Result, application::AuraApplication, config::AuraNodeConfig, state::AuraState,
};

// Import directly from crates
use malachitebft_peer::PeerId as NodeId;

/// The main Aura node that coordinates all components
#[derive(Debug)]
pub struct AuraNode {
    /// Node configuration
    config: AuraNodeConfig,
    /// Application state
    state: Arc<Mutex<AuraState>>,
    /// Application service
    application: Arc<AuraApplication>,
    /// Tokio runtime for async operations
    runtime: Runtime,
}

impl AuraNode {
    /// Create a new AuraNode with the given configuration
    pub fn new(config: AuraNodeConfig, private_key: Arc<aura_core::PrivateKey>) -> Result<Self> {
        // Create tokio runtime
        let runtime =
            Runtime::new().map_err(|e| Error::Other(format!("Failed to create runtime: {}", e)))?;

        // Create node ID from configuration
        let node_id = config.node_id.clone();

        // Initialize state
        let state = Arc::new(Mutex::new(AuraState::new(&config.db_path, private_key)?));

        // Create application
        let application = Arc::new(AuraApplication::new(state.clone(), node_id));

        Ok(Self {
            config,
            state,
            application,
            runtime,
        })
    }

    /// Start the node and all its components
    pub fn start(&self) -> Result<()> {
        info!("Starting Aura node with ID: {}", self.config.node_id);

        self.runtime.block_on(async {
            // In a real implementation, this would:
            // 1. Initialize the consensus engine with our application
            // 2. Start P2P networking
            // 3. Start RPC server if configured
            // 4. Start other node services

            // Example of how you might initialize the Malachite engine:
            // let engine_config = self.create_engine_config();
            // let engine = malachitebft_engine::Engine::new(
            //     engine_config,
            //     self.application.clone(),
            // ).await.map_err(|e| Error::Consensus(e.to_string()))?;
            //
            // engine.start().await.map_err(|e| Error::Consensus(e.to_string()))?;

            info!("Aura node started successfully");
            Ok(())
        })
    }

    /// Stop the node and all its components
    pub fn stop(&self) -> Result<()> {
        info!("Stopping Aura node");

        self.runtime.block_on(async {
            // In a real implementation, this would:
            // 1. Stop the consensus engine
            // 2. Stop P2P networking
            // 3. Stop RPC server
            // 4. Stop other node services
            // 5. Flush state to disk

            info!("Aura node stopped successfully");
            Ok(())
        })
    }

    /// Get a reference to the node's configuration
    pub fn config(&self) -> &AuraNodeConfig {
        &self.config
    }

    /// Get the current blockchain height
    pub fn height(&self) -> Result<u64> {
        let state = self.state.lock().map_err(|e| Error::State(e.to_string()))?;
        Ok(state.height_value())
    }
}
