use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tracing::info;

use crate::{
    Error, Result,
    state::{AuraState, Block},
};

// Create our own ApplicationService trait for simplicity
#[async_trait]
pub trait AppService {
    type Error;

    async fn current_height(&self) -> std::result::Result<u64, Self::Error>;
    async fn apply_block(&self, block: Block) -> std::result::Result<(), Self::Error>;
    async fn propose_block(
        &self,
        height: u64,
        round: u64,
    ) -> std::result::Result<Block, Self::Error>;
}

/// AuraApplication implements a simplified application service
#[derive(Debug)]
pub struct AuraApplication {
    /// The application state
    state: Arc<Mutex<AuraState>>,
    /// Node ID in the network
    node_id: String,
}

impl AuraApplication {
    /// Create a new AuraApplication with the given state
    pub fn new(state: Arc<Mutex<AuraState>>, node_id: String) -> Self {
        Self { state, node_id }
    }
}

#[async_trait]
impl AppService for AuraApplication {
    type Error = Error;

    /// Get current height of the application state
    async fn current_height(&self) -> Result<u64> {
        let state = self.state.lock().map_err(|e| Error::State(e.to_string()))?;
        Ok(state.height_value())
    }

    /// Apply a committed block to the application state
    async fn apply_block(&self, block: Block) -> Result<()> {
        info!("Applying block at height {}", block.height);

        let mut state = self.state.lock().map_err(|e| Error::State(e.to_string()))?;

        // Parse and apply transactions from the block data
        // Update the state height
        state.apply_block(block)?;

        Ok(())
    }

    /// Generate a new block proposal
    async fn propose_block(&self, height: u64, round: u64) -> Result<Block> {
        info!("Proposing block at height {} round {}", height, round);

        let state = self.state.lock().map_err(|e| Error::State(e.to_string()))?;

        // Create a new block with transactions from the mempool
        let new_block = state.create_block_proposal(height, round, self.node_id.clone())?;

        Ok(new_block)
    }
}
