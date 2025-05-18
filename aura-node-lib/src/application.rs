use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tracing::info;

use crate::{
    Error, Result,
    state::{AuraState, Block},
};

// Define our application service trait with needed methods
#[async_trait]
pub trait AppService {
    async fn current_height(&self) -> Result<u64>;
    async fn propose_block(&self, height: u64, round: u64) -> Result<Block>;
    async fn apply_block(&self, block: Block) -> Result<()>;
}

/// AuraApplication implements our AppService trait
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
    /// Get current height of the application state
    async fn current_height(&self) -> Result<u64> {
        let state = self.state.lock().map_err(|e| Error::State(e.to_string()))?;
        Ok(state.height_value())
    }

    /// Generate a new block proposal
    async fn propose_block(&self, height: u64, round: u64) -> Result<Block> {
        info!("Proposing block at height {} round {}", height, round);

        let _state = self.state.lock().map_err(|e| Error::State(e.to_string()))?;

        // Create a new block with transactions from the mempool
        let block = Block {
            height,
            proposer: self.node_id.clone(),
            transactions: Vec::new(), // Empty for now
        };

        Ok(block)
    }

    /// Apply a committed block to the application state
    async fn apply_block(&self, block: Block) -> Result<()> {
        info!("Applying block at height {}", block.height);

        let mut state = self.state.lock().map_err(|e| Error::State(e.to_string()))?;

        // Call begin_block, deliver transactions, end_block, and commit
        state.begin_block(block.height)?;

        for tx in block.transactions {
            state.deliver_tx(tx)?;
        }

        state.end_block(block.height)?;
        state.commit_block()?;

        Ok(())
    }
}
