use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tracing::info;

// Import directly from the packages to avoid issues
use informalsystems_malachitebft_app::ApplicationService;
use informalsystems_malachitebft_app::PeerId as NodeId;
use informalsystems_malachitebft_core_types::{
    Height, Round, Signature, Value as Block, ValueId as BlockId,
};

use crate::{Error, Result, state::AuraState};

/// AuraApplication implements the Malachite ApplicationService trait
/// to integrate Aura business logic with the consensus engine.
#[derive(Debug)]
pub struct AuraApplication {
    /// The application state
    state: Arc<Mutex<AuraState>>,
    /// Node ID in the network
    node_id: NodeId,
}

impl AuraApplication {
    /// Create a new AuraApplication with the given state
    pub fn new(state: Arc<Mutex<AuraState>>, node_id: NodeId) -> Self {
        Self { state, node_id }
    }
}

#[async_trait]
impl ApplicationService for AuraApplication {
    type Error = Error;

    /// Get current height of the application state
    async fn height(&self) -> Result<Height> {
        let state = self.state.lock().map_err(|e| Error::State(e.to_string()))?;
        Ok(state.height())
    }

    /// Check block is valid for current application state
    async fn check_block(&self, block: &Block) -> Result<()> {
        info!("Checking block {:?} at height {}", block.id(), block.height);

        // Implement block validation logic here
        // For example:
        // 1. Verify transactions in the block
        // 2. Check block structure
        // 3. Verify signatures

        Ok(())
    }

    /// Apply a committed block to the application state
    async fn apply_block(&self, block: Block) -> Result<()> {
        info!("Applying block {:?} at height {}", block.id(), block.height);

        let mut state = self.state.lock().map_err(|e| Error::State(e.to_string()))?;

        // Parse and apply transactions from the block data
        // Update the state height
        state.apply_block(block)?;

        Ok(())
    }

    /// Generate a new block proposal
    async fn propose_block(&self, height: Height, round: Round) -> Result<Block> {
        info!("Proposing block at height {} round {}", height, round);

        let state = self.state.lock().map_err(|e| Error::State(e.to_string()))?;

        // Create a new block with transactions from the mempool
        let new_block = state.create_block_proposal(height, round, self.node_id.clone())?;

        Ok(new_block)
    }

    /// Sign a block proposal
    async fn sign_proposal(
        &self,
        block_id: BlockId,
        height: Height,
        round: Round,
    ) -> Result<Signature> {
        info!(
            "Signing proposal for block {:?} at height {} round {}",
            block_id, height, round
        );

        let state = self.state.lock().map_err(|e| Error::State(e.to_string()))?;

        // Sign the block proposal
        let signature = state.sign_block(block_id, height, round)?;

        Ok(signature)
    }

    /// Verify a signature on a block proposal
    async fn verify_proposal_signature(
        &self,
        signer: &NodeId,
        block_id: BlockId,
        height: Height,
        round: Round,
        signature: &Signature,
    ) -> Result<()> {
        info!(
            "Verifying signature from {:?} for block {:?}",
            signer, block_id
        );

        let state = self.state.lock().map_err(|e| Error::State(e.to_string()))?;

        // Verify the signature
        state.verify_signature(signer, block_id, height, round, signature)?;

        Ok(())
    }
}
