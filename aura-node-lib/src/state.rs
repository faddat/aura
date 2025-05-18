use std::{path::Path, sync::Arc};

use redb::{Database, TableDefinition};
use tracing::{debug, info};

// Use simple types for now
use crate::{Error, Result};

// Mock types to avoid Malachite dependencies in this file
type NodeId = String;
// We'll use our own simple Block type for the state
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Block {
    pub height: u64,
    pub round: u64,
    pub proposer: String,
    pub data: Vec<u8>,
}

/// Table definitions for the state database
const HEIGHT_TABLE: TableDefinition<&str, u64> = TableDefinition::new("height");
const BLOCKS_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("blocks");

/// Represents the application state for the Aura blockchain
#[derive(Debug)]
pub struct AuraState {
    /// State database
    db: Database,
    /// Current blockchain height
    current_height: u64,
    /// Private key for signing blocks (would typically come from secure storage)
    #[allow(dead_code)]
    private_key: Arc<aura_core::PrivateKey>,
}

impl AuraState {
    /// Create a new AuraState
    pub fn new(db_path: impl AsRef<Path>, private_key: Arc<aura_core::PrivateKey>) -> Result<Self> {
        let db = Database::create(db_path)?;

        // Initialize or read the current height
        let current_height = Self::get_or_init_height(&db)?;

        Ok(Self {
            db,
            current_height,
            private_key,
        })
    }

    /// Get the current blockchain height as a u64
    pub fn height_value(&self) -> u64 {
        self.current_height
    }

    /// Apply a block to the state
    pub fn apply_block(&mut self, block: Block) -> Result<()> {
        debug!("Applying block at height {}", block.height);

        // Verify block height is next in sequence
        if block.height != self.current_height + 1 {
            return Err(Error::State(format!(
                "Block height {} is not next in sequence after current height {}",
                block.height, self.current_height
            )));
        }

        // Start a write transaction
        let write_txn = self.db.begin_write()?;

        // Store the block
        {
            let mut blocks_table = write_txn.open_table(BLOCKS_TABLE)?;
            let block_bytes = serde_json::to_vec(&block)
                .map_err(|e| Error::Other(format!("Failed to serialize block: {}", e)))?;
            blocks_table.insert(block.height, block_bytes.as_slice())?;
        }

        // Update current height
        {
            let mut height_table = write_txn.open_table(HEIGHT_TABLE)?;
            height_table.insert("current", block.height)?;
        }

        // Commit the transaction
        write_txn.commit()?;

        // Update the in-memory height
        self.current_height = block.height;

        info!("Applied block at height {}", block.height);
        Ok(())
    }

    /// Create a new block proposal
    pub fn create_block_proposal(&self, height: u64, round: u64, node_id: NodeId) -> Result<Block> {
        // Create a simple block
        let block = Block {
            height,
            round,
            proposer: node_id,
            data: Vec::new(), // Empty block data for now
        };

        Ok(block)
    }

    /// Get the current height or initialize to 0 if not set
    fn get_or_init_height(db: &Database) -> Result<u64> {
        // First try to read the height from the table
        let read_txn = db.begin_read()?;
        let height = match read_txn.open_table(HEIGHT_TABLE) {
            Ok(table) => {
                if let Some(height_guard) = table.get("current")? {
                    // We found the height in the table
                    let height = height_guard.value();
                    drop(table);
                    drop(read_txn);
                    height
                } else {
                    // Height key exists but no value, initialize to 0
                    drop(table);
                    drop(read_txn);

                    // Create a new write transaction
                    let write_txn = db.begin_write()?;
                    {
                        let mut height_table = write_txn.open_table(HEIGHT_TABLE)?;
                        height_table.insert("current", 0u64)?;
                    }
                    write_txn.commit()?;
                    0
                }
            }
            Err(_) => {
                // Table doesn't exist, drop read transaction
                drop(read_txn);

                // Create a new write transaction
                let write_txn = db.begin_write()?;
                {
                    let mut height_table = write_txn.open_table(HEIGHT_TABLE)?;
                    height_table.insert("current", 0u64)?;
                }
                write_txn.commit()?;
                0
            }
        };

        Ok(height)
    }
}
