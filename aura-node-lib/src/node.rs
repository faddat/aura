use std::{collections::VecDeque, path::Path, sync::Arc};

use aura_core::Transaction;
use redb::{Database, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info};

use crate::{Error, Result};

// Simple Block structure for node-lib internal use, not tied to Malachite yet.
// This will hold aura_core::Transaction objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub height: u64,
    pub round: u64,       // Simplified round
    pub proposer: String, // NodeId as String for now
    pub transactions: Vec<Transaction>, // Aura core transactions
                          // pub prev_block_hash: [u8; 32], // Could add later
                          // pub timestamp: u64,
}

/// Table definitions for the state database
const METADATA_TABLE: TableDefinition<&str, u64> = TableDefinition::new("metadata"); // For "current_height"
#[allow(dead_code)]
const BLOCKS_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("blocks"); // Key: height, Value: serialized Block
#[allow(dead_code)]
const TRANSACTIONS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("transactions"); // Key: tx_id, Value: serialized Transaction (optional, for indexing)

/// Represents the application state for the Aura blockchain
#[derive(Debug)]
pub struct AuraState {
    #[allow(dead_code)]
    db: Database,
    current_height: u64,
    #[allow(dead_code)] // Will be used for actual signing later
    private_key: Arc<aura_core::PrivateKey>,
    // Simple in-memory mempool
    #[allow(dead_code)]
    mempool: VecDeque<Transaction>,
}

impl AuraState {
    #[allow(dead_code)]
    pub fn new(db_path: impl AsRef<Path>, private_key: Arc<aura_core::PrivateKey>) -> Result<Self> {
        let db = Database::create(db_path)?;
        let current_height = Self::get_or_init_height(&db)?;
        info!("AuraState initialized. Current height: {}", current_height);
        Ok(Self {
            db,
            current_height,
            private_key,
            mempool: VecDeque::new(),
        })
    }

    #[allow(dead_code)]
    pub fn height_value(&self) -> u64 {
        self.current_height
    }

    // Method to add a transaction to the mempool (e.g., from RPC)
    #[allow(dead_code)]
    pub fn add_transaction_to_mempool(&mut self, tx: Transaction) -> Result<()> {
        // Basic validation could happen here before adding to mempool
        info!("Adding transaction {:?} to mempool", tx.id()?);
        self.mempool.push_back(tx);
        Ok(())
    }

    #[allow(dead_code)]
    fn get_transactions_for_block(&mut self, max_txs: usize) -> Vec<Transaction> {
        let mut txs = Vec::new();
        for _ in 0..max_txs {
            if let Some(tx) = self.mempool.pop_front() {
                txs.push(tx);
            } else {
                break;
            }
        }
        txs
    }

    #[allow(dead_code)]
    pub fn apply_block(&mut self, block: Block) -> Result<()> {
        debug!("Attempting to apply block at height {}", block.height);

        if block.height != self.current_height + 1 {
            return Err(Error::State(format!(
                "Block height {} is not next in sequence after current height {}",
                block.height, self.current_height
            )));
        }

        let write_txn = self.db.begin_write()?;
        {
            // Scope for mutable borrow of write_txn
            // Process transactions
            for tx in &block.transactions {
                info!("Processing tx {:?} in block {}", tx.id()?, block.height);
                // 1. (Mock ZKP) Verify proof - In a real scenario, ZkpHandler is used.
                //    aura_core::zkp::ZkpHandler::verify_proof(...) -> Ok(true) for mock
                // 2. Check nullifiers (mock for now)
                for nullifier in &tx.spent_nullifiers {
                    debug!("Checking nullifier {:?} (mock)", nullifier.to_bytes());
                    // TODO: Check against a redb nullifier set table
                }
                // 3. Add new note commitments (mock for now)
                for commitment in &tx.new_note_commitments {
                    debug!("Adding note commitment {:?} (mock)", commitment.to_bytes());
                    // TODO: Add to a redb note commitment table/Merkle tree
                }
                // 4. (Optional) Store transaction by ID for indexing
                let mut tx_table = write_txn.open_table(TRANSACTIONS_TABLE)?;
                let tx_id_bytes = tx.id()?;
                let tx_bytes = serde_json::to_vec(tx)
                    .map_err(|e| Error::State(format!("Failed to serialize tx: {}", e)))?;
                tx_table.insert(tx_id_bytes.as_ref(), tx_bytes.as_slice())?; // Store serialized tx
            }

            // Store the block
            let mut blocks_table = write_txn.open_table(BLOCKS_TABLE)?;
            let block_bytes = serde_json::to_vec(&block)
                .map_err(|e| Error::State(format!("Failed to serialize block: {}", e)))?;
            blocks_table.insert(&block.height, block_bytes.as_slice())?;

            // Update current height
            let mut metadata_table = write_txn.open_table(METADATA_TABLE)?;
            metadata_table.insert("current_height", &block.height)?;
        } // write_txn borrow ends

        write_txn.commit()?;

        self.current_height = block.height;
        info!(
            "Successfully applied block at height {}. New current height: {}",
            block.height, self.current_height
        );
        Ok(())
    }

    #[allow(dead_code)]
    pub fn create_block_proposal(
        &mut self, // Changed to &mut to allow taking transactions from mempool
        height: u64,
        round: u64,
        node_id: String,
    ) -> Result<Block> {
        let transactions = self.get_transactions_for_block(10); // Take up to 10 txs
        info!(
            "Creating block proposal for height {} with {} transactions.",
            height,
            transactions.len()
        );

        let block = Block {
            height,
            round,
            proposer: node_id,
            transactions,
        };
        Ok(block)
    }

    fn get_or_init_height(db: &Database) -> Result<u64> {
        let read_txn = db.begin_read()?;

        // Try to read the height
        match read_txn.open_table(METADATA_TABLE) {
            Ok(table) => {
                match table.get("current_height")? {
                    Some(height_guard) => {
                        let height_value = height_guard.value();
                        Ok(height_value)
                    }
                    None => {
                        // Height key exists but no value, initialize to 0
                        drop(read_txn);
                        let write_txn = db.begin_write()?;
                        {
                            let mut metadata_table = write_txn.open_table(METADATA_TABLE)?;
                            metadata_table.insert("current_height", &0u64)?;
                        }
                        write_txn.commit()?;
                        Ok(0)
                    }
                }
            }
            Err(_) => {
                // Table doesn't exist, create it and set height to 0
                drop(read_txn);
                let write_txn = db.begin_write()?;
                {
                    // In newer redb versions, tables are created automatically when opened
                    let mut metadata_table = write_txn.open_table(METADATA_TABLE)?;
                    metadata_table.insert("current_height", &0u64)?;
                }
                write_txn.commit()?;
                Ok(0)
            }
        }
    }

    // Placeholder for app_hash calculation if needed by Malachite
    #[allow(dead_code)]
    pub fn app_hash(&self) -> Result<Vec<u8>> {
        // For now, just hash the current height as a placeholder
        let mut hasher = Sha256::new();
        hasher.update(self.current_height.to_le_bytes());
        Ok(hasher.finalize().to_vec())
    }

    // Placeholder for committing state and getting app hash
    #[allow(dead_code)]
    pub fn commit_and_get_app_hash(&mut self) -> Result<Vec<u8>> {
        // redb commits transactions atomically. If self.db.begin_write() and .commit()
        // are used in apply_block, the commit is already handled there.
        // This function might just calculate and return the app_hash based on persisted state.
        self.app_hash()
    }
}

// No demo function needed as we're using a different approach to avoid dead code warnings
