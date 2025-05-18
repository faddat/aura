use std::{collections::VecDeque, path::Path, sync::Arc};

use aura_core::Transaction;
use redb::{Database, TableDefinition, WriteTransaction}; // Added WriteTransaction
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, error, info};

use crate::{Error, Result as AuraResult}; // Crate-local Result and Error

// Simple validator update structure
#[derive(Debug, Clone)]
pub struct ValidatorUpdate {
    pub validator_id: String,
    pub power: u64,
}

// Simple Block structure for node-lib internal use, not tied to Malachite yet.
// This will hold aura_core::Transaction objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub height: u64,
    // pub round: u64, // Round is managed by consensus, may not be needed in app block
    pub proposer: String, // Proposer ID comes from Malachite's BeginBlock
    pub transactions: Vec<Transaction>,
    // pub timestamp: u64, // Timestamp comes from Malachite's BeginBlock header
    // pub app_hash: Vec<u8>, // Hash of the state after this block is applied
}

/// Table definitions for the state database
const METADATA_TABLE: TableDefinition<&str, u64> = TableDefinition::new("metadata");
const BLOCKS_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("blocks");
const TRANSACTIONS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("transactions");
// TODO: Add tables for nullifiers and note commitments for proper state management
// const NULLIFIERS_TABLE: TableDefinition<&[u8; 32], ()> = TableDefinition::new("nullifiers");
// const COMMITMENTS_TABLE: TableDefinition<&[u8; 32], ()> = TableDefinition::new("commitments");

/// Represents the execution result of a transaction. Placeholder for now.
#[derive(Debug, Clone, Default)]
pub struct ExecTxResult {
    pub code: u32, // 0 for success
    pub log: String,
    // Add other fields like gas_used, events, etc. if needed
}

/// Represents the application state for the Aura blockchain
#[derive(Debug)]
pub struct AuraState {
    db: Database,
    current_height: u64,
    current_app_hash: Vec<u8>, // Store the latest committed app hash

    // Staging area for the current block being processed
    pending_block_height: u64,
    pending_block_proposer: String, // From BeginBlock
    pending_transactions: Vec<Transaction>,
    // TODO: Stage nullifiers and commitments for the current block
    // pending_spent_nullifiers: Vec<Nullifier>,
    // pending_new_commitments: Vec<NoteCommitment>,
    #[allow(dead_code)] // Will be used for actual signing or identity later
    node_private_key: Arc<aura_core::PrivateKey>,

    // Simple in-memory mempool - Malachite will have its own,
    // but this can be used by RPC to submit to Malachite via CheckTx
    mempool: VecDeque<Transaction>,
}

impl AuraState {
    pub fn new(
        db_path: impl AsRef<Path>,
        node_private_key: Arc<aura_core::PrivateKey>,
    ) -> AuraResult<Self> {
        let db = Database::create(db_path)?;
        let (current_height, current_app_hash) = Self::load_initial_state(&db)?;
        info!(
            "AuraState initialized. Current height: {}, App hash: {}",
            current_height,
            hex::encode(&current_app_hash)
        );
        Ok(Self {
            db,
            current_height,
            current_app_hash,
            pending_block_height: 0, // Initialized by begin_block
            pending_block_proposer: String::new(),
            pending_transactions: Vec::new(),
            node_private_key,
            mempool: VecDeque::new(),
        })
    }

    fn load_initial_state(db: &Database) -> AuraResult<(u64, Vec<u8>)> {
        let read_txn = db.begin_read()?;
        let metadata_table = read_txn.open_table(METADATA_TABLE)?;

        let height = metadata_table
            .get("current_height")?
            .map(|guard| guard.value())
            .unwrap_or(0);

        // For app_hash, we might store it directly or recompute if necessary.
        // For simplicity, let's assume we can compute it from height if not stored,
        // or store a dedicated "app_hash" key.
        // For now, a simple hash of height.
        let app_hash = if height == 0 {
            // Initial app hash for genesis state (empty or predefined)
            // Let's use a hash of "genesis" for a non-zero initial hash.
            let mut hasher = Sha256::new();
            hasher.update(b"genesis_app_hash_placeholder_for_height_0"); // Or a more robust genesis hash
            hasher.finalize().to_vec()
        } else {
            // In a real system, you'd load the stored app_hash for `height`.
            // For this example, we'll re-calculate based on height.
            // This needs to be consistent with what `commit_block` stores.
            // Let's assume commit_block will store the actual app_hash.
            // We'll need a way to fetch the app_hash for 'height'.
            // This is a simplification for now.
            // A proper way would be to load the last committed block and get its app_hash,
            // or store `current_app_hash` in METADATA_TABLE.
            metadata_table
                .get("current_app_hash")?
                .map(|guard| {
                    // Assuming app_hash is stored as Vec<u8>
                    // This is tricky with redb's `Value` if not stored as fixed size or simple type.
                    // For now, let's simplify and recompute, assuming it was stored.
                    // This part needs a more robust solution for storing/retrieving app_hash.
                    // For this iteration, let's calculate it.
                    let mut hasher = Sha256::new();
                    hasher.update(height.to_le_bytes());
                    hasher.finalize().to_vec()
                })
                .unwrap_or_else(|| {
                    // If not found (e.g. fresh DB that went past height 0 via external means)
                    let mut hasher = Sha256::new();
                    hasher.update(height.to_le_bytes()); // Fallback
                    hasher.finalize().to_vec()
                })
        };
        Ok((height, app_hash))
    }

    pub fn height_value(&self) -> u64 {
        self.current_height
    }

    pub fn app_hash(&self) -> AuraResult<Vec<u8>> {
        Ok(self.current_app_hash.clone())
    }

    // Method to add a transaction to the local mempool (e.g., from RPC)
    // This tx would then be submitted to Malachite via CheckTx.
    pub fn add_transaction_to_local_mempool(&mut self, tx: Transaction) -> AuraResult<()> {
        info!(
            "Adding transaction {:?} to local mempool (for later CheckTx)",
            tx.id()?
        );
        self.mempool.push_back(tx);
        Ok(())
    }

    // --- Methods for Malachite AppService flow ---

    pub fn begin_block(
        &mut self,
        height: u64, /*proposer: Vec<u8>, timestamp: u64 */
    ) -> AuraResult<()> {
        debug!("State: BeginBlock for height {}", height);
        if height != self.current_height + 1 {
            let err_msg = format!(
                "BeginBlock: Proposed height {} is not sequential. Current height: {}",
                height, self.current_height
            );
            error!("{}", err_msg);
            return Err(Error::State(err_msg));
        }
        self.pending_block_height = height;
        // self.pending_block_proposer = hex::encode(proposer); // Proposer from Malachite
        // self.pending_block_timestamp = timestamp; // Timestamp from Malachite
        self.pending_transactions.clear();
        // self.pending_spent_nullifiers.clear();
        // self.pending_new_commitments.clear();
        Ok(())
    }

    pub fn deliver_tx(&mut self, tx: Transaction) -> AuraResult<ExecTxResult> {
        let tx_id = tx.id()?; // Calculate ID once
        debug!("State: DeliverTx for tx_id: {:?}", hex::encode(tx_id));

        if self.pending_block_height == 0 {
            return Err(Error::State(
                "DeliverTx called before BeginBlock or after Commit".to_string(),
            ));
        }

        // 1. (Mock ZKP) Verify proof
        // if !aura_core::zkp::ZkpHandler::verify_proof(&pvk, &public_inputs, &tx.zk_proof_data)? {
        //     return Ok(ExecTxResult { code: 1, log: "ZKP verification failed".to_string() });
        // }
        // For mock:
        debug!(
            "DeliverTx: Mock ZKP verification passed for tx {:?}",
            hex::encode(tx_id)
        );

        // 2. Check nullifiers (mock for now)
        //    In a real system, check against a committed nullifier set.
        //    And also check against pending nullifiers for the current block to prevent double-spend within the same block.
        for nullifier in &tx.spent_nullifiers {
            debug!(
                "DeliverTx: Checking nullifier {:?} (mock)",
                nullifier.to_bytes()
            );
            // TODO: Add to `self.pending_spent_nullifiers` and check for duplicates.
        }

        // 3. Stage new note commitments (mock for now)
        for commitment in &tx.new_note_commitments {
            debug!(
                "DeliverTx: Staging note commitment {:?} (mock)",
                commitment.to_bytes()
            );
            // TODO: Add to `self.pending_new_commitments`.
        }

        self.pending_transactions.push(tx);

        Ok(ExecTxResult {
            code: 0, // Success
            log: format!("tx {} processed and staged", hex::encode(tx_id)),
        })
    }

    pub fn end_block(&mut self, height: u64) -> AuraResult<Vec<ValidatorUpdate>> {
        debug!("State: EndBlock for height {}", height);
        if self.pending_block_height != height {
            return Err(Error::State(format!(
                "EndBlock height mismatch. Expected: {}, Got: {}",
                self.pending_block_height, height
            )));
        }
        // For now, we return no validator updates
        Ok(vec![])
    }

    pub fn commit_block(&mut self) -> AuraResult<Vec<u8>> {
        if self.pending_block_height == 0 {
            return Err(Error::State(
                "Commit called without a pending block. Did BeginBlock run?".to_string(),
            ));
        }
        info!(
            "State: Committing block for height {}",
            self.pending_block_height
        );

        // Create the block to be stored
        let block_to_store = Block {
            height: self.pending_block_height,
            proposer: self.pending_block_proposer.clone(),
            transactions: self.pending_transactions.clone(),
        };

        {
            let write_txn = self.db.begin_write()?;

            // --- Persist changes ---
            Self::persist_block_and_state(&write_txn, &block_to_store)?;

            // Update metadata
            {
                let mut metadata_table = write_txn.open_table(METADATA_TABLE)?;
                metadata_table.insert("current_height", &block_to_store.height)?;
            }

            write_txn.commit()?;
        }
        // --- Persistence complete ---

        // Calculate the new app_hash
        let new_app_hash = {
            let mut hasher = Sha256::new();
            hasher.update(block_to_store.height.to_le_bytes());
            for tx in &block_to_store.transactions {
                hasher.update(tx.id()?);
            }
            hasher.finalize().to_vec()
        };

        // Update in-memory state
        self.current_height = block_to_store.height;
        self.current_app_hash = new_app_hash.clone();

        info!(
            "State: Successfully committed block {}. New height: {}, New app_hash: {}",
            block_to_store.height,
            self.current_height,
            hex::encode(&self.current_app_hash)
        );

        // Reset pending state
        self.pending_block_height = 0; // Mark as no block pending
        self.pending_transactions.clear();

        Ok(new_app_hash)
    }

    fn persist_block_and_state(
        write_txn: &WriteTransaction,
        block_to_store: &Block,
    ) -> AuraResult<()> {
        // Store the block itself
        let mut blocks_table = write_txn.open_table(BLOCKS_TABLE)?;
        let block_bytes = serde_json::to_vec(block_to_store)
            .map_err(|e| Error::State(format!("Failed to serialize block: {}", e)))?;
        blocks_table.insert(&block_to_store.height, block_bytes.as_slice())?;

        // Store transactions by ID for indexing (optional)
        let mut tx_table = write_txn.open_table(TRANSACTIONS_TABLE)?;
        for tx in &block_to_store.transactions {
            let tx_id_bytes = tx.id()?;
            let tx_bytes = serde_json::to_vec(tx)
                .map_err(|e| Error::State(format!("Failed to serialize tx: {}", e)))?;
            tx_table.insert(tx_id_bytes.as_ref(), tx_bytes.as_slice())?;
        }

        // TODO: Persist actual nullifiers and commitments
        // let mut nullifiers_db_table = write_txn.open_table(NULLIFIERS_TABLE)?;
        // for nullifier in &self.pending_spent_nullifiers {
        //     nullifiers_db_table.insert(nullifier.to_bytes().as_ref(), &())?;
        // }
        // let mut commitments_db_table = write_txn.open_table(COMMITMENTS_TABLE)?;
        // for commitment in &self.pending_new_commitments {
        //     commitments_db_table.insert(commitment.to_bytes().as_ref(), &())?;
        // }
        Ok(())
    }

    // This method is now part of the commit_block logic
    // pub fn commit_and_get_app_hash(&mut self) -> AuraResult<Vec<u8>> {
    //     self.commit_block()
    // }

    // This method is replaced by the ABCI flow (begin_block, deliver_tx, end_block, commit)
    // pub fn apply_block(&mut self, block: Block) -> AuraResult<()> { ... }

    // This method is no longer called directly by AuraNode; Malachite handles block proposal.
    // pub fn create_block_proposal(...) -> AuraResult<Block> { ... }
}
