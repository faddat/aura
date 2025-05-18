use std::{collections::VecDeque, path::Path, sync::Arc};

use crate::malachitebft_core_types::Round;
use aura_core::Transaction;
use redb::{Database, TableDefinition, WriteTransaction};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, error, info, warn};

use crate::{Error, Result as AuraResult};

// Derive Ord and PartialOrd for Block and ValidatorUpdate
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ValidatorUpdate {
    pub pub_key: Vec<u8>,
    pub power: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Block {
    pub height: u64,
    pub proposer_address: String,
    pub timestamp: i64,
    pub transactions: Vec<Transaction>,
}

const METADATA_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("metadata");
const BLOCKS_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("blocks");
const TRANSACTIONS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("transactions");

#[derive(Debug, Clone, Default)]
pub struct ExecTxResult {
    pub code: u32,
    pub log: String,
}

#[derive(Debug)]
pub struct AuraState {
    db: Database,
    pub current_height: u64,
    current_app_hash: Vec<u8>,
    pub pending_block_height: u64,
    pending_block_proposer_address: String,
    pending_block_timestamp: i64,
    pending_transactions: Vec<Transaction>,
    #[allow(dead_code)]
    node_private_key: Arc<aura_core::PrivateKey>,
    pub current_round: Round,
    mempool: VecDeque<Transaction>,
}

const GENESIS_APP_HASH_PLACEHOLDER: &[u8] = b"genesis_app_hash_placeholder_for_height_0";

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
            hex::encode(current_app_hash) // Corrected typo: current_app_hash
        );
        Ok(Self {
            db,
            current_height,
            current_app_hash,
            pending_block_height: 0,
            pending_block_proposer_address: String::new(),
            pending_block_timestamp: chrono::Utc::now().timestamp(),
            pending_transactions: Vec::new(),
            node_private_key,
            current_round: Round::new(0),
            mempool: VecDeque::new(),
        })
    }

    fn load_initial_state(db: &Database) -> AuraResult<(u64, Vec<u8>)> {
        let read_txn = db.begin_read()?;
        let metadata_table = read_txn.open_table(METADATA_TABLE)?;

        let height_bytes_opt = metadata_table.get("current_height")?;
        let height = height_bytes_opt
            .map(|guard| {
                let bytes_slice = guard.value();
                if bytes_slice.len() == 8 {
                    u64::from_le_bytes(
                        bytes_slice
                            .try_into()
                            .expect("Slice to array conversion failed for height"),
                    )
                } else {
                    warn!("Invalid byte length for 'current_height' in DB, defaulting to 0.");
                    0
                }
            })
            .unwrap_or(0);

        let app_hash_opt = metadata_table.get("current_app_hash")?;
        let app_hash = app_hash_opt
            .map(|guard| guard.value().to_vec())
            .unwrap_or_else(|| {
                info!("No 'current_app_hash' found in DB, using initial genesis hash.");
                let mut hasher = Sha256::new();
                hasher.update(GENESIS_APP_HASH_PLACEHOLDER);
                hasher.finalize().to_vec()
            });

        let final_app_hash = if height == 0 {
            let mut hasher = Sha256::new();
            hasher.update(GENESIS_APP_HASH_PLACEHOLDER);
            hasher.finalize().to_vec()
        } else {
            app_hash
        };

        Ok((height, final_app_hash))
    }

    pub fn height_value(&self) -> u64 {
        self.current_height
    }

    pub fn app_hash(&self) -> AuraResult<Vec<u8>> {
        Ok(self.current_app_hash.clone())
    }

    pub fn add_transaction_to_local_mempool(&mut self, tx: Transaction) -> AuraResult<()> {
        info!("Adding transaction {:?} to local mempool", tx.id()?);
        self.mempool.push_back(tx);
        Ok(())
    }

    pub fn begin_block(
        &mut self,
        height: u64,
        proposer_address: Vec<u8>,
        timestamp: i64,
    ) -> AuraResult<()> {
        debug!(
            "State: BeginBlock for height {}, proposer: {}, timestamp: {}",
            height,
            hex::encode(&proposer_address),
            timestamp
        );
        // It's okay for pending_block_height to be 0 if this is the first block after init.
        // The check should be against current_height.
        if self.pending_block_height != 0 && height != self.current_height + 1 {
            warn!(
                "BeginBlock: Overwriting a pending block (pending: {}, new: {}, current_committed: {}). This might happen if a previous commit failed or was interrupted.",
                self.pending_block_height, height, self.current_height
            );
        }
        if self.pending_block_height == 0
            && height != self.current_height + 1
            && self.current_height != 0
        {
            // If it's not the very first block (height 1 from current 0)
            if height != self.current_height + 1 {
                let err_msg = format!(
                    "BeginBlock: Proposed height {} is not sequential after current committed height {}. (Pending block was 0)",
                    height, self.current_height
                );
                error!("{}", err_msg);
                return Err(Error::State(err_msg));
            }
        }

        self.pending_block_height = height;
        self.pending_block_proposer_address = hex::encode(proposer_address);
        self.pending_block_timestamp = timestamp;
        self.pending_transactions.clear();
        Ok(())
    }

    pub fn deliver_tx(&mut self, tx: Transaction) -> AuraResult<ExecTxResult> {
        let tx_id = tx.id()?;
        debug!("State: DeliverTx for tx_id: {:?}", hex::encode(tx_id));

        if self.pending_block_height == 0 {
            return Err(Error::State(
                "DeliverTx called before BeginBlock or after Commit".to_string(),
            ));
        }

        debug!(
            "DeliverTx: Mock ZKP verification passed for tx {:?}",
            hex::encode(tx_id)
        );
        for nullifier in &tx.spent_nullifiers {
            debug!(
                "DeliverTx: Checking nullifier {:?} (mock)",
                nullifier.to_bytes()
            );
        }
        for commitment in &tx.new_note_commitments {
            debug!(
                "DeliverTx: Staging note commitment {:?} (mock)",
                commitment.to_bytes()
            );
        }
        self.pending_transactions.push(tx);
        Ok(ExecTxResult {
            code: 0,
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
        Ok(vec![])
    }

    pub fn commit_block(&mut self) -> AuraResult<Vec<u8>> {
        if self.pending_block_height == 0 {
            return Err(Error::State(
                "Commit called without a pending block.".to_string(),
            ));
        }
        if self.pending_block_height != self.current_height + 1
            && !(self.current_height == 0 && self.pending_block_height == 1)
        {
            // This check might be too strict if recovering or restarting a height, but good for normal flow.
            error!(
                "State: Commit_block height mismatch! Pending: {}, Current Committed: {}. Aborting commit.",
                self.pending_block_height, self.current_height
            );
            return Err(Error::State(format!(
                "Commit_block height mismatch. Pending: {}, Current Committed: {}.",
                self.pending_block_height, self.current_height
            )));
        }
        info!(
            "State: Committing block for height {}",
            self.pending_block_height
        );

        let block_to_store = Block {
            height: self.pending_block_height,
            proposer_address: self.pending_block_proposer_address.clone(),
            timestamp: self.pending_block_timestamp,
            transactions: self.pending_transactions.clone(),
        };

        let new_app_hash = {
            let mut hasher = Sha256::new();
            hasher.update(block_to_store.height.to_le_bytes());
            for tx in &block_to_store.transactions {
                hasher.update(tx.id()?);
            }
            hasher.update(block_to_store.proposer_address.as_bytes());
            hasher.update(block_to_store.timestamp.to_le_bytes());
            hasher.finalize().to_vec()
        };

        self.save_block_to_db(&block_to_store, &new_app_hash)?;

        self.current_height = block_to_store.height;
        self.current_app_hash = new_app_hash.clone();

        info!(
            "State: Successfully committed block {}. New height: {}, New app_hash: {}",
            block_to_store.height,
            self.current_height,
            hex::encode(&self.current_app_hash)
        );

        self.pending_block_height = 0;
        self.pending_transactions.clear();

        Ok(new_app_hash)
    }

    fn save_block_to_db(&self, block: &Block, app_hash: &[u8]) -> AuraResult<()> {
        let write_txn = self.db.begin_write()?;
        Self::persist_block_and_txs(&write_txn, block)?;

        let mut metadata_table = write_txn.open_table(METADATA_TABLE)?;
        metadata_table.insert("current_height", &block.height.to_le_bytes().as_slice())?;
        metadata_table.insert("current_app_hash", app_hash)?;

        drop(metadata_table);
        write_txn.commit()?;
        Ok(())
    }

    fn persist_block_and_txs(
        write_txn: &WriteTransaction,
        block_to_store: &Block,
    ) -> AuraResult<()> {
        let mut blocks_table = write_txn.open_table(BLOCKS_TABLE)?;
        let block_bytes = serde_json::to_vec(block_to_store)
            .map_err(|e| Error::State(format!("Failed to serialize block: {}", e)))?;
        blocks_table.insert(&block_to_store.height, block_bytes.as_slice())?;

        let mut tx_table = write_txn.open_table(TRANSACTIONS_TABLE)?;
        for tx in &block_to_store.transactions {
            let tx_id_bytes = tx.id()?;
            let tx_bytes = serde_json::to_vec(tx)
                .map_err(|e| Error::State(format!("Failed to serialize tx: {}", e)))?;
            tx_table.insert(tx_id_bytes.as_ref(), tx_bytes.as_slice())?;
        }
        Ok(())
    }
}
