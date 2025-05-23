use std::{cmp::Ordering, collections::VecDeque, path::Path, sync::Arc};

use crate::malachitebft_core_types::{Round, Value as MalachiteValue};
use aura_core::Transaction;
use redb::{Database, ReadableTable, TableDefinition, WriteTransaction};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, error, info, warn};

use crate::{Error, Result as AuraResult};
use ark_serialize::CanonicalDeserialize;
use aura_core::{CurveFr, ZkpHandler, ZkpParameters};
use once_cell::sync::Lazy;

// ZKP parameters (demo): generate once with dummy circuit
static ZKP_PARAMS: Lazy<ZkpParameters> =
    Lazy::new(|| ZkpParameters::generate_dummy_for_circuit().unwrap());

// Derive Ord and PartialOrd for Block and ValidatorUpdate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorUpdate {
    pub pub_key: Vec<u8>,
    pub power: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    db_path: std::path::PathBuf,
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

// Manually implement the required traits using current_height for comparison
impl PartialEq for AuraState {
    fn eq(&self, other: &Self) -> bool {
        self.current_height == other.current_height
    }
}

impl Eq for AuraState {}

impl PartialOrd for AuraState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AuraState {
    fn cmp(&self, other: &Self) -> Ordering {
        self.current_height.cmp(&other.current_height)
    }
}

const GENESIS_APP_HASH_PLACEHOLDER: &[u8] = b"genesis_app_hash_placeholder_for_height_0";

// Implement Value trait for AuraState
impl MalachiteValue for AuraState {
    type Id = u64;

    fn id(&self) -> Self::Id {
        self.current_height
    }
}

impl AuraState {
    pub fn new(
        db_path: impl AsRef<Path>,
        node_private_key: Arc<aura_core::PrivateKey>,
    ) -> AuraResult<Self> {
        let db_path_buf = db_path.as_ref().to_path_buf();
        let db = Database::create(&db_path_buf)?;
        // create tables if they are missing (first run)
        Self::init_db(&db)?;
        let (current_height, current_app_hash) = Self::load_initial_state(&db)?;
        info!(
            "AuraState initialized. Current height: {}, App hash: {}",
            current_height,
            hex::encode(&current_app_hash)
        );
        Ok(Self {
            db,
            db_path: db_path_buf,
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

    pub fn get_pending_block(&self) -> AuraResult<Block> {
        if self.pending_block_height == 0 {
            return Err(Error::State("No pending block".into()));
        }

        Ok(Block {
            height: self.pending_block_height,
            proposer_address: self.pending_block_proposer_address.clone(),
            timestamp: self.pending_block_timestamp,
            transactions: self.pending_transactions.clone(),
        })
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

        // Real ZKP verification: reconstruct public inputs and verify proof
        // Deserialize anchor into field element
        let anchor_fr = CurveFr::deserialize_uncompressed(&mut &tx.anchor[..])
            .map_err(|e| Error::State(format!("Failed to parse anchor: {}", e)))?;
        let fee_val = tx.fee.0;
        // Expect exactly one nullifier and two commitments
        if tx.spent_nullifiers.len() != 1 || tx.new_note_commitments.len() != 2 {
            return Err(Error::State(
                "Invalid transaction format: wrong number of nullifiers or commitments".to_string(),
            ));
        }
        // Deserialize nullifier and commitments to field elements
        let nullifier_fr =
            CurveFr::deserialize_uncompressed(&mut &tx.spent_nullifiers[0].to_bytes()[..])
                .map_err(|e| Error::State(format!("Failed to parse nullifier: {}", e)))?;
        let out_commit_fr =
            CurveFr::deserialize_uncompressed(&mut &tx.new_note_commitments[0].to_bytes()[..])
                .map_err(|e| Error::State(format!("Failed to parse output commitment: {}", e)))?;
        let change_commit_fr =
            CurveFr::deserialize_uncompressed(&mut &tx.new_note_commitments[1].to_bytes()[..])
                .map_err(|e| Error::State(format!("Failed to parse change commitment: {}", e)))?;
        let public_inputs = ZkpHandler::prepare_public_inputs_for_verification(
            anchor_fr,
            fee_val,
            nullifier_fr,
            out_commit_fr,
            change_commit_fr,
        );
        let proof_ok = ZkpHandler::verify_proof(
            &ZKP_PARAMS.prepared_verifying_key,
            &public_inputs,
            &tx.zk_proof_data,
        )
        .map_err(|e| Error::State(format!("ZKP verify error: {}", e)))?;
        if !proof_ok {
            return Err(Error::State("ZKP verification failed".to_string()));
        }
        debug!("DeliverTx: ZKP verified for tx {:?}", hex::encode(tx_id));
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

    /// Retrieve a stored block by height.  Returns an error if the block is not
    /// present in the database.
    pub fn get_block(&self, height: u64) -> AuraResult<Block> {
        let read_txn = self.db.begin_read()?;
        let blocks_table = read_txn.open_table(BLOCKS_TABLE)?;
        if let Some(entry) = blocks_table.get(&height)? {
            let block_bytes = entry.value();
            let block: Block = serde_json::from_slice(block_bytes)
                .map_err(|e| Error::State(format!("Failed to deserialize block: {}", e)))?;
            Ok(block)
        } else {
            Err(Error::State(format!("Block at height {height} not found")))
        }
    }

    /// Minimum height retained in the state database
    pub fn min_height(&self) -> AuraResult<u64> {
        let read_txn = self.db.begin_read()?;
        let blocks_table = read_txn.open_table(BLOCKS_TABLE)?;
        if let Some((key_guard, _)) = blocks_table.first()? {
            Ok(key_guard.value())
        } else {
            Ok(0)
        }
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

    /// Ensure metadata and other tables exist so that initial load succeeds on a fresh DB
    fn init_db(db: &Database) -> AuraResult<()> {
        let write_txn = db.begin_write()?;
        // Opening the table creates it if it does not exist
        write_txn.open_table(METADATA_TABLE)?;
        write_txn.open_table(BLOCKS_TABLE)?;
        write_txn.open_table(TRANSACTIONS_TABLE)?;
        write_txn.commit()?;
        Ok(())
    }
}

impl Clone for AuraState {
    fn clone(&self) -> Self {
        let db =
            Database::open(&self.db_path).expect("Failed to open database when cloning AuraState");
        Self {
            db,
            db_path: self.db_path.clone(),
            current_height: self.current_height,
            current_app_hash: self.current_app_hash.clone(),
            pending_block_height: self.pending_block_height,
            pending_block_proposer_address: self.pending_block_proposer_address.clone(),
            pending_block_timestamp: self.pending_block_timestamp,
            pending_transactions: self.pending_transactions.clone(),
            node_private_key: Arc::clone(&self.node_private_key),
            current_round: self.current_round,
            mempool: self.mempool.clone(),
        }
    }
}
