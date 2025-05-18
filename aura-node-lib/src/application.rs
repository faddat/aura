use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use malachitebft_app::{
    AppService as MalachiteAppService,
    types::sync::{Request, Response},
};
use malachitebft_core_types::{
    app::{
        BlockBeginRequest, BlockBeginResponse, BlockEndRequest, BlockEndResponse, CheckTxRequest,
        CheckTxResponse, CommitRequest, CommitResponse, CommitResponseData, DeliverTxRequest,
        DeliverTxResponse, InfoRequest, InfoResponse, InfoResponseData, InitChainRequest,
        InitChainResponse, QueryRequest, QueryResponse, QueryResponseData,
    },
    block::Header as MalachiteHeader, // For extracting proposer and time
    time::Timestamp, // Needed for InfoResponseData and converting Malachite's timestamp
};
use tracing::{debug, error, info, warn};

use crate::{
    Error as AuraError, // Renamed to avoid conflict with MalachiteAppService::Error
    state::{AuraState, Block as AuraInternalBlock, ExecTxResult}, // AuraInternalBlock is what AuraState produces/consumes
};

/// AuraApplication implements Malachite's AppService trait
#[derive(Debug)]
pub struct AuraApplication {
    state: Arc<Mutex<AuraState>>,
    #[allow(dead_code)] // May be useful for logging or app-specific logic
    node_id: String,
}

impl AuraApplication {
    pub fn new(state: Arc<Mutex<AuraState>>, node_id: String) -> Self {
        Self { state, node_id }
    }
}

#[async_trait]
impl MalachiteAppService for AuraApplication {
    type Error = AuraError; // Your existing Error type
    type Transaction = aura_core::Transaction; // Your core transaction type

    async fn info(&self, request: Request<InfoRequest>) -> Response<InfoResponse> {
        debug!("Received InfoRequest: {:?}", request.into_inner());
        let state_guard = self.state.lock().map_err(|e| {
            error!("Info: Mutex lock failed: {}", e);
            AuraError::State(format!("Mutex lock failed: {}", e))
        })?; // Propagate error if lock fails

        let app_hash_vec = state_guard.app_hash().unwrap_or_else(|e| {
            warn!("Info: Failed to get app_hash, using default: {:?}", e);
            vec![]
        });

        let response_data = InfoResponseData {
            data: "Aura Node".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            app_version: 1, // Placeholder for your app's specific version
            last_block_height: state_guard.height_value() as i64,
            last_block_app_hash: app_hash_vec.into(),
            latest_block_time: Some(Timestamp::unix_epoch()), // Placeholder; ideally, load from last block
        };
        info!("Responding to InfoRequest with: {:?}", response_data);
        Response::new(response_data)
    }

    async fn check_tx(
        &self,
        request: Request<CheckTxRequest<Self::Transaction>>,
    ) -> Response<CheckTxResponse> {
        let req_data = request.into_inner();
        let tx_id_result = req_data.tx.id(); // Assuming aura_core::Transaction has id()

        match tx_id_result {
            Ok(tx_id) => {
                info!(
                    "Received CheckTxRequest: tx_id: {:?}, kind: {:?}",
                    hex::encode(tx_id),
                    req_data.kind
                );
                // TODO: Implement actual stateless and stateful transaction validation.
                // This includes checking signature, ZKP (if possible statelessly), format.
                // For now, accept all transactions.
                // A real implementation might involve:
                // 1. Deserialize transaction bytes.
                // 2. Perform stateless checks (format, signatures).
                // 3. If `recheck` is true, perform stateful checks (e.g., account existence, nonces)
                //    using a snapshot of the last committed state.
                Response::new(CheckTxResponse::new(
                    0,
                    vec![],
                    "tx accepted (mock)".to_string(),
                ))
            }
            Err(e) => {
                warn!("CheckTxRequest: Failed to get tx_id: {:?}", e);
                Response::new(CheckTxResponse::new(
                    1, // Error code
                    vec![],
                    format!("failed to get tx_id for check_tx: {:?}", e),
                ))
            }
        }
    }

    async fn init_chain(
        &self,
        request: Request<InitChainRequest<Self::Transaction>>,
    ) -> Response<InitChainResponse> {
        let req_data = request.into_inner();
        info!(
            "Received InitChainRequest (app_state_bytes len: {}, initial_height: {})",
            req_data.app_state_bytes.len(),
            req_data.initial_height
        );
        // TODO: If req_data.app_state_bytes is provided, initialize AuraState from it.
        // This might involve parsing a genesis file specific to Aura's application state.
        // Your current AuraState::new handles DB initialization. If Malachite provides
        // app_state_bytes, you might need a new AuraState method like `init_from_genesis_bytes`.
        // For now, we assume AuraState is already initialized via AuraNode::new using its own genesis logic.
        // The app_hash returned here must reflect the actual initial state.

        let state_guard = self
            .state
            .lock()
            .map_err(|e| AuraError::State(e.to_string()))?;
        let app_hash = state_guard.app_hash().unwrap_or_default().into();

        Response::new(InitChainResponse {
            consensus_params: req_data.consensus_params,
            validators: req_data.validators, // Malachite handles validator set based on its genesis.
            app_hash,
        })
    }

    async fn query(&self, request: Request<QueryRequest>) -> Response<QueryResponse> {
        let req_data = request.into_inner();
        info!(
            "Received QueryRequest: path: {}, data: {:?}, height: {}, prove: {}",
            req_data.path,
            String::from_utf8_lossy(&req_data.data),
            req_data.height,
            req_data.prove
        );

        // TODO: Implement actual query logic against AuraState.
        // E.g., query balance, transaction status, note existence.
        // This would involve locking AuraState and reading from the redb database.
        let state_guard = self
            .state
            .lock()
            .map_err(|e| AuraError::State(e.to_string()))?;
        let height_to_query = if req_data.height == 0 {
            state_guard.height_value()
        } else {
            req_data.height as u64
        };

        let query_response_data = QueryResponseData {
            code: 1, // Non-zero for "not found" or "not implemented"
            log: "query not implemented".to_string(),
            info: "".to_string(),
            index: 0,
            key: req_data.data,
            value: Default::default(),
            proof_ops: None,
            height: height_to_query as i64,
            codespace: "".to_string(),
        };
        Response::new(query_response_data)
    }

    // Note: Malachite's BlockBeginRequest uses malachitebft_core_types::Block.
    // We only need its header for begin_block.
    async fn begin_block(
        &self,
        // The request uses Malachite's Block type, not our internal one.
        request: Request<BlockBeginRequest<Block<Self::Transaction>>>,
    ) -> Response<BlockBeginResponse> {
        let req_data = request.into_inner();
        let malachite_header: MalachiteHeader<Self::Transaction> = req_data.header; // This is malachite's Header

        info!(
            "Received BeginBlockRequest: hash: {:?}, height: {}, time: {:?}, proposer: {:?}",
            hex::encode(req_data.hash), // Hash of the *previous* block's app state or consensus hash
            malachite_header.height,
            malachite_header.time,
            malachite_header.proposer_address
        );

        let mut state_guard = self
            .state
            .lock()
            .map_err(|e| AuraError::State(e.to_string()))?;

        // Convert Malachite's timestamp to i64 (seconds or nanos based on AuraState's expectation)
        let timestamp_secs = malachite_header.time.unix_timestamp();
        // let timestamp_nanos = malachite_header.time.unix_timestamp_nanos(); // if AuraState expects nanos

        match state_guard.begin_block(
            malachite_header.height.into(),           // u64
            malachite_header.proposer_address.into(), // Vec<u8>
            timestamp_secs,                           // i64
        ) {
            Ok(_) => Response::new(BlockBeginResponse { events: vec![] }),
            Err(e) => {
                error!("BeginBlock failed: {:?}", e);
                // Malachite expects a Response. How to signal critical error here?
                // For now, return empty response and log. Malachite might halt.
                // Ideally, the error type of AppService should be used, but response must be formed.
                // One way is to have specific error events.
                Response::new(BlockBeginResponse { events: vec![] }) // Or panic if unrecoverable
            }
        }
    }

    async fn deliver_tx(
        &self,
        request: Request<DeliverTxRequest<Self::Transaction>>,
    ) -> Response<DeliverTxResponse> {
        let tx = request.into_inner().tx;
        let tx_id_hex = tx
            .id()
            .map(hex::encode)
            .unwrap_or_else(|_| "unknown_id".to_string());
        info!("Received DeliverTxRequest: tx_id: {:?}", tx_id_hex);

        let mut state_guard = self
            .state
            .lock()
            .map_err(|e| AuraError::State(e.to_string()))?;
        match state_guard.deliver_tx(tx) {
            Ok(exec_result) => Response::new(DeliverTxResponse {
                code: exec_result.code,
                data: Default::default(), // Or some result data
                log: exec_result.log,
                info: "".to_string(),
                gas_wanted: 0, // Placeholder
                gas_used: 0,   // Placeholder
                events: vec![],
                codespace: "".to_string(),
            }),
            Err(e) => {
                warn!("DeliverTx for tx_id {:?} failed: {:?}", tx_id_hex, e);
                Response::new(DeliverTxResponse {
                    code: 1, // Application-specific error code for delivery failure
                    data: Default::default(),
                    log: format!("tx delivery failed: {:?}", e),
                    info: "".to_string(),
                    gas_wanted: 0,
                    gas_used: 0,
                    events: vec![],
                    codespace: "".to_string(),
                })
            }
        }
    }

    async fn end_block(&self, request: Request<BlockEndRequest>) -> Response<BlockEndResponse> {
        let req_data = request.into_inner();
        info!("Received EndBlockRequest: height: {}", req_data.height);

        let mut state_guard = self
            .state
            .lock()
            .map_err(|e| AuraError::State(e.to_string()))?;
        match state_guard.end_block(req_data.height as u64) {
            Ok(validator_updates_app) => {
                // Convert your app's validator updates to Malachite's ValidatorUpdate type
                let malachite_validator_updates = validator_updates_app
                    .into_iter()
                    .map(|app_update| informalsystems_malachitebft_core_types::validator::ValidatorUpdate {
                        // This assumes your state::ValidatorUpdate fields map directly
                        // You might need to convert pub_key format if different (e.g. from raw bytes to crypto::PublicKey)
                        // For now, let's assume direct mapping is not possible without more info on Malachite's key type.
                        // Placeholder:
                        pub_key: informalsystems_malachitebft_core_types::crypto::PublicKey::from_raw_ed25519(
                            &app_update.pub_key,
                        )
                        .unwrap_or_else(|| panic!("Invalid pubkey bytes for ValidatorUpdate")),
                        power: app_update.power,
                    })
                    .collect();

                Response::new(BlockEndResponse {
                    validator_updates: malachite_validator_updates,
                    consensus_param_updates: None, // Or from app logic
                    events: vec![],
                })
            }
            Err(e) => {
                error!("EndBlock failed: {:?}", e);
                Response::new(BlockEndResponse::default()) // Return default on error
            }
        }
    }

    async fn commit(&self, _request: Request<CommitRequest>) -> Response<CommitResponse> {
        info!("Received CommitRequest");
        let mut state_guard = self
            .state
            .lock()
            .map_err(|e| AuraError::State(e.to_string()))?;

        match state_guard.commit_block() {
            Ok(app_hash_vec) => {
                let response_data = CommitResponseData {
                    app_hash: app_hash_vec.into(),
                    retain_height: 0, // Or app-specific logic
                };
                info!(
                    "Commit successful. New app_hash: {:?}, New height: {}",
                    hex::encode(response_data.app_hash.as_bytes()),
                    state_guard.height_value()
                );
                Response::new(response_data)
            }
            Err(e) => {
                error!(
                    "Critical: Commit failed: {:?}. This node might be in an inconsistent state.",
                    e
                );
                // This is a serious problem. Malachite might halt or retry.
                // Returning a default or stale app_hash can lead to divergence.
                // For now, returning a default response, but this needs careful consideration.
                // A panic might be safer if the state is truly unrecoverable.
                Response::new(CommitResponseData {
                    app_hash: state_guard.app_hash().unwrap_or_default().into(), // Stale hash
                    retain_height: 0,
                })
            }
        }
    }
}
