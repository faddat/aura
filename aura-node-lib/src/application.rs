use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use malachitebft_app::{AppService as MalachiteAppService, Request, Response};
use malachitebft_core_types::{
    BlockBeginRequest,
    BlockBeginResponse, // Added Block from Malachite for BlockBeginRequest
    BlockEndRequest,
    BlockEndResponse,
    CheckTxRequest,
    CheckTxResponse,
    CommitRequest,
    CommitResponse,
    CommitResponseData,
    DeliverTxRequest,
    DeliverTxResponse,
    ExecTxResult,
    InfoRequest,
    InfoResponse,
    InfoResponseData,
    InitChainRequest,
    InitChainResponse,
    QueryRequest,
    QueryResponse,
    QueryResponseData,
    Timestamp, // Needed for InfoResponseData
};
use tracing::{debug, info, warn};

use crate::{
    Error,
    Result as AuraResult,                           // Crate specific result
    state::{AuraState, Block as AuraInternalBlock}, // Renamed to avoid conflict
};

// Define an alias for our internal block type if needed, or ensure it matches
// Malachite's expectations. For BlockBeginRequest, Malachite expects its own Block type.
// We will use aura_core::Transaction for Self::Transaction and crate::state::Block for Self::Block.

/// AuraApplication implements Malachite's AppService trait
#[derive(Debug)]
pub struct AuraApplication {
    /// The application state
    state: Arc<Mutex<AuraState>>,
    /// Node ID in the network (can be useful for logging or app-specific logic)
    #[allow(dead_code)]
    node_id: String,
}

impl AuraApplication {
    /// Create a new AuraApplication with the given state
    pub fn new(state: Arc<Mutex<AuraState>>, node_id: String) -> Self {
        Self { state, node_id }
    }
}

#[async_trait]
impl MalachiteAppService for AuraApplication {
    type Error = Error; // Your existing Error type
    type Transaction = aura_core::Transaction; // Your core transaction type
    type Block = AuraInternalBlock; // Your internal block type

    async fn info(&self, request: Request<InfoRequest>) -> Response<InfoResponse> {
        debug!("Received InfoRequest: {:?}", request.into_inner());
        let state = self.state.lock().map_err(|e| Error::State(e.to_string()))?; // Handle Mutex poisoning

        let response_data = InfoResponseData {
            data: "Aura Node".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            app_version: 1, // Placeholder
            last_block_height: state.height_value() as i64,
            last_block_app_hash: state.app_hash().unwrap_or_default().into(), // Bytes into tendermint::block::AppHash
            latest_block_time: Some(Timestamp::unix_epoch()), // Placeholder, update if you store block times
        };
        info!("Responding to InfoRequest with: {:?}", response_data);
        Response::new(response_data)
    }

    async fn check_tx(
        &self,
        request: Request<CheckTxRequest<Self::Transaction>>,
    ) -> Response<CheckTxResponse> {
        let req_data = request.into_inner();
        let tx_id_result = req_data.tx.id();

        match tx_id_result {
            Ok(tx_id) => {
                info!(
                    "Received CheckTxRequest: tx_id: {:?}, kind: {:?}",
                    hex::encode(tx_id),
                    req_data.kind
                );
                // TODO: Implement actual stateless and stateful (if `recheck`) transaction validation.
                // For now, accept all transactions.
                Response::new(CheckTxResponse::new(
                    0,
                    vec![],
                    "tx accepted (mock)".to_string(),
                ))
            }
            Err(e) => {
                warn!("CheckTxRequest: Failed to get tx_id: {:?}", e);
                Response::new(CheckTxResponse::new(
                    1,
                    vec![],
                    format!("failed to process tx for check_tx: {:?}", e),
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
            "Received InitChainRequest: time: {:?}, chain_id: {}, consensus_params: {:?}, validators: {:?}, app_state_bytes: (len {}) initial_height: {}",
            req_data.time,
            req_data.chain_id,
            req_data.consensus_params,
            req_data.validators,
            req_data.app_state_bytes.len(),
            req_data.initial_height,
        );

        // TODO: Initialize AuraState from app_state_bytes if provided and different from current genesis logic.
        // For now, we assume AuraState is already initialized via AuraNode::new and its own genesis.
        // The app_hash returned here should reflect the initial state.

        let state = self.state.lock().map_err(|e| Error::State(e.to_string()))?;
        let app_hash = state.app_hash().unwrap_or_default().into();

        Response::new(InitChainResponse {
            consensus_params: req_data.consensus_params, // Or updated ones
            validators: req_data.validators,             // Or updated ones
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

        // TODO: Implement actual query logic (e.g., get balance, tx status)
        // For now, return a generic "not implemented" or empty response.
        let query_response_data = QueryResponseData {
            code: 1, // Non-zero indicates error or not found
            log: "query not implemented".to_string(),
            info: "".to_string(),
            index: 0,
            key: req_data.data, // Echo back the key for now
            value: Default::default(),
            proof_ops: None,
            height: req_data.height as i64, // Height of the query
            codespace: "".to_string(),
        };
        Response::new(query_response_data)
    }

    async fn begin_block(
        &self,
        request: Request<BlockBeginRequest<Self::Block>>,
    ) -> Response<BlockBeginResponse> {
        let req_data = request.into_inner();
        info!(
            "Received BeginBlockRequest: hash: {:?}, header: (height {}, time {:?}), last_commit_info: {:?}",
            hex::encode(req_data.hash),
            req_data.header.height,
            req_data.header.time,
            req_data.last_commit_info
        );

        let mut state = self.state.lock().map_err(|e| Error::State(e.to_string()))?;
        // Malachite's Block has header, data (txs), evidence, last_commit.
        // Our AuraInternalBlock is simpler. This request gives us the header.
        // We need to prepare AuraState for a new block.
        // The actual block application will be piecemeal in deliver_tx and finalized in commit.
        state
            .begin_block(req_data.header.height.into())
            .map_err(|e| {
                error!("BeginBlock: Error preparing state: {:?}", e);
                e // Propagate the error
            })?;

        Response::new(BlockBeginResponse { events: vec![] })
    }

    async fn deliver_tx(
        &self,
        request: Request<DeliverTxRequest<Self::Transaction>>,
    ) -> Response<DeliverTxResponse> {
        let tx = request.into_inner().tx;
        let tx_id_result = tx.id();

        match tx_id_result {
            Ok(tx_id) => {
                info!("Received DeliverTxRequest: tx_id: {:?}", hex::encode(tx_id));

                let mut state = self.state.lock().map_err(|e| Error::State(e.to_string()))?;
                match state.deliver_tx(tx) {
                    // deliver_tx in AuraState now handles individual tx processing logic
                    Ok(_exec_result_placeholder) => {
                        // Convert your ExecTxResult or similar to DeliverTxResponse fields
                        Response::new(DeliverTxResponse {
                            code: 0, // Success
                            data: Default::default(),
                            log: "tx delivered (mock)".to_string(),
                            info: "".to_string(),
                            gas_wanted: 0, // Placeholder
                            gas_used: 0,   // Placeholder
                            events: vec![],
                            codespace: "".to_string(),
                        })
                    }
                    Err(e) => {
                        warn!(
                            "DeliverTx: Error processing transaction {:?}: {:?}",
                            hex::encode(tx_id),
                            e
                        );
                        Response::new(DeliverTxResponse {
                            code: 1, // Application-specific error code
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
            Err(e) => {
                warn!("DeliverTxRequest: Failed to get tx_id for a tx: {:?}", e);
                Response::new(DeliverTxResponse {
                    code: 2, // Error before processing
                    data: Default::default(),
                    log: format!("failed to get tx_id for deliver_tx: {:?}", e),
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

        let mut state = self.state.lock().map_err(|e| Error::State(e.to_string()))?;
        // Finalize block logic before commit, e.g., validator updates.
        // Our `AuraState` needs an `end_block` method.
        let _validator_updates = state.end_block(req_data.height as u64).map_err(|e| {
            error!("EndBlock: Error: {:?}", e);
            e
        })?;

        Response::new(BlockEndResponse {
            validator_updates: vec![], // TODO: Populate if your app manages validators
            consensus_param_updates: None,
            events: vec![],
        })
    }

    async fn commit(&self, _request: Request<CommitRequest>) -> Response<CommitResponse> {
        info!("Received CommitRequest");
        let mut state = self.state.lock().map_err(|e| Error::State(e.to_string()))?;

        // This is where the current block's data is persisted to redb,
        // height is updated, and the new app_hash is calculated.
        // The `AuraState::apply_block` logic needs to be fully moved here or into `deliver_tx`
        // and `commit` just finalizes.
        match state.commit_block() {
            Ok(app_hash_vec) => {
                let response_data = CommitResponseData {
                    app_hash: app_hash_vec.into(),
                    retain_height: 0, // Or specific height to retain based on app logic
                };
                info!(
                    "Commit successful. New app_hash: {:?}, New height: {}",
                    hex::encode(response_data.app_hash.as_bytes()),
                    state.height_value()
                );
                Response::new(response_data)
            }
            Err(e) => {
                error!("Commit failed: {:?}", e);
                // This is a critical error. Malachite might halt or handle it.
                // We need to return an error that `malachitebft_app::AppService::Error` can represent.
                // For now, we'll panic, but ideally, convert `e` to `Self::Error` and let Malachite handle.
                // This requires `Error` to be convertible to `malachitebft_app::BoxError`.
                // Our current `Error` (thiserror) should be fine.
                // Malachite expects the `Response` to be returned.
                // A panic here will stop this node.
                // A proper error response is better if Malachite can handle it gracefully.
                // For now, we can't easily return a Response::Error(...) here,
                // so let's try to form a CommitResponse indicating failure if possible,
                // or just log and potentially let Malachite deal with a non-advancing app_hash.
                // A simple way is to return a previous or empty app_hash and log heavily.
                // Malachite might retry or have other mechanisms.
                //
                // For now, let's assume commit always succeeds or panics if state is inconsistent.
                // A more robust solution would be to return `Response::Err(e)`.
                // However, the `AppService` trait methods return `Response<T>`, not `Result<Response<T>>`.
                // The error handling is typically done by `T` itself containing error codes.
                // `CommitResponse` does not have error fields. If commit fails, it's a critical issue.
                // We will let it panic for now if state.commit_block() returns Err.
                // Or, more gracefully, log the error and return a potentially "stale" or default app_hash.
                // Let's log and return a default hash to avoid panic, but this isn't ideal.
                warn!(
                    "Commit failed with error: {:?}. Returning default app_hash.",
                    e
                );
                Response::new(CommitResponseData {
                    app_hash: Default::default(), // Empty app hash indicates problem
                    retain_height: 0,
                })
            }
        }
    }
}
