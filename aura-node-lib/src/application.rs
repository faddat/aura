use std::sync::{Arc, Mutex};

use async_trait::async_trait;
// Use the aliased package names as in Cargo.toml
use crate::malachitebft_core_types::{
    BlockBeginRequest, BlockBeginResponse, BlockEndRequest, BlockEndResponse, CheckTxRequest,
    CheckTxResponse, CommitRequest, CommitResponse, CommitResponseData, DeliverTxRequest,
    DeliverTxResponse, InfoRequest, InfoResponse, InfoResponseData, InitChainRequest,
    InitChainResponse, QueryRequest, QueryResponse, QueryResponseData,
    block::{Block as MalachiteBlock, Header as MalachiteHeader},
    crypto::PublicKey as MalachitePublicKey,
    time::Timestamp,
    validator::ValidatorUpdate as MalachiteValidatorUpdate,
};
use malachitebft_app_channel::app::{
    AppService as MalachiteAppService,
    types::sync::{Request, Response},
};

use tracing::{debug, error, info, warn};

use crate::{
    Error as AuraError,
    state::{AuraState, ValidatorUpdate as AuraValidatorUpdateApp},
};

#[derive(Debug)]
pub struct AuraApplication {
    state: Arc<Mutex<AuraState>>,
    #[allow(dead_code)]
    node_id: String,
}

impl AuraApplication {
    pub fn new(state: Arc<Mutex<AuraState>>, node_id: String) -> Self {
        Self { state, node_id }
    }
}

#[async_trait]
impl MalachiteAppService for AuraApplication {
    type Error = AuraError;
    type Transaction = aura_core::Transaction;

    async fn info(&self, request: Request<InfoRequest>) -> Response<InfoResponse> {
        debug!("Received InfoRequest: {:?}", request.into_inner());
        let state_guard = self.state.lock().map_err(|e| {
            error!("Info: Mutex lock failed: {}", e);
            AuraError::State(format!("Mutex lock failed: {}", e))
        })?;

        let app_hash_vec = state_guard.app_hash().unwrap_or_else(|e| {
            warn!("Info: Failed to get app_hash, using default: {:?}", e);
            vec![]
        });

        let response_data = InfoResponseData {
            data: "Aura Node".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            app_version: 1,
            last_block_height: state_guard.height_value() as i64,
            last_block_app_hash: app_hash_vec.into(),
            latest_block_time: Some(Timestamp::unix_epoch()),
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

        let state_guard = self
            .state
            .lock()
            .map_err(|e| AuraError::State(e.to_string()))?;
        let app_hash = state_guard.app_hash().unwrap_or_default().into();

        Response::new(InitChainResponse {
            consensus_params: req_data.consensus_params,
            validators: req_data.validators,
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
            code: 1,
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

    async fn begin_block(
        &self,
        request: Request<BlockBeginRequest<MalachiteBlock<Self::Transaction>>>,
    ) -> Response<BlockBeginResponse> {
        let req_data = request.into_inner();
        let malachite_header: MalachiteHeader<Self::Transaction> = req_data.header;

        info!(
            "Received BeginBlockRequest: hash: {:?}, height: {}, time: {:?}, proposer: {:?}",
            hex::encode(req_data.hash),
            malachite_header.height,
            malachite_header.time,
            malachite_header.proposer_address
        );

        let mut state_guard = self
            .state
            .lock()
            .map_err(|e| AuraError::State(e.to_string()))?;

        let timestamp_secs = malachite_header.time.unix_timestamp();

        match state_guard.begin_block(
            malachite_header.height.into(),
            malachite_header.proposer_address.into(),
            timestamp_secs,
        ) {
            Ok(_) => Response::new(BlockBeginResponse { events: vec![] }),
            Err(e) => {
                error!("BeginBlock failed: {:?}", e);
                Response::new(BlockBeginResponse { events: vec![] })
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
                data: Default::default(),
                log: exec_result.log,
                info: "".to_string(),
                gas_wanted: 0,
                gas_used: 0,
                events: vec![],
                codespace: "".to_string(),
            }),
            Err(e) => {
                warn!("DeliverTx for tx_id {:?} failed: {:?}", tx_id_hex, e);
                Response::new(DeliverTxResponse {
                    code: 1,
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
                let malachite_validator_updates = validator_updates_app
                    .into_iter()
                    .map(
                        |app_update: AuraValidatorUpdateApp| MalachiteValidatorUpdate {
                            pub_key: MalachitePublicKey::from_raw_ed25519(&app_update.pub_key)
                                .unwrap_or_else(|| {
                                    panic!("Invalid pubkey bytes for ValidatorUpdate")
                                }),
                            power: app_update.power,
                        },
                    )
                    .collect();

                Response::new(BlockEndResponse {
                    validator_updates: malachite_validator_updates,
                    consensus_param_updates: None,
                    events: vec![],
                })
            }
            Err(e) => {
                error!("EndBlock failed: {:?}", e);
                Response::new(BlockEndResponse::default())
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
                    retain_height: 0,
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
                Response::new(CommitResponseData {
                    app_hash: state_guard.app_hash().unwrap_or_default().into(),
                    retain_height: 0,
                })
            }
        }
    }
}
