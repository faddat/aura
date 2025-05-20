use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::rpc::spawn_rpc_server;
use async_trait::async_trait;
use eyre::eyre;
use tokio::task::JoinHandle;
use tracing::{Instrument, debug, error, info};

use crate::config::AuraNodeConfig as AuraAppNodeConfig;
use crate::state::AuraState;

// --- Malachite App Imports ---
use malachitebft_app::events::{RxEvent, TxEvent};
use malachitebft_app::node::{
    EngineHandle, Node as MalachiteAppNode, NodeConfig, NodeHandle as MalachiteAppNodeHandle,
};

use chrono::Utc;

use malachitebft_core_consensus::{LocallyProposedValue, ProposedValue};
use malachitebft_core_types::{Round, Validity};

use malachitebft_app_channel::{
    AppMsg, Channels, ConsensusMsg, start_engine as malachite_start_engine,
};

use malachitebft_app_channel::app::types::Keypair as TestKeypair;

// --- Malachite Engine ---

// --- Malachite Config ---
use malachitebft_config::{ConsensusConfig, ValueSyncConfig};

// --- Malachite Test Types (for concrete implementations of traits) ---
use bytes::Bytes;
use malachitebft_app_channel::NetworkMsg;
use malachitebft_engine::util::streaming::{StreamId, StreamMessage};
use malachitebft_test::{
    Address as TestAddress, Ed25519Provider, Genesis as TestGenesis, Height as TestHeight,
    PrivateKey as TestPrivateKey, PublicKey as TestPublicKey, TestContext,
    ValidatorSet as TestValidatorSet, Value as TestValue, codec::proto::ProtobufCodec,
};
use malachitebft_test::{ProposalData, ProposalFin, ProposalInit, ProposalPart};
use sha3::{Digest, Keccak256};

// --- Placeholder for Malachite's Top-Level Config ---
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MalachiteTopLevelConfig {
    pub moniker: String,
    pub home: PathBuf,
    pub genesis_file: PathBuf,
    pub priv_validator_key_file: PathBuf,
    pub node_key_file: PathBuf,
    pub p2p: malachitebft_config::P2pConfig,
    pub consensus: malachitebft_config::ConsensusConfig,
}

impl MalachiteTopLevelConfig {
    pub fn load_toml_file<P: AsRef<Path>>(path: P) -> Result<Self, anyhow::Error> {
        let config_str = fs::read_to_string(path.as_ref())?;
        toml::from_str(&config_str).map_err(anyhow::Error::from)
    }
}

impl NodeConfig for MalachiteTopLevelConfig {
    fn moniker(&self) -> &str {
        &self.moniker
    }

    fn consensus(&self) -> &ConsensusConfig {
        &self.consensus
    }

    fn value_sync(&self) -> &ValueSyncConfig {
        // Since we don't have a value_sync field, we need to return a default one
        static DEFAULT_VALUE_SYNC: once_cell::sync::Lazy<ValueSyncConfig> =
            once_cell::sync::Lazy::new(ValueSyncConfig::default);
        &DEFAULT_VALUE_SYNC
    }
}

#[derive(Clone)]
pub struct AuraNode {
    pub home_dir: PathBuf,
    pub aura_app_config: AuraAppNodeConfig,
    pub malachite_config_path: PathBuf,
    _app_level_private_key: Arc<aura_core::PrivateKey>,
}

pub struct AuraNodeRunningHandle {
    pub app_logic_handle: JoinHandle<()>,
    pub engine_handle: EngineHandle,
    pub tx_event: TxEvent<TestContext>,
    pub rpc_handle: Option<JoinHandle<()>>,
}

#[async_trait]
impl MalachiteAppNodeHandle<TestContext> for AuraNodeRunningHandle {
    fn subscribe(&self) -> RxEvent<TestContext> {
        self.tx_event.subscribe()
    }
    async fn kill(&self, _reason: Option<String>) -> eyre::Result<()> {
        self.engine_handle.actor.kill_and_wait(None).await?;
        self.app_logic_handle.abort();
        if let Some(handle) = &self.rpc_handle {
            handle.abort();
        }
        self.engine_handle.handle.abort();
        Ok(())
    }
}

#[async_trait]
impl MalachiteAppNode for AuraNode {
    type Context = TestContext;
    type Config = MalachiteTopLevelConfig;
    type Genesis = TestGenesis;
    type PrivateKeyFile = TestPrivateKey;
    type SigningProvider = Ed25519Provider;
    type NodeHandle = AuraNodeRunningHandle;

    fn get_home_dir(&self) -> PathBuf {
        self.home_dir.clone()
    }

    fn load_config(&self) -> eyre::Result<Self::Config> {
        MalachiteTopLevelConfig::load_toml_file(&self.malachite_config_path)
            .map_err(|e| eyre!("Failed to load Malachite config: {}", e))
    }

    fn get_address(&self, pk: &TestPublicKey) -> TestAddress {
        TestAddress::from_public_key(pk)
    }

    fn get_public_key(&self, pk: &Self::PrivateKeyFile) -> TestPublicKey {
        pk.public_key()
    }

    fn get_keypair(&self, pk: Self::PrivateKeyFile) -> TestKeypair {
        TestKeypair::ed25519_from_bytes(pk.inner().to_bytes())
            .expect("Failed to create keypair from TestPrivateKey bytes")
    }

    fn load_private_key(&self, file_content: Self::PrivateKeyFile) -> TestPrivateKey {
        file_content
    }

    fn load_private_key_file(&self) -> eyre::Result<Self::PrivateKeyFile> {
        let config = self.load_config()?;
        let key_path = if config.priv_validator_key_file.is_absolute() {
            config.priv_validator_key_file.clone()
        } else {
            self.get_home_dir().join(config.priv_validator_key_file)
        };
        let key_str = fs::read_to_string(&key_path)
            .map_err(|e| eyre!("Failed to read private key file {:?}: {}", key_path, e))?;
        serde_json::from_str(&key_str)
            .map_err(|e| eyre!("Failed to parse private key file {:?}: {}", key_path, e))
    }

    fn get_signing_provider(&self, private_key: Self::PrivateKeyFile) -> Self::SigningProvider {
        Ed25519Provider::new(private_key)
    }

    fn load_genesis(&self) -> eyre::Result<Self::Genesis> {
        let config = self.load_config()?;
        let genesis_path = if config.genesis_file.is_absolute() {
            config.genesis_file.clone()
        } else {
            self.get_home_dir().join(config.genesis_file)
        };
        let genesis_str = fs::read_to_string(&genesis_path)
            .map_err(|e| eyre!("Failed to read genesis file {:?}: {}", genesis_path, e))?;
        serde_json::from_str(&genesis_str)
            .map_err(|e| eyre!("Failed to parse genesis file {:?}: {}", genesis_path, e))
    }

    async fn start(&self) -> eyre::Result<<Self as MalachiteAppNode>::NodeHandle> {
        info!("AuraNode (MalachiteNode impl) starting process...");
        let malachite_config = self.load_config()?;

        let span = tracing::info_span!("aura_node_malachite_instance", moniker = %malachite_config.moniker);
        let _enter = span.enter();

        let aura_malachite_ctx = TestContext::default();
        let malachite_genesis = self.load_genesis()?;
        let initial_validator_set = malachite_genesis.validator_set.clone();
        info!(
            "Loaded Malachite consensus genesis with {} validators.",
            initial_validator_set.len()
        );

        let codec = ProtobufCodec;

        let app_state_db_path = self.get_home_dir().join(
            self.aura_app_config
                .db_path
                .file_name()
                .expect("App DB path should have a filename"),
        );
        fs::create_dir_all(app_state_db_path.parent().unwrap_or_else(|| Path::new(".")))?;
        let app_state = AuraState::new(app_state_db_path, self._app_level_private_key.clone())
            .map_err(|e| eyre!("Failed to create AuraState: {}", e))?;
        let app_state_arc = Arc::new(Mutex::new(app_state));
        let app_state_arc_rpc = app_state_arc.clone();

        info!("Calling malachitebft_app_channel::start_engine...");
        let (channels, engine_handle) = malachite_start_engine(
            aura_malachite_ctx.clone(),
            codec,
            self.clone(),
            malachite_config.clone(),
            None,
            initial_validator_set.clone(),
        )
        .await?;
        info!("Malachite engine started via app-channel.");

        let tx_event_channel = channels.events.clone();
        let app_logic_task_span =
            tracing::info_span!("app_message_loop", moniker = %malachite_config.moniker);

        let init_vs_for_loop = initial_validator_set.clone();

        // Prepare signing provider and address for proposal parts
        let validator_priv_key = self
            .load_private_key_file()
            .map_err(|e| eyre!("Failed to load validator private key: {e}"))?;
        let signing_provider = Ed25519Provider::new(validator_priv_key.clone());
        let node_address = self.get_address(&validator_priv_key.public_key());

        let app_logic_handle = tokio::spawn(async move {
            if let Err(e) = app_message_loop(
                app_state_arc,
                aura_malachite_ctx,
                channels,
                init_vs_for_loop,
                signing_provider,
                node_address,
            )
            .instrument(app_logic_task_span)
            .await
            {
                error!(?e, "Application message loop exited with error");
            }
        });
        info!("Spawned application message loop task.");

        let rpc_handle = self
            .aura_app_config
            .rpc
            .as_ref()
            .map(|rpc_cfg| spawn_rpc_server(app_state_arc_rpc, rpc_cfg.listen_addr.clone()));

        Ok(AuraNodeRunningHandle {
            app_logic_handle,
            engine_handle,
            tx_event: tx_event_channel,
            rpc_handle,
        })
    }

    async fn run(self) -> eyre::Result<()> {
        let handles = self.start().await?;
        if let Some(rpc) = handles.rpc_handle {
            tokio::spawn(async move {
                let _ = rpc.await;
            });
        }
        handles.app_logic_handle.await.map_err(Into::into)
    }
}

/// Type alias for proposal buffer data
type ProposalBufferData = (Option<(TestHeight, Round, TestAddress)>, Vec<u64>);

/// Application message loop that handles incoming consensus messages
pub async fn app_message_loop(
    app_state_arc: Arc<Mutex<AuraState>>,
    _ctx: TestContext,
    mut channels: Channels<TestContext>,
    initial_validator_set: TestValidatorSet,
    signing_provider: Ed25519Provider,
    node_address: TestAddress,
) -> eyre::Result<()> {
    let mut proposal_buffers: HashMap<String, ProposalBufferData> = HashMap::new();
    info!("Application message loop started. Waiting for messages from consensus...");
    loop {
        tokio::select! {
                    Some(msg) = channels.consensus.recv() => {
                        debug!("AppLoop: Received AppMsg from consensus: {}", msg_type_name(&msg));
                        match msg {
                            AppMsg::ConsensusReady { reply, .. } => {
                                let state = app_state_arc.lock().map_err(|e| eyre!("Mutex lock failed for ConsensusReady: {}", e))?;
                                let start_height = if state.height_value() == 0 {
                                    TestHeight::new(1)
                                } else {
                                    TestHeight::new(state.height_value() + 1)
                                };
                                let validator_set = initial_validator_set.clone();
                                info!(%start_height, "AppLoop: Consensus is ready. Replying with StartHeight.");
                                if reply.send((start_height, validator_set)).is_err() {
                                    error!("AppLoop: Failed to send ConsensusReady reply (StartHeight)");
                                }
                            }
                            AppMsg::StartedRound { height, round, proposer, reply_value } => {
                                let mut state_guard = app_state_arc.lock().map_err(|e| eyre!("Mutex lock failed for StartedRound: {}", e))?;
                                // Begin a new block for this height so commit will be successful later
                                let ts = Utc::now().timestamp();
                                let proposer_bytes = proposer.into_inner().to_vec();
                                if let Err(e) = state_guard.begin_block(height.as_u64(), proposer_bytes, ts) {
                                    error!("AppLoop: begin_block failed: {:?}", e);
                                }
                                // Do NOT bump committed current_height here; we only track the committed height.
                                state_guard.current_round = round;
                                info!(%height, %round, %proposer, "AppLoop: Started round.");
                                 if reply_value.send(Vec::new()).is_err() {
                                    error!("AppLoop: Failed to send reply for StartedRound (value reply)");
                                 }
                            }
                            AppMsg::GetValue { height, round, reply, .. } => {
                                info!(%height, %round, "AppLoop: Consensus requesting a value (block) to propose.");

                                // Serialize the pending block so that it can be streamed
                                let block_bytes = {
                                    let state = app_state_arc.lock().map_err(|e| eyre!("Mutex lock failed for GetValue: {}", e))?;
                                    let block = state.get_pending_block()?;
                                    serde_json::to_vec(&block)?
                                };

                                let mut test_value = TestValue::new(height.as_u64());
                                test_value.extensions = Bytes::from(block_bytes.clone());

                                let locally_proposed_value = LocallyProposedValue {
                                    height,
                                    round,
                                    value: test_value,
                                };

                                if reply.send(locally_proposed_value).is_err() {
                                    error!("AppLoop: Failed to send GetValue reply (LocallyProposedValue)");
                                }

                                // Stream the full serialized block to peers
                                if let Err(e) = stream_proposal_parts(&mut channels, &app_state_arc, height, round, &signing_provider, node_address).await {
                                    error!(?e, "AppLoop: Failed to stream proposal parts");
                                }
                            }
                            AppMsg::ReceivedProposalPart { from, part, reply } => {
                                use malachitebft_engine::util::streaming::StreamContent;
                                let part_type_str = match &part.content {
                                    StreamContent::Data(p) => format!("{:?}", p),
                                    StreamContent::Fin => "Fin".to_string(),
                                };
                                info!(peer_id = %from, sequence = %part.sequence, part_type = %part_type_str, "AppLoop: Received proposal part.");

                                // Key the buffer directly by StreamId for stability and efficiency.
                                let stream_key = part.stream_id.clone();

                                match &part.content {
                                    StreamContent::Data(ProposalPart::Init(init)) => {
        proposal_buffers.insert(stream_key.to_string(), (Some((init.height, init.round, init.proposer)), Vec::new()));
                                        if reply.send(None).is_err() {
                                            error!("AppLoop: Failed to send ReceivedProposalPart reply (Init)");
                                        }
                                    }
                                    StreamContent::Data(ProposalPart::Data(data)) => {
        proposal_buffers
            .entry(stream_key.to_string())
            .or_insert((None, Vec::new()))
            .1
            .push(data.factor);
                                        if reply.send(None).is_err() {
                                            error!("AppLoop: Failed to send ReceivedProposalPart reply (Data)");
                                        }
                                    }
                                    StreamContent::Fin | StreamContent::Data(ProposalPart::Fin(_)) => {
        if let Some((info_opt, factors)) = proposal_buffers.remove(&stream_key.to_string()) {
                                            if let Some((height, round, proposer)) = info_opt {
                                                let bytes = factors_to_bytes(&factors);
                                                let mut value = TestValue::new(height.as_u64());
                                                value.extensions = Bytes::from(bytes);
                                                let proposed = ProposedValue {
                                                    height,
                                                    round,
                                                    valid_round: Round::Nil,
                                                    proposer,
                                                    value,
                                                    validity: Validity::Valid,
                                                };
                                                if reply.send(Some(proposed)).is_err() {
                                                    error!("AppLoop: Failed to send ReceivedProposalPart reply (Some)");
                                                }
                                            } else if reply.send(None).is_err() {
                                                error!("AppLoop: Failed to send ReceivedProposalPart reply (Missing Init)");
                                            }
                                        } else if reply.send(None).is_err() {
                                            error!("AppLoop: Failed to send ReceivedProposalPart reply (Fin w/o buffer)");
                                        }
                                    }
                                }
                            }
                            AppMsg::RestreamProposal { height, round, .. } => {
                                info!(%height, %round, "AppLoop: Restream proposal");
                                if let Err(e) = stream_proposal_parts(&mut channels, &app_state_arc, height, round, &signing_provider, node_address).await {
                                    error!(?e, "AppLoop: Failed to restream proposal parts");
                                }
                            }
                            AppMsg::Decided { certificate, extensions: _, reply } => {
                                info!(height = %certificate.height, round = %certificate.round, value_id = %certificate.value_id, "AppLoop: Consensus decided. Committing block.");
                                let mut state_guard = app_state_arc.lock().map_err(|e| eyre!("Mutex lock for Decided: {}", e))?;

                                if certificate.height.as_u64() != state_guard.pending_block_height {
                                     error!("AppLoop: Decided height {} does not match pending block height {}. This indicates a potential state mismatch or missed BeginBlock call.",
                                        certificate.height.as_u64(), state_guard.pending_block_height);
                                }

                                match state_guard.commit_block() {
                                    Ok(_app_hash) => {
                                        let next_height = TestHeight::new(state_guard.height_value() + 1);
                                        let validator_set = initial_validator_set.clone();
                                        info!("AppLoop: Commit successful. Replying to start next height: {}", next_height);
                                        if reply.send(ConsensusMsg::StartHeight(next_height, validator_set)).is_err() {
                                            error!("AppLoop: Failed to send Decided reply (StartHeight)");
                                        }
                                    }
                                    Err(e) => {
                                        error!("AppLoop: Commit failed after Decided: {:?}. Requesting restart for height {}.", e, state_guard.pending_block_height);
                                        let current_pending_height = TestHeight::new(state_guard.pending_block_height);
                                        let validator_set = initial_validator_set.clone();
                                        if reply.send(ConsensusMsg::RestartHeight(current_pending_height, validator_set)).is_err() {
                                             error!("AppLoop: Failed to send Decided reply (RestartHeight)");
                                        }
                                    }
                                }
                            }
                            AppMsg::ExtendVote { reply, .. } => {
                                if reply.send(None).is_err() {
                                    error!("AppLoop: Failed to send ExtendVote reply");
                                }
                            }
                            AppMsg::VerifyVoteExtension { reply, .. } => {
                                if reply.send(Ok(())).is_err() {
                                    error!("AppLoop: Failed to send VerifyVoteExtension reply");
                                }
                            }
                            AppMsg::GetValidatorSet { height, reply } => {
                                info!("AppLoop: GetValidatorSet called for height {}", height);
                                if reply.send(Some(initial_validator_set.clone())).is_err() {
                                    error!("AppLoop: Failed to send GetValidatorSet reply");
                                }
                            }
                            AppMsg::GetHistoryMinHeight { reply } => {
                                info!("AppLoop: GetHistoryMinHeight called");
                                let state = app_state_arc.lock().map_err(|e| eyre!("Mutex lock failed: {}", e))?;
                                let min_h = TestHeight::new(state.min_height()?);
                                if reply.send(min_h).is_err() {
                                    error!("AppLoop: Failed to send GetHistoryMinHeight reply");
                                }
                            }
                            AppMsg::GetDecidedValue { height, reply } => {
                                info!("AppLoop: GetDecidedValue called for height {}", height);
                                let _state = app_state_arc.lock().map_err(|e| eyre!("Mutex lock failed: {}", e))?;
                                // Just return None for now as expected by the test
                                if reply.send(None).is_err() {
                                    error!("AppLoop: Failed to send GetDecidedValue reply");
                                }
                            }
                            AppMsg::ProcessSyncedValue { height, round, proposer, value_bytes: _, reply } => {
                                info!(%height, %round, "AppLoop: Processing synced value");
                                let state = app_state_arc.lock().map_err(|e| eyre!("Mutex lock failed: {}", e))?;
                                let proposed = ProposedValue {
                                    height,
                                    round,
                                    valid_round: Round::Nil,
                                    proposer,
                                    value: TestValue::new(height.as_u64()),
                                    validity: if state.get_block(height.as_u64()).is_ok() { Validity::Valid } else { Validity::Invalid },
                                };
                                if reply.send(proposed).is_err() {
                                   error!("AppLoop: Failed to send ProcessSyncedValue reply");
                                }
                            }
                        }
                    }
                    else => {
                        info!("AppLoop: Consensus channel closed or select! macro completed. Exiting loop.");
                        break;
                    }
                }
    }
    Ok(())
}

fn msg_type_name(msg: &AppMsg<TestContext>) -> &'static str {
    match msg {
        AppMsg::ConsensusReady { .. } => "ConsensusReady",
        AppMsg::StartedRound { .. } => "StartedRound",
        AppMsg::GetValue { .. } => "GetValue",
        AppMsg::ExtendVote { .. } => "ExtendVote",
        AppMsg::VerifyVoteExtension { .. } => "VerifyVoteExtension",
        AppMsg::RestreamProposal { .. } => "RestreamProposal",
        AppMsg::GetHistoryMinHeight { .. } => "GetHistoryMinHeight",
        AppMsg::ReceivedProposalPart { .. } => "ReceivedProposalPart",
        AppMsg::GetValidatorSet { .. } => "GetValidatorSet",
        AppMsg::Decided { .. } => "Decided",
        AppMsg::GetDecidedValue { .. } => "GetDecidedValue",
        AppMsg::ProcessSyncedValue { .. } => "ProcessSyncedValue",
        #[allow(unreachable_patterns)]
        _ => "UnknownAppMsg",
    }
}

impl AuraNode {
    /// Create a new AuraNode instance used by external crates / CLI.
    pub fn new(
        home_dir: PathBuf,
        aura_app_config: AuraAppNodeConfig,
        malachite_config_path: PathBuf,
        private_key: Arc<aura_core::PrivateKey>,
    ) -> Self {
        Self {
            home_dir,
            aura_app_config,
            malachite_config_path,
            _app_level_private_key: private_key,
        }
    }
}

/// Stream a very small, dummy proposal consisting of Init, one Data, and Fin parts.
/// This is a placeholder implementation that satisfies the consensus engine's
/// expectation of receiving proposal parts for the value produced in `GetValue`.
async fn stream_proposal_parts(
    channels: &mut Channels<TestContext>,
    state_arc: &Arc<Mutex<AuraState>>,
    height: TestHeight,
    round: Round,
    signing_provider: &Ed25519Provider,
    proposer: TestAddress,
) -> eyre::Result<()> {
    use malachitebft_engine::util::streaming::{Sequence, StreamContent};

    // Build deterministic stream id
    let mut id_bytes = Vec::with_capacity(16);
    id_bytes.extend_from_slice(&height.as_u64().to_be_bytes());
    id_bytes.extend_from_slice(&(round.as_i64() as u64).to_be_bytes());
    let stream_id = StreamId::new(Bytes::from(id_bytes));

    // Serialize the pending block
    let block_bytes = {
        let state = state_arc
            .lock()
            .map_err(|e| eyre!("Mutex lock failed for streaming: {}", e))?;
        let block = state.get_pending_block()?;
        serde_json::to_vec(&block)?
    };

    let mut sequence: Sequence = 0;

    // --- Init part ---
    let init_part = ProposalPart::Init(ProposalInit::new(height, round, Round::Nil, proposer));
    let init_msg = StreamMessage::new(stream_id.clone(), sequence, StreamContent::Data(init_part));
    channels
        .network
        .send(NetworkMsg::PublishProposalPart(init_msg))
        .await?;
    sequence += 1;

    // --- Data parts --- first send length then bytes split in u64 chunks
    let mut hasher = Keccak256::new();
    hasher.update(height.as_u64().to_be_bytes());
    hasher.update(round.as_i64().to_be_bytes());

    let len_part = ProposalPart::Data(ProposalData::new(block_bytes.len() as u64));
    hasher.update((block_bytes.len() as u64).to_be_bytes());
    let len_msg = StreamMessage::new(stream_id.clone(), sequence, StreamContent::Data(len_part));
    channels
        .network
        .send(NetworkMsg::PublishProposalPart(len_msg))
        .await?;
    sequence += 1;

    for chunk in block_bytes.chunks(8) {
        let mut arr = [0u8; 8];
        arr[..chunk.len()].copy_from_slice(chunk);
        let num = u64::from_be_bytes(arr);
        hasher.update(num.to_be_bytes());
        let data_part = ProposalPart::Data(ProposalData::new(num));
        let data_msg =
            StreamMessage::new(stream_id.clone(), sequence, StreamContent::Data(data_part));
        channels
            .network
            .send(NetworkMsg::PublishProposalPart(data_msg))
            .await?;
        sequence += 1;
    }

    // Compute signature
    let hash = hasher.finalize();
    let signature = signing_provider.sign(&hash);
    let fin_part = ProposalPart::Fin(ProposalFin::new(signature));
    let fin_msg = StreamMessage::new(stream_id.clone(), sequence, StreamContent::Data(fin_part));
    channels
        .network
        .send(NetworkMsg::PublishProposalPart(fin_msg))
        .await?;

    // Send explicit FIN marker
    let fin_marker = StreamMessage::new(stream_id, sequence + 1, StreamContent::Fin);
    channels
        .network
        .send(NetworkMsg::PublishProposalPart(fin_marker))
        .await?;

    Ok(())
}

fn factors_to_bytes(factors: &[u64]) -> Vec<u8> {
    if factors.is_empty() {
        return Vec::new();
    }
    let total_len = factors[0] as usize;
    // Build bytes from factors; avoid reserving unbounded capacity from untrusted input
    let mut bytes = Vec::new();
    for &num in factors.iter().skip(1) {
        bytes.extend_from_slice(&num.to_be_bytes());
    }
    bytes.truncate(total_len);
    bytes
}
