use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use eyre::eyre;
use tokio::task::JoinHandle;
use tracing::{Instrument, debug, error, info, warn};

use crate::config::AuraNodeConfig as AuraAppNodeConfig;
use crate::state::AuraState;

// --- Malachite App Imports ---
use malachitebft_app::events::{RxEvent, TxEvent};
use malachitebft_app::node::{
    EngineHandle, Node as MalachiteAppNode, NodeConfig, NodeHandle as MalachiteAppNodeHandle,
};

use malachitebft_engine::util::streaming::StreamContent;

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
use malachitebft_test::{
    Address as TestAddress, Ed25519Provider, Genesis as TestGenesis,
    Height as TestHeight, PrivateKey as TestPrivateKey, PublicKey as TestPublicKey, TestContext, ValidatorSet as TestValidatorSet, Value as TestValue, codec::proto::ProtobufCodec,
};

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
}

#[async_trait]
impl MalachiteAppNodeHandle<TestContext> for AuraNodeRunningHandle {
    fn subscribe(&self) -> RxEvent<TestContext> {
        self.tx_event.subscribe()
    }
    async fn kill(&self, _reason: Option<String>) -> eyre::Result<()> {
        self.engine_handle.actor.kill_and_wait(None).await?;
        self.app_logic_handle.abort();
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
            self
                .aura_app_config
                .db_path
                .file_name()
                .expect("App DB path should have a filename"),
        );
        fs::create_dir_all(app_state_db_path.parent().unwrap_or_else(|| Path::new(".")))?;
        let app_state = AuraState::new(app_state_db_path, self._app_level_private_key.clone())
            .map_err(|e| eyre!("Failed to create AuraState: {}", e))?;
        let app_state_arc = Arc::new(Mutex::new(app_state));

        info!("Calling malachitebft_app_channel::start_engine...");
        let (channels, engine_handle) = malachite_start_engine(
            aura_malachite_ctx.clone(),
            codec,
            self.clone(),
            malachite_config.clone(),
            None,
            initial_validator_set,
        )
        .await?;
        info!("Malachite engine started via app-channel.");

        let tx_event_channel = channels.events.clone();
        let app_logic_task_span =
            tracing::info_span!("app_message_loop", moniker = %malachite_config.moniker);
        let app_logic_handle = tokio::spawn(async move {
            if let Err(e) = app_message_loop(app_state_arc, aura_malachite_ctx, channels)
                .instrument(app_logic_task_span)
                .await
            {
                error!(?e, "Application message loop exited with error");
            }
        });
        info!("Spawned application message loop task.");

        Ok(AuraNodeRunningHandle {
            app_logic_handle,
            engine_handle,
            tx_event: tx_event_channel,
        })
    }

    async fn run(self) -> eyre::Result<()> {
        let handles = self.start().await?;
        handles.app_logic_handle.await.map_err(Into::into)
    }
}

async fn app_message_loop(
    app_state_arc: Arc<Mutex<AuraState>>,
    _ctx: TestContext,
    mut channels: Channels<TestContext>,
) -> eyre::Result<()> {
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
                        let validator_set = TestValidatorSet::new(vec![]);
                        info!(%start_height, "AppLoop: Consensus is ready. Replying with StartHeight.");
                        if reply.send((start_height, validator_set)).is_err() {
                            error!("AppLoop: Failed to send ConsensusReady reply (StartHeight)");
                        }
                    }
                    AppMsg::StartedRound { height, round, proposer, reply_value } => {
                        let mut state_guard = app_state_arc.lock().map_err(|e| eyre!("Mutex lock failed for StartedRound: {}", e))?;
                        state_guard.current_height = height.as_u64();
                        state_guard.current_round = round;
                        info!(%height, %round, %proposer, "AppLoop: Started round.");
                         if reply_value.send(Vec::new()).is_err() {
                            error!("AppLoop: Failed to send reply for StartedRound (value reply)");
                         }
                    }
                    AppMsg::GetValue { height, round, reply, .. } => {
                        info!(%height, %round, "AppLoop: Consensus requesting a value (block) to propose.");

                        let test_value = TestValue::new(height.as_u64());

                        let locally_proposed_value = LocallyProposedValue {
                            height,
                            round,
                            value: test_value,
                        };

                        if reply.send(locally_proposed_value).is_err() {
                            error!("AppLoop: Failed to send GetValue reply (LocallyProposedValue)");
                        }

                        warn!("AppLoop: TODO: Implement streaming of AuraInternalBlock as TestProposalParts for GetValue");

                    }
                    AppMsg::ReceivedProposalPart { from, part, reply } => {
                        let part_type_str = match &part.content {
                            StreamContent::Data(p) => format!("{:?}", p),
                            StreamContent::Fin => "Fin".to_string(),
                        };
                        info!(peer_id = %from, sequence = %part.sequence, part_type = %part_type_str, "AppLoop: Received proposal part.");
                        if reply.send(None).is_err() {
                             error!("AppLoop: Failed to send ReceivedProposalPart reply");
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
                                let validator_set = TestValidatorSet::new(vec![]);
                                info!("AppLoop: Commit successful. Replying to start next height: {}", next_height);
                                if reply.send(ConsensusMsg::StartHeight(next_height, validator_set)).is_err() {
                                    error!("AppLoop: Failed to send Decided reply (StartHeight)");
                                }
                            }
                            Err(e) => {
                                error!("AppLoop: Commit failed after Decided: {:?}. Requesting restart for height {}.", e, state_guard.pending_block_height);
                                let current_pending_height = TestHeight::new(state_guard.pending_block_height);
                                let validator_set = TestValidatorSet::new(vec![]);
                                if reply.send(ConsensusMsg::RestartHeight(current_pending_height, validator_set)).is_err() {
                                     error!("AppLoop: Failed to send Decided reply (RestartHeight)");
                                }
                            }
                        }
                    }
                    AppMsg::ExtendVote { reply, .. } => {
                        if reply.send(None).is_err() { error!("AppLoop: Failed to send ExtendVote reply"); }
                    }
                    AppMsg::VerifyVoteExtension { reply, .. } => {
                        if reply.send(Ok(())).is_err() { error!("AppLoop: Failed to send VerifyVoteExtension reply");}
                    }
                    AppMsg::GetValidatorSet { height, reply } => {
                        info!("AppLoop: GetValidatorSet called for height {}", height);
                        let vs_placeholder = TestValidatorSet::new(vec![]);
                        if reply.send(Some(vs_placeholder)).is_err() {
                            error!("AppLoop: Failed to send GetValidatorSet reply");
                        }
                    }
                    AppMsg::GetHistoryMinHeight { reply } => {
                         info!("AppLoop: GetHistoryMinHeight called");
                        let min_h_placeholder = TestHeight::new(0);
                        if reply.send(min_h_placeholder).is_err() {
                             error!("AppLoop: Failed to send GetHistoryMinHeight reply");
                        }
                    }
                     AppMsg::GetDecidedValue { height, reply } => {
                        info!("AppLoop: GetDecidedValue called for height {}", height);
                        if reply.send(None).is_err() {
                            error!("AppLoop: Failed to send GetDecidedValue reply");
                        }
                    }
                    AppMsg::ProcessSyncedValue { height, round, proposer, value_bytes, reply } => {
                        info!(%height, %round, "AppLoop: Processing synced value ({} bytes)", value_bytes.len());
                        let placeholder_value = TestValue::new(height.as_u64());
                        let proposed = ProposedValue {
                            height,
                            round,
                            valid_round: Round::Nil,
                            proposer,
                            value: placeholder_value,
                            validity: Validity::Valid,
                        };
                        if reply.send(proposed).is_err() {
                           error!("AppLoop: Failed to send ProcessSyncedValue reply");
                        }
                    }
                    _ => { warn!("AppLoop: Unhandled AppMsg variant: {}", msg_type_name(&msg));}
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
